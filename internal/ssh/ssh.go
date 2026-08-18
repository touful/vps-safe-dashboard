// Package ssh 实现 M-03 SSH 登录解析模块（方案 3.3）。
// 数据源双分支：journald（journalctl -f -o json 流式，默认）| rsyslog（tail -F auth.log，分支 B1）。
package ssh

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"sentry-agent/internal/event"
)

// RunSSHParser 流式解析 SSH 认证日志，产出每次登录尝试（方案 3.3 签名 + sys 通道）。
// source: journald | rsyslog。journald 模式依赖 journalctl 二进制（纯 Go journal 解析器
// 为容器形态 V1b-2 验证项，M4 前按方案 6.4.4 排期实现或引入解析库，接口不变）。
//
// 配置联动说明：config 的 ssh.verbose_fingerprint（默认 true）为部署侧要求
// （sshd LogLevel VERBOSE，部署脚本写入 /etc/ssh/sshd_config.d/99-verbose.conf），
// 解析器本身不因该配置改变行为——日志中无指纹时 Fingerprint 字段自然留空
// （用户拒绝 VERBOSE 时指纹恒为空，结果/用户/方式仍记录，符合方案 3.3）。
func RunSSHParser(ctx context.Context, source string, sink chan<- event.SSHAttempt, sys chan<- event.SystemEvent) error {
	rep := event.NewRateLimiter(time.Minute)
	switch source {
	case "journald":
		return runJournald(ctx, sink, sys, rep)
	case "rsyslog":
		return runRsyslog(ctx, sink, sys, rep)
	default:
		return fmt.Errorf("未知 ssh.source=%q", source)
	}
}

// runJournald 通过 journalctl -f -o json SYSLOG_IDENTIFIER=sshd 流式读取 SSH 认证日志。
func runJournald(ctx context.Context, sink chan<- event.SSHAttempt, sys chan<- event.SystemEvent, rep *event.RateLimiter) error {
	journalctl, err := exec.LookPath("journalctl")
	if err != nil {
		return fmt.Errorf("journald 模式需要 journalctl 二进制（不可用时请改用 ssh.source=rsyslog）: %w", err)
	}
	cmd := exec.CommandContext(ctx, journalctl, "-f", "-n", "0", "-o", "json", "SYSLOG_IDENTIFIER=sshd")
	// 注：-n 0 防止启动时重放历史条目（M2 落库防重复入库）；若需启动补历史应显式设计 cursor 续读。
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("journalctl stdout 管道创建失败: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("journalctl 启动失败: %w", err)
	}
	scanner := bufio.NewScanner(pipe)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		entry, err := parseJournalLine(scanner.Bytes())
		if err != nil {
			continue // 非 JSON 行（如 journalctl 自身输出），跳过
		}
		handleLine(ctx, sink, sys, rep, entry.Message, entry.ts())
	}
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return nil // 正常退出（ctx 取消）
	}
	return fmt.Errorf("journalctl 流提前结束: %w", waitErr)
}

// runRsyslog 通过 tail -F -n 0 /var/log/auth.log 流式读取（分支 B1，rsyslog/syslogd 落盘）。
// tail -F 语义：文件轮转（rename）后自动跟随新文件，不追溯历史。
func runRsyslog(ctx context.Context, sink chan<- event.SSHAttempt, sys chan<- event.SystemEvent, rep *event.RateLimiter) error {
	tail, err := exec.LookPath("tail")
	if err != nil {
		return fmt.Errorf("rsyslog 模式需要 tail 二进制: %w", err)
	}
	cmd := exec.CommandContext(ctx, tail, "-F", "-n", "0", "/var/log/auth.log")
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("tail stdout 管道创建失败: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("tail 启动失败: %w", err)
	}
	scanner := bufio.NewScanner(pipe)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		ts := time.Now().Unix()
		if t, ok := parseSyslogTimestamp(line); ok {
			ts = t // 使用日志行内时间戳（rsyslog 模式；journald 模式由条目时间戳提供）
		}
		handleLine(ctx, sink, sys, rep, line, ts)
	}
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return nil
	}
	return fmt.Errorf("tail 流提前结束: %w", waitErr)
}

// handleLine 对单行做匹配解析；匹配则发送，不匹配限频上报（方案 3.3：限频 1/分钟）。
func handleLine(ctx context.Context, sink chan<- event.SSHAttempt, sys chan<- event.SystemEvent, rep *event.RateLimiter, line string, ts int64) {
	attempt, ok := ParseSSHLine(line, ts)
	if !ok {
		rep.Report(sys, "ssh", "info", "无法匹配的 SSH 日志行（已忽略）: "+event.Truncate512(line))
		return
	}
	select {
	case sink <- attempt:
	case <-ctx.Done():
	}
}

// journalEntry journalctl -o json 输出的条目（仅取所需字段）。
type journalEntry struct {
	Message        string `json:"MESSAGE"`
	SourceRealtime string `json:"_SOURCE_REALTIME_TIMESTAMP"` // 微秒字符串
	Realtime       string `json:"__REALTIME_TIMESTAMP"`       // 微秒字符串
}

// parseJournalLine 解析 journalctl JSON 行。
func parseJournalLine(data []byte) (journalEntry, error) {
	var e journalEntry
	if err := json.Unmarshal(data, &e); err != nil {
		return e, err
	}
	return e, nil
}

// ts 提取条目时间戳（Unix 秒）：优先源侧时间戳，缺失用接收时间，再缺失用当前时间。
func (e *journalEntry) ts() int64 {
	if v, ok := event.MicrosToUnix(e.SourceRealtime); ok {
		return v
	}
	if v, ok := event.MicrosToUnix(e.Realtime); ok {
		return v
	}
	return time.Now().Unix()
}
