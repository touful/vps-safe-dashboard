// Package fw 实现 M-04 防火墙日志解析模块（方案 3.4）。
// 流式解析内核日志中的 SENTRY_FW 前缀行（nft/iptables LOG），产出结构化防火墙事件。
//
// 口径警示（方案 3.4 与验收标准 C-03 强制要求）：
// 攻击端口统计（"被攻击端口 TOP"）只允许使用本模块 FirewallEvent.DPT 字段；
// SSH 认证日志中的 port 字段是客户端源端口，不是被攻击端口，禁止混用。
package fw

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"sentry-agent/internal/event"
)

// RunFwParser 流式解析内核日志（方案 3.4 签名 + sys 通道）。
// source: journald-kernel（journalctl -f -o json -k，默认）| kmsg（/dev/kmsg，分支 B1）。
// 仅处理包含 prefix 的行，其余内核日志行忽略。
// filter 为采集层来源过滤（DEV-031 优化②：内网/自身来源事件发送前丢弃）。
func RunFwParser(ctx context.Context, source, prefix string, filter FwFilter, sink chan<- event.FirewallEvent, sys chan<- event.SystemEvent) error {
	rep := event.NewRateLimiter(time.Minute)
	stats := newFilterStats()
	switch source {
	case "journald-kernel":
		return runJournaldKernel(ctx, prefix, filter, stats, sink, sys, rep)
	case "kmsg":
		return runKmsg(ctx, prefix, filter, stats, sink, sys, rep)
	default:
		return fmt.Errorf("未知 fw.source=%q", source)
	}
}

// journalKernelEntry journalctl -o json -k 输出的条目字段。
type journalKernelEntry struct {
	Message  string `json:"MESSAGE"`
	Realtime string `json:"__REALTIME_TIMESTAMP"` // 微秒字符串
}

// runJournaldKernel 通过 journalctl -f -o json -k 读取内核日志（含 nft/iptables LOG 输出）。
func runJournaldKernel(ctx context.Context, prefix string, filter FwFilter, stats *filterStats, sink chan<- event.FirewallEvent, sys chan<- event.SystemEvent, rep *event.RateLimiter) error {
	journalctl, err := exec.LookPath("journalctl")
	if err != nil {
		return fmt.Errorf("journald-kernel 模式需要 journalctl 二进制（不可用时请改用 fw.source=kmsg）: %w", err)
	}
	cmd := exec.CommandContext(ctx, journalctl, "-f", "-n", "0", "-o", "json", "-k")
	// 注：-n 0 防止启动时重放历史内核日志（避免历史 SENTRY_FW 行重复入流）。
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
		var e journalKernelEntry
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			continue
		}
		// 时间戳：journal 微秒转 Unix 秒；空串/非数字回退当前时间。
		ts := time.Now().Unix()
		if v, ok := event.MicrosToUnix(e.Realtime); ok {
			ts = v
		}
		handleLine(ctx, sink, sys, rep, e.Message, ts, prefix, filter, stats)
	}
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return nil
	}
	return fmt.Errorf("journalctl -k 流提前结束: %w", waitErr)
}

// runKmsg 直接读取 /dev/kmsg（分支 B1，非 systemd 环境；需特权访问）。
// 防重放（tester D-07 / auditor m-03）：打开后先排空环形缓冲历史到当前尾部，
// 仅解析之后的实时消息——"注入 N 条仅产出 N 条"。
// 可取消读（tester D-08）：非阻塞读 + 轮询，ctx 取消可及时退出。
// 具体实现平台分离（unix 包仅 Linux 可编译）：fw_kmsg_linux.go / fw_kmsg_other.go。
func runKmsg(ctx context.Context, prefix string, filter FwFilter, stats *filterStats, sink chan<- event.FirewallEvent, sys chan<- event.SystemEvent, rep *event.RateLimiter) error {
	return kmsgReadLoop(ctx, func(line string) {
		handleLine(ctx, sink, sys, rep, line, time.Now().Unix(), prefix, filter, stats)
	})
}

// handleLine 处理单行内核日志：前缀匹配则解析发送；前缀匹配但解析失败限频告警；非前缀行忽略。
// DEV-031 优化②：解析成功后、入队前执行采集层来源过滤（内网/自身来源丢弃并留痕）。
func handleLine(ctx context.Context, sink chan<- event.FirewallEvent, sys chan<- event.SystemEvent, rep *event.RateLimiter, line string, ts int64, prefix string, filter FwFilter, stats *filterStats) {
	if !strings.Contains(line, prefix) {
		return // 非 SENTRY_FW 前缀行，忽略（方案 3.4：仅处理该前缀行）
	}
	ev, ok := ParseFWLine(line, prefix)
	if !ok {
		rep.Report(sys, "fw", "warn", "前缀匹配但解析失败的内核日志行: "+event.Truncate512(line))
		return
	}
	ev.TS = ts
	if filter.ShouldDrop(ev) {
		if stats != nil {
			stats.drop(sys)
		}
		return // 采集层过滤：内网/自身来源不进事件流（B.2.1：API/导出全链路自动干净）
	}
	select {
	case sink <- ev:
	case <-ctx.Done():
	}
}
