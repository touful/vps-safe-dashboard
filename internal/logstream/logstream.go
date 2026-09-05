// Package logstream 提供子进程日志流的公共消费骨架。
// ssh/fw/f2b 三包的日志源（journalctl/tail 子进程）为同一形态骨架：
// LookPath（调用方自持，含各自降级提示）→ CommandContext → StdoutPipe → Start →
// 1MB Scanner 逐行回调 → Wait 收尾。本包封装该骨架，调用方只保留命令构造
// 与行解析回调（解析纯函数仍在各包）。
// 流死亡处理：Run 单次消费（终止即返回错误）；RunRestarted 在其外层提供
// 限频自动重启（审计 M-1：流死亡不再静默停采，见函数注释）。
package logstream

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"time"
)

// maxLineSize 单行缓冲上限（1MB；与原各包 scanner.Buffer 配置一致，防超长行 OOM）。
const maxLineSize = 1024 * 1024

// Run 启动子进程并逐行消费其 stdout。
// name 标识日志源，用于三段错误文案（保持各调用方原文案语义）：
//   - "%s stdout 管道创建失败: ..."（管道创建失败）
//   - "%s 启动失败: ..."（Start 失败）
//   - "%s 流提前结束: ..."（ctx 未取消时流终止）
//
// 收尾语义（与原各包实现一致）：ctx 取消 → nil（正常退出）；
// 其余流终止 → 错误返回（不重启，由调用方上报留痕）。
func Run(ctx context.Context, cmd *exec.Cmd, name string, onLine func(line []byte)) error {
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("%s stdout 管道创建失败: %w", name, err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("%s 启动失败: %w", name, err)
	}
	scanner := bufio.NewScanner(pipe)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineSize)
	for scanner.Scan() {
		onLine(scanner.Bytes())
	}
	// scanner.Err() 检查（审计 C1）：单行超 maxLineSize 时 Scanner 以 ErrTooLong 停止，
	// 若不检查会被下方 waitErr（broken pipe）掩盖，排障时根因丢失。
	scanErr := scanner.Err()
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return nil // 正常退出（ctx 取消）
	}
	if scanErr != nil {
		return fmt.Errorf("%s 流读取失败: %w（后续流终止: %v）", name, scanErr, waitErr)
	}
	return fmt.Errorf("%s 流提前结束: %w", name, waitErr)
}

// 重启 backoff 参数（包级变量便于测试压缩时序）。
var (
	restartBaseBackoff = 2 * time.Second
	restartMaxBackoff  = time.Minute
)

// RunRestarted 包装 Run，提供流死亡限频自动重启（审计 M-1）。
// journalctl/tail 子进程可能因 OOM、日志轮转异常、管道断裂等意外终止；原策略
// "流死亡仅报错退出"会让对应通道采集静默冻结直至进程重启（conntrack 主通道
// 有重启防护而日志通道没有，不对称）。策略：
//   - 仅 ctx 取消为正常退出；其余终止按指数 backoff 重启（2s 起步、翻倍、60s 封顶）；
//   - 留痕限频：首次终止必报，此后每分钟最多一条（防刷屏 system_events），report
//     由调用方注入（各包 sys 通道；建议传独立限频器，避免与业务留痕互相挤占窗口）。
//
// LookPath 等"调用方前置检查"应留在本函数之外——持续性配置错误（二进制不存在）
// 由调用方直接返回，不进入无限重启循环。
func RunRestarted(ctx context.Context, name string, newCmd func() *exec.Cmd, onLine func([]byte), report func(msg string)) error {
	return runRestarted(ctx, name, newCmd, onLine, report, Run)
}

// runRestarted 可注入 run 的内部实现（测试用 fake 替换单次流消费）。
func runRestarted(ctx context.Context, name string, newCmd func() *exec.Cmd, onLine func([]byte), report func(msg string), run func(context.Context, *exec.Cmd, string, func([]byte)) error) error {
	const reportInterval = time.Minute
	backoff := restartBaseBackoff
	var lastReport time.Time
	first := true
	for {
		err := run(ctx, newCmd(), name, onLine)
		if ctx.Err() != nil {
			return nil // ctx 取消（含本轮 run 因取消而返回），正常退出
		}
		now := time.Now()
		if first || now.Sub(lastReport) >= reportInterval {
			report(err.Error())
			lastReport = now
		}
		first = false
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		if backoff < restartMaxBackoff {
			backoff *= 2
			if backoff > restartMaxBackoff {
				backoff = restartMaxBackoff
			}
		}
	}
}
