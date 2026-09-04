// Package logstream 提供子进程日志流的公共消费骨架。
// ssh/fw/f2b 三包的日志源（journalctl/tail 子进程）为同一形态骨架：
// LookPath（调用方自持，含各自降级提示）→ CommandContext → StdoutPipe → Start →
// 1MB Scanner 逐行回调 → Wait 收尾。本包封装该骨架，调用方只保留命令构造
// 与行解析回调（解析纯函数仍在各包）。
// 行为零变化：不引入流死亡自动重启（当前各包策略为"流死亡仅报错退出，由调用方决定后续"）。
package logstream

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
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
