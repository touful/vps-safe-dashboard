// Package f2b 实现 M-05 攻击态势聚合（fail2ban 只读集成，方案 3.5）。
// M2 完成：日志流式监听（Ban/Unban/Found 行解析入队）+ 封禁名单只读查询（QueryBanned）。
package f2b

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"os/exec"
	"time"

	_ "modernc.org/sqlite" // 纯 Go 驱动（与主库一致，CGO_ENABLED=0 兼容）

	"sentry-agent/internal/event"
)

// RunF2BListener 流式读取 fail2ban 日志，产出封禁事件（方案 3.5 签名 + sys 通道）。
// 实现：tail -F -n 0 子进程（轮转跟随，不追溯历史），逐行解析 Ban/Unban/Found。
func RunF2BListener(ctx context.Context, logPath string, sink chan<- event.BanEvent, sys chan<- event.SystemEvent) error {
	tail, err := exec.LookPath("tail")
	if err != nil {
		return fmt.Errorf("f2b 监听需要 tail 二进制: %w", err)
	}
	cmd := exec.CommandContext(ctx, tail, "-F", "-n", "0", logPath)
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
		if t, ok := ParseF2BTime(line); ok {
			ts = t // 使用日志行内时间戳（auditor m-01：与 ssh/fw 口径一致）
		}
		ev, ok := ParseF2BLine(line, ts)
		if !ok {
			continue // fail2ban.log 含大量非 Ban/Unban/Found 行，正常忽略
		}
		select {
		case sink <- ev:
		case <-ctx.Done():
		}
	}
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return nil
	}
	return fmt.Errorf("fail2ban 日志流提前结束: %v", waitErr)
}

// QueryBanned 查询 fail2ban.sqlite3 当前封禁名单（方案 3.5，每 60s 刷新）。
// 只读打开（mode=ro），fail2ban v1.x 的 bans 表：bans(jail, ip, timeofban)，
// unban 时行被删除——SELECT DISTINCT ip FROM bans 即当前封禁集合。
// 已知限制：fail2ban 版本差异（旧版无 sqlite 库 / 表名不同）返回错误由调用方记录；
// IPv6 封禁地址跳过（BanEvent.IP 为 uint32，M2 记录）。
// DSN 参数化（A-11，auditor Note）：路径含 '?'/'#' 等 DSN 特殊字符时须 URL 编码，
// 否则被 DSN 解析器误读（store 包 openDB 同规则）。
func QueryBanned(ctx context.Context, dbPath string) ([]uint32, error) {
	db, err := sql.Open("sqlite", readOnlyDSN(dbPath))
	if err != nil {
		return nil, fmt.Errorf("打开 fail2ban 库失败: %w", err)
	}
	defer db.Close()
	rows, err := db.QueryContext(ctx, `SELECT DISTINCT ip FROM bans`)
	if err != nil {
		return nil, fmt.Errorf("查询 bans 表失败（fail2ban 库结构兼容性）: %w", err)
	}
	defer rows.Close()
	var out []uint32
	for rows.Next() {
		var ipStr string
		if err := rows.Scan(&ipStr); err != nil {
			return nil, err
		}
		ip := net.ParseIP(ipStr)
		if ip == nil || ip.To4() == nil {
			continue // IPv6 跳过（字段限制）
		}
		out = append(out, event.IPv4ToUint32(ip))
	}
	return out, rows.Err()
}

// readOnlyDSN 构造只读 DSN（A-11）：路径 URL 编码（PathEscape 保留 '/'，转义 '?'/'#' 等），
// 追加 mode=ro 查询参数。
func readOnlyDSN(path string) string {
	return "file:" + url.PathEscape(path) + "?mode=ro"
}
