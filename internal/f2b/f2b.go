// Package f2b 实现 M-05 攻击态势聚合（fail2ban 只读集成，方案 3.5）。
// M2 完成：日志流式监听（Ban/Unban/Found 行解析入队）+ 封禁名单只读查询（QueryBanned）。
package f2b

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
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

// BannedQueryError 封禁名单查询分类错误（DEV-031 优化①：探测式适配，按根因分类）。
// Kind 取值：
//   - "unreadable"：库不可访问（打开/探测失败）——空目录挂载（Docker bind mount 源不存在
//     形态）、权限/ACL 缺失、路径错位（附检查建议）
//   - "empty"：bans 表不存在——库为空/未初始化（dbfile 配置未生效）、0.9.x 及更早无 sqlite 库
//   - "schema"：bans 表存在但缺 ip 列——未知版本结构差异（附 PRAGMA table_info 摘要）
type BannedQueryError struct {
	Kind string
	Msg  string
	Err  error
}

func (e *BannedQueryError) Error() string { return e.Msg }
func (e *BannedQueryError) Unwrap() error { return e.Err }

// QueryBanned 探测式查询 fail2ban.sqlite3 当前封禁名单（方案 3.5，每 60s 刷新）。
// 只读打开（mode=ro + busy_timeout=5000，缓解 fail2ban 写库瞬间 SQLITE_BUSY）。
// 兼容策略（B.1.2）：不猜根因——先探测 bans 表存在性（sqlite_master），再探测列
// （PRAGMA table_info），按实际列构造查询；适配 fail2ban 0.10.x~1.x 常见结构
// （bans(jail, ip, timeofban)，unban 时行被删除——SELECT DISTINCT ip FROM bans
// 即当前封禁集合，仅依赖 ip 列，不要求 timeofban 齐备，R-06）。
// 错误按根因分类（BannedQueryError.Kind），调用方告警携带分类与修复指引。
// 已知限制：IPv6 封禁地址跳过（BanEvent.IP 为 uint32，M2 记录）。
func QueryBanned(ctx context.Context, dbPath string) ([]uint32, error) {
	db, err := sql.Open("sqlite", readOnlyDSN(dbPath))
	if err != nil {
		return nil, &BannedQueryError{Kind: "unreadable", Msg: fmt.Sprintf("打开 fail2ban 库失败: %v", err), Err: err}
	}
	defer db.Close()
	// 探测 1：bans 表是否存在（sqlite_master）。
	var tableName string
	err = db.QueryRowContext(ctx, `SELECT name FROM sqlite_master WHERE type='table' AND name='bans'`).Scan(&tableName)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, &BannedQueryError{Kind: "empty",
				Msg: "fail2ban 库未初始化或为空（bans 表不存在）：请宿主确认 fail2ban.conf 的 dbfile 配置已生效并重启 fail2ban 触发建表，或重跑 install_fail2ban.sh 的 ACL 设置（fail2ban 0.9.x 及更早无 sqlite 库，不适用）",
				Err: err}
		}
		return nil, &BannedQueryError{Kind: "unreadable", Msg: fmt.Sprintf("探测 fail2ban 库表结构失败: %v", err), Err: err}
	}
	// 探测 2：bans 表列结构（PRAGMA table_info，兼容版本差异）。
	cols, err := tableColumns(ctx, db, "bans")
	if err != nil {
		return nil, &BannedQueryError{Kind: "unreadable", Msg: fmt.Sprintf("读取 bans 表结构失败: %v", err), Err: err}
	}
	if !containsStr(cols, "ip") {
		return nil, &BannedQueryError{Kind: "schema",
			Msg:  fmt.Sprintf("fail2ban bans 表结构不兼容（缺 ip 列，实际列: %v）——请现场核查 schema 并反馈 fail2ban 版本号", cols),
			Err:  nil}
	}
	rows, err := db.QueryContext(ctx, `SELECT DISTINCT ip FROM bans`)
	if err != nil {
		return nil, &BannedQueryError{Kind: "unreadable", Msg: fmt.Sprintf("查询 bans 表失败（fail2ban 库结构兼容性）: %v", err), Err: err}
	}
	defer rows.Close()
	var out []uint32
	for rows.Next() {
		var ipStr string
		if err := rows.Scan(&ipStr); err != nil {
			// 分类一致性（reviewer R-05）：扫描错误归 unreadable（罕见路径：列类型异常）。
			return nil, &BannedQueryError{Kind: "unreadable", Msg: fmt.Sprintf("读取 bans 行失败: %v", err), Err: err}
		}
		ip := net.ParseIP(ipStr)
		if ip == nil || ip.To4() == nil {
			continue // IPv6 跳过（字段限制）
		}
		out = append(out, event.IPv4ToUint32(ip))
	}
	if err := rows.Err(); err != nil {
		return nil, &BannedQueryError{Kind: "unreadable", Msg: fmt.Sprintf("遍历 bans 表失败: %v", err), Err: err}
	}
	return out, nil
}

// tableColumns 读取表列名列表（PRAGMA table_info 输出摘要）。
func tableColumns(ctx context.Context, db *sql.DB, table string) ([]string, error) {
	rows, err := db.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var cid, name, typ string
		var notnull, pk int
		var dflt any // dflt_value 可为 NULL，用 any 接收
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			return nil, err
		}
		cols = append(cols, name)
	}
	return cols, rows.Err()
}

// containsStr 判断切片是否含指定字符串。
func containsStr(cols []string, want string) bool {
	for _, c := range cols {
		if c == want {
			return true
		}
	}
	return false
}

// readOnlyDSN 构造只读 DSN（A-11）：路径 URL 编码（PathEscape 保留 '/'，转义 '?'/'#' 等），
// 追加 mode=ro + busy_timeout=5000（DEV-031 优化①：缓解 fail2ban 写库瞬间 SQLITE_BUSY）。
func readOnlyDSN(path string) string {
	return "file:" + url.PathEscape(path) + "?mode=ro&_pragma=busy_timeout(5000)"
}
