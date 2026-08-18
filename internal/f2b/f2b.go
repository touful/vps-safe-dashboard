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
// 已知限制（现场核查结论 1）：容器环境日志 640 root:systemd-journal
// 对 user 1000 不可读，本监听会启动失败并留痕（不阻塞名单查询——名单走 sqlite）。
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
	return fmt.Errorf("fail2ban 日志流提前结束: %w", waitErr)
}

// BannedQueryError 封禁名单查询分类错误（探测式适配，按根因分类）。
// Kind 取值：
//   - "unreadable"：库不可访问（打开/探测失败）——空目录挂载（Docker bind mount 源不存在
//     形态）、权限/ACL 缺失、路径错位（附检查建议）
//   - "empty"：bips/bans 表均不存在——库为空/未初始化（dbfile 配置未生效）、0.9.x 及更早无 sqlite 库
//   - "schema"：表存在但缺 ip 列（或 bips 缺 timeofban/bantime 无法活跃判定时回退 bans）——
//     未知版本结构差异（附 PRAGMA table_info 摘要）
//   - "hotjournal"：库处于 hot journal 待恢复状态（崩溃/断电残留），只读打开失败——
//     本次返回空名单，下轮自动重试（现场核查结论 5）
type BannedQueryError struct {
	Kind string
	Msg  string
	Err  error
}

func (e *BannedQueryError) Error() string { return e.Msg }
func (e *BannedQueryError) Unwrap() error { return e.Err }

// readonlyRecoveryCode SQLITE_READONLY_RECOVERY 扩展错误码（SQLITE_READONLY | (1<<8) = 264）：
// hot journal（进程崩溃/断电残留未恢复日志）场景只读打开可能触发（DEV-032 现场核查结论 5；
// 实测 modernc v1.56.0 Windows/Linux 均不触发、直接读主库，此处防御驱动/版本/环境差异）。
const readonlyRecoveryCode = 264

// bipsActiveWhere bips 表活跃封禁判定 WHERE 片段（现场核查结论 3/5）：
//   - bantime = -1：永久封禁恒保留（豁免，必须）
//   - bantime IS NULL：schema 无 NOT NULL，理论可为 NULL——未知时长保守保留（防漏报，不误删）
//   - timeofban IS NULL：schema 无 NOT NULL，理论可为 NULL——未知封禁时刻保守保留
//     （与 bantime NULL 豁免对称，防漏报）
//   - timeofban + bantime > ?：未过期保留（now 为 Unix 秒参数）
//   - 其余（已过期/异常残留）：过滤。bans 非历史表（unban 即删行，结论 6），bips 同理双删。
const bipsActiveWhere = `bantime = -1 OR bantime IS NULL OR timeofban IS NULL OR (timeofban + bantime) > ?`

// QueryBanned 探测式查询 fail2ban.sqlite3 当前封禁名单（方案 3.5，每 60s 刷新）。
// 只读打开（mode=ro + busy_timeout=5000，缓解 fail2ban 写库瞬间 SQLITE_BUSY）。
// 数据源（现场核查结论 1）：只能走 sqlite——日志 640 root:systemd-journal
// 容器 user 1000 不可读，不能走日志解析；库 644 root:root 可读。
// 表结构（结论 2）：fail2ban 1.x 五表结构，封禁记录在 bans 与 bips 双表（addBan/delBan
// 双写双删）；bips 列 ip/jail/timeofban/bantime/bancount/data（ip+jail 唯一）。
// 查询策略（结论 2/3/6）：优先 bips 表（含 bantime，支持活跃判定与异常残留过滤）；
// bips 缺失或缺 timeofban/bantime 列时回退 bans 表（0.10.x 兼容：unban 即删行，行即当前
// 封禁集合，仅依赖 ip 列，无 bantime 可做时间过滤）。
// 防御（结论 5）：hot journal 场景 mode=ro 可能报 SQLITE_READONLY_RECOVERY——降级为空名单
// （Kind=hotjournal，调用方 info 级留痕），下轮 60s 重试，不崩溃。
// 错误按根因分类（BannedQueryError.Kind），调用方告警携带分类与修复指引。
// 已知限制：IPv6 封禁地址跳过（BanEvent.IP 为 uint32，M2 记录）。
func QueryBanned(ctx context.Context, dbPath string) ([]uint32, error) {
	db, err := sql.Open("sqlite", readOnlyDSN(dbPath))
	if err != nil {
		return nil, &BannedQueryError{Kind: "unreadable", Msg: fmt.Sprintf("打开 fail2ban 库失败: %v", err), Err: err}
	}
	defer db.Close()
	// 探测 1：bips 表（fail2ban 1.x，含 bantime 列支持活跃判定）。
	if ok, err := tableExists(ctx, db, "bips"); err != nil {
		return nil, classifyQueryErr(err, "探测 fail2ban 库表结构失败")
	} else if ok {
		return queryBannedBips(ctx, db)
	}
	// 探测 2：bans 表（0.10.x 兼容回退；unban 即删行，SELECT DISTINCT ip 即当前封禁集合）。
	return queryBannedBans(ctx, db)
}

// queryBannedBips 从 bips 表查询当前封禁（fail2ban 1.x 标准结构）。
// 列探测：缺 ip 列 → schema 错误；缺 timeofban/bantime（未知版本）→ 回退 bans 路径。
func queryBannedBips(ctx context.Context, db *sql.DB) ([]uint32, error) {
	cols, err := tableColumns(ctx, db, "bips")
	if err != nil {
		return nil, classifyQueryErr(err, "读取 bips 表结构失败")
	}
	if !containsStr(cols, "ip") {
		return nil, &BannedQueryError{Kind: "schema",
			Msg: fmt.Sprintf("fail2ban bips 表结构不兼容（缺 ip 列，实际列: %v）——请现场核查 schema 并反馈 fail2ban 版本号", cols),
			Err: nil}
	}
	if !containsStr(cols, "timeofban") || !containsStr(cols, "bantime") {
		// 无 bantime 无法活跃判定：回退 bans 路径（bans 行=当前封禁集合，双表双写语义）。
		return queryBannedBans(ctx, db)
	}
	// 标准结构：活跃判定查询（bantime=-1 永久豁免 / NULL 保守保留 / 未过期保留 / 残留过滤）。
	// DISTINCT：bips UNIQUE(ip, jail)，同 IP 可同时封禁于多个 jail
	// （如 sshd + recidive）——按 IP 去重，与 bans 回退路径口径一致。
	rows, err := db.QueryContext(ctx, `SELECT DISTINCT ip FROM bips WHERE `+bipsActiveWhere, time.Now().Unix())
	if err != nil {
		return nil, classifyQueryErr(err, "查询 bips 表失败（fail2ban 库结构兼容性）")
	}
	defer rows.Close()
	out, err := scanBannedIPs(rows)
	if err != nil {
		return nil, classifyQueryErr(err, "读取 bips 行失败")
	}
	return out, nil
}

// queryBannedBans 从 bans 表查询当前封禁（0.10.x 兼容回退路径）。
// 探测存在性与 ip 列；bans 无 bantime 列，行即当前封禁集合（unban 即删行），全量返回。
func queryBannedBans(ctx context.Context, db *sql.DB) ([]uint32, error) {
	ok, err := tableExists(ctx, db, "bans")
	if err != nil {
		return nil, classifyQueryErr(err, "探测 fail2ban 库表结构失败")
	}
	if !ok {
		return nil, &BannedQueryError{Kind: "empty",
			Msg: "fail2ban 库未初始化或为空（bips/bans 表均不存在）：请宿主确认 fail2ban.conf 的 dbfile 配置已生效并重启 fail2ban 触发建表，或重跑 install_fail2ban.sh 的 ACL 设置（fail2ban 0.9.x 及更早无 sqlite 库，不适用）",
			Err: nil}
	}
	cols, err := tableColumns(ctx, db, "bans")
	if err != nil {
		return nil, classifyQueryErr(err, "读取 bans 表结构失败")
	}
	if !containsStr(cols, "ip") {
		return nil, &BannedQueryError{Kind: "schema",
			Msg: fmt.Sprintf("fail2ban bans 表结构不兼容（缺 ip 列，实际列: %v）——请现场核查 schema 并反馈 fail2ban 版本号", cols),
			Err: nil}
	}
	rows, err := db.QueryContext(ctx, `SELECT DISTINCT ip FROM bans`)
	if err != nil {
		return nil, classifyQueryErr(err, "查询 bans 表失败（fail2ban 库结构兼容性）")
	}
	defer rows.Close()
	out, err := scanBannedIPs(rows)
	if err != nil {
		return nil, classifyQueryErr(err, "读取 bans 行失败")
	}
	return out, nil
}

// scanBannedIPs 遍历查询结果：IPv4 转 uint32；IPv6 跳过（字段限制）。
func scanBannedIPs(rows *sql.Rows) ([]uint32, error) {
	var out []uint32
	for rows.Next() {
		var ipStr string
		if err := rows.Scan(&ipStr); err != nil {
			// 分类一致性：扫描错误归 unreadable（罕见路径：列类型异常）。
			return nil, fmt.Errorf("读取封禁行失败: %w", err)
		}
		ip := net.ParseIP(ipStr)
		if ip == nil || ip.To4() == nil {
			continue // IPv6 跳过（字段限制）
		}
		out = append(out, event.IPv4ToUint32(ip))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("遍历封禁行失败: %w", err)
	}
	return out, nil
}

// tableExists 判断表是否存在（sqlite_master，表名参数化）。
func tableExists(ctx context.Context, db *sql.DB, table string) (bool, error) {
	var name string
	err := db.QueryRowContext(ctx, `SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&name)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return false, err
}

// sqliteCodeError SQLite 扩展错误码提取接口（modernc *sqlite.Error 实现 Code() 方法；
// 接口化便于单测构造，不依赖驱动具体类型）。
type sqliteCodeError interface{ Code() int }

// classifyQueryErr 查询类错误分类（现场核查结论 5）：
// hot journal 场景（SQLITE_READONLY_RECOVERY=264）→ Kind=hotjournal（调用方 info 级留痕，
// 返回空名单，下轮 60s 重试，不崩溃）；其余归 unreadable。
func classifyQueryErr(err error, msg string) error {
	var ce sqliteCodeError
	if errors.As(err, &ce) && ce.Code() == readonlyRecoveryCode {
		return &BannedQueryError{Kind: "hotjournal",
			Msg: "fail2ban 库处于 hot journal 待恢复状态（崩溃/断电残留），本次返回空名单，60s 后自动重试；宿主可用读写方式打开一次触发恢复（重启 fail2ban 亦会恢复）",
			Err: err}
	}
	return &BannedQueryError{Kind: "unreadable", Msg: msg + ": " + err.Error(), Err: err}
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

// readOnlyDSN 构造只读 DSN：路径 URL 编码（PathEscape 保留 '/'，转义 '?'/'#' 等），
// 追加 mode=ro + busy_timeout=5000（缓解 fail2ban 写库瞬间 SQLITE_BUSY）。
// URI 解析由 modernc 驱动自动启用（file: 前缀即触发；实证：只读写拒绝、busy_timeout 生效）。
func readOnlyDSN(path string) string {
	return "file:" + url.PathEscape(path) + "?mode=ro&_pragma=busy_timeout(5000)"
}
