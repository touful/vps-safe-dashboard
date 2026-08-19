package f2b

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"sentry-agent/internal/dbdsn"
)

// TestQueryBannedBipsNoTimeColsFallback：bips 存在但缺 timeofban/bantime（未知版本）
// 时回退 bans 路径（bans 行=当前封禁集合），不报 schema 错误。
func TestQueryBannedBipsNoTimeColsFallback(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "fail2ban.sqlite3")
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE bips (ip TEXT, jail TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE bans (jail TEXT NOT NULL, ip TEXT NOT NULL, timeofban INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO bans VALUES ('sshd','203.0.113.5',1)`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	got, err := QueryBanned(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("QueryBanned 失败: %v", err)
	}
	if len(got) != 1 || got[0] != 0xCB007105 {
		t.Errorf("bips 缺时间列应回退 bans 全量: %v", got)
	}
}

// TestQueryBannedSchemaMismatch 库存在但 bips/bans 表均无 → "empty" 分类错误（探测式适配：
// 库为空/未初始化或 fail2ban 0.9.x 及更早无 sqlite 库；附修复指引文案）。
func TestQueryBannedSchemaMismatch(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "fail2ban.sqlite3")
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE other (x TEXT)`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	_, err = QueryBanned(context.Background(), dbPath)
	if err == nil {
		t.Fatal("无 bips/bans 表应报错")
	}
	var qe *BannedQueryError
	if !errors.As(err, &qe) {
		t.Fatalf("错误类型 = %T, 期望 *BannedQueryError", err)
	}
	if qe.Kind != "empty" {
		t.Errorf("分类 = %q, 期望 empty（库未初始化/为空）", qe.Kind)
	}
	if !strings.Contains(qe.Msg, "未初始化") {
		t.Errorf("文案应含修复指引关键词（未初始化），实际: %s", qe.Msg)
	}
}

// TestQueryBannedEmptyDB 0 字节空库（dbfile 未生效形态）→ "empty" 分类错误。
func TestQueryBannedEmptyDB(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "fail2ban.sqlite3")
	if err := os.WriteFile(dbPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := QueryBanned(context.Background(), dbPath)
	if err == nil {
		t.Fatal("空库应报错")
	}
	var qe *BannedQueryError
	if !errors.As(err, &qe) {
		t.Fatalf("错误类型 = %T, 期望 *BannedQueryError", err)
	}
	if qe.Kind != "empty" {
		t.Errorf("分类 = %q, 期望 empty", qe.Kind)
	}
	if !strings.Contains(qe.Msg, "未初始化") {
		t.Errorf("文案应含'未初始化'，实际: %s", qe.Msg)
	}
}

// TestQueryBannedMissingIPColumn bans 表存在但缺 ip 列 → "schema" 分类错误（附列信息）。
func TestQueryBannedMissingIPColumn(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "fail2ban.sqlite3")
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	// 未知版本结构：bans 表存在但列名不同（如 addr 代替 ip）；bips 不存在。
	if _, err := db.Exec(`CREATE TABLE bans (jail TEXT, addr TEXT, timeofban INTEGER)`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	_, err = QueryBanned(context.Background(), dbPath)
	if err == nil {
		t.Fatal("缺 ip 列应报错")
	}
	var qe *BannedQueryError
	if !errors.As(err, &qe) {
		t.Fatalf("错误类型 = %T, 期望 *BannedQueryError", err)
	}
	if qe.Kind != "schema" {
		t.Errorf("分类 = %q, 期望 schema（结构不兼容）", qe.Kind)
	}
	if !strings.Contains(qe.Msg, "addr") {
		t.Errorf("文案应附实际列信息（PRAGMA table_info 摘要），实际: %s", qe.Msg)
	}
}

// TestQueryBannedBipsMissingIPColumn bips 表存在但缺 ip 列 → "schema" 分类错误。
func TestQueryBannedBipsMissingIPColumn(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "fail2ban.sqlite3")
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE bips (jail TEXT, addr TEXT, timeofban INTEGER, bantime INTEGER)`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	_, err = QueryBanned(context.Background(), dbPath)
	if err == nil {
		t.Fatal("bips 缺 ip 列应报错")
	}
	var qe *BannedQueryError
	if !errors.As(err, &qe) {
		t.Fatalf("错误类型 = %T, 期望 *BannedQueryError", err)
	}
	if qe.Kind != "schema" {
		t.Errorf("分类 = %q, 期望 schema（结构不兼容）", qe.Kind)
	}
}

// TestQueryBannedMissingFile 文件不存在（bind mount 源缺失/路径错位形态）→ "unreadable" 分类。
func TestQueryBannedMissingFile(t *testing.T) {
	dir := t.TempDir()
	_, err := QueryBanned(context.Background(), filepath.Join(dir, "missing.sqlite3"))
	if err == nil {
		t.Fatal("文件不存在应报错")
	}
	var qe *BannedQueryError
	if !errors.As(err, &qe) {
		t.Fatalf("错误类型 = %T, 期望 *BannedQueryError", err)
	}
	if qe.Kind != "unreadable" {
		t.Errorf("分类 = %q, 期望 unreadable（库不可访问）", qe.Kind)
	}
}

// fakeCodeError 模拟 SQLite 扩展错误码（接口化识别，见 sqliteCodeError）。
type fakeCodeError struct{ code int }

func (f fakeCodeError) Error() string { return "fake sqlite error" }
func (f fakeCodeError) Code() int     { return f.code }

// TestClassifyQueryErrHotJournal：SQLITE_READONLY_RECOVERY（264）→
// hotjournal 分类（调用方 info 级留痕、返回空名单、下轮重试）；普通 readonly（8）与
// 其他错误归 unreadable；包装错误 errors.As 穿透识别。
func TestClassifyQueryErrHotJournal(t *testing.T) {
	cases := []struct {
		name string
		err  error
		kind string
	}{
		{"readonly recovery 264", fakeCodeError{code: 264}, "hotjournal"},
		{"wrapped readonly recovery", fmt.Errorf("查询失败: %w", fakeCodeError{code: 264}), "hotjournal"},
		{"plain readonly 8", fakeCodeError{code: 8}, "unreadable"},
		{"generic error", errors.New("boom"), "unreadable"},
		{"wrapped generic", fmt.Errorf("打开失败: %w", errors.New("no such file")), "unreadable"},
	}
	for _, c := range cases {
		err := classifyQueryErr(c.err, "ctx")
		var qe *BannedQueryError
		if !errors.As(err, &qe) {
			t.Fatalf("%s: 应返回 *BannedQueryError, 实际 %T", c.name, err)
		}
		if qe.Kind != c.kind {
			t.Errorf("%s: 分类 = %q, 期望 %q", c.name, qe.Kind, c.kind)
		}
	}
	if err := classifyQueryErr(fakeCodeError{code: 264}, "ctx"); !strings.Contains(err.Error(), "hot journal") {
		t.Errorf("hotjournal 文案应说明降级与重试语义: %v", err)
	}
}

// TestReadOnlyDSNRejectsWrite（核对点 4 证据）：mode=ro 只读打开生效——
// 写操作被 SQLite 拒绝（readonly database），查询正常。
func TestReadOnlyDSNRejectsWrite(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "fail2ban.sqlite3")
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE bans (jail TEXT NOT NULL, ip TEXT NOT NULL, timeofban INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO bans VALUES ('sshd','203.0.113.5',1)`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	ro, err := sql.Open("sqlite", dbdsn.ReadOnly(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	var n int
	if err := ro.QueryRow(`SELECT COUNT(*) FROM bans`).Scan(&n); err != nil {
		t.Fatalf("只读查询失败: %v", err)
	}
	if n != 1 {
		t.Errorf("只读查询计数 = %d, 期望 1", n)
	}
	if _, werr := ro.Exec(`INSERT INTO bans VALUES ('x','198.51.100.1',1)`); werr == nil {
		t.Fatal("只读模式写操作应被拒绝（mode=ro 生效）")
	} else if !strings.Contains(werr.Error(), "readonly") && !strings.Contains(werr.Error(), "read-only") {
		t.Errorf("写拒绝错误应含 readonly 语义: %v", werr)
	}
}

// TestQueryBannedInvalidDB：非 SQLite 文件（垃圾字节）→ tableExists 探测
// 失败 → unreadable 分类（真实驱动错误路径，覆盖 tableExists 错误分支）。
func TestQueryBannedInvalidDB(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "fail2ban.sqlite3")
	if err := os.WriteFile(dbPath, []byte("this is not a sqlite database file, padding padding padding"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := QueryBanned(context.Background(), dbPath)
	if err == nil {
		t.Fatal("损坏库应报错")
	}
	var qe *BannedQueryError
	if !errors.As(err, &qe) {
		t.Fatalf("错误类型 = %T, 期望 *BannedQueryError", err)
	}
	if qe.Kind != "unreadable" {
		t.Errorf("分类 = %q, 期望 unreadable（库不可访问）", qe.Kind)
	}
}

// TestQueryBannedNonTextIPSkipped：ip 列值为非 IP 文本/数字（SQLite 动态类型
// 不强制）→ 该行被 ParseIP 跳过、不崩溃、不影响正常行（实测 modernc 将 INTEGER 宽容
// 转换为文本，不触发扫描错误——防御行为验证）。
func TestQueryBannedNonTextIPSkipped(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "fail2ban.sqlite3")
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE bans (jail TEXT NOT NULL, ip TEXT NOT NULL, timeofban INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO bans VALUES ('sshd', 12345, 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO bans VALUES ('sshd', 'not-an-ip', 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO bans VALUES ('sshd', '203.0.113.5', 1)`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	got, err := QueryBanned(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("QueryBanned 失败: %v", err)
	}
	if len(got) != 1 || got[0] != 0xCB007105 {
		t.Errorf("仅正常 IP 应返回，垃圾行跳过: %v", got)
	}
}

// TestReadOnlyDSNBusyTimeout：只读 DSN 追加 busy_timeout=5000。
func TestReadOnlyDSNBusyTimeout(t *testing.T) {
	dsn := dbdsn.ReadOnly("/var/lib/fail2ban/fail2ban.sqlite3")
	if !strings.Contains(dsn, "mode=ro") {
		t.Errorf("DSN 应含 mode=ro: %s", dsn)
	}
	if !strings.Contains(dsn, "busy_timeout(5000)") {
		t.Errorf("DSN 应含 busy_timeout=5000: %s", dsn)
	}
}

// TestReadOnlyDSNSpecialChars：路径含 '?'/'#' 等 DSN 特殊字符时查询正常。
// 注意：创建环节亦须用转义 DSN——未转义时 SQLite URI 解析会把 '?' 视为查询分隔符，
// 实际创建的文件名被截断（这正是本函数要防的路径语义错误）。
// Windows 文件系统不允许 '?'/'#' 文件名（创建即失败），该场景在 Linux/WSL 验证。
func TestReadOnlyDSNSpecialChars(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 文件名不允许 '?'/'#'，在 Linux/WSL 验证")
	}
	dir := t.TempDir()
	// 路径含 '?' 与 '#'（DSN 解析器会误读的字符）。
	dbPath := filepath.Join(dir, "fail?2ban#x.sqlite3")
	db, err := sql.Open("sqlite", "file:"+url.PathEscape(dbPath)) // 创建用转义路径（写模式）
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE bans (jail TEXT NOT NULL, ip TEXT NOT NULL, timeofban INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO bans (jail, ip, timeofban) VALUES ('sshd', '203.0.113.5', 1)`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	got, err := QueryBanned(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("含特殊字符路径查询失败（DSN 转义问题）: %v", err)
	}
	if len(got) != 1 || got[0] != 0xCB007105 {
		t.Errorf("查询结果错误: %v", got)
	}
}
