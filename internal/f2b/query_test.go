package f2b

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestQueryBanned 只读查询 fail2ban.sqlite3 封禁名单（M2 联调）。
func TestQueryBanned(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "fail2ban.sqlite3")
	// 构造 fail2ban v1.x 风格 bans 表。
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE bans (jail TEXT NOT NULL, ip TEXT NOT NULL, timeofban INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"203.0.113.5", "198.51.100.7", "203.0.113.9"} {
		if _, err := db.Exec(`INSERT INTO bans (jail, ip, timeofban) VALUES ('sshd', ?, 1)`, ip); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	got, err := QueryBanned(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("QueryBanned 失败: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("封禁数 = %d, 期望 3", len(got))
	}
	// 203.0.113.5 = 0xCB007105
	found := false
	for _, ip := range got {
		if ip == 0xCB007105 {
			found = true
		}
	}
	if !found {
		t.Error("未找到期望的封禁 IP")
	}

	// 文件不存在 → 错误（调用方记录告警）。
	if _, err := QueryBanned(context.Background(), filepath.Join(dir, "missing.sqlite3")); err == nil {
		t.Error("文件不存在应报错")
	}
}

// TestQueryBannedSchemaMismatch 库存在但无 bans 表 → "empty" 分类错误（DEV-031 优化①：
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
		t.Fatal("无 bans 表应报错")
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
	// 预创建 0 字节文件（fail2ban dbfile 未启用时的空库形态）。
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
	// 未知版本结构：bans 表存在但列名不同（如 addr 代替 ip）。
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

// TestReadOnlyDSNBusyTimeout（DEV-031 优化①）：只读 DSN 追加 busy_timeout=5000。
func TestReadOnlyDSNBusyTimeout(t *testing.T) {
	dsn := readOnlyDSN("/var/lib/fail2ban/fail2ban.sqlite3")
	if !strings.Contains(dsn, "mode=ro") {
		t.Errorf("DSN 应含 mode=ro: %s", dsn)
	}
	if !strings.Contains(dsn, "busy_timeout(5000)") {
		t.Errorf("DSN 应含 busy_timeout=5000: %s", dsn)
	}
}

// TestReadOnlyDSNSpecialChars（A-11）：路径含 '?'/'#' 等 DSN 特殊字符时查询正常。
// 注意：创建环节亦须用转义 DSN——未转义时 SQLite URI 解析会把 '?' 视为查询分隔符，
// 实际创建的文件名被截断（这正是 A-11 要防的路径语义错误）。
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
