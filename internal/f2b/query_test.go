package f2b

import (
	"context"
	"database/sql"
	"net/url"
	"path/filepath"
	"runtime"
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

// TestQueryBannedSchemaMismatch 库存在但表结构不兼容 → 错误（版本差异留痕）。
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
	if _, err := QueryBanned(context.Background(), dbPath); err == nil {
		t.Error("无 bans 表应报错")
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
