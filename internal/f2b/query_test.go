package f2b

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

// newF2BDB 创建 fail2ban 1.x 风格库（bips+bans 双表，addBan/delBan 双写双删语义，
// DEV-032 现场核查结论 2）；返回连接与库路径。
func newF2BDB(t *testing.T, dir string) (*sql.DB, string) {
	t.Helper()
	dbPath := filepath.Join(dir, "fail2ban.sqlite3")
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	// bips 列：ip/jail/timeofban/bantime/bancount/data（bantime 无 NOT NULL，理论可为 NULL）。
	if _, err := db.Exec(`CREATE TABLE bips (id INTEGER PRIMARY KEY, ip TEXT NOT NULL, jail TEXT NOT NULL,
		timeofban INTEGER NOT NULL, bantime INTEGER, bancount INTEGER NOT NULL, data TEXT, UNIQUE(ip, jail))`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE bans (id INTEGER PRIMARY KEY, jail TEXT NOT NULL, ip TEXT NOT NULL,
		timeofban INTEGER NOT NULL, UNIQUE(jail, ip))`); err != nil {
		t.Fatal(err)
	}
	return db, dbPath
}

// addBan 双表写入一条封禁（bantime 为 any：-1 永久 / 正数限时 / nil NULL）。
func addBan(t *testing.T, db *sql.DB, ip string, timeofban int64, bantime any) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO bips (ip, jail, timeofban, bantime, bancount, data) VALUES (?, 'sshd', ?, ?, 1, NULL)`, ip, timeofban, bantime); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO bans (jail, ip, timeofban) VALUES ('sshd', ?, ?)`, ip, timeofban); err != nil {
		t.Fatal(err)
	}
}

// TestQueryBannedActive（DEV-033，DEV-032 核查结论 3/6）：bips 路径活跃判定——
// 未过期保留、bantime=-1 永久封禁豁免保留、bantime NULL 保守保留、过期异常残留过滤。
func TestQueryBannedActive(t *testing.T) {
	dir := t.TempDir()
	db, dbPath := newF2BDB(t, dir)
	now := time.Now().Unix()
	addBan(t, db, "203.0.113.5", now-100, 1000)  // 未过期（timeofban+bantime > now）→ 保留
	addBan(t, db, "198.51.100.7", 1, -1)         // 永久封禁（bantime=-1，远古 timeofban）→ 豁免保留
	addBan(t, db, "198.51.100.10", 1, nil)       // bantime NULL（schema 无 NOT NULL）→ 保守保留
	addBan(t, db, "203.0.113.9", now-10000, 100) // 已过期（异常残留）→ 过滤
	db.Close()

	got, err := QueryBanned(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("QueryBanned 失败: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("封禁数 = %d, 期望 3（未过期+永久+NULL；过期残留过滤）: %v", len(got), got)
	}
	want := map[uint32]bool{0xCB007105: true, 0xC6336407: true, 0xC633640A: true} // .5/.7/.10
	for _, ip := range got {
		if !want[ip] {
			t.Errorf("不应包含 IP %08x（过期残留或未知）", ip)
		}
		delete(want, ip)
	}
	if len(want) != 0 {
		t.Errorf("缺失期望 IP: %v", want)
	}
}

// TestQueryBannedBantimeMinusOnePermanent（DEV-033 新增测试）：bantime=-1 永久封禁
// 恒保留（timeofban 即使远早于 now 也不过滤——必须豁免）。
func TestQueryBannedBantimeMinusOnePermanent(t *testing.T) {
	dir := t.TempDir()
	db, dbPath := newF2BDB(t, dir)
	addBan(t, db, "203.0.113.5", 1, -1) // 1970 年封禁 + 永久
	db.Close()

	got, err := QueryBanned(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("QueryBanned 失败: %v", err)
	}
	if len(got) != 1 || got[0] != 0xCB007105 {
		t.Errorf("永久封禁应保留: %v", got)
	}
}

// TestQueryBannedBantimeNullNoCrash（DEV-033 新增测试）：bantime NULL（schema 无
// NOT NULL，理论可为 NULL）不崩溃、不误删（保守保留，防漏报）。
func TestQueryBannedBantimeNullNoCrash(t *testing.T) {
	dir := t.TempDir()
	db, dbPath := newF2BDB(t, dir)
	addBan(t, db, "203.0.113.5", 1, nil)
	db.Close()

	got, err := QueryBanned(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("QueryBanned 失败: %v", err)
	}
	if len(got) != 1 || got[0] != 0xCB007105 {
		t.Errorf("bantime NULL 行应保守保留: %v", got)
	}
}

// TestQueryBannedExpiredFiltered：过期封禁（timeofban+bantime <= now）按时间条件过滤。
func TestQueryBannedExpiredFiltered(t *testing.T) {
	dir := t.TempDir()
	db, dbPath := newF2BDB(t, dir)
	now := time.Now().Unix()
	addBan(t, db, "203.0.113.5", now-2000, 100) // 过期（到期 now-1900）
	addBan(t, db, "198.51.100.7", now-500, 100) // 过期（到期 now-400）
	db.Close()

	got, err := QueryBanned(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("QueryBanned 失败: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("过期封禁应全部过滤: %v", got)
	}
}

// TestQueryBannedSameIPMultiJail（reviewer R-02）：同 IP 封禁于多个 jail（bips
// UNIQUE(ip,jail) 允许，如 sshd + recidive）→ DISTINCT 去重返回 1 条，与 bans 回退路径口径一致。
func TestQueryBannedSameIPMultiJail(t *testing.T) {
	dir := t.TempDir()
	db, dbPath := newF2BDB(t, dir)
	now := time.Now().Unix()
	for _, jail := range []string{"sshd", "recidive"} {
		if _, err := db.Exec(`INSERT INTO bips (ip, jail, timeofban, bantime, bancount, data) VALUES ('203.0.113.5', ?, ?, 3600, 1, NULL)`, jail, now-100); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	got, err := QueryBanned(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("QueryBanned 失败: %v", err)
	}
	if len(got) != 1 || got[0] != 0xCB007105 {
		t.Errorf("同 IP 多 jail 应去重为 1: %v", got)
	}
}

// TestQueryBannedBansFallback（0.10.x 兼容回退路径）：库无 bips 表（旧版 fail2ban）时
// 回退 bans 表全量返回（unban 即删行，行即当前封禁集合，无 bantime 可过滤）。
func TestQueryBannedBansFallback(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "fail2ban.sqlite3")
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
		t.Fatalf("回退路径封禁数 = %d, 期望 3", len(got))
	}
	found := false
	for _, ip := range got {
		if ip == 0xCB007105 { // 203.0.113.5
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
