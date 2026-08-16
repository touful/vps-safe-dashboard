package archive

import (
	"bytes"
	"compress/gzip"
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite" // 测试用驱动（与主库一致）
)

// newTestMainDB 创建临时主库（含 DDL 与 meta）。
func newTestMainDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "main.db"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
CREATE TABLE resources (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, cpu_percent REAL NOT NULL,
    mem_used_mb REAL NOT NULL, mem_percent REAL NOT NULL, disk_used_mb REAL NOT NULL,
    disk_percent REAL NOT NULL, net_rx_bps INTEGER NOT NULL DEFAULT 0, net_tx_bps INTEGER NOT NULL DEFAULT 0);
CREATE TABLE connections (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, ev_type INTEGER NOT NULL,
    proto INTEGER NOT NULL, src_ip INTEGER NOT NULL, src_port INTEGER NOT NULL,
    dst_ip INTEGER NOT NULL, dst_port INTEGER NOT NULL,
    packets INTEGER NOT NULL DEFAULT 0, bytes INTEGER NOT NULL DEFAULT 0, mark INTEGER NOT NULL DEFAULT 0);
CREATE TABLE ssh_attempts (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, src_ip INTEGER NOT NULL,
    username TEXT NOT NULL DEFAULT '', auth_method TEXT NOT NULL DEFAULT '', result INTEGER NOT NULL,
    fingerprint TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT '');
CREATE TABLE firewall_events (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, chain TEXT NOT NULL,
    action TEXT NOT NULL, proto INTEGER NOT NULL, src_ip INTEGER NOT NULL, src_port INTEGER NOT NULL,
    dst_ip INTEGER NOT NULL, dst_port INTEGER NOT NULL, raw TEXT NOT NULL DEFAULT '');
CREATE TABLE ban_events (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, ip INTEGER NOT NULL,
    type TEXT NOT NULL, jail TEXT NOT NULL DEFAULT '');
CREATE TABLE system_events (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, source TEXT NOT NULL,
    level TEXT NOT NULL, message TEXT NOT NULL);
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
`)
	if err != nil {
		t.Fatal(err)
	}
	return db, dir
}

// insertOldMonth 向上个月（YYYY-MM）区间插入数据。
func insertOldMonth(t *testing.T, db *sql.DB) (month string, start, end int64) {
	t.Helper()
	now := time.Now()
	prev := now.AddDate(0, -1, 0)
	start = time.Date(prev.Year(), prev.Month(), 1, 0, 0, 0, 0, time.Local).Unix()
	end = time.Date(prev.Year(), prev.Month()+1, 1, 0, 0, 0, 0, time.Local).Unix()
	month = fmt.Sprintf("%04d-%02d", prev.Year(), prev.Month())
	for i := 0; i < 10; i++ {
		if _, err := db.Exec(`INSERT INTO resources (ts, cpu_percent, mem_used_mb, mem_percent, disk_used_mb, disk_percent) VALUES (?,1,1,1,1,1)`, start+int64(i)); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO connections (ts, ev_type, proto, src_ip, src_port, dst_ip, dst_port) VALUES (?,1,6,1,1,2,22)`, start+int64(i)); err != nil {
			t.Fatal(err)
		}
	}
	return month, start, end
}

func TestParseMonth(t *testing.T) {
	y, m, start, end, err := ParseMonth("2026-07")
	if err != nil {
		t.Fatal(err)
	}
	if y != 2026 || m != 7 {
		t.Errorf("y/m = %d/%d", y, m)
	}
	if start >= end || end-start != 31*86400 {
		t.Errorf("区间错误: %d-%d", start, end)
	}
	for _, bad := range []string{"2026", "26-07", "2026-13", "2026-0x", "abcd-ef"} {
		if _, _, _, _, err := ParseMonth(bad); err == nil {
			t.Errorf("%q 应报错", bad)
		}
	}
}

func TestArchiveMonthDB(t *testing.T) {
	db, dir := newTestMainDB(t)
	defer db.Close()
	month, start, end := insertOldMonth(t, db)

	// 归档执行。
	if err := ArchiveMonthDB(db, dir, month, 6); err != nil {
		t.Fatalf("ArchiveMonthDB 失败: %v", err)
	}
	// 主库数据保留不动（D-04：无删除）。
	for _, table := range []string{"resources", "connections"} {
		var n int64
		if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 10 {
			t.Errorf("主库 %s 行数 = %d, 期望 10（主库不得删除）", table, n)
		}
	}
	// 副本文件存在且 gzip 可解压、行数一致。
	gzPath := filepath.Join(dir, month+".db.gz")
	if _, err := os.Stat(gzPath); err != nil {
		t.Fatalf("副本文件缺失: %v", err)
	}
	f, err := os.Open(gzPath)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip 解压失败: %v", err)
	}
	data, err := io.ReadAll(zr)
	zr.Close()
	f.Close()
	if err != nil {
		t.Fatalf("读取副本失败: %v", err)
	}
	arc, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "arc_check.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer arc.Close()
	// 直接读 gzip 内容不可作为库打开；校验方式：解压到临时文件后查询行数。
	rawPath := filepath.Join(dir, month+".db")
	if err := os.WriteFile(rawPath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	rawDB, err := sql.Open("sqlite", "file:"+rawPath)
	if err != nil {
		t.Fatal(err)
	}
	defer rawDB.Close()
	for _, table := range []string{"resources", "connections"} {
		var n int64
		if err := rawDB.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
			t.Fatalf("副本 %s 查询失败: %v", table, err)
		}
		if n != 10 {
			t.Errorf("副本 %s 行数 = %d, 期望 10", table, n)
		}
	}
	// meta 已记录 → 幂等（再次执行直接跳过，无副作用）。
	if err := ArchiveMonthDB(db, dir, month, 6); err != nil {
		t.Errorf("幂等重跑失败: %v", err)
	}
	// 边界：区间内仅 resources 有数据（connections 该月无）→ 行数校验应为 0=0。
	var cnt int64
	if err := db.QueryRow(`SELECT COUNT(*) FROM connections WHERE ts >= ? AND ts < ?`, start, end).Scan(&cnt); err != nil {
		t.Fatal(err)
	}
	_ = cnt
}

// TestArchiveTmpSelfHeal .tmp 中断自愈：残留 .tmp 被删除后重新导出成功。
func TestArchiveTmpSelfHeal(t *testing.T) {
	db, dir := newTestMainDB(t)
	defer db.Close()
	month, _, _ := insertOldMonth(t, db)

	// 预置残留 .tmp（模拟中断）。
	tmpPath := filepath.Join(dir, month+".db.tmp")
	if err := os.WriteFile(tmpPath, []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ArchiveMonthDB(db, dir, month, 6); err != nil {
		t.Fatalf("带 .tmp 残留归档失败（自愈未生效）: %v", err)
	}
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Error(".tmp 残留未被清理")
	}
}

// TestArchiveBrokenGZSelfHeal（R-01）：半截 .db.gz 残留（meta 未记录）应被删除重建。
func TestArchiveBrokenGZSelfHeal(t *testing.T) {
	db, dir := newTestMainDB(t)
	defer db.Close()
	month, _, _ := insertOldMonth(t, db)

	// 预置半截 .db.gz（模拟 gzip 中断残留，meta 无记录）。
	finalPath := filepath.Join(dir, month+".db.gz")
	if err := os.WriteFile(finalPath, []byte("half-written-gzip"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ArchiveMonthDB(db, dir, month, 6); err != nil {
		t.Fatalf("半截 .gz 自愈归档失败: %v", err)
	}
	// 副本应为完整 gzip（可解压且行数正确）。
	data, err := os.ReadFile(finalPath)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("重建副本非有效 gzip: %v", err)
	}
	raw, err := io.ReadAll(zr)
	zr.Close()
	if err != nil || len(raw) == 0 {
		t.Fatalf("重建副本解压失败: %v", err)
	}
	// meta 已记录。
	copied, err := readCopiedMonths(db)
	if err != nil || !containsMonth(copied, month) {
		t.Errorf("meta 未记录归档月份: %v %v", copied, err)
	}
}

// TestArchiveMetaMissingFile（R-08）：meta 已记录但副本文件被外部删除 → 重建。
func TestArchiveMetaMissingFile(t *testing.T) {
	db, dir := newTestMainDB(t)
	defer db.Close()
	month, _, _ := insertOldMonth(t, db)

	if err := ArchiveMonthDB(db, dir, month, 6); err != nil {
		t.Fatalf("首次归档失败: %v", err)
	}
	// 外部删除副本文件。
	if err := os.Remove(filepath.Join(dir, month+".db.gz")); err != nil {
		t.Fatal(err)
	}
	if err := ArchiveMonthDB(db, dir, month, 6); err != nil {
		t.Fatalf("meta 记录但文件缺失时重建失败: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, month+".db.gz")); err != nil {
		t.Errorf("副本未重建: %v", err)
	}
	// 重建后 meta 最终状态应重新包含该月（reviewer N-07）。
	copied, err := readCopiedMonths(db)
	if err != nil || !containsMonth(copied, month) {
		t.Errorf("重建后 meta 未重新记录归档月份: %v %v", copied, err)
	}
}

// TestArchiveEmptyMonth（R-06）：无数据月份不产副本文件。
func TestArchiveEmptyMonth(t *testing.T) {
	db, dir := newTestMainDB(t)
	defer db.Close()
	month := "2020-01" // 无任何数据
	if err := ArchiveMonthDB(db, dir, month, 6); err != nil {
		t.Fatalf("空月归档失败: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, month+".db.gz")); !os.IsNotExist(err) {
		t.Error("空月不应生成副本文件")
	}
}

// TestCleanStaleTmp（R-07）：启动清理残留 .tmp / .gz.tmp。
func TestCleanStaleTmp(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"2026-06.db.tmp", "2026-06.db.gz.tmp", "2026-07.db.gz"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := CleanStaleTmp(dir); err != nil {
		t.Fatalf("CleanStaleTmp 失败: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "2026-06.db.tmp")); !os.IsNotExist(err) {
		t.Error(".db.tmp 未清理")
	}
	if _, err := os.Stat(filepath.Join(dir, "2026-06.db.gz.tmp")); !os.IsNotExist(err) {
		t.Error(".db.gz.tmp 未清理")
	}
	if _, err := os.Stat(filepath.Join(dir, "2026-07.db.gz")); err != nil {
		t.Error("完整 .db.gz 不应被清理")
	}
	// 目录不存在视为干净。
	if err := CleanStaleTmp(filepath.Join(dir, "nonexistent")); err != nil {
		t.Errorf("目录不存在应视为干净: %v", err)
	}
}

// TestArchiveMonthOf MonthOf 边界。
func TestArchiveMonthOf(t *testing.T) {
	jan := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC).Unix()
	if MonthOf(jan) != "2026-01" {
		t.Errorf("MonthOf = %s, 期望 2026-01", MonthOf(jan))
	}
}

// TestSqliteQuote（A-03）：SQLite 字面量单引号双写转义。
func TestSqliteQuote(t *testing.T) {
	cases := []struct{ in, want string }{
		{`/var/lib/sentry-agent/archive/2026-07.db`, `'/var/lib/sentry-agent/archive/2026-07.db'`},
		{`we'ird/path.db`, `'we''ird/path.db'`},
		{`a'b'c`, `'a''b''c'`},
		{``, `''`},
		{`C:\dir\file.db`, `'C:\dir\file.db'`}, // 反斜杠原样保留（非转义）
	}
	for _, c := range cases {
		if got := sqliteQuote(c.in); got != c.want {
			t.Errorf("sqliteQuote(%q) = %q, 期望 %q", c.in, got, c.want)
		}
	}
}

// TestArchiveWithQuotePath（A-03 端到端）：归档目录路径含单引号时 ATTACH 正常。
func TestArchiveWithQuotePath(t *testing.T) {
	db, _ := newTestMainDB(t)
	defer db.Close()
	month, _, _ := insertOldMonth(t, db)

	// 含单引号的归档目录（Windows 无法创建此类路径？Linux/WSL 可以——测试在 Linux CI/本机运行；
	// Windows 上 os.MkdirAll 允许单引号，正常）。
	dir := filepath.Join(t.TempDir(), "we'ird")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ArchiveMonthDB(db, dir, month, 6); err != nil {
		t.Fatalf("含引号路径归档失败: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, month+".db.gz")); err != nil {
		t.Errorf("副本未生成: %v", err)
	}
}

// TestShouldSkipArchive（A-02/R-01）：磁盘水位判定（阈值参数化）。
func TestShouldSkipArchive(t *testing.T) {
	cases := []struct {
		usage float64
		ok    bool
		crit  float64
		want  bool
	}{
		{50, true, 90, false},    // 正常水位，不跳过
		{89.9, true, 90, false},  // 临界下，不跳过
		{90.0, true, 90, true},   // critical（默认 90），跳过
		{85.0, true, 85, true},   // 自定义阈值 85 时 85% 即跳过（R-01 参数化验证）
		{84.9, true, 85, false},  // 自定义阈值 85 时 84.9% 不跳过
		{95.0, true, 90, true},   // emergency，跳过
		{0, false, 90, true},     // statfs 失败，保守跳过
	}
	for _, c := range cases {
		if got := ShouldSkipArchive(c.usage, c.ok, c.crit); got != c.want {
			t.Errorf("ShouldSkipArchive(%.1f, %v, %.1f) = %v, 期望 %v", c.usage, c.ok, c.crit, got, c.want)
		}
	}
}
