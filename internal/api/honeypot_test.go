package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// newHoneypotTestServer 创建带 cred_events 表与种子数据的 API Server。
// 与 newTestServer 独立（不侵入既有 fixture；cred_events 为 DEV-HONEY-001 新增表）。
func newHoneypotTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE cred_events (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL,
		proto TEXT NOT NULL, src_ip INTEGER NOT NULL, username TEXT NOT NULL DEFAULT '',
		password TEXT NOT NULL DEFAULT '', extra TEXT NOT NULL DEFAULT '');
		CREATE INDEX idx_cred_ts ON cred_events(ts);
		CREATE INDEX idx_cred_proto ON cred_events(proto);
		CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
		INSERT INTO meta(key, value) VALUES('schema_version', '1');`)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	// 种子：2 条 telnet（明文密码）+ 1 条 mysql（hash）+ 1 条超窗（30d 外，验证 range 过滤）。
	rows := [][]any{
		{now - 60, "telnet", 0xCB007105, "root", "toor123", ""},
		{now - 120, "mysql", 0xCB007106, "admin", "0123456789abcdef", "密码 hash，不可逆"},
		{now - 300, "telnet", 0xCB007107, "user", "pass456", ""},
		{now - 40*86400, "ftp", 0xCB007108, "old", "oldpass", ""},
	}
	for _, r := range rows {
		if _, err := db.Exec(`INSERT INTO cred_events (ts, proto, src_ip, username, password, extra) VALUES (?,?,?,?,?,?)`, r...); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	srv, err := NewServer(dbPath, filepath.Join(dir, "archive"), "http://127.0.0.1:8080", true, nil)
	if err != nil {
		t.Fatalf("NewServer 失败: %v", err)
	}
	srv.SetLimits(1000, 1000, 1000, 100)
	srv.SetDBPath(dbPath)
	t.Cleanup(func() { srv.Close() })
	return srv, dbPath
}

// doHoneypotGet 请求 /honeypot/events 并解码。
func doHoneypotGet(t *testing.T, srv *Server, path string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// TestHoneypotEventsQuery 查询与响应字段（src_ip 点分十进制、range 回显）。
func TestHoneypotEventsQuery(t *testing.T) {
	srv, _ := newHoneypotTestServer(t)
	code, out := doHoneypotGet(t, srv, "/api/v1/honeypot/events?range=24h")
	if code != http.StatusOK {
		t.Fatalf("状态码 = %d", code)
	}
	if out["range"] != "24h" {
		t.Errorf("range = %v", out["range"])
	}
	rows, _ := out["rows"].([]any)
	if len(rows) != 3 {
		t.Fatalf("rows 长度 = %d, 期望 3（24h 窗口内；30d 外旧数据被过滤）", len(rows))
	}
	row := rows[0].(map[string]any)
	// 最新一条是 telnet root。
	if row["proto"] != "telnet" || row["username"] != "root" || row["password"] != "toor123" {
		t.Errorf("最新行 = %v", row)
	}
	if row["src_ip"] != "203.0.113.5" {
		t.Errorf("src_ip = %v, 期望 203.0.113.5", row["src_ip"])
	}
	if _, ok := row["ts"].(float64); !ok {
		t.Errorf("ts 字段异常: %v", row["ts"])
	}
}

// TestHoneypotEventsProtoFilter proto 过滤。
func TestHoneypotEventsProtoFilter(t *testing.T) {
	srv, _ := newHoneypotTestServer(t)
	code, out := doHoneypotGet(t, srv, "/api/v1/honeypot/events?range=24h&proto=mysql")
	if code != http.StatusOK {
		t.Fatalf("状态码 = %d", code)
	}
	rows, _ := out["rows"].([]any)
	if len(rows) != 1 {
		t.Fatalf("mysql 行数 = %d, 期望 1", len(rows))
	}
	row := rows[0].(map[string]any)
	if row["proto"] != "mysql" || row["extra"] == "" {
		t.Errorf("mysql 行 = %v", row)
	}
	// 不存在的协议 → 空数组（非 null，JSON 兼容前端三态）。
	_, out2 := doHoneypotGet(t, srv, "/api/v1/honeypot/events?range=24h&proto=rdp")
	rows2, _ := out2["rows"].([]any)
	if len(rows2) != 0 {
		t.Fatalf("rdp 行数 = %d, 期望 0", len(rows2))
	}
}

// TestHoneypotEventsLimit limit 上限（500）与非法值回退默认。
func TestHoneypotEventsLimit(t *testing.T) {
	srv, _ := newHoneypotTestServer(t)
	// 非法 range 回显 24h。
	_, out := doHoneypotGet(t, srv, "/api/v1/honeypot/events?range=bogus")
	if out["range"] != "24h" {
		t.Errorf("非法 range 回显 = %v, 期望 24h", out["range"])
	}
	// limit 超上限不报错（钳制 500）。
	code, _ := doHoneypotGet(t, srv, "/api/v1/honeypot/events?range=30d&limit=9999")
	if code != http.StatusOK {
		t.Errorf("limit=9999 状态码 = %d, 期望 200（钳制 500）", code)
	}
	// 30d 全量 3 行（40 天前的旧数据在窗口外被过滤）。
	_, out2 := doHoneypotGet(t, srv, "/api/v1/honeypot/events?range=30d")
	rows2, _ := out2["rows"].([]any)
	if len(rows2) != 3 {
		t.Errorf("30d 行数 = %d, 期望 3（40 天前旧数据应被过滤）", len(rows2))
	}
}

// newHoneyCredsTestServer 凭据字典聚合/导出测试 fixture（DEV-HONEY-002）：
// 与 newHoneypotTestServer 独立——种子覆盖去重（同组多源多次）、跨协议同密码、
// 三类 kind（plaintext/hash/none）与 mssql 还原失败降级场景。
func newHoneyCredsTestServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE cred_events (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL,
		proto TEXT NOT NULL, src_ip INTEGER NOT NULL, username TEXT NOT NULL DEFAULT '',
		password TEXT NOT NULL DEFAULT '', extra TEXT NOT NULL DEFAULT '');
		CREATE INDEX idx_cred_ts ON cred_events(ts);
		CREATE INDEX idx_cred_proto ON cred_events(proto);
		CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
		INSERT INTO meta(key, value) VALUES('schema_version', '1');`)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	const ipA, ipB = 0xCB007105, 0xCB007106 // 203.0.113.5 / 203.0.113.6
	rows := [][]any{
		// telnet root/toor123 ×3（两个源 IP）——聚合组 count=3、src_ip_cnt=2。
		{now - 100, "telnet", ipA, "root", "toor123", ""},
		{now - 200, "telnet", ipA, "root", "toor123", ""},
		{now - 300, "telnet", ipB, "root", "toor123", ""},
		// telnet admin/admin888——与 ftp 同密码（passwords 导出跨协议去重用）。
		{now - 400, "telnet", ipB, "admin", "admin888", ""},
		// mysql 不可逆摘要。
		{now - 500, "mysql", ipA, "root", "0123456789abcdef", "mysql_native_password 密码 hash"},
		// ftp admin/admin888。
		{now - 600, "ftp", ipA, "admin", "admin888", ""},
		// mssql 还原失败条目（extra 注明）——kind 降级 hash。
		{now - 700, "mssql", ipA, "sa", "01a402a3", "TDS 混淆密码还原失败（非可打印/畸形），记录 hex 摘要"},
		// memcached 无认证。
		{now - 800, "memcached", ipA, "", "", "协议无认证机制，无法捕获凭据；命令概览: get (get foo)"},
	}
	for _, r := range rows {
		if _, err := db.Exec(`INSERT INTO cred_events (ts, proto, src_ip, username, password, extra) VALUES (?,?,?,?,?,?)`, r...); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	srv, err := NewServer(dbPath, filepath.Join(dir, "archive"), "http://127.0.0.1:8080", true, nil)
	if err != nil {
		t.Fatalf("NewServer 失败: %v", err)
	}
	srv.SetLimits(1000, 1000, 1000, 100)
	srv.SetDBPath(dbPath)
	t.Cleanup(func() { srv.Close() })
	return srv
}

// TestHoneypotCredsAgg 凭据字典聚合：去重组数、count/first/last/src_ip_cnt、kind 分类、
// 次数降序与 proto 过滤。
func TestHoneypotCredsAgg(t *testing.T) {
	srv := newHoneyCredsTestServer(t)
	code, out := doHoneypotGet(t, srv, "/api/v1/honeypot/creds?range=24h")
	if code != http.StatusOK {
		t.Fatalf("状态码 = %d", code)
	}
	rows, _ := out["rows"].([]any)
	if len(rows) != 6 {
		t.Fatalf("聚合组数 = %d, 期望 6（8 条事件去重：telnet root×3 合 1 组 + 其余 5 组）", len(rows))
	}
	top := rows[0].(map[string]any) // count=3 的 telnet root/toor123 组排首位
	if top["proto"] != "telnet" || top["username"] != "root" || top["password"] != "toor123" {
		t.Fatalf("首行 = %v", top)
	}
	if top["count"] != float64(3) || top["src_ip_cnt"] != float64(2) {
		t.Errorf("count/src_ip_cnt = %v/%v, 期望 3/2", top["count"], top["src_ip_cnt"])
	}
	if top["kind"] != "plaintext" {
		t.Errorf("telnet kind = %v", top["kind"])
	}
	// kind 逐类断言：mysql hash、mssql 还原失败降级 hash、memcached none。
	kinds := map[string]string{}
	for _, r := range rows {
		m := r.(map[string]any)
		kinds[m["proto"].(string)] = m["kind"].(string)
	}
	if kinds["mysql"] != "hash" {
		t.Errorf("mysql kind = %v, 期望 hash", kinds["mysql"])
	}
	if kinds["mssql"] != "hash" {
		t.Errorf("mssql（还原失败）kind = %v, 期望 hash", kinds["mssql"])
	}
	if kinds["memcached"] != "none" {
		t.Errorf("memcached kind = %v, 期望 none", kinds["memcached"])
	}
	// proto 过滤。
	_, out2 := doHoneypotGet(t, srv, "/api/v1/honeypot/creds?range=24h&proto=mysql")
	rows2, _ := out2["rows"].([]any)
	if len(rows2) != 1 {
		t.Fatalf("mysql 聚合组 = %d, 期望 1", len(rows2))
	}
}

// TestExportCredsFormats 字典导出三格式：pairs 仅明文非空、passwords 跨协议去重、
// csv 全量带表头；非法 format 400。
func TestExportCredsFormats(t *testing.T) {
	srv := newHoneyCredsTestServer(t)
	get := func(path string) (int, string) {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		srv.mux.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	// pairs：仅 telnet×2 + ftp（mysql/mssql 摘要与 memcached 空密码排除），
	// count 降序（toor123 组 3 次 → admin888 telnet 1 次 → admin888 ftp 1 次）。
	code, body := get("/api/v1/export/creds?format=pairs&range=24h")
	if code != http.StatusOK {
		t.Fatalf("pairs 状态码 = %d", code)
	}
	want := "root:toor123\nadmin:admin888\nadmin:admin888\n"
	if body != want {
		t.Errorf("pairs = %q, 期望 %q", body, want)
	}
	// passwords：admin888 跨协议去重为 1 行。
	code, body = get("/api/v1/export/creds?format=passwords&range=24h")
	if code != http.StatusOK {
		t.Fatalf("passwords 状态码 = %d", code)
	}
	if body != "toor123\nadmin888\n" {
		t.Errorf("passwords = %q", body)
	}
	// csv：表头 + 7 组（含摘要与无认证条目，kind 如实标注）。
	code, body = get("/api/v1/export/creds?format=csv&range=24h")
	if code != http.StatusOK {
		t.Fatalf("csv 状态码 = %d", code)
	}
	lines := strings.Split(strings.TrimRight(body, "\n"), "\n")
	if len(lines) != 7 {
		t.Fatalf("csv 行数 = %d, 期望 7（表头 + 6 组）", len(lines))
	}
	if lines[0] != "username,password,protocol,kind,count,first_seen,last_seen,src_ip_count" {
		t.Errorf("csv 表头 = %q", lines[0])
	}
	if !strings.Contains(body, "0123456789abcdef,mysql,hash") {
		t.Errorf("csv 应含 mysql hash 条目")
	}
	// 非法 format。
	code, _ = get("/api/v1/export/creds?format=bogus&range=24h")
	if code != http.StatusBadRequest {
		t.Errorf("非法 format 状态码 = %d, 期望 400", code)
	}
	// 参数缺失（range 与 from/to 二选一约束复用 parseExportWindow）。
	code, _ = get("/api/v1/export/creds?format=csv")
	if code != http.StatusBadRequest {
		t.Errorf("缺时间窗状态码 = %d, 期望 400", code)
	}
}
