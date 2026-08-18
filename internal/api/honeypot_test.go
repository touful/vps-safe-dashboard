package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
