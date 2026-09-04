package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// doChannelsGet 请求 /api/v1/channels 并解码（200 时）。
func doChannelsGet(t *testing.T, srv *Server) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/channels", nil))
	var out map[string]any
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("响应 JSON 解析失败: %v", err)
		}
	}
	return rec.Code, out
}

// seedChannelsExtra 向测试库补种 ban_events / cred_events / system_events
// （newTestServer 未覆盖的三表），供通道健康端点验证非空 last_ts 与告警过滤。
func seedChannelsExtra(t *testing.T, dbPath string, banCredTS int64, warns []system_eventsSeed) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO ban_events (ts, ip, type, jail) VALUES (?,?,?,?)`,
		banCredTS, 0xCB007105, "ban", "sshd"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO cred_events (ts, proto, src_ip, username, password) VALUES (?,?,?,?,?)`,
		banCredTS, "mysql", 0xCB007105, "root", "hunter2"); err != nil {
		t.Fatal(err)
	}
	for _, w := range warns {
		if _, err := db.Exec(`INSERT INTO system_events (ts, source, level, message) VALUES (?,?,?,?)`,
			w.ts, w.source, w.level, w.message); err != nil {
			t.Fatal(err)
		}
	}
}

// system_eventsSeed system_events 补种行。
type system_eventsSeed struct {
	ts      int64
	source  string
	level   string
	message string
}

// TestChannelsBasic：表顺序与空表 0 → 补种后非空 last_ts 与 recent_warnings 过滤。
func TestChannelsBasic(t *testing.T) {
	srv, dbPath := newTestServer(t)
	srv.SetRetentionDays(7)
	now := time.Now().Unix()

	// 阶段一：未补种（ban/cred/system 三表为空）。
	code, out := doChannelsGet(t, srv)
	if code != http.StatusOK {
		t.Fatalf("code = %d", code)
	}
	if _, ok := out["now"].(float64); !ok {
		t.Errorf("now 字段缺失或非法: %v", out["now"])
	}
	if out["retention_days"] != float64(7) {
		t.Errorf("retention_days = %v, 期望 7", out["retention_days"])
	}
	if _, ok := out["db_size_mb"].(float64); !ok {
		t.Errorf("db_size_mb 字段缺失或非法: %v", out["db_size_mb"])
	}
	if _, ok := out["overrun_total"].(float64); !ok {
		t.Errorf("overrun_total 字段缺失或非法: %v", out["overrun_total"])
	}
	// tables：固定 7 表顺序。
	wantOrder := []string{"connections", "ssh_attempts", "firewall_events", "ban_events",
		"cred_events", "resources", "system_events"}
	tables, _ := out["tables"].([]any)
	if len(tables) != 7 {
		t.Fatalf("tables 长度 = %d, 期望 7", len(tables))
	}
	lastTS := map[string]float64{}
	for i, tv := range tables {
		tm := tv.(map[string]any)
		if tm["name"] != wantOrder[i] {
			t.Errorf("tables[%d].name = %v, 期望 %v（顺序为契约）", i, tm["name"], wantOrder[i])
		}
		lastTS[tm["name"].(string)] = tm["last_ts"].(float64)
	}
	// 空表 last_ts = 0。
	for _, name := range []string{"ban_events", "cred_events", "system_events"} {
		if lastTS[name] != 0 {
			t.Errorf("空表 %s last_ts = %v, 期望 0", name, lastTS[name])
		}
	}
	// newTestServer 已种表的 last_ts > 0 且不超过当前时刻。
	for _, name := range []string{"connections", "ssh_attempts", "firewall_events", "resources"} {
		if lastTS[name] <= 0 || lastTS[name] > float64(now+1) {
			t.Errorf("%s last_ts = %v, 期望 (0, now]", name, lastTS[name])
		}
	}
	// 未补种时 recent_warnings 为空数组（非 null）。
	if w, ok := out["recent_warnings"].([]any); !ok || len(w) != 0 {
		t.Errorf("recent_warnings = %v, 期望空数组", out["recent_warnings"])
	}

	// 阶段二：补种三表（ro 连接顺序读已提交数据，无并发）。
	seedChannelsExtra(t, dbPath, 100, []system_eventsSeed{
		{now - 5, "conntrack", "error", "表满丢弃"},
		{now - 10, "api", "warn", "API 限流拒绝: /api/v1/summary"},
		{now - 1, "api", "info", "信息级不入告警"},
	})
	code, out = doChannelsGet(t, srv)
	if code != http.StatusOK {
		t.Fatalf("补种后 code = %d", code)
	}
	tables, _ = out["tables"].([]any)
	lastTS = map[string]float64{}
	for _, tv := range tables {
		tm := tv.(map[string]any)
		lastTS[tm["name"].(string)] = tm["last_ts"].(float64)
	}
	if lastTS["ban_events"] != 100 || lastTS["cred_events"] != 100 {
		t.Errorf("补种后 ban/cred last_ts = %v/%v, 期望 100/100", lastTS["ban_events"], lastTS["cred_events"])
	}
	if lastTS["system_events"] != float64(now-1) {
		t.Errorf("system_events last_ts = %v, 期望 %v（含 info 级）", lastTS["system_events"], now-1)
	}
	// recent_warnings：仅 warn/error，ts 降序；info 被过滤。
	warnings, _ := out["recent_warnings"].([]any)
	if len(warnings) != 2 {
		t.Fatalf("recent_warnings 长度 = %d, 期望 2（info 被过滤）", len(warnings))
	}
	w0 := warnings[0].(map[string]any)
	w1 := warnings[1].(map[string]any)
	if w0["level"] != "error" || w0["source"] != "conntrack" || w0["ts"] != float64(now-5) {
		t.Errorf("warnings[0] = %v, 期望 error/conntrack/ts=%d", w0, now-5)
	}
	if w1["level"] != "warn" || w1["source"] != "api" || w1["ts"] != float64(now-10) {
		t.Errorf("warnings[1] = %v, 期望 warn/api/ts=%d", w1, now-10)
	}
	if w0["message"] == "" {
		t.Error("message 字段缺失")
	}
}

// TestChannelsWarningsLimit：告警条数上限 20。
func TestChannelsWarningsLimit(t *testing.T) {
	srv, dbPath := newTestServer(t)
	now := time.Now().Unix()
	var seeds []system_eventsSeed
	for i := 0; i < 25; i++ {
		seeds = append(seeds, system_eventsSeed{now - int64(i), "api", "warn", "限流拒绝"})
	}
	seedChannelsExtra(t, dbPath, 100, seeds)
	code, out := doChannelsGet(t, srv)
	if code != http.StatusOK {
		t.Fatalf("code = %d", code)
	}
	warnings, _ := out["recent_warnings"].([]any)
	if len(warnings) != 20 {
		t.Errorf("recent_warnings 长度 = %d, 期望 20（LIMIT 上限）", len(warnings))
	}
	// 降序：首条为最新（ts=now）。
	if w0 := warnings[0].(map[string]any); w0["ts"] != float64(now) {
		t.Errorf("warnings[0].ts = %v, 期望 %d（降序）", w0["ts"], now)
	}
}
