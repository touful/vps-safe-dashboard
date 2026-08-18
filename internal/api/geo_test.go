package api

import (
	"database/sql"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// fakeGeo 可注入的 GeoLookuper（测试用；map key 为点分十进制 IP）。
type fakeGeo struct {
	ok    bool
	codes map[string]string // ip → country code
	names map[string]string // ip → country name
}

func (f *fakeGeo) OK() bool { return f.ok }

func (f *fakeGeo) Lookup(ip net.IP) (string, string, bool) {
	if !f.ok {
		return "", "", false
	}
	code, hit := f.codes[ip.String()]
	if !hit {
		return "", "", false
	}
	return code, f.names[ip.String()], true
}

// doGetGeo 请求 /attacks/geo 并解码。
func doGetGeo(t *testing.T, srv *Server, path string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// TestGeoAttacksBasic：种子库 3 条 SSH 失败（同 IP）聚合为 1 行 count=3，国家信息来自 geo 注入。
func TestGeoAttacksBasic(t *testing.T) {
	srv, _ := newTestServer(t)
	srv.SetGeo(&fakeGeo{ok: true,
		codes: map[string]string{"203.0.113.5": "US"},
		names: map[string]string{"203.0.113.5": "United States"}})
	code, out := doGetGeo(t, srv, "/api/v1/attacks/geo?range=24h")
	if code != http.StatusOK {
		t.Fatalf("状态码 = %d", code)
	}
	if out["mmdb_ok"] != true {
		t.Errorf("mmdb_ok = %v, 期望 true", out["mmdb_ok"])
	}
	if out["range"] != "24h" {
		t.Errorf("range = %v", out["range"])
	}
	rows, _ := out["rows"].([]any)
	if len(rows) != 1 {
		t.Fatalf("rows 长度 = %d, 期望 1（同 IP 聚合）", len(rows))
	}
	row := rows[0].(map[string]any)
	if row["ip"] != "203.0.113.5" || row["country_code"] != "US" ||
		row["country_name"] != "United States" || row["count"] != float64(3) {
		t.Errorf("row = %v", row)
	}
}

// TestGeoAttacksNoGeo：未注入 geo → mmdb_ok=false、国家 Unknown（降级）。
func TestGeoAttacksNoGeo(t *testing.T) {
	srv, _ := newTestServer(t)
	code, out := doGetGeo(t, srv, "/api/v1/attacks/geo")
	if code != http.StatusOK {
		t.Fatalf("状态码 = %d", code)
	}
	if out["mmdb_ok"] != false {
		t.Errorf("mmdb_ok = %v, 期望 false", out["mmdb_ok"])
	}
	rows := out["rows"].([]any)
	if len(rows) != 1 {
		t.Fatalf("rows 长度 = %d", len(rows))
	}
	row := rows[0].(map[string]any)
	if row["country_code"] != "Unknown" || row["country_name"] != "Unknown" {
		t.Errorf("降级国家 = %v/%v, 期望 Unknown", row["country_code"], row["country_name"])
	}
	// 注入未加载 reader（OK=false）同样降级
	srv.SetGeo(&fakeGeo{ok: false})
	_, out = doGetGeo(t, srv, "/api/v1/attacks/geo")
	if out["mmdb_ok"] != false {
		t.Errorf("未加载 reader mmdb_ok = %v", out["mmdb_ok"])
	}
}

// TestGeoAttacksFilters：country 过滤（含 Unknown 语义）与 min_count 过滤。
func TestGeoAttacksFilters(t *testing.T) {
	srv, dbPath := newTestServer(t)
	srv.SetGeo(&fakeGeo{ok: true,
		codes: map[string]string{"203.0.113.5": "US"},
		names: map[string]string{"203.0.113.5": "United States"}})
	// 补插第二来源 IP（US 之外）1 次失败，形成 2 行
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO ssh_attempts (ts, src_ip, username, auth_method, result, detail) VALUES (?,?,?,?,?,?)`,
		time.Now().Unix(), 0xCB007106, "admin", "password", 0, "Failed"); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		q    string
		want int // 期望行数
	}{
		{"", 2},
		{"&country=US", 1},
		{"&country=CN", 0},           // 未命中国家 → 空
		{"&country=Unknown", 0},       // 全部命中 geo → 无 Unknown 行
		{"&min_count=5", 0},           // 最大 count=3 < 5
		{"&min_count=3", 1},           // 203.0.113.5 count=3
		{"&country=US&min_count=3", 1},
		{"&country=US&min_count=4", 0},
	}
	for _, c := range cases {
		// heavy 桶 burst 固定 6（SetLimits 忽略 burst 参数）：快速连续请求会触发 429，
		// 每轮 sleep 5ms 让 1000 rps 补充令牌（与 TestExportCSVParams 同模式）。
		time.Sleep(5 * time.Millisecond)
		code, out := doGetGeo(t, srv, "/api/v1/attacks/geo?range=24h"+c.q)
		if code != http.StatusOK {
			t.Fatalf("q=%s 状态码 = %d", c.q, code)
		}
		rows, _ := out["rows"].([]any)
		if n := len(rows); n != c.want {
			t.Errorf("q=%s 行数 = %d, 期望 %d", c.q, n, c.want)
		}
	}
}

// TestGeoAttacksRangeEcho：非法 range 回显 24h（与 rangeSeconds 口径一致）。
func TestGeoAttacksRangeEcho(t *testing.T) {
	srv, _ := newTestServer(t)
	srv.SetGeo(&fakeGeo{ok: true})
	_, out := doGetGeo(t, srv, "/api/v1/attacks/geo?range=bogus")
	if out["range"] != "24h" {
		t.Errorf("非法 range 回显 = %v, 期望 24h", out["range"])
	}
}

// TestExportAttacksCSV：无表头三列（IP,国家或地区,累计攻击次数）+ 响应头 + 逗号转义。
func TestExportAttacksCSV(t *testing.T) {
	srv, _ := newTestServer(t)
	srv.SetGeo(&fakeGeo{ok: true,
		codes: map[string]string{"203.0.113.5": "KR"},
		names: map[string]string{"203.0.113.5": "Korea, Republic of"}})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/export/attacks_csv?range=24h", nil)
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("Content-Type = %q", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") || !strings.Contains(cd, ".csv") {
		t.Errorf("Content-Disposition = %q", cd)
	}
	body := rec.Body.String()
	// 国家名含逗号 → RFC 4180 引号转义
	if want := "203.0.113.5,\"Korea, Republic of\",3\n"; body != want {
		t.Errorf("CSV = %q, 期望 %q", body, want)
	}
}

// TestExportAttacksCSVFilters：country/min_count 参数与 /attacks/geo 同口径生效。
func TestExportAttacksCSVFilters(t *testing.T) {
	srv, _ := newTestServer(t)
	srv.SetGeo(&fakeGeo{ok: true,
		codes: map[string]string{"203.0.113.5": "US"},
		names: map[string]string{"203.0.113.5": "United States"}})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/export/attacks_csv?range=24h&country=CN", nil)
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("country=CN 应为空 CSV, got %q", rec.Body.String())
	}
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/export/attacks_csv?range=24h&min_count=5", nil)
	rec2 := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec2, req2)
	if rec2.Body.Len() != 0 {
		t.Errorf("min_count=5 应为空 CSV, got %q", rec2.Body.String())
	}
}
