package api

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// newQueryRowsTestServer 创建 5 个明细端点（connections/ssh/firewall/bans/honeypot events）
// 共用的参数矩阵测试 fixture（T5 泛型写出器重构回归）：每表插入 ts 递减、可按各端点
// 过滤参数区分的少量行——
//   connections 3（proto 6×2+17×1；dst_port 22/80/53；src_ip ipA×2+ipB×1）
//   ssh_attempts 3（src_ip ipA×2+ipB×1；result 0×2+1×1；username root×2+admin×1）
//   firewall_events 3（action drop/reject/inbound；dst_port 22/80/443）
//   ban_events 2；cred_events 2（proto telnet/mysql）
// ts 取 now-10/-20/-30（默认 24h 窗口内）。表结构统一走 createTestSchema（m5 单一来源）。
func newQueryRowsTestServer(t *testing.T) (*Server, int64) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	createTestSchema(t, db)
	now := time.Now().Unix()
	const (
		ipA = 0xCB007105 // 203.0.113.5
		ipB = 0xCB007106 // 203.0.113.6
		dst = 0x0A000002 // 10.0.0.2
	)
	ins := func(query string, args ...any) {
		if _, err := db.Exec(query, args...); err != nil {
			t.Fatal(err)
		}
	}
	ins(`INSERT INTO connections (ts, ev_type, proto, src_ip, src_port, dst_ip, dst_port) VALUES (?,?,?,?,?,?,?)`, now-10, 1, 6, ipA, 40001, dst, 22)
	ins(`INSERT INTO connections (ts, ev_type, proto, src_ip, src_port, dst_ip, dst_port) VALUES (?,?,?,?,?,?,?)`, now-20, 1, 6, ipB, 40002, dst, 80)
	ins(`INSERT INTO connections (ts, ev_type, proto, src_ip, src_port, dst_ip, dst_port) VALUES (?,?,?,?,?,?,?)`, now-30, 2, 17, ipA, 40003, dst, 53)
	ins(`INSERT INTO ssh_attempts (ts, src_ip, username, auth_method, result, detail) VALUES (?,?,?,?,?,?)`, now-10, ipA, "root", "password", 0, "Failed password")
	ins(`INSERT INTO ssh_attempts (ts, src_ip, username, auth_method, result, detail) VALUES (?,?,?,?,?,?)`, now-20, ipB, "admin", "password", 0, "Failed password")
	ins(`INSERT INTO ssh_attempts (ts, src_ip, username, auth_method, result, detail) VALUES (?,?,?,?,?,?)`, now-30, ipA, "root", "publickey", 1, "Accepted publickey")
	ins(`INSERT INTO firewall_events (ts, chain, action, proto, src_ip, src_port, dst_ip, dst_port, raw) VALUES (?,?,?,?,?,?,?,?,?)`, now-10, "input", "drop", 6, ipA, 40000, dst, 22, "SENTRY_FW")
	ins(`INSERT INTO firewall_events (ts, chain, action, proto, src_ip, src_port, dst_ip, dst_port, raw) VALUES (?,?,?,?,?,?,?,?,?)`, now-20, "input", "reject", 6, ipB, 40000, dst, 80, "SENTRY_FW")
	ins(`INSERT INTO firewall_events (ts, chain, action, proto, src_ip, src_port, dst_ip, dst_port, raw) VALUES (?,?,?,?,?,?,?,?,?)`, now-30, "input", "inbound", 6, ipA, 40000, dst, 443, "SENTRY_FW")
	ins(`INSERT INTO ban_events (ts, ip, type, jail) VALUES (?,?,?,?)`, now-10, ipA, "ban", "sshd")
	ins(`INSERT INTO ban_events (ts, ip, type, jail) VALUES (?,?,?,?)`, now-20, ipB, "ban", "recidive")
	ins(`INSERT INTO cred_events (ts, proto, src_ip, username, password, extra) VALUES (?,?,?,?,?,?)`, now-10, "telnet", ipA, "root", "toor", "")
	ins(`INSERT INTO cred_events (ts, proto, src_ip, username, password, extra) VALUES (?,?,?,?,?,?)`, now-20, "mysql", ipB, "admin", "0123456789abcdef", "hash")
	db.Close()

	srv, err := NewServer(dbPath, filepath.Join(dir, "archive"), "http://127.0.0.1:8080", true, nil)
	if err != nil {
		t.Fatalf("NewServer 失败: %v", err)
	}
	// 放宽限流（同 newTestServer 理由：参数矩阵测试不被默认桶误伤）。
	srv.SetLimits(1000, 1000, 1000, 100)
	srv.SetDBPath(dbPath)
	t.Cleanup(func() { srv.Close() })
	return srv, now
}

// doGetRaw 请求并返回原始响应体（空结果 [] 非 null 的字节级断言用）。
func doGetRaw(t *testing.T, srv *Server, path string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// TestQueryRowsParamMatrix 5 明细端点参数组合矩阵（表驱动）：无参数默认 / LIMIT 生效 /
// limit 超上限钳制（不报错） / limit 非法值回退默认 / 过滤参数生效。
// hBans 无过滤参数（仅 range/limit，过滤维度 N/A）；since/until 仅 hConnections 有，
// 由 TestQueryRowsSinceUntil 单独覆盖。
func TestQueryRowsParamMatrix(t *testing.T) {
	srv, now := newQueryRowsTestServer(t)
	srcA := strconv.FormatUint(0xCB007105, 10)
	cases := []struct {
		name    string
		path    string
		wantLen int
	}{
		// 无参数默认（limit 默认 200/100 > 种子行数，全量返回）。
		{"connections 无参数默认", "/api/v1/connections", 3},
		{"ssh 无参数默认", "/api/v1/ssh", 3},
		{"firewall 无参数默认", "/api/v1/firewall", 3},
		{"bans 无参数默认", "/api/v1/bans", 2},
		{"honeypot events 无参数默认", "/api/v1/honeypot/events", 2},
		// LIMIT ? 占位生效。
		{"connections limit=1", "/api/v1/connections?limit=1", 1},
		{"bans limit=1", "/api/v1/bans?limit=1", 1},
		{"honeypot events limit=1", "/api/v1/honeypot/events?limit=1", 1},
		// limit 超上限钳制（1000/500）：不报错，返回种子全量。
		{"connections limit=99999 钳制", "/api/v1/connections?limit=99999", 3},
		{"ssh limit=99999 钳制", "/api/v1/ssh?limit=99999", 3},
		{"firewall limit=99999 钳制", "/api/v1/firewall?limit=99999", 3},
		{"bans limit=99999 钳制", "/api/v1/bans?limit=99999", 2},
		{"honeypot events limit=99999 钳制", "/api/v1/honeypot/events?limit=99999", 2},
		// limit 非法值回退默认（parseUintParam def），行为同无参数。
		{"connections limit=abc", "/api/v1/connections?limit=abc", 3},
		{"bans limit=-1", "/api/v1/bans?limit=-1", 2},
		{"honeypot events limit=1.5", "/api/v1/honeypot/events?limit=1.5", 2},
		// 过滤参数生效（各端点 WHERE 构建不变）。
		{"connections proto=6", "/api/v1/connections?proto=6", 2},
		{"connections dst_port=80", "/api/v1/connections?dst_port=80", 1},
		{"connections src_ip=ipA", "/api/v1/connections?src_ip=" + srcA, 2},
		{"ssh src_ip=ipA", "/api/v1/ssh?src_ip=" + srcA, 2},
		{"ssh result=1", "/api/v1/ssh?result=1", 1},
		{"ssh username=admin", "/api/v1/ssh?username=admin", 1},
		{"firewall action=drop", "/api/v1/firewall?action=drop", 1},
		{"firewall dst_port=443", "/api/v1/firewall?dst_port=443", 1},
		{"honeypot events proto=mysql", "/api/v1/honeypot/events?proto=mysql", 1},
	}
	for _, tc := range cases {
		code, out := doGet(t, srv, tc.path)
		if code != http.StatusOK {
			t.Errorf("%s: 状态码 = %d, 期望 200", tc.name, code)
			continue
		}
		rows, ok := out["rows"].([]any)
		if !ok {
			t.Errorf("%s: rows 字段异常: %v", tc.name, out["rows"])
			continue
		}
		if len(rows) != tc.wantLen {
			t.Errorf("%s: rows 数 = %d, 期望 %d", tc.name, len(rows), tc.wantLen)
		}
	}
	// ORDER BY ts DESC：各端点 limit=1 首行均为最新一条（now-10）。
	for _, tc := range []struct{ name, path string }{
		{"connections", "/api/v1/connections"},
		{"ssh", "/api/v1/ssh"},
		{"firewall", "/api/v1/firewall"},
		{"bans", "/api/v1/bans"},
		{"honeypot events", "/api/v1/honeypot/events"},
	} {
		code, out := doGet(t, srv, tc.path+"?limit=1")
		if code != http.StatusOK {
			t.Errorf("%s 首行抽检: 状态码 = %d", tc.name, code)
			continue
		}
		rows := out["rows"].([]any)
		if len(rows) != 1 {
			t.Errorf("%s 首行抽检: rows 数 = %d, 期望 1", tc.name, len(rows))
			continue
		}
		if got := rows[0].(map[string]any)["ts"].(float64); got != float64(now-10) {
			t.Errorf("%s 首行 ts = %v, 期望 %d（最新优先）", tc.name, got, now-10)
		}
	}
}

// TestQueryRowsSinceUntil hConnections 专有 since/until 参数（Unix 秒，含端点）：
// 单独与组合过滤；其余 4 端点无该参数，传入须被忽略（返回全量，不误用为过滤条件）。
func TestQueryRowsSinceUntil(t *testing.T) {
	srv, now := newQueryRowsTestServer(t)
	since := strconv.FormatInt(now-15, 10)
	until := strconv.FormatInt(now-15, 10)
	// since=[now-15, ∞) → 仅 now-10 一行。
	code, out := doGet(t, srv, "/api/v1/connections?since="+since)
	if code != http.StatusOK || len(out["rows"].([]any)) != 1 {
		t.Errorf("since 过滤异常: %d %v", code, out["rows"])
	}
	// until=(-∞, now-15] → now-20、now-30 两行。
	code, out = doGet(t, srv, "/api/v1/connections?until="+until)
	if code != http.StatusOK || len(out["rows"].([]any)) != 2 {
		t.Errorf("until 过滤异常: %d %v", code, out["rows"])
	}
	// 组合 [now-25, now-15] → 仅 now-20 一行。
	comb := "/api/v1/connections?since=" + strconv.FormatInt(now-25, 10) + "&until=" + until
	code, out = doGet(t, srv, comb)
	if code != http.StatusOK || len(out["rows"].([]any)) != 1 {
		t.Errorf("since+until 组合异常: %d %v", code, out["rows"])
	}
	// 其余端点不识别 since/until：远未来值须被忽略，返回全量。
	for _, tc := range []struct {
		name    string
		path    string
		wantLen int
	}{
		{"ssh since 忽略", "/api/v1/ssh", 3},
		{"firewall since 忽略", "/api/v1/firewall", 3},
		{"bans since 忽略", "/api/v1/bans", 2},
		{"honeypot events since 忽略", "/api/v1/honeypot/events", 2},
	} {
		code, out := doGet(t, srv, tc.path+"?since="+strconv.FormatInt(now+86400, 10))
		if code != http.StatusOK {
			t.Errorf("%s: 状态码 = %d", tc.name, code)
			continue
		}
		if rows, ok := out["rows"].([]any); !ok || len(rows) != tc.wantLen {
			t.Errorf("%s: rows = %v, 期望 %d 行（since 不生效）", tc.name, out["rows"], tc.wantLen)
		}
	}
}

// TestQueryRowsEmptyResult 空结果输出 [] 非 null（m4 修复语义在 T5 重构后逐端点固化，
// 泛型写出器经 nonNil 统一；原始字节断言 "rows":[]）。bans 空表场景用无种子空库。
func TestQueryRowsEmptyResult(t *testing.T) {
	srv, _ := newQueryRowsTestServer(t)
	emptySrv := newTestServerWithNoOrigin(t) // 全空库
	cases := []struct {
		name string
		srv  *Server
		path string
	}{
		{"connections 过滤无命中", srv, "/api/v1/connections?dst_port=99999"},
		{"ssh 过滤无命中", srv, "/api/v1/ssh?src_ip=1"},
		{"firewall 过滤无命中", srv, "/api/v1/firewall?action=nope"},
		{"honeypot events 过滤无命中", srv, "/api/v1/honeypot/events?proto=rdp"},
		{"bans 空表", emptySrv, "/api/v1/bans"},
	}
	for _, tc := range cases {
		code, body := doGetRaw(t, tc.srv, tc.path)
		if code != http.StatusOK {
			t.Errorf("%s: 状态码 = %d, 期望 200", tc.name, code)
			continue
		}
		if !strings.Contains(body, `"rows":[]`) {
			t.Errorf("%s: 空结果应输出 []，body = %s", tc.name, body)
		}
		if strings.Contains(body, `"rows":null`) {
			t.Errorf("%s: 空结果不应输出 null，body = %s", tc.name, body)
		}
	}
}
