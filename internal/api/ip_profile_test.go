package api

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"database/sql"

	_ "modernc.org/sqlite"

	"sentry-agent/internal/event"
)

// doIPGet 请求 /api/v1/ip 并返回（状态码, 解码 map, 原始 body）。
func doIPGet(t *testing.T, srv *Server, url string) (int, map[string]any, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, url, nil))
	var out map[string]any
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("响应 JSON 解析失败: %v", err)
		}
	}
	return rec.Code, out, rec.Body.String()
}

// seedIPProfileExtra 向测试库补种 ban_events / cred_events（newTestServer 未覆盖的两表）。
// srv.db 为只读连接，须独立开写连接；写完即关（与 newTestServer 同模式）。
func seedIPProfileExtra(t *testing.T, dbPath string, ts int64) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO ban_events (ts, ip, type, jail) VALUES (?,?,?,?)`,
		ts, 0xCB007105, "ban", "sshd"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO cred_events (ts, proto, src_ip, username, password) VALUES (?,?,?,?,?)`,
		ts, "mysql", 0xCB007105, "root", "hunter2"); err != nil {
		t.Fatal(err)
	}
}

// TestIPProfileParamValidation 参数校验：缺失 / 非法 / IPv6 均 400。
func TestIPProfileParamValidation(t *testing.T) {
	srv, _ := newTestServer(t)
	cases := []struct {
		url    string
		substr string // 期望错误提示包含的子串（空串不检查）
	}{
		{"/api/v1/ip", "ip"},                 // 缺参数
		{"/api/v1/ip?ip=not-an-ip", "非法"},    // 解析失败
		{"/api/v1/ip?ip=::1", "IPv6 不支持"},    // IPv6 明确提示
		{"/api/v1/ip?ip=2001:db8::1", "IPv6"}, // IPv6 明确提示
		{"/api/v1/ip?ip=0.0.0.0", "占位"},      // 审计 C8：0.0.0.0 为 IPv6 归源占位值（src_ip=0），拒绝画像防错误归因
	}
	for _, c := range cases {
		code, _, body := doIPGet(t, srv, c.url)
		if code != http.StatusBadRequest {
			t.Errorf("%s → code = %d, 期望 400", c.url, code)
		}
		if c.substr != "" && !strings.Contains(body, c.substr) {
			t.Errorf("%s → body = %q, 期望包含 %q", c.url, body, c.substr)
		}
	}
}

// TestIPProfileAggregate 种子数据后各段聚合正确（含 bans/creds 补种段）。
func TestIPProfileAggregate(t *testing.T) {
	srv, dbPath := newTestServer(t)
	now := time.Now().Unix()
	seedIPProfileExtra(t, dbPath, now-10)
	code, out, body := doIPGet(t, srv, "/api/v1/ip?ip=203.0.113.5")
	if code != http.StatusOK {
		t.Fatalf("code = %d, body = %s", code, body)
	}
	if out["ip"] != "203.0.113.5" {
		t.Errorf("ip = %v", out["ip"])
	}
	if out["window_hours"] != float64(168) {
		t.Errorf("window_hours = %v, 期望 168", out["window_hours"])
	}
	if out["country"] != nil {
		t.Errorf("未注入 geo 时 country 应为 null，实际 %v", out["country"])
	}
	if out["banned_now"] != false {
		t.Errorf("未注入 bannedFn 时 banned_now 应为 false，实际 %v", out["banned_now"])
	}
	// connections 段：种子 5 条中 4 条 src=203.0.113.5（.6 的 1 条不计入）。
	conn := out["connections"].(map[string]any)
	if conn["total"] != float64(4) {
		t.Errorf("connections.total = %v, 期望 4", conn["total"])
	}
	if conn["first_ts"].(float64) <= 0 || conn["last_ts"].(float64) < conn["first_ts"].(float64) {
		t.Errorf("connections 首末时间异常: %v", conn)
	}
	ports := conn["top_dst_ports"].([]any)
	if len(ports) != 1 || ports[0].(map[string]any)["dst_port"] != float64(22) || ports[0].(map[string]any)["count"] != float64(4) {
		t.Errorf("top_dst_ports = %v, 期望 [{22,4}]", ports)
	}
	protos := conn["protos"].([]any)
	if len(protos) != 1 || protos[0].(map[string]any)["proto"] != float64(6) || protos[0].(map[string]any)["count"] != float64(4) {
		t.Errorf("protos = %v, 期望 [{6,4}]", protos)
	}
	// ssh 段：3 条失败（result=0），username 全 root。
	ssh := out["ssh"].(map[string]any)
	if ssh["total"] != float64(3) || ssh["failed"] != float64(3) || ssh["ok"] != float64(0) {
		t.Errorf("ssh total/failed/ok = %v/%v/%v, 期望 3/3/0", ssh["total"], ssh["failed"], ssh["ok"])
	}
	users := ssh["top_usernames"].([]any)
	if len(users) != 1 || users[0].(map[string]any)["username"] != "root" || users[0].(map[string]any)["count"] != float64(3) {
		t.Errorf("top_usernames = %v, 期望 [{root,3}]", users)
	}
	// firewall 段：4 条 drop。
	fw := out["firewall"].(map[string]any)
	if fw["total"] != float64(4) {
		t.Errorf("firewall.total = %v, 期望 4", fw["total"])
	}
	actions := fw["top_actions"].([]any)
	if len(actions) != 1 || actions[0].(map[string]any)["action"] != "drop" || actions[0].(map[string]any)["count"] != float64(4) {
		t.Errorf("top_actions = %v, 期望 [{drop,4}]", actions)
	}
	// bans 段：补种 1 条。
	bans := out["bans"].(map[string]any)
	if bans["total"] != float64(1) {
		t.Errorf("bans.total = %v, 期望 1", bans["total"])
	}
	banRecent := bans["recent"].([]any)
	if len(banRecent) != 1 {
		t.Fatalf("bans.recent 长度 = %d, 期望 1", len(banRecent))
	}
	br := banRecent[0].(map[string]any)
	if br["type"] != "ban" || br["jail"] != "sshd" {
		t.Errorf("bans.recent[0] = %v, 期望 type=ban jail=sshd", br)
	}
	// creds 段：补种 1 条；响应体不得含 password 字段（XSS 面收敛）。
	creds := out["creds"].(map[string]any)
	if creds["total"] != float64(1) {
		t.Errorf("creds.total = %v, 期望 1", creds["total"])
	}
	credRecent := creds["recent"].([]any)
	if len(credRecent) != 1 {
		t.Fatalf("creds.recent 长度 = %d, 期望 1", len(credRecent))
	}
	cr := credRecent[0].(map[string]any)
	if cr["proto"] != "mysql" || cr["username"] != "root" {
		t.Errorf("creds.recent[0] = %v, 期望 proto=mysql username=root", cr)
	}
	if len(cr) != 3 {
		t.Errorf("creds.recent[0] 字段数 = %d, 期望 3（ts/proto/username，无 password）", len(cr))
	}
	if strings.Contains(body, "password") {
		t.Error("响应体包含 password 字段，违背契约（攻击者可控输入不入画像）")
	}
}

// TestIPProfileEmptyIP 无数据 IP：各段零值 + 空数组恒非 null（m4 口径）。
func TestIPProfileEmptyIP(t *testing.T) {
	srv, _ := newTestServer(t)
	code, out, _ := doIPGet(t, srv, "/api/v1/ip?ip=203.0.113.99")
	if code != http.StatusOK {
		t.Fatalf("code = %d", code)
	}
	for _, seg := range []string{"connections", "ssh", "firewall", "bans", "creds"} {
		m, ok := out[seg].(map[string]any)
		if !ok {
			t.Fatalf("%s 段缺失", seg)
		}
		if m["total"] != float64(0) {
			t.Errorf("%s.total = %v, 期望 0", seg, m["total"])
		}
	}
	conn := out["connections"].(map[string]any)
	if conn["first_ts"] != float64(0) || conn["last_ts"] != float64(0) {
		t.Errorf("空段首末时间应为 0: %v", conn)
	}
	// 空数组：类型断言失败即说明输出为 null。
	for seg, key := range map[string]string{
		"connections": "top_dst_ports", "ssh": "top_usernames",
		"firewall": "top_actions", "bans": "recent", "creds": "recent",
	} {
		arr, ok := out[seg].(map[string]any)[key].([]any)
		if !ok || len(arr) != 0 {
			t.Errorf("%s.%s 应为空数组（非 null）: %v", seg, key, out[seg].(map[string]any)[key])
		}
	}
	if ssh := out["ssh"].(map[string]any); ssh["first_ts"] != float64(0) {
		t.Errorf("ssh.first_ts = %v, 期望 0", ssh["first_ts"])
	}
}

// TestIPProfileGeoAndBanned geo 注入时 country 正确 / 未注入或未命中 null；
// bannedFn 注入时 banned_now 命中与未命中。
func TestIPProfileGeoAndBanned(t *testing.T) {
	srv, _ := newTestServer(t)
	// geo 未注入 → null。
	_, out, _ := doIPGet(t, srv, "/api/v1/ip?ip=203.0.113.5")
	if out["country"] != nil {
		t.Fatalf("未注入 geo country 应为 null，实际 %v", out["country"])
	}
	// geo 注入且命中 → 国家对象。
	srv.SetGeo(&fakeGeo{ok: true,
		codes: map[string]string{"203.0.113.5": "US"},
		names: map[string]string{"203.0.113.5": "United States"}})
	_, out, _ = doIPGet(t, srv, "/api/v1/ip?ip=203.0.113.5")
	country, ok := out["country"].(map[string]any)
	if !ok || country["code"] != "US" || country["name"] != "United States" {
		t.Errorf("country = %v, 期望 {US, United States}", out["country"])
	}
	// geo 注入但未命中该 IP → null。
	_, out, _ = doIPGet(t, srv, "/api/v1/ip?ip=203.0.113.99")
	if out["country"] != nil {
		t.Errorf("未命中 IP country 应为 null，实际 %v", out["country"])
	}
	// bannedFn：名单含目标 IP → true。
	srv.SetBannedList(func() ([]uint32, int64) {
		return []uint32{event.IPv4ToUint32(net.ParseIP("203.0.113.5"))}, 0
	})
	_, out, _ = doIPGet(t, srv, "/api/v1/ip?ip=203.0.113.5")
	if out["banned_now"] != true {
		t.Errorf("banned_now = %v, 期望 true", out["banned_now"])
	}
	// 名单不含目标 IP → false。
	_, out, _ = doIPGet(t, srv, "/api/v1/ip?ip=203.0.113.99")
	if out["banned_now"] != false {
		t.Errorf("banned_now = %v, 期望 false", out["banned_now"])
	}
}
