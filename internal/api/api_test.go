package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	_ "modernc.org/sqlite"

	"sentry-agent/internal/event"
)

// newTestServer 创建带测试数据的 API Server（临时主库 + 各表少量数据）。
func newTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	db, err := sql.Open("sqlite", "file:"+dbPath)
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
    packets INTEGER NOT NULL DEFAULT 0, bytes INTEGER NOT NULL DEFAULT 0, mark INTEGER NOT NULL DEFAULT 0,
    src_ip6 TEXT NOT NULL DEFAULT '', dst_ip6 TEXT NOT NULL DEFAULT '');
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
INSERT INTO meta(key, value) VALUES('schema_version', '1');
`)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	// 数据：5 条资源、5 条连接（2 NEW + 2 UPDATE + 1 DESTROY）、3 条 SSH 失败、4 条防火墙 drop。
	// 资源时间对齐到 60s 桶边界（R-11：避免 now%60<4 时跨桶导致 flaky）。
	base := now - now%60
	for i := 0; i < 5; i++ {
		if _, err := db.Exec(`INSERT INTO resources (ts, cpu_percent, mem_used_mb, mem_percent, disk_used_mb, disk_percent, net_rx_bps, net_tx_bps) VALUES (?,?,?,?,?,?,?,?)`,
			base+int64(i), 10+float64(i), 100, 20, 200, 30, 1000, 500); err != nil {
			t.Fatal(err)
		}
	}
	connData := []struct {
		ev  int
		src uint32
		dst uint32
		dstPort int
	}{
		{1, 0xCB007105, 0x0A000002, 22},
		{1, 0xCB007105, 0x0A000002, 22},
		{2, 0xCB007105, 0x0A000002, 22},
		{2, 0xCB007106, 0x0A000002, 22},
		{3, 0xCB007105, 0x0A000002, 22},
	}
	for i, c := range connData {
		if _, err := db.Exec(`INSERT INTO connections (ts, ev_type, proto, src_ip, src_port, dst_ip, dst_port) VALUES (?,?,?,?,?,?,?)`,
			now-int64(i), c.ev, 6, c.src, 50000+uint32(i), c.dst, c.dstPort); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 3; i++ {
		if _, err := db.Exec(`INSERT INTO ssh_attempts (ts, src_ip, username, auth_method, result, detail) VALUES (?,?,?,?,?,?)`,
			now-int64(i), 0xCB007105, "root", "password", 0, "Failed password"); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 4; i++ {
		if _, err := db.Exec(`INSERT INTO firewall_events (ts, chain, action, proto, src_ip, src_port, dst_ip, dst_port, raw) VALUES (?,?,?,?,?,?,?,?,?)`,
			now-int64(i), "input", "drop", 6, 0xCB007105, 50000, 0x0A000002, 22+i, "SENTRY_FW"); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	srv, err := NewServer(dbPath, filepath.Join(dir, "archive"), "http://127.0.0.1:8080", true,
		func() *event.ConnSnapshot {
			// Cnt=-1：count 文件不可读（测试环境无 /proc），回退 ss 口径（DEV-033）。
			return &event.ConnSnapshot{TS: now, Cnt: -1, Conn: []event.SnapConn{
				{Proto: 6, SrcIP: 0xCB007105, SrcPort: 50000, DstIP: 0x0A000002, DstPort: 22, State: "ESTAB"},
			}}
		})
	if err != nil {
		t.Fatalf("NewServer 失败: %v", err)
	}
	// DEV-P1-001（VS-04）：放宽限流参数（1000 rps/burst），避免既有功能测试被默认
	// 速率限制干扰（限流行为由独立 TestRateLimit* 专项覆盖）。
	srv.SetLimits(1000, 1000, 1000, 100)
	srv.SetDBPath(dbPath)
	t.Cleanup(func() { srv.Close() })
	return srv, dbPath
}

// doGet 发送 GET 请求并返回解码后的 map。
func doGet(t *testing.T, srv *Server, path string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)
	var out map[string]any
	if rec.Code == 200 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("响应 JSON 解析失败: %v", err)
		}
	}
	return rec.Code, out
}

func TestSummary(t *testing.T) {
	srv, _ := newTestServer(t)
	code, out := doGet(t, srv, "/api/v1/summary?range=1h")
	if code != 200 {
		t.Fatalf("code = %d", code)
	}
	if out["ssh_fail"].(float64) != 3 {
		t.Errorf("ssh_fail = %v, 期望 3", out["ssh_fail"])
	}
	if out["fw_events"].(float64) != 4 {
		t.Errorf("fw_events = %v, 期望 4", out["fw_events"])
	}
	if out["active_conns"].(float64) != 1 {
		t.Errorf("active_conns = %v, 期望 1（ss 快照回退口径，Cnt=-1）", out["active_conns"])
	}
	// DEV-045：summary top_ports 与 hTopPorts 同口径（全量防火墙事件）——种子 4 条 drop（22/23/24/25）。
	top := out["top_ports"].([]any)
	if len(top) != 4 {
		t.Fatalf("top_ports 数 = %d, 期望 4", len(top))
	}
	gotPorts := map[float64]bool{}
	for _, p := range top {
		m := p.(map[string]any)
		gotPorts[m["dst_port"].(float64)] = true
		if m["hits"].(float64) != 1 {
			t.Errorf("端口 %v hits = %v, 期望 1", m["dst_port"], m["hits"])
		}
	}
	for _, want := range []float64{22, 23, 24, 25} {
		if !gotPorts[want] {
			t.Errorf("top_ports 缺少端口 %v，实际 %v", want, gotPorts)
		}
	}
}

// TestActiveConnsCntPriority（DEV-033 新增测试，DEV-032 核查结论 8）：活跃连接数优先
// conntrack count 文件值（Cnt>=0，含 0）；Cnt=-1（不可读）回退 ss 快照连接数。
func TestActiveConnsCntPriority(t *testing.T) {
	dir := t.TempDir()
	mkSrv := func(snap *event.ConnSnapshot) *Server {
		// NewServer 为惰性只读打开，本测试仅调用 activeConns（不触库查询）。
		srv, err := NewServer(filepath.Join(dir, "state.db"), filepath.Join(dir, "archive"), "http://127.0.0.1:8080", true, func() *event.ConnSnapshot { return snap })
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { srv.Close() })
		return srv
	}
	// Cnt 有值（含 0）→ 用 count。
	for _, tc := range []struct {
		cnt  int64
		want int
	}{
		{31, 31}, {0, 0},
	} {
		srv := mkSrv(&event.ConnSnapshot{TS: 1, Cnt: tc.cnt, Conn: []event.SnapConn{{}, {}}})
		if got := srv.activeConns(); got != tc.want {
			t.Errorf("Cnt=%d: activeConns = %d, 期望 %d（count 优先）", tc.cnt, got, tc.want)
		}
	}
	// Cnt=-1（不可读）→ 回退 ss 快照长度。
	srv := mkSrv(&event.ConnSnapshot{TS: 1, Cnt: -1, Conn: []event.SnapConn{{}, {}, {}}})
	if got := srv.activeConns(); got != 3 {
		t.Errorf("Cnt=-1: activeConns = %d, 期望 3（ss 回退）", got)
	}
	// snapshotFn nil → 0。
	if got := (&Server{}).activeConns(); got != 0 {
		t.Errorf("nil snapshotFn: activeConns = %d, 期望 0", got)
	}
}

// TestActiveConnsFallbackTrace（AUDIT-005 A-03）：Cnt=-1 回退 ss 口径时限频留痕一次
// （info，1/小时）；Cnt>=0 不产生回退留痕。
func TestActiveConnsFallbackTrace(t *testing.T) {
	dir := t.TempDir()
	ch := make(chan event.SystemEvent, 8)
	srv, err := NewServer(filepath.Join(dir, "state.db"), filepath.Join(dir, "archive"),
		"http://127.0.0.1:8080", true, func() *event.ConnSnapshot {
			return &event.ConnSnapshot{TS: 1, Cnt: -1, Conn: []event.SnapConn{{}, {}}}
		})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	srv.SetSystemChannel(ch)

	// 首次回退 → 留痕。
	if got := srv.activeConns(); got != 2 {
		t.Errorf("activeConns = %d, 期望 2（ss 回退口径）", got)
	}
	select {
	case ev := <-ch:
		if ev.Level != "info" || !strings.Contains(ev.Message, "回退") {
			t.Errorf("回退留痕异常: %+v", ev)
		}
	default:
		t.Error("Cnt=-1 回退应产生留痕（AUDIT-005 A-03）")
	}
	// 限频内再次回退 → 不重复留痕。
	if got := srv.activeConns(); got != 2 {
		t.Errorf("activeConns = %d, 期望 2", got)
	}
	select {
	case ev := <-ch:
		t.Errorf("限频内不应重复留痕: %+v", ev)
	default:
	}
}

// TestHealthRetentionDays（AUDIT-005 A-04）：health 返回 retention_days（前端提示数据源）。
func TestHealthRetentionDays(t *testing.T) {
	srv, _ := newTestServer(t)
	srv.SetRetentionDays(7)
	code, out := doGet(t, srv, "/api/v1/health")
	if code != 200 {
		t.Fatalf("code = %d", code)
	}
	if out["retention_days"].(float64) != 7 {
		t.Errorf("retention_days = %v, 期望 7", out["retention_days"])
	}
	// 未注入（默认 0）→ 返回 0（前端显示"数据永久保留"）。
	srv2, _ := newTestServer(t)
	code2, out2 := doGet(t, srv2, "/api/v1/health")
	if code2 != 200 || out2["retention_days"].(float64) != 0 {
		t.Errorf("默认 retention_days 异常: %d %v", code2, out2["retention_days"])
	}
}

// TestTopPortsDPT（DEV-045）：TOP 端口统计所有防火墙事件（inbound/reject/drop 均计入"被探测端口"）。
func TestTopPortsDPT(t *testing.T) {
	srv, dbPath := newTestServer(t)
	// 补插 inbound/reject 事件（种子数据为 4 条 drop，端口 22/23/24/25）：
	// 端口 22 再 +2 inbound（合计 3）、端口 80 +1 reject、端口 81 +1 inbound。
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().Unix()
	for _, x := range []struct {
		action string
		port   int
	}{
		{"inbound", 22}, {"inbound", 22}, {"reject", 80}, {"inbound", 81},
	} {
		if _, err := db.Exec(`INSERT INTO firewall_events (ts, chain, action, proto, src_ip, src_port, dst_ip, dst_port, raw)
			VALUES (?,?,?,?,?,?,?,?,?)`, now, "input", x.action, 6, 0xCB007105, 50000, 0x0A000002, x.port, "SENTRY_FW"); err != nil {
			t.Fatal(err)
		}
	}
	code, out := doGet(t, srv, "/api/v1/attacks/top_ports?range=24h&top=5")
	if code != 200 {
		t.Fatalf("code = %d", code)
	}
	rows, ok := out["rows"].([]any)
	if !ok || len(rows) != 5 {
		t.Fatalf("rows 数量错误: %v", out["rows"])
	}
	// 端口按 DPT 全量聚合：22 = 1 drop + 2 inbound = 3，居首；80/81 来自 reject/inbound。
	first := rows[0].(map[string]any)
	if first["dst_port"].(float64) != 22 {
		t.Errorf("TOP1 端口 = %v, 期望 22", first["dst_port"])
	}
	if first["hits"].(float64) != 3 {
		t.Errorf("TOP1 hits = %v, 期望 3", first["hits"])
	}
	// 其余端口各 1：23/24/25（drop）+ 80（reject）+ 81（inbound）。
	if len(rows) != 5 {
		t.Errorf("rows 数 = %d, 期望 5", len(rows))
	}
}

func TestTopSources(t *testing.T) {
	srv, _ := newTestServer(t)
	code, out := doGet(t, srv, "/api/v1/attacks/top_sources?range=24h&top=5")
	if code != 200 {
		t.Fatalf("code = %d", code)
	}
	rows := out["rows"].([]any)
	if len(rows) == 0 {
		t.Fatal("无数据")
	}
	if rows[0].(map[string]any)["src_ip"].(float64) != 0xCB007105 {
		t.Error("攻击源 IP 聚合错误")
	}
}

func TestConnectionsQuery(t *testing.T) {
	srv, _ := newTestServer(t)
	code, out := doGet(t, srv, "/api/v1/connections?limit=10")
	if code != 200 {
		t.Fatalf("code = %d", code)
	}
	rows := out["rows"].([]any)
	if len(rows) != 5 {
		t.Errorf("连接行数 = %d, 期望 5", len(rows))
	}
}

func TestSSHAndFirewallAndBans(t *testing.T) {
	srv, _ := newTestServer(t)
	if code, out := doGet(t, srv, "/api/v1/ssh?range=24h"); code != 200 || len(out["rows"].([]any)) != 3 {
		t.Errorf("ssh 查询异常: %d %v", code, out)
	}
	if code, out := doGet(t, srv, "/api/v1/firewall?range=24h"); code != 200 || len(out["rows"].([]any)) != 4 {
		t.Errorf("firewall 查询异常: %d %v", code, out)
	}
	if code, out := doGet(t, srv, "/api/v1/ssh/timeline?range=24h"); code != 200 || len(out["rows"].([]any)) == 0 {
		t.Errorf("ssh timeline 异常: %d %v", code, out)
	}
	if code, out := doGet(t, srv, "/api/v1/bans?range=24h"); code != 200 {
		t.Errorf("bans 异常: %d %v", code, out)
	}
}

// TestFirewallTimeline（DEV-017 → DEV-045）：小时桶聚合 + drop/accept/reject/inbound 四通道计数 + 补零 + range 回显。
func TestFirewallTimeline(t *testing.T) {
	srv, dbPath := newTestServer(t)
	now := time.Now().Unix()
	// 补插跨小时数据：当前小时 2 drop + 1 accept + 2 reject + 3 inbound，
	// 上一小时 1 drop + 1 inbound，更早 2 小时前 3 accept + 1 reject。
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// 清空 newTestServer 自带防火墙数据，使桶计数精确可控（避免 now 跨小时边界导致 flaky）。
	if _, err := db.Exec(`DELETE FROM firewall_events`); err != nil {
		t.Fatal(err)
	}
	curHour := (now / 3600) * 3600
	ins := []struct {
		ts     int64
		action string
	}{
		{curHour + 10, "drop"},
		{curHour + 20, "drop"},
		{curHour + 30, "accept"},
		{curHour + 40, "reject"},
		{curHour + 50, "reject"},
		{curHour + 60, "inbound"},
		{curHour + 70, "inbound"},
		{curHour + 80, "inbound"},
		{curHour - 3600 + 5, "drop"},
		{curHour - 3600 + 6, "inbound"},
		{curHour - 7200 + 5, "accept"},
		{curHour - 7200 + 6, "accept"},
		{curHour - 7200 + 7, "accept"},
		{curHour - 7200 + 8, "reject"},
	}
	for _, x := range ins {
		if _, err := db.Exec(`INSERT INTO firewall_events (ts, chain, action, proto, src_ip, src_port, dst_ip, dst_port, raw)
			VALUES (?,?,?,?,?,?,?,?,?)`, x.ts, "input", x.action, 6, 1, 1, 2, 22, "SENTRY_FW"); err != nil {
			t.Fatal(err)
		}
	}
	code, out := doGet(t, srv, "/api/v1/firewall/timeline?range=24h")
	if code != 200 {
		t.Fatalf("code = %d", code)
	}
	if out["granularity"] != "1h" {
		t.Errorf("granularity = %v, 期望 1h", out["granularity"])
	}
	if out["range"] != "24h" {
		t.Errorf("range 回显 = %v, 期望 24h", out["range"])
	}
	buckets := out["buckets"].([]any)
	if len(buckets) < 2 {
		t.Fatalf("buckets 数 = %d, 期望 >= 2（含补零）", len(buckets))
	}
	// 断言桶内 drop/accept/reject/inbound 四通道计数正确。
	counted := map[int64][4]int64{}
	for _, b := range buckets {
		m := b.(map[string]any)
		ts := int64(m["ts"].(float64))
		counted[ts] = [4]int64{
			int64(m["drop"].(float64)), int64(m["accept"].(float64)),
			int64(m["reject"].(float64)), int64(m["inbound"].(float64)),
		}
	}
	if got := counted[curHour]; got != [4]int64{2, 1, 2, 3} {
		t.Errorf("当前小时 drop/accept/reject/inbound = %v, 期望 {2 1 2 3}", got)
	}
	if got := counted[curHour-3600]; got != [4]int64{1, 0, 0, 1} {
		t.Errorf("上一小时 drop/accept/reject/inbound = %v, 期望 {1 0 0 1}", got)
	}
	if got := counted[curHour-7200]; got != [4]int64{0, 3, 1, 0} {
		t.Errorf("两小时前 drop/accept/reject/inbound = %v, 期望 {0 3 1 0}", got)
	}
	// 断言补零：桶时间连续（相邻差 3600）。
	for i := 1; i < len(buckets); i++ {
		prev := int64(buckets[i-1].(map[string]any)["ts"].(float64))
		cur := int64(buckets[i].(map[string]any)["ts"].(float64))
		if cur-prev != 3600 {
			t.Fatalf("桶不连续: %d → %d", prev, cur)
		}
	}
	// range 默认（不传参数）回显 24h。
	code2, out2 := doGet(t, srv, "/api/v1/firewall/timeline")
	if code2 != 200 || out2["range"] != "24h" {
		t.Errorf("默认 range 异常: %d %v", code2, out2)
	}
	// R-15：非法 range 回显 24h（与 rangeSeconds 回退口径一致）。
	code3, out3 := doGet(t, srv, "/api/v1/firewall/timeline?range=2d")
	if code3 != 200 || out3["range"] != "24h" {
		t.Errorf("非法 range 回显异常: %d %v", code3, out3)
	}
	// R-15：30d 桶数 = 30*24+1（含当前小时），且时间连续。
	code4, out4 := doGet(t, srv, "/api/v1/firewall/timeline?range=30d")
	if code4 != 200 {
		t.Fatalf("30d code = %d", code4)
	}
	b4 := out4["buckets"].([]any)
	want := 30*24 + 1
	if len(b4) != want {
		t.Errorf("30d buckets = %d, 期望 %d", len(b4), want)
	}
}

func TestHealthAndArchive(t *testing.T) {
	srv, dbPath := newTestServer(t)
	srv.SetDBPath(dbPath)
	code, out := doGet(t, srv, "/api/v1/health")
	if code != 200 {
		t.Fatalf("code = %d", code)
	}
	if out["ok"] != true {
		t.Error("health ok 应为 true")
	}
	if out["schema_version"] != "1" {
		t.Errorf("schema_version = %v", out["schema_version"])
	}
	if code, out := doGet(t, srv, "/api/v1/archive"); code != 200 {
		t.Errorf("archive 异常: %d", code)
	} else if out["rows"] == nil {
		t.Error("archive rows 缺失")
	}
}

func TestSnapshot(t *testing.T) {
	srv, _ := newTestServer(t)
	code, out := doGet(t, srv, "/api/v1/snapshot")
	if code != 200 {
		t.Fatalf("code = %d", code)
	}
	rows := out["rows"].([]any)
	if len(rows) != 1 {
		t.Fatalf("快照行数 = %d", len(rows))
	}
	row := rows[0].(map[string]any)
	// IP 转点分十进制（API 层转换）。
	if row["src_ip"] != "203.0.113.5" {
		t.Errorf("src_ip = %v, 期望 203.0.113.5", row["src_ip"])
	}
	if row["dst_ip"] != "10.0.0.2" {
		t.Errorf("dst_ip = %v, 期望 10.0.0.2", row["dst_ip"])
	}
}

// TestWSServerOrigin 独立启动 httptest 服务验证 WS Origin 白名单（D-04）。
func TestWSServerOrigin(t *testing.T) {
	srv, _ := newTestServer(t)
	ts := httptest.NewServer(srv.mux)
	defer ts.Close()
	// 错误 Origin → 403。
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/ws", nil)
	req.Header.Set("Origin", "http://evil.example.com")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("非法 Origin 状态码 = %d, 期望 403", resp.StatusCode)
	}
	// 白名单 Origin → 非 403（101 升级或 400 均非 403；用 WS 客户端完整验证见 WSL 实测）。
	req2, _ := http.NewRequest(http.MethodGet, ts.URL+"/ws", nil)
	req2.Header.Set("Origin", "http://127.0.0.1:8080")
	req2.Header.Set("Connection", "Upgrade")
	req2.Header.Set("Upgrade", "websocket")
	req2.Header.Set("Sec-WebSocket-Version", "13")
	req2.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	resp2, err := http.DefaultClient.Do(req2)
	if err == nil {
		resp2.Body.Close()
		if resp2.StatusCode == http.StatusForbidden {
			t.Error("白名单 Origin 不应被拒")
		}
	}
}

// TestResources（R-02）：资源查询 step 聚合与分支。
func TestResources(t *testing.T) {
	srv, _ := newTestServer(t)
	// step=60s：5 条数据（间隔 1s）聚合为 1 个 bucket。
	code, out := doGet(t, srv, "/api/v1/resources?range=24h&step=60s")
	if code != 200 {
		t.Fatalf("code = %d", code)
	}
	points := out["points"].([]any)
	if len(points) != 1 {
		t.Fatalf("60s 聚合点数 = %d, 期望 1", len(points))
	}
	p := points[0].(map[string]any)
	// CPU 均值应在数据范围（10~14）内。
	if p["cpu"].(float64) < 10 || p["cpu"].(float64) > 14 {
		t.Errorf("CPU 聚合均值异常: %v", p["cpu"])
	}
	// step=5s：点数 >=1 且 <=5（bucket 数依赖 now 的 5s 对齐，不做精确断言）。
	code, out = doGet(t, srv, "/api/v1/resources?range=24h&step=5s")
	if code != 200 {
		t.Fatalf("code = %d", code)
	}
	points = out["points"].([]any)
	if len(points) < 1 || len(points) > 5 {
		t.Errorf("5s 聚合点数 = %d, 期望 1~5", len(points))
	}
	if out["step_s"].(float64) != 5 {
		t.Errorf("step_s = %v, 期望 5", out["step_s"])
	}
	// 非法 step 回退默认 60s。
	code, out = doGet(t, srv, "/api/v1/resources?range=24h&step=xxx")
	if code != 200 || out["step_s"].(float64) != 60 {
		t.Errorf("非法 step 应回退 60s: %d %v", code, out["step_s"])
	}
}

// TestHealthDBDown（R-06）：DB 不可用时 health 返回 500 + ok 缺失。
func TestHealthDBDown(t *testing.T) {
	srv, _ := newTestServer(t)
	// 关闭只读连接模拟 DB 故障。
	srv.db.Close()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("DB 故障时 health 状态码 = %d, 期望 500", rec.Code)
	}
}

// newTestServerWithNoOrigin 允许无 Origin 的 Server（M-02 测试用）。
func newTestServerWithNoOrigin(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE resources (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, cpu_percent REAL NOT NULL,
    mem_used_mb REAL NOT NULL, mem_percent REAL NOT NULL, disk_used_mb REAL NOT NULL,
    disk_percent REAL NOT NULL, net_rx_bps INTEGER NOT NULL DEFAULT 0, net_tx_bps INTEGER NOT NULL DEFAULT 0);
CREATE TABLE connections (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, ev_type INTEGER NOT NULL,
    proto INTEGER NOT NULL, src_ip INTEGER NOT NULL, src_port INTEGER NOT NULL,
    dst_ip INTEGER NOT NULL, dst_port INTEGER NOT NULL,
    packets INTEGER NOT NULL DEFAULT 0, bytes INTEGER NOT NULL DEFAULT 0, mark INTEGER NOT NULL DEFAULT 0,
    src_ip6 TEXT NOT NULL DEFAULT '', dst_ip6 TEXT NOT NULL DEFAULT '');
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
INSERT INTO meta(key, value) VALUES('schema_version', '1');
`)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	srv, err := NewServer(dbPath, filepath.Join(dir, "archive"), "http://127.0.0.1:8080", true, nil)
	if err != nil {
		t.Fatalf("NewServer 失败: %v", err)
	}
	// DEV-P1-001（VS-04）：放宽限流（同 newTestServer 理由；/ws 路由本身不限流，
	// 此设置仅防 WS 测试前的其他请求被默认桶误伤）。
	srv.SetLimits(1000, 1000, 1000, 100)
	t.Cleanup(func() { srv.Close() })
	return srv
}

// TestWSNoOrigin（M-02）：非回环（allowNoOrigin=false）拒绝无 Origin；回环放行。
func TestWSNoOrigin(t *testing.T) {
	// 非回环模式（默认 NewServer 的 allowNoOrigin 由测试决定——直接构造两种）。
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	// 复用 newTestServerWithNoOrigin 的建库逻辑，分别以 false/true 创建。
	srvStrict, err := NewServer(dbPath, filepath.Join(dir, "arch"), "http://127.0.0.1:8080", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srvStrict.Close()

	// 无 Origin + 非回环 → 403。
	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	rec := httptest.NewRecorder()
	srvStrict.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("非回环无 Origin 状态码 = %d, 期望 403", rec.Code)
	}

	// 回环模式（allowNoOrigin=true）无 Origin → 非 403。
	srvLoose := newTestServerWithNoOrigin(t)
	rec2 := httptest.NewRecorder()
	srvLoose.mux.ServeHTTP(rec2, req)
	if rec2.Code == http.StatusForbidden {
		t.Error("回环模式无 Origin 不应被拒")
	}
}

// TestFrameConnStatsCursors（W-01）：双游标计数语义——晚落库事件不永久排除。
func TestFrameConnStatsCursors(t *testing.T) {
	srv, _ := newTestServer(t)
	// 初始游标 0：全部 5 条连接（2 NEW + 2 UPDATE + 1 DESTROY）中 NEW=2、DESTROY=1。
	newCnt, destCnt, newMax, destMax, _, ok := srv.frameConnStats(0, 0)
	if !ok {
		t.Fatal("查询失败")
	}
	if newCnt != 2 || destCnt != 1 {
		t.Errorf("首轮计数 new=%d dest=%d, 期望 2/1", newCnt, destCnt)
	}
	// 游标推进后：无新事件 → 0。
	newCnt2, destCnt2, _, _, _, _ := srv.frameConnStats(newMax, destMax)
	if newCnt2 != 0 || destCnt2 != 0 {
		t.Errorf("游标推进后计数 new=%d dest=%d, 期望 0/0", newCnt2, destCnt2)
	}
	// 模拟晚落库：插入 1 条 NEW（id 递增）后旧游标仍能计到。
	db, err := sql.Open("sqlite", "file:"+srv.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().Unix()
	if _, err := db.Exec(`INSERT INTO connections (ts, ev_type, proto, src_ip, src_port, dst_ip, dst_port) VALUES (?,1,6,1,1,2,22)`, now); err != nil {
		t.Fatal(err)
	}
	// 用"落后一个事件"的游标（newMax 对应插入前）→ 应计到 1 条。
	newCnt3, _, _, _, _, _ := srv.frameConnStats(newMax, destMax)
	if newCnt3 != 1 {
		t.Errorf("晚落库事件计数 new=%d, 期望 1（晚落库不永久排除）", newCnt3)
	}
	// 跨类型互漏检查：DESTROY 游标不受 NEW 插入影响。
	_, destCnt3, _, _, _, _ := srv.frameConnStats(0, destMax)
	if destCnt3 != 0 {
		t.Errorf("跨类型互漏: dest=%d, 期望 0", destCnt3)
	}
	// DESTROY 晚落库（R-02）：NEW 游标已推进后，新插入 DESTROY 仍应被 DESTROY 游标计到。
	if _, err := db.Exec(`INSERT INTO connections (ts, ev_type, proto, src_ip, src_port, dst_ip, dst_port) VALUES (?,3,6,1,1,2,22)`, now); err != nil {
		t.Fatal(err)
	}
	_, destCnt4, _, destMax4, _, _ := srv.frameConnStats(0, destMax)
	if destCnt4 != 1 {
		t.Errorf("DESTROY 晚落库计数 dest=%d, 期望 1", destCnt4)
	}
	// 查询失败路径（R-02）：关闭只读连接后 ok=false 且游标不变（不推进）。
	_ = destMax4
	srv.db.Close()
	_, _, _, _, _, ok2 := srv.frameConnStats(newMax, destMax4)
	if ok2 {
		t.Error("DB 关闭后应返回 ok=false")
	}
	// 失败后游标不推进语义由 PushLoop 的 ok 分支保证（此处验证返回值不误推进）：
	// frameConnStats 失败时返回的 newMax/destMax 为入参原值。
	n5, d5, nm5, dm5, _, ok3 := srv.frameConnStats(123, 456)
	if ok3 {
		t.Error("DB 关闭后仍应 ok=false")
	}
	if n5 != 0 || d5 != 0 || nm5 != 123 || dm5 != 456 {
		t.Errorf("失败路径返回值错误: %d/%d/%d/%d", n5, d5, nm5, dm5)
	}
}

// TestReadOnlyConnection 只读连接与写线程并发（auditor 坑点验证：WAL 多读者）。
func TestReadOnlyConnection(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	// 写连接（模拟写线程）。
	wdb, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wdb.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY, v INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	// 只读连接（API 形态）。
	rdb, err := sql.Open("sqlite", "file:"+urlPathEscape(dbPath)+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	// 写线程插入 + 只读查询并发。
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			_, _ = wdb.Exec(`INSERT INTO t(v) VALUES (?)`, i)
		}
	}()
	for i := 0; i < 50; i++ {
		var n int
		if err := rdb.QueryRow(`SELECT COUNT(*) FROM t`).Scan(&n); err != nil {
			t.Fatalf("只读查询失败（WAL 并发读问题）: %v", err)
		}
	}
	<-done
	rdb.Close()
	wdb.Close()
}

// ---- DEV-P1-001（VS-04）API 速率限制专项测试 ----
// 默认限制参数：全局 10 rps / burst 20，heavy 1 rps / burst 2（与 config.Defaults 一致）。

// TestRateLimitGlobal 全局桶：超过 burst 后返回 429（含 Retry-After 头）。
// 断言设计：低速率（1 rps）窗口下 8 个连续请求，burst 5 内必全过（200 ≥ 5），
// 超出部分受时间窗补充影响不精确计数，仅断言至少出现 429（8-5-补充<1 → 至少 2 个）。
func TestRateLimitGlobal(t *testing.T) {
	srv, _ := newTestServer(t)
	srv.SetLimits(1, 5, 1, 100) // 1 rps / burst 5：降低补充速率使超出窗口确定性更稳
	code200 := 0
	code429 := 0
	var retryAfter string
	for i := 0; i < 8; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/ssh?range=1h", nil)
		rec := httptest.NewRecorder()
		srv.mux.ServeHTTP(rec, req)
		switch rec.Code {
		case http.StatusOK:
			code200++
		case http.StatusTooManyRequests:
			code429++
			if retryAfter == "" {
				retryAfter = rec.Header().Get("Retry-After")
			}
		default:
			t.Fatalf("第 %d 次请求状态码 = %d, 期望 200/429", i+1, rec.Code)
		}
	}
	if code200 < 5 {
		t.Errorf("200 次数 = %d, 期望 >= 5（burst 容量内必过）", code200)
	}
	if code429 < 1 {
		t.Errorf("429 次数 = %d, 期望 >= 1（超出 burst 必被限）", code429)
	}
	if retryAfter != "1" {
		t.Errorf("Retry-After 头 = %q, 期望 1", retryAfter)
	}
}

// TestRateLimitHeavy 重聚合端点：独立重桶（1 rps / burst 6），第 7 个请求 429。
// burst=6 覆盖真实浏览器双轮重叠窗口（Chrome 6 连接限制下慢查询排队，见 api.go routes 注释）。
func TestRateLimitHeavy(t *testing.T) {
	srv, _ := newTestServer(t)
	srv.SetLimits(10, 20, 1, 100)
	for i := 0; i < 7; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/summary?range=1h", nil)
		rec := httptest.NewRecorder()
		srv.mux.ServeHTTP(rec, req)
		want := http.StatusOK
		if i >= 6 {
			want = http.StatusTooManyRequests
		}
		if rec.Code != want {
			t.Fatalf("第 %d 次 summary 请求状态码 = %d, 期望 %d", i+1, rec.Code, want)
		}
	}
}

// TestRateLimitHealthExempt 健康检查豁免限流（运维探活不被误伤）。
func TestRateLimitHealthExempt(t *testing.T) {
	srv, _ := newTestServer(t)
	srv.SetLimits(10, 20, 1, 100)
	for i := 0; i < 25; i++ { // 超过全局 burst 20 仍应全 200
		req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
		rec := httptest.NewRecorder()
		srv.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("第 %d 次 health 请求状态码 = %d, 期望 200（豁免限流）", i+1, rec.Code)
		}
	}
}

// TestRateLimitNormalPollNotAffected 正常前端轮询节奏不受限流影响：
// 模拟前端 5s 轮询（一轮 9 请求：6 普通 + 3 heavy）。首轮消耗 heavy 桶 3 令牌（满桶 3），
// 轮间模拟 5s 间隔（sleep 3.2s 即补充 ≥3 令牌，cap 3），两轮均无 429——
// 真实 5s 间隔下 heavy 消耗 0.6 rps < 补充 1 rps，稳态永不亏空。
func TestRateLimitNormalPollNotAffected(t *testing.T) {
	srv, _ := newTestServer(t)
	srv.SetLimits(10, 20, 1, 100)
	paths := []string{
		"/api/v1/summary?range=1h",
		"/api/v1/ssh?range=1h",
		"/api/v1/firewall?range=1h",
		"/api/v1/connections?range=1h",
		"/api/v1/bans?range=1h",
		"/api/v1/attacks/top_ports?range=1h",
		"/api/v1/attacks/top_sources?range=1h",
		"/api/v1/ssh/timeline?range=1h",
		"/api/v1/firewall/timeline?range=1h",
	}
	for round := 0; round < 2; round++ {
		for _, p := range paths {
			req := httptest.NewRequest(http.MethodGet, p, nil)
			rec := httptest.NewRecorder()
			srv.mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("第 %d 轮 %s 状态码 = %d, 期望 200（正常轮询不得误伤）", round+1, p, rec.Code)
			}
		}
		if round == 0 {
			time.Sleep(3200 * time.Millisecond) // 模拟轮询间隔（补充 heavy 令牌）
		}
	}
}

var _ = os.Getenv // 防未使用（保留 os 依赖）

// ---- DEV-P1-001（VS-03）WS 连接限制专项测试 ----

// wsDialURL 构造 httptest 服务的 WS URL（Origin 用白名单 http://127.0.0.1:8080）。
func wsDialURL(ts *httptest.Server) (string, http.Header) {
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"
	return wsURL, http.Header{"Origin": {"http://127.0.0.1:8080"}}
}

// wsRejectProbe 以 HTTP 升级请求探测 /ws（非完整 WS 客户端，用于断言 4xx/5xx 状态码）。
func wsRejectProbe(t *testing.T, ts *httptest.Server, origin string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/ws", nil)
	req.Header.Set("Origin", origin)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// TestWSMaxConnsReject（VS-03）：连接数达到 ws_max_conns 上限后新连接返回 503；
// 断开一个连接后占位释放，可重新建立连接。
func TestWSMaxConnsReject(t *testing.T) {
	srv, _ := newTestServer(t)
	srv.SetLimits(1000, 1000, 1000, 2) // WS 上限 2
	ts := httptest.NewServer(srv.mux)
	defer ts.Close()
	wsURL, hdr := wsDialURL(ts)

	c1, _, err := websocket.DefaultDialer.Dial(wsURL, hdr)
	if err != nil {
		t.Fatalf("第 1 个 WS 连接失败: %v", err)
	}
	c2, _, err := websocket.DefaultDialer.Dial(wsURL, hdr)
	if err != nil {
		t.Fatalf("第 2 个 WS 连接失败: %v", err)
	}
	if code := wsRejectProbe(t, ts, "http://127.0.0.1:8080"); code != http.StatusServiceUnavailable {
		t.Errorf("超限请求状态码 = %d, 期望 503", code)
	}

	// 断开 1 个后占位释放，可重连（服务端读循环退出触发 remove，轮询等待）。
	c1.Close()
	c2.Close()
	deadline := time.Now().Add(3 * time.Second)
	for {
		c3, _, err := websocket.DefaultDialer.Dial(wsURL, hdr)
		if err == nil {
			c3.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("断开后 3s 内无法重连（占位未释放或上限未回退）")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestWSUpgradeFailRollback（VS-03）：Upgrade 失败（非 WS 请求）必须回滚占位——
// 占位泄漏会使上限被僵尸连接逐渐耗尽；回滚正确时后续真实 WS 连接仍可建立。
func TestWSUpgradeFailRollback(t *testing.T) {
	srv, _ := newTestServer(t)
	srv.SetLimits(1000, 1000, 1000, 1) // 上限 1
	ts := httptest.NewServer(srv.mux)
	defer ts.Close()
	wsURL, hdr := wsDialURL(ts)

	// 非 WS 请求（无 Upgrade 头）打 /ws：Upgrade 失败路径。
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/ws", nil)
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// 升级失败回滚后，上限 1 仍可建立真实 WS 连接。
	deadline := time.Now().Add(3 * time.Second)
	for {
		c1, _, err := websocket.DefaultDialer.Dial(wsURL, hdr)
		if err == nil {
			c1.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("Upgrade 失败后占位未回滚，真实 WS 连接被拒")
		}
		time.Sleep(50 * time.Millisecond)
	}
}
