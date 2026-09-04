package api

import (
	"database/sql"
	"encoding/csv"
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

// readTableCSV 解析 CSV body 为记录切片（含表头；csv.Reader 正确处理带引号换行的字段）。
func readTableCSV(t *testing.T, body string) [][]string {
	t.Helper()
	recs, err := csv.NewReader(strings.NewReader(body)).ReadAll()
	if err != nil {
		t.Fatalf("CSV 解析失败: %v", err)
	}
	return recs
}

// openTestDB 打开测试库直连（写入种子数据用；与既有 TestExportCSVWriteErrorBreak 同模式）。
func openTestDB(t *testing.T, dbPath string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// TestExportTableBadType：type 缺失/非法 → 400，错误信息列出全部合法值。
func TestExportTableBadType(t *testing.T) {
	srv, _ := newTestServer(t)
	for _, p := range []string{"/api/v1/export/table", "/api/v1/export/table?type=bogus", "/api/v1/export/table?type=SSH"} {
		rec := doExport(t, srv, p)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s 状态码 = %d, 期望 400", p, rec.Code)
		}
		for _, want := range []string{"ssh", "fw", "hp", "conn", "bans", "sys"} {
			if !strings.Contains(rec.Body.String(), want) {
				t.Errorf("%s 错误信息 %q 缺合法值 %q", p, rec.Body.String(), want)
			}
		}
	}
}

// tableCase 单类型导出断言输入（insert/args 种一条窗口内数据；wantRow 为期望数据行，不含 ts 列——ts 单独断言 RFC3339）。
type tableCase struct {
	typ     string
	insert  string
	args    []any
	wantRow []string
}

// TestExportTableTypes 六类型各一例：表头固定列名、Content-Disposition 文件名格式、
// 字段值精确匹配、ts 为 RFC3339 且等于种子时刻。ssh 的 username/detail、hp 的
// password、fw 的 raw 均含逗号/引号/换行（攻击者可控字段）——顺带覆盖 RFC 4180 转义。
func TestExportTableTypes(t *testing.T) {
	tsIn := time.Now().Unix() - 60
	cases := []tableCase{
		{
			typ:    "ssh",
			insert: `INSERT INTO ssh_attempts (ts, src_ip, username, auth_method, result, fingerprint, detail) VALUES (?,?,?,?,?,?,?)`,
			args:   []any{tsIn, 0xCB007105, "ro,\"ot\"x\ny", "password", 0, "SHA256:abc", "Failed password, \"root\""},
			wantRow: []string{"203.0.113.5", "ro,\"ot\"x\ny", "password", "0", "SHA256:abc", "Failed password, \"root\""},
		},
		{
			typ:    "fw",
			insert: `INSERT INTO firewall_events (ts, chain, action, proto, src_ip, src_port, dst_ip, dst_port, raw) VALUES (?,?,?,?,?,?,?,?,?)`,
			args:   []any{tsIn, "input", "drop", 6, 0xCB007105, 50000, 0x0A000002, 22, "PROTO=TCP, DPT=\"22\""},
			wantRow: []string{"input", "drop", "6", "203.0.113.5", "50000", "10.0.0.2", "22", "PROTO=TCP, DPT=\"22\""},
		},
		{
			// 敏感口径：hp 明文密码导出（与 /export/creds 同级），转义覆盖 password 特殊字符。
			typ:    "hp",
			insert: `INSERT INTO cred_events (ts, proto, src_ip, username, password, extra) VALUES (?,?,?,?,?,?)`,
			args:   []any{tsIn, "telnet", 0xCB007105, "admin", "p@ss,\"wo\nrd", "plaintext"},
			wantRow: []string{"telnet", "203.0.113.5", "admin", "p@ss,\"wo\nrd", "plaintext"},
		},
		{
			typ:    "bans",
			insert: `INSERT INTO ban_events (ts, ip, type, jail) VALUES (?,?,?,?)`,
			args:   []any{tsIn, 0xCB007105, "ban", "sshd"},
			wantRow: []string{"203.0.113.5", "ban", "sshd"},
		},
		{
			typ:    "sys",
			insert: `INSERT INTO system_events (ts, source, level, message) VALUES (?,?,?,?)`,
			args:   []any{tsIn, "conntrack", "warn", "溢出, 丢弃 \"N\" 条"},
			wantRow: []string{"conntrack", "warn", "溢出, 丢弃 \"N\" 条"},
		},
		{
			// conn 简例行（IPv4，ip6 列空串）；proto 输出整数协议号（与查询端点同口径）。
			typ:    "conn",
			insert: `INSERT INTO connections (ts, ev_type, proto, src_ip, src_port, dst_ip, dst_port, packets, bytes, mark, src_ip6, dst_ip6) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
			args:   []any{tsIn, 1, 6, 0xCB007105, 40000, 0x0A000002, 22, 3, 128, 0, "", ""},
			wantRow: []string{"1", "6", "203.0.113.5", "40000", "10.0.0.2", "22", "3", "128", "0", "", ""},
		},
	}
	for _, c := range cases {
		t.Run(c.typ, func(t *testing.T) {
			srv, dbPath := newTestServer(t)
			if _, err := openTestDB(t, dbPath).Exec(c.insert, c.args...); err != nil {
				t.Fatal(err)
			}
			// 用精确 from/to 单秒窗口：newTestServer 预置 ssh/fw/conn 种子（ts≈now），
			// range=1h 会将其一并导出；本用例仅断言本测试种子，窗口锚定 tsIn。
			rec := doExport(t, srv, fmt.Sprintf("/api/v1/export/table?type=%s&from=%d&to=%d", c.typ, tsIn, tsIn))
			if rec.Code != http.StatusOK {
				t.Fatalf("状态码 = %d, 期望 200", rec.Code)
			}
			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
				t.Errorf("Content-Type = %q, 期望 text/csv 前缀", ct)
			}
			dispRe := regexp.MustCompile(`^attachment; filename="sentry-` + c.typ + `-\d{8}-\d{6}\.csv"$`)
			if cd := rec.Header().Get("Content-Disposition"); !dispRe.MatchString(cd) {
				t.Errorf("Content-Disposition = %q, 期望匹配 %v", cd, dispRe)
			}
			recs := readTableCSV(t, rec.Body.String())
			if len(recs) != 2 {
				t.Fatalf("记录数 = %d, 期望 2（表头+1 数据行）", len(recs))
			}
			if !reflect.DeepEqual(recs[0], exportTableSpecs[c.typ].cols) {
				t.Errorf("表头 = %v, 期望 %v", recs[0], exportTableSpecs[c.typ].cols)
			}
			row := recs[1]
			tsv, err := time.Parse(time.RFC3339, row[0])
			if err != nil {
				t.Fatalf("ts 非 RFC3339: %q (%v)", row[0], err)
			}
			if tsv.Unix() != tsIn {
				t.Errorf("ts = %q (unix %d), 期望 %d", row[0], tsv.Unix(), tsIn)
			}
			if !reflect.DeepEqual(row[1:], c.wantRow) {
				t.Errorf("数据行 = %q, 期望 %q", row[1:], c.wantRow)
			}
		})
	}
}

// TestExportTableConnIPv6：conn 类型 IPv6 列原样输出快照断言（TEXT 原文；IPv4 行为空串）、
// proto 数值口径、计数器字段。ORDER BY ts DESC → 后插的 tsIn+1 IPv6 行在前。
func TestExportTableConnIPv6(t *testing.T) {
	srv, dbPath := newTestServer(t)
	db := openTestDB(t, dbPath)
	tsIn := time.Now().Unix() - 60
	ins := `INSERT INTO connections (ts, ev_type, proto, src_ip, src_port, dst_ip, dst_port, packets, bytes, mark, src_ip6, dst_ip6) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`
	if _, err := db.Exec(ins, tsIn, 3, 17, 0xCB007105, 40000, 0x0A000002, 53, 10, 2048, 255, "2001:db8::1", "2001:db8::2"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ins, tsIn+1, 1, 6, 0xCB007105, 40001, 0x0A000002, 22, 0, 0, 0, "", ""); err != nil {
		t.Fatal(err)
	}
	rec := doExport(t, srv, fmt.Sprintf("/api/v1/export/table?type=conn&from=%d&to=%d", tsIn, tsIn+1))
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, 期望 200", rec.Code)
	}
	recs := readTableCSV(t, rec.Body.String())
	if len(recs) != 3 {
		t.Fatalf("记录数 = %d, 期望 3（表头+2 数据行）", len(recs))
	}
	want := [][]string{
		{csvTS(tsIn + 1), "1", "6", "203.0.113.5", "40001", "10.0.0.2", "22", "0", "0", "0", "", ""},
		{csvTS(tsIn), "3", "17", "203.0.113.5", "40000", "10.0.0.2", "53", "10", "2048", "255", "2001:db8::1", "2001:db8::2"},
	}
	for i, w := range want {
		if !reflect.DeepEqual(recs[i+1], w) {
			t.Errorf("第 %d 数据行 = %q, 期望 %q", i+1, recs[i+1], w)
		}
	}
}

// TestExportTableWindowFilter：窗口过滤生效——窗口外种子行不出现在输出。
func TestExportTableWindowFilter(t *testing.T) {
	srv, dbPath := newTestServer(t)
	db := openTestDB(t, dbPath)
	now := time.Now().Unix()
	ins := `INSERT INTO ban_events (ts, ip, type, jail) VALUES (?,?,?,?)`
	if _, err := db.Exec(ins, now-60, 0xCB007105, "ban", "sshd"); err != nil { // 窗口内
		t.Fatal(err)
	}
	if _, err := db.Exec(ins, now-100000, 0xCB007105, "ban", "recidive"); err != nil { // 窗口外（range=1h）
		t.Fatal(err)
	}
	rec := doExport(t, srv, "/api/v1/export/table?type=bans&range=1h")
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, 期望 200", rec.Code)
	}
	recs := readTableCSV(t, rec.Body.String())
	if len(recs) != 2 {
		t.Fatalf("记录数 = %d, 期望 2（表头+仅窗口内 1 行）", len(recs))
	}
	if strings.Contains(rec.Body.String(), "recidive") {
		t.Error("窗口外数据泄漏到输出")
	}
	if !reflect.DeepEqual(recs[1], []string{csvTS(now - 60), "203.0.113.5", "ban", "sshd"}) {
		t.Errorf("数据行 = %q, 期望窗口内种子行", recs[1])
	}
}

// TestExportTableEmptyHeaderOnly：空窗口 → 200 + 仅表头一行（带表头导出与
// export/csv 无表头空文件口径不同：pandas/Excel 读到稳定列名）。
func TestExportTableEmptyHeaderOnly(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := doExport(t, srv, "/api/v1/export/table?type=sys&from=100&to=200")
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, 期望 200", rec.Code)
	}
	recs := readTableCSV(t, rec.Body.String())
	if len(recs) != 1 || !reflect.DeepEqual(recs[0], exportTableSpecs["sys"].cols) {
		t.Errorf("空窗口输出 = %v, 期望仅表头 %v", recs, exportTableSpecs["sys"].cols)
	}
}

// TestExportTableWindowParams：窗口参数校验复用 parseExportWindow（与 export/csv 同口径）。
func TestExportTableWindowParams(t *testing.T) {
	srv, _ := newTestServer(t)
	for _, p := range []string{
		"/api/v1/export/table?type=ssh",                       // 窗口参数缺失
		"/api/v1/export/table?type=ssh&range=24h&from=1&to=2", // 二选一冲突
		"/api/v1/export/table?type=ssh&from=200&to=100",       // from > to
	} {
		if rec := doExport(t, srv, p); rec.Code != http.StatusBadRequest {
			t.Errorf("%s 状态码 = %d, 期望 400", p, rec.Code)
		}
	}
	// from/to 合法路径 → 200（parseExportWindow 共用口径的冒烟验证）。
	if rec := doExport(t, srv, "/api/v1/export/table?type=ssh&from=1&to=2"); rec.Code != http.StatusOK {
		t.Errorf("合法 from/to 状态码 = %d, 期望 200", rec.Code)
	}
}
