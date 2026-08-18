package api

import (
	"database/sql"
	"encoding/csv"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"sentry-agent/internal/event"
)

// doExport 发送导出请求（CSV 响应，不做 JSON 解码）。
func doExport(t *testing.T, srv *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)
	return rec
}

// TestExportCSVParams（DEV-EXPORT-001）：参数校验 400 分支。
// 覆盖：都缺 / 同时给 / from>to / 跨度>90 天 / 非数字 / int64 溢出回绕（R-01 reviewer 整改）。
func TestExportCSVParams(t *testing.T) {
	srv, _ := newTestServer(t)
	cases := []string{
		"/api/v1/export/csv",                       // 都缺
		"/api/v1/export/csv?range=24h&from=1&to=2", // 同时给
		"/api/v1/export/csv?from=200&to=100",       // from > to
		"/api/v1/export/csv?from=0&to=100000000",   // 跨度 > 90 天（1157 天）
		"/api/v1/export/csv?from=abc&to=100",       // from 非数字
		"/api/v1/export/csv?from=1&to=xyz",         // to 非数字
		"/api/v1/export/csv?from=1",                // 仅 from 缺 to
		// int64 溢出回绕：to-from 溢出为负可绕过跨度上限，span<0 兜底必须 400。
		"/api/v1/export/csv?from=-9223372036854775808&to=9223372036854775807",
		"/api/v1/export/csv?from=-5000000000000000000&to=5000000000000000000",
	}
	for _, p := range cases {
		// heavy 桶 burst 固定 6（SetLimits 忽略 burst 参数）：9 个快速请求会触发 429，
		// 每轮 sleep 5ms 让 1000 rps 补充令牌（5ms 补 5 个），保证全部走到参数校验分支。
		time.Sleep(5 * time.Millisecond)
		rec := doExport(t, srv, p)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s 状态码 = %d, 期望 400", p, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), `"error"`) {
			t.Errorf("%s 响应应含 JSON error 字段", p)
		}
	}
}

// TestExportCSVBoundary（DEV-EXPORT-001，R-05 reviewer 整改）：合法边界语义固化——
// from==to 单秒窗口 200、负时间戳合法（空数据）、非法 range 回退 24h（与 rangeSeconds 一致）。
func TestExportCSVBoundary(t *testing.T) {
	srv, _ := newTestServer(t)
	now := time.Now().Unix()
	cases := []struct {
		path string
		want int
	}{
		{fmt.Sprintf("/api/v1/export/csv?from=%d&to=%d", now, now), http.StatusOK}, // from==to
		{"/api/v1/export/csv?from=-100&to=100", http.StatusOK},                     // 负时间戳合法 → 空数据
		{"/api/v1/export/csv?range=bogus", http.StatusOK},                          // 非法 range 回退 24h
	}
	for _, c := range cases {
		rec := doExport(t, srv, c.path)
		if rec.Code != c.want {
			t.Errorf("%s 状态码 = %d, 期望 %d", c.path, rec.Code, c.want)
		}
	}
	// 非法 range 回退 24h 应含数据（newTestServer 数据均在 24h 内）。
	if rec := doExport(t, srv, "/api/v1/export/csv?range=bogus"); rec.Body.Len() == 0 {
		t.Error("range=bogus 回退 24h 后应含数据（非空）")
	}
}

// TestExportCSVFormat（DEV-EXPORT-001）：无表头、三列、三源合并、SSH 端口 22、封禁端口空、
// 时间格式与升序、IP 点分十进制。集合断言对同 ts 排序不敏感（SQLite 无稳定排序保证）。
func TestExportCSVFormat(t *testing.T) {
	srv, dbPath := newTestServer(t)
	now := time.Now().Unix()
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// 补插 1 条封禁（newTestServer 自带数据无 ban）。
	if _, err := db.Exec(`INSERT INTO ban_events (ts, ip, type, jail) VALUES (?,?,?,?)`,
		now+100, 0xCB007108, "ban", "sshd"); err != nil {
		t.Fatal(err)
	}
	// 窗口覆盖全部 8 行：4 fw drop（ts now-3..now）+ 3 ssh fail（ts now-2..now）+ 1 ban（ts now+100）。
	rec := doExport(t, srv, fmt.Sprintf("/api/v1/export/csv?from=%d&to=%d", now-10, now+200))
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, 期望 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("Content-Type = %q, 期望 text/csv 前缀", ct)
	}
	// R-06（reviewer 整改）：完整文件名格式断言（sentry_export_YYYYMMDD_HHMMSS.csv，引号闭合）。
	// 注：正则用双引号字符串字面量（避免反引号嵌套）。
	dispRe := regexp.MustCompile("^attachment; filename=\"sentry_export_\\d{8}_\\d{6}\\.csv\"$")
	if cd := rec.Header().Get("Content-Disposition"); !dispRe.MatchString(cd) {
		t.Errorf("Content-Disposition = %q, 期望格式 attachment; filename=\"sentry_export_YYYYMMDD_HHMMSS.csv\"", cd)
	}
	body := rec.Body.String()
	if body == "" {
		t.Fatal("非空窗口导出为空")
	}
	lines := strings.Split(strings.TrimRight(body, "\n"), "\n")
	if len(lines) != 8 {
		t.Fatalf("行数 = %d, 期望 8（4 fw drop + 3 ssh fail + 1 ban）", len(lines))
	}
	// 无表头：首行即数据行（3 列，中间列为时间）。
	first := strings.Split(lines[0], ",")
	if len(first) != 3 || !strings.Contains(first[1], "-") {
		t.Errorf("首行 = %q, 应为数据行（无表头）", lines[0])
	}
	// 逐行断言：3 列、时间格式、时间非递减、端口分布、封禁行端口空。
	portCnt := map[string]int{} // 端口计数（"" 为空字段）
	ipCnt := map[string]int{}
	var prevTS int64
	for i, ln := range lines {
		parts := strings.Split(ln, ",")
		if len(parts) != 3 {
			t.Fatalf("第 %d 行列数 = %d, 期望 3: %q", i+1, len(parts), ln)
		}
		if !timeRe.MatchString(parts[1]) {
			t.Errorf("第 %d 行时间格式非法: %q", i+1, parts[1])
		}
		ts, err := time.Parse("2006-01-02 15:04:05", parts[1])
		if err != nil {
			t.Fatalf("第 %d 行时间解析失败: %v", i+1, err)
		}
		if ts.Unix() < prevTS {
			t.Errorf("第 %d 行时间非升序: %d < %d", i+1, ts.Unix(), prevTS)
		}
		prevTS = ts.Unix()
		ipCnt[parts[0]]++
		portCnt[parts[2]]++
	}
	// SSH 失败 3 行端口=22；fw drop 4 行端口=22/23/24/25（22 出现 4 次：1 fw + 3 ssh）。
	if portCnt["22"] != 4 {
		t.Errorf("端口 22 行数 = %d, 期望 4（1 fw drop :22 + 3 ssh 失败固定 22）", portCnt["22"])
	}
	for _, p := range []string{"23", "24", "25"} {
		if portCnt[p] != 1 {
			t.Errorf("端口 %s 行数 = %d, 期望 1", p, portCnt[p])
		}
	}
	if portCnt[""] != 1 {
		t.Errorf("空端口行数 = %d, 期望 1（封禁行 ip,ts,）", portCnt[""])
	}
	// IP 分布：fw/ssh 源 203.0.113.5（7 行）+ 封禁 IP 203.0.113.8（1 行）。
	if ipCnt["203.0.113.5"] != 7 || ipCnt["203.0.113.8"] != 1 {
		t.Errorf("IP 分布 = %v, 期望 203.0.113.5×7 + 203.0.113.8×1", ipCnt)
	}
	// 封禁行 ts 最大（now+100），应排最后且端口为空。
	if last := lines[len(lines)-1]; !strings.HasPrefix(last, "203.0.113.8,") || !strings.HasSuffix(last, ",") {
		t.Errorf("末行 = %q, 应为封禁行（端口空字段）", last)
	}
}

var timeRe = mustTimeRe()

func mustTimeRe() *regexp.Regexp {
	return regexp.MustCompile(`^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$`)
}

// TestExportCSVRange（DEV-EXPORT-001）：预设 range 参数复用现有语义，1h 窗口覆盖全部测试数据。
func TestExportCSVRange(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := doExport(t, srv, "/api/v1/export/csv?range=1h")
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, 期望 200", rec.Code)
	}
	if n := len(strings.Split(strings.TrimRight(rec.Body.String(), "\n"), "\n")); n != 7 {
		t.Errorf("range=1h 行数 = %d, 期望 7（4 fw drop + 3 ssh fail，无 ban）", n)
	}
}

// TestExportCSVEmpty（DEV-EXPORT-001）：无数据窗口 → 200 + 空 body + 正确响应头（前端提示空数据依据）。
func TestExportCSVEmpty(t *testing.T) {
	srv, _ := newTestServer(t)
	now := time.Now().Unix()
	rec := doExport(t, srv, fmt.Sprintf("/api/v1/export/csv?from=%d&to=%d", now+100000, now+200000))
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, 期望 200（空数据仍 200）", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("空窗口 body = %q, 期望空", rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("Content-Type = %q, 期望 text/csv 前缀", ct)
	}
	// R-06（reviewer 整改）：完整文件名格式断言（sentry_export_YYYYMMDD_HHMMSS.csv，引号闭合）。
	// 注：正则用双引号字符串字面量（避免反引号嵌套）。
	dispRe := regexp.MustCompile("^attachment; filename=\"sentry_export_\\d{8}_\\d{6}\\.csv\"$")
	if cd := rec.Header().Get("Content-Disposition"); !dispRe.MatchString(cd) {
		t.Errorf("Content-Disposition = %q, 期望格式 attachment; filename=\"sentry_export_YYYYMMDD_HHMMSS.csv\"", cd)
	}
}

// TestExportCSVEscape（DEV-EXPORT-001）：RFC 4180 转义行为验证——标准库 csv.Writer 即
// 转义实现（含逗号/引号/换行字段加引号并转义；空端口输出空字段；行尾 \n）。
func TestExportCSVEscape(t *testing.T) {
	var b strings.Builder
	cw := csv.NewWriter(&b)
	_ = cw.Write([]string{"1.2.3.4", "2026-08-16 10:00:00", ""})
	_ = cw.Write([]string{"a,b", `x"y`, "l\nn"})
	cw.Flush()
	want := "1.2.3.4,2026-08-16 10:00:00,\n\"a,b\",\"x\"\"y\",\"l\nn\"\n"
	if got := b.String(); got != want {
		t.Errorf("CSV 转义输出 = %q, 期望 %q", got, want)
	}
}

// TestExportRateLimitHeavy（DEV-EXPORT-001）：导出端点纳入 heavy 限流（1 rps / burst 6，
// 第 7 个请求 429，与 summary 等 heavy 端点同一包装）。
func TestExportRateLimitHeavy(t *testing.T) {
	srv, _ := newTestServer(t)
	srv.SetLimits(10, 20, 1, 100)
	for i := 0; i < 7; i++ {
		rec := doExport(t, srv, "/api/v1/export/csv?range=1h")
		want := http.StatusOK
		if i >= 6 {
			want = http.StatusTooManyRequests
		}
		if rec.Code != want {
			t.Fatalf("第 %d 次导出请求状态码 = %d, 期望 %d", i+1, rec.Code, want)
		}
		// R-06（reviewer 整改）：429 响应契约断言 Retry-After 头（limitHeavy 统一设置）。
		if rec.Code == http.StatusTooManyRequests && rec.Header().Get("Retry-After") != "1" {
			t.Errorf("429 响应 Retry-After = %q, 期望 1", rec.Header().Get("Retry-After"))
		}
	}
}

// failWriter 模拟客户端断开：底层写入全部失败（csv.Writer 缓冲 <4096B 时错误
// 延迟到 Flush 才暴露，>4096B 时 Write 阶段即报错）。
type failWriter struct{}

func (failWriter) Header() http.Header       { return http.Header{} }
func (failWriter) Write([]byte) (int, error) { return 0, errors.New("模拟客户端断开") }
func (failWriter) WriteHeader(int)           {}

// TestExportCSVFlushError（DEV-CLEAN-001，M-01 修复）：正常路径 Flush 失败（客户端断开）
// 必须留痕——csv.Writer 缓冲 <4096B 时错误只在 Flush 暴露，Flush 后不查 cw.Error()
// 则写错误被静默吞掉。注入 sysCh 断言 limitWarn 输出 warn 级"导出写入失败"。
func TestExportCSVFlushError(t *testing.T) {
	srv, _ := newTestServer(t)
	sysCh := make(chan event.SystemEvent, 8)
	srv.SetSystemChannel(sysCh)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/export/csv?range=24h", nil)
	srv.hExportCSV(failWriter{}, req) // 直接调 handler（绕过限流包装，与限流测试隔离）
	select {
	case ev := <-sysCh:
		if ev.Level != "warn" || ev.Source != "api" || !strings.Contains(ev.Message, "导出写入失败") {
			t.Errorf("留痕事件 = %+v, 期望 warn/api/含导出写入失败", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Flush 写错误未产生留痕")
	}
}

// TestExportCSVWriteErrorBreak（DEV-CLEAN-001，M-01 修复）：写路径错误（数据 >4096B
// 触发 csv.Writer 缓冲满，Write 阶段即报错）应停止迭代并留痕。预插 200 行 fw drop
//（≈7KB 输出 > 内部缓冲 4096B）使 Write 阶段报错。
func TestExportCSVWriteErrorBreak(t *testing.T) {
	srv, dbPath := newTestServer(t)
	sysCh := make(chan event.SystemEvent, 8)
	srv.SetSystemChannel(sysCh)
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().Unix()
	// 单条多 VALUES 批量插入（逐条 Exec 在 modernc 下 ~50ms/条，批量避免测试拖慢）。
	var sb strings.Builder
	sb.WriteString(`INSERT INTO firewall_events (ts, chain, action, proto, src_ip, src_port, dst_ip, dst_port, raw) VALUES `)
	for i := 0; i < 200; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(fmt.Sprintf("(%d,'input','drop',6,3413623045,50000,167772674,8080,'SENTRY_FW')", now-int64(i)))
	}
	if _, err := db.Exec(sb.String()); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/export/csv?range=24h", nil)
	srv.hExportCSV(failWriter{}, req)
	select {
	case ev := <-sysCh:
		if ev.Level != "warn" || ev.Source != "api" || !strings.Contains(ev.Message, "导出写入失败") {
			t.Errorf("留痕事件 = %+v, 期望 warn/api/含导出写入失败", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Write 写错误未产生留痕")
	}
}
