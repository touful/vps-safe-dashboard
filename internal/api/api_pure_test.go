package api

import (
	"net/http/httptest"
	"testing"
	"time"

	"sentry-agent/internal/dbdsn"
)

// TestRangeSeconds range 参数解析（TEST-004：补齐 §2.2 纳入函数直接单测）。
// 验证窗口秒数：rangeSeconds 返回 now - window，与 time.Now() 差值应等于窗口。
func TestRangeSeconds(t *testing.T) {
	cases := []struct {
		name  string
		query string
		want  int64 // 期望窗口秒数
	}{
		{"1h", "range=1h", 3600},
		{"24h", "range=24h", 86400},
		{"7d", "range=7d", 7 * 86400},
		{"30d", "range=30d", 30 * 86400},
		{"空值默认24h", "", 86400},
		{"非法值默认24h", "range=bad", 86400},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/v1/x?"+c.query, nil)
			got := rangeSeconds(req)
			window := time.Now().Unix() - got
			if window < c.want-2 || window > c.want+2 {
				t.Errorf("rangeSeconds(%q) 窗口 = %d 秒, 期望 %d（±2s 容忍）", c.query, window, c.want)
			}
		})
	}
}

// TestParseUintParam 无符号整数参数解析（非法/缺失返回默认值）。
func TestParseUintParam(t *testing.T) {
	cases := []struct {
		name string
		url  string
		key  string
		def  uint64
		want uint64
	}{
		{"正常", "/x?top=5", "top", 10, 5},
		{"缺失用默认", "/x", "top", 10, 10},
		{"非数字用默认", "/x?top=abc", "top", 10, 10},
		{"负数用默认", "/x?top=-1", "top", 10, 10},
		{"零合法", "/x?top=0", "top", 10, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", c.url, nil)
			if got := parseUintParam(req, c.key, c.def); got != c.want {
				t.Errorf("parseUintParam(%q, %q, %d) = %d, 期望 %d", c.url, c.key, c.def, got, c.want)
			}
		})
	}
}

// TestReadOnlyDSNEscape 只读 DSN 路径 URL 编码（url.PathEscape：整路径转义，
// 含斜杠；DSN 特殊字符转义；DEV-ARCH-002 D9 收敛后测 dbdsn.ReadOnly）。
func TestReadOnlyDSNEscape(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"plain.db", "file:plain.db?mode=ro&_pragma=busy_timeout(5000)"},
		{"a b.db", "file:a%20b.db?mode=ro&_pragma=busy_timeout(5000)"},
		{"q?.db", "file:q%3F.db?mode=ro&_pragma=busy_timeout(5000)"},
		{"h#.db", "file:h%23.db?mode=ro&_pragma=busy_timeout(5000)"},
		{"p%.db", "file:p%25.db?mode=ro&_pragma=busy_timeout(5000)"},
		{"a&b=c.db", "file:a&b=c.db?mode=ro&_pragma=busy_timeout(5000)"}, // & 与 = 非 path 保留字符，不转义（正确语义）
		{"ab.db", "file:ab.db?mode=ro&_pragma=busy_timeout(5000)"},
	}
	for _, c := range cases {
		if got := dbdsn.ReadOnly(c.in); got != c.want {
			t.Errorf("dbdsn.ReadOnly(%q) = %q, 期望 %q", c.in, got, c.want)
		}
	}
}

// TestWSFallbackURL CSP ws:// 兜底条目推导（工程修复回归：原硬编码
// ws://127.0.0.1:8080，改监听地址后老浏览器 WS 被 CSP 拦截）。
func TestWSFallbackURL(t *testing.T) {
	cases := []struct {
		listen string
		want   string
	}{
		{"127.0.0.1:8080", "ws://127.0.0.1:8080"},     // 默认部署形态
		{"127.0.0.1:9090", "ws://127.0.0.1:9090"},     // 改端口
		{"localhost:8080", "ws://localhost:8080"},     // localhost
		{"192.168.1.5:8080", "ws://192.168.1.5:8080"}, // 具体地址
		{":8080", "ws://127.0.0.1:8080"},              // 空 host=全接口 → 回环兜底
		{"0.0.0.0:8080", "ws://127.0.0.1:8080"},       // 通配 → 回环兜底
		{"[::]:8080", "ws://127.0.0.1:8080"},          // IPv6 通配 → 回环兜底
		{"8080", "ws://127.0.0.1:8080"},               // 异常输入 → 默认形态
		{"", "ws://127.0.0.1:8080"},                   // 未注入 → 默认形态
	}
	for _, c := range cases {
		if got := wsFallbackURL(c.listen); got != c.want {
			t.Errorf("wsFallbackURL(%q) = %q, 期望 %q", c.listen, got, c.want)
		}
	}
}
