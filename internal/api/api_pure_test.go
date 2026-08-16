package api

import (
	"net/http/httptest"
	"testing"
	"time"
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

// TestIPToDotted uint32 → 点分十进制（含 0 与边界）。
func TestIPToDotted(t *testing.T) {
	cases := []struct {
		in   uint32
		want string
	}{
		{0, "0.0.0.0"},
		{0xCB007105, "203.0.113.5"},
		{0x0A000002, "10.0.0.2"},
		{0xFFFFFFFF, "255.255.255.255"},
		{0x01020304, "1.2.3.4"},
	}
	for _, c := range cases {
		if got := ipToDotted(c.in); got != c.want {
			t.Errorf("ipToDotted(%d) = %s, 期望 %s", c.in, got, c.want)
		}
	}
}

// TestURLPathEscape 路径 URL 编码（url.PathEscape：整路径转义，含斜杠；DSN 特殊字符转义）。
func TestURLPathEscape(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"plain.db", "plain.db"},
		{"a b.db", "a%20b.db"},
		{"q?.db", "q%3F.db"},
		{"h#.db", "h%23.db"},
		{"p%.db", "p%25.db"},
		{"a&b=c.db", "a&b=c.db"}, // & 与 = 非 path 保留字符，url.PathEscape 不转义（正确语义）
		{"ab.db", "ab.db"},
	}
	for _, c := range cases {
		if got := urlPathEscape(c.in); got != c.want {
			t.Errorf("urlPathEscape(%q) = %q, 期望 %q", c.in, got, c.want)
		}
	}
}
