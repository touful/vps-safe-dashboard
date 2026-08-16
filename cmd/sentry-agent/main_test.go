package main

import "testing"

// TestIsLoopbackListen（R-01）：空 host/非回环/回环判定。
func TestIsLoopbackListen(t *testing.T) {
	cases := []struct {
		listen string
		want   bool
	}{
		{"127.0.0.1:8080", true},
		{"localhost:8080", true},
		{"[::1]:8080", true},
		{"0.0.0.0:8080", false},
		{"[::]:8080", false},
		{":8080", false}, // 空 host = 监听全部接口（R-01 修复点）
		{"<LAN_IP>:8080", false},
		{"bad", false}, // 非法输入保守判非回环
		{"", false},
	}
	for _, c := range cases {
		if got := isLoopbackListen(c.listen); got != c.want {
			t.Errorf("isLoopbackListen(%q) = %v, 期望 %v", c.listen, got, c.want)
		}
	}
}
