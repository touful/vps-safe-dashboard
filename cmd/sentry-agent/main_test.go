package main

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	_ "modernc.org/sqlite" // 纯 Go 驱动（refreshBanned 测试用临时库）

	"sentry-agent/internal/config"
	"sentry-agent/internal/event"
	"sentry-agent/internal/out"
)

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

// TestRunConnChannelFallbackMode（DEV-031 B.4.5）：conntrack.mode=fallback 时不尝试
// 主通道，直接走降级并留痕 info（不出现"通道不可用"warn——预期降级噪音消除）。
func TestRunConnChannelFallbackMode(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := out.NewChannels(16)
	cfg := config.Defaults()
	cfg.Conntrack.Mode = "fallback"
	cfg.Conntrack.FallbackIntervalS = 5

	done := make(chan struct{})
	go func() {
		defer close(done)
		runConnChannel(ctx, cfg, ch, &atomic.Uint64{})
	}()

	deadline := time.After(3 * time.Second)
	for {
		select {
		case ev := <-ch.System:
			// 盲区修复（reviewer R-N1）：收到 fallback 留痕前若出现任何 conntrack warn
			// （如"通道不可用"），说明实现回归为先尝试主通道——立即失败。
			if ev.Source == "conntrack" && ev.Level == "warn" {
				t.Errorf("fallback 模式不应产生 conntrack warn（预期降级噪音消除），实际: %s", ev.Message)
			}
			if strings.Contains(ev.Message, "mode=fallback") {
				if ev.Level != "info" {
					t.Errorf("fallback 模式留痕等级 = %s, 期望 info", ev.Level)
				}
				if strings.Contains(ev.Message, "通道不可用") {
					t.Errorf("主动降级不应报'通道不可用'warn 文案，实际: %s", ev.Message)
				}
				cancel()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Fatal("runConnChannel 未在 ctx 取消后退出")
				}
				return
			}
		case <-deadline:
			t.Fatal("未出现 conntrack.mode=fallback 留痕（应直接进入降级）")
		}
	}
}

// TestRefreshBannedImmediate（DEV-031 B.1.5）：启动后立即查询一次（不等 60s ticker）。
func TestRefreshBannedImmediate(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "fail2ban.sqlite3")
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE bans (jail TEXT NOT NULL, ip TEXT NOT NULL, timeofban INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"203.0.113.5", "198.51.100.7"} {
		if _, err := db.Exec(`INSERT INTO bans (jail, ip, timeofban) VALUES ('sshd', ?, 1)`, ip); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sys := make(chan event.SystemEvent, 16)
	go refreshBanned(ctx, dbPath, sys)

	// 60s ticker 未触发前应已有首条查询留痕（启动立即执行）。
	select {
	case ev := <-sys:
		if !strings.Contains(ev.Message, "当前封禁 IP 数: 2") {
			t.Errorf("首查留痕文案错误: %s", ev.Message)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("启动后应立即查询（60s ticker 未触发前应有首条留痕）")
	}
}
