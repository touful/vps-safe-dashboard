//go:build linux

// 容器集成测试（订阅有效性修复验证）：
// Windows 本机无法测 netlink，需在 Linux 容器内执行（见交付文档）：
//
//	无 NET_ADMIN：docker run --rm -v <repo>:/src -w /src golang:1.26.6-alpine \
//	    sh -c "go test ./internal/conn/ -run TestSubscriptionIntegrationNoCap -count=1 -v"
//	有 NET_ADMIN：同上，加 --cap-add=NET_ADMIN，-run TestSubscriptionIntegrationWithCap
//
// 预期：
//
//	无 NET_ADMIN → Register 返回 EPERM → 连续 3 次启动失败 → RunConntrackListener
//	返回错误（触发 B5 降级），且 system_event 有"启动失败/放弃降级"留痕。
//	有 NET_ADMIN → 订阅验证通过 → 收到"启动成功"info 留痕。
package conn

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"sentry-agent/internal/config"
	"sentry-agent/internal/event"
)

// hasNetAdmin 读取 /proc/self/status 的 CapEff 位检测 CAP_NET_ADMIN（bit 12）——
// 两条集成测试依赖互斥的 cap 环境，据此自适应跳过（任一环境全量运行均稳定）。
func hasNetAdmin() bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			v, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), 16, 64)
			return err == nil && v&(1<<12) != 0
		}
	}
	return false
}

// integrationCfg 集成测试最小配置（关闭 acct 写入，避免环境差异）。
func integrationCfg() config.ConntrackCfg {
	return config.ConntrackCfg{
		BufferSizeKB:         2048,
		EnableAcct:           false,
		OverrunWarnIntervalS: 60,
		FallbackIntervalS:    5,
		Mode:                 "auto",
	}
}

// TestSubscriptionIntegrationNoCap 无 NET_ADMIN：主通道必须失败并降级留痕（防静默）。
func TestSubscriptionIntegrationNoCap(t *testing.T) {
	if hasNetAdmin() {
		t.Skip("当前容器有 NET_ADMIN，不满足无 cap 前提（用默认 cap 容器运行本测试）")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	sys := make(chan event.SystemEvent, 64)

	err := RunConntrackListener(ctx, integrationCfg(), nil, nil, sys, nil)
	if err == nil {
		t.Fatal("无 NET_ADMIN 环境主通道应失败（返回错误触发 B5 降级）")
	}
	if !strings.Contains(err.Error(), "放弃主通道") {
		t.Errorf("错误应含放弃主通道语义: %v", err)
	}

	// 留痕核对：至少一条 conntrack 启动失败/降级 warn。
	var found bool
	for {
		select {
		case ev := <-sys:
			if ev.Source == "conntrack" && ev.Level == "warn" &&
				(strings.Contains(ev.Message, "启动失败") || strings.Contains(ev.Message, "降级")) {
				found = true
			}
		default:
			// 通道已排空
			if !found {
				t.Fatal("未收到 conntrack 启动失败/降级留痕（静默失效重现）")
			}
			return
		}
	}
}

// TestSubscriptionIntegrationWithCap 有 NET_ADMIN：订阅验证通过并留痕启动成功 info。
func TestSubscriptionIntegrationWithCap(t *testing.T) {
	if !hasNetAdmin() {
		t.Skip("当前容器无 NET_ADMIN（用 --cap-add=NET_ADMIN 容器运行本测试）")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sys := make(chan event.SystemEvent, 64)

	errc := make(chan error, 1)
	go func() { errc <- RunConntrackListener(ctx, integrationCfg(), nil, nil, sys, nil) }()

	deadline := time.After(30 * time.Second)
	for {
		select {
		case ev := <-sys:
			if ev.Source == "conntrack" && strings.Contains(ev.Message, "启动成功") {
				cancel() // 验证完成，正常退出
				select {
				case err := <-errc:
					if err != nil {
						t.Errorf("退出应返回 nil: %v", err)
					}
				case <-time.After(5 * time.Second):
					t.Error("主通道未在取消后退出")
				}
				return
			}
		case err := <-errc:
			t.Fatalf("主通道意外退出: %v", err)
		case <-deadline:
			t.Fatal("未收到主通道启动成功留痕（订阅验证或留痕缺失）")
		}
	}
}
