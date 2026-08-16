// 采集层过滤接线测试（DEV-031 优化②，B.2.5 集成用例）：
// handleLine 对混合 SRC 行流：内网来源丢弃、公网来源入队、过滤计数留痕（限频）。
package fw

import (
	"context"
	"testing"

	"sentry-agent/internal/event"
)

// TestHandleLineFilter 混合行流：内网行丢弃 + 公网行入队 + 计数留痕。
func TestHandleLineFilter(t *testing.T) {
	ctx := context.Background()
	sink := make(chan event.FirewallEvent, 8)
	sys := make(chan event.SystemEvent, 8)
	ns, _ := ParseCIDRs(nil)
	filter := FwFilter{ExcludeInternal: true, FilterDstInternal: false, CIDRs: ns}
	stats := newFilterStats()

	lines := []string{
		// 公网 SRC → 保留。
		"SENTRY_FW:input:drop IN=eth0 OUT= SRC=203.0.113.5 DST=10.0.0.2 LEN=40 PROTO=TCP SPT=50022 DPT=22",
		// 内网 SRC（NPM 容器 172.19.0.2 轮询形态）→ 过滤。
		"SENTRY_FW:input:drop IN=eth0 OUT= SRC=172.19.0.2 DST=10.0.0.2 LEN=40 PROTO=TCP SPT=4001 DPT=8080",
		// 内网 SRC（阿里云 CGNAT 100.100.30.25）→ 过滤。
		"SENTRY_FW:input:drop IN=eth0 OUT= SRC=100.100.30.25 DST=10.0.0.2 LEN=40 PROTO=TCP SPT=12345 DPT=80",
		// 公网 SRC → 内网 DST（forward 链外部→容器真实威胁）→ 默认模式保留。
		"SENTRY_FW:forward:drop IN=eth0 OUT=docker0 SRC=198.51.100.7 DST=172.19.0.2 LEN=40 PROTO=TCP SPT=5555 DPT=4001",
		// IPv6 行（SRC/DST 转 0）→ 保留（保守）。
		"SENTRY_FW:input:drop SRC=2001:db8::1 DST=2001:db8::2 PROTO=TCP",
	}
	for _, l := range lines {
		handleLine(ctx, sink, sys, nil, l, 1700000000, "SENTRY_FW:", filter, stats)
	}
	close(sink)
	var got []event.FirewallEvent
	for ev := range sink {
		got = append(got, ev)
	}
	if len(got) != 3 {
		t.Fatalf("入队事件数 = %d, 期望 3（公网×2 + IPv6×1）", len(got))
	}
	for _, ev := range got {
		if ev.SrcIP == 0xAC130002 { // 172.19.0.2
			t.Error("内网来源事件不应入队")
		}
		if ev.SrcIP == 0x64641E19 { // 100.100.30.25
			t.Error("CGNAT 内网来源事件不应入队")
		}
	}
	// 计数留痕：默认模式仅过滤 2 条内网 SRC（forward 外部→容器与 IPv6 行保留）。
	if n := stats.dropped.Load(); n != 2 {
		t.Errorf("过滤计数 = %d, 期望 2", n)
	}
}

// TestFilterStatsDrop 过滤留痕限频（1 小时）：首条上报，后续被限频。
func TestFilterStatsDrop(t *testing.T) {
	sys := make(chan event.SystemEvent, 8)
	stats := newFilterStats()
	stats.drop(sys)
	stats.drop(sys)
	stats.drop(sys)
	if stats.dropped.Load() != 3 {
		t.Errorf("计数 = %d, 期望 3", stats.dropped.Load())
	}
	if len(sys) != 1 {
		t.Errorf("限频留痕条数 = %d, 期望 1（1 小时限频）", len(sys))
	}
	ev := <-sys
	if ev.Source != "fw" || ev.Level != "info" {
		t.Errorf("留痕字段错误: %+v", ev)
	}
}

// TestHandleLineFilterNilStats stats 为 nil 时不 panic（防御：统计通道未注入场景）。
func TestHandleLineFilterNilStats(t *testing.T) {
	ctx := context.Background()
	sink := make(chan event.FirewallEvent, 4)
	ns, _ := ParseCIDRs(nil)
	filter := FwFilter{ExcludeInternal: true, FilterDstInternal: false, CIDRs: ns}
	handleLine(ctx, sink, nil, nil,
		"SENTRY_FW:input:drop SRC=172.19.0.2 DST=10.0.0.2 PROTO=TCP", 1, "SENTRY_FW:", filter, nil)
	if len(sink) != 0 {
		t.Error("内网行应被过滤")
	}
}
