// 采集层过滤接线测试（B.2.5 集成用例）：
// handleLine 对混合 SRC 行流：内网来源丢弃、公网来源入队、过滤计数留痕（限频）。
package fw

import (
	"context"
	"testing"
	"time"

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

// TestHandleLineFilterExcludeIPs 接线层排除指定来源 IP（DEV-039 用户需求2）：
// 操作方 IP 行丢弃、其他公网行入队、过滤计数留痕。
func TestHandleLineFilterExcludeIPs(t *testing.T) {
	ctx := context.Background()
	sink := make(chan event.FirewallEvent, 8)
	sys := make(chan event.SystemEvent, 8)
	ns, _ := ParseCIDRs(nil)
	exIPs, _ := ParseExcludeIPs([]string{"182.136.147.161"})
	filter := FwFilter{ExcludeInternal: true, FilterDstInternal: false, CIDRs: ns, ExcludeIPs: exIPs}
	stats := newFilterStats()

	lines := []string{
		// 操作方 IP（exclude_ips 命中）→ 丢弃。
		"SENTRY_FW:PREROUTING:drop IN=eth0 OUT= SRC=182.136.147.161 DST=172.17.39.111 LEN=40 PROTO=TCP SPT=50022 DPT=22",
		// 其他公网 SRC → 保留。
		"SENTRY_FW:PREROUTING:drop IN=eth0 OUT= SRC=203.0.113.5 DST=172.17.39.111 LEN=40 PROTO=TCP SPT=50022 DPT=22",
		// 内网 SRC → 过滤（exclude_internal 生效）。
		"SENTRY_FW:PREROUTING:drop IN=br-bbdb2d12d511 OUT= SRC=172.19.0.2 DST=172.18.0.1 LEN=52 PROTO=TCP SPT=47922 DPT=4001",
	}
	for _, l := range lines {
		handleLine(ctx, sink, sys, nil, l, 1700000000, "SENTRY_FW:", filter, stats)
	}
	close(sink)
	var got []event.FirewallEvent
	for ev := range sink {
		got = append(got, ev)
	}
	if len(got) != 1 {
		t.Fatalf("入队事件数 = %d, 期望 1（仅其他公网行）", len(got))
	}
	if got[0].SrcIP != 0xCB007105 { // 203.0.113.5
		t.Errorf("入队事件 SRC 错误: %d", got[0].SrcIP)
	}
	// 计数留痕：操作方 IP 1 条 + 内网 SRC 1 条 = 2 条。
	if n := stats.dropped.Load(); n != 2 {
		t.Errorf("过滤计数 = %d, 期望 2", n)
	}
}

// TestHandleLineParseFail 前缀匹配但解析失败（无 SRC/DST 键）→ 限频 warn 留痕、不入队。
func TestHandleLineParseFail(t *testing.T) {
	ctx := context.Background()
	sink := make(chan event.FirewallEvent, 4)
	sys := make(chan event.SystemEvent, 8)
	rep := event.NewRateLimiter(time.Minute)
	ns, _ := ParseCIDRs(nil)
	filter := FwFilter{ExcludeInternal: true, FilterDstInternal: false, CIDRs: ns}
	handleLine(ctx, sink, sys, rep,
		"SENTRY_FW:garbage-no-kv", 1, "SENTRY_FW:", filter, newFilterStats())
	if len(sink) != 0 {
		t.Error("解析失败行不应入队")
	}
	if len(sys) != 1 {
		t.Fatalf("warn 留痕条数 = %d, 期望 1", len(sys))
	}
	ev := <-sys
	if ev.Source != "fw" || ev.Level != "warn" {
		t.Errorf("留痕字段错误: %+v", ev)
	}
}

// TestHandleLineCtxDone ctx 取消且 sink 满时走 ctx.Done 分支（不阻塞）。
func TestHandleLineCtxDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 立即取消
	sink := make(chan event.FirewallEvent, 1)
	sink <- event.FirewallEvent{} // 填满 sink
	ns, _ := ParseCIDRs(nil)
	filter := FwFilter{ExcludeInternal: true, FilterDstInternal: false, CIDRs: ns}
	// 不应阻塞（ctx.Done 分支返回）。
	handleLine(ctx, sink, nil, nil,
		"SENTRY_FW:input:drop SRC=203.0.113.5 DST=10.0.0.2 PROTO=TCP", 1, "SENTRY_FW:", filter, nil)
}

// TestRunFwParserUnknownSource 未知 fw.source → 返回错误（RunFwParser default 分支）。
func TestRunFwParserUnknownSource(t *testing.T) {
	ctx := context.Background()
	sink := make(chan event.FirewallEvent, 4)
	sys := make(chan event.SystemEvent, 4)
	if err := RunFwParser(ctx, "bad-source", "SENTRY_FW:", FwFilter{}, sink, sys); err == nil {
		t.Error("未知 source 应返回错误")
	}
}

// TestRunFwParserJournaldMissing journalctl 不存在 → 返回错误（Windows 无 journalctl）。
func TestRunFwParserJournaldMissing(t *testing.T) {
	ctx := context.Background()
	sink := make(chan event.FirewallEvent, 4)
	sys := make(chan event.SystemEvent, 4)
	if err := RunFwParser(ctx, "journald-kernel", "SENTRY_FW:", FwFilter{}, sink, sys); err == nil {
		t.Error("journalctl 缺失应返回错误")
	}
}

// TestRunFwParserKmsgOther 非 Linux 平台 kmsg 占位 → 返回"仅支持 Linux"错误。
func TestRunFwParserKmsgOther(t *testing.T) {
	ctx := context.Background()
	sink := make(chan event.FirewallEvent, 4)
	sys := make(chan event.SystemEvent, 4)
	if err := RunFwParser(ctx, "kmsg", "SENTRY_FW:", FwFilter{}, sink, sys); err == nil {
		t.Error("非 Linux kmsg 应返回错误")
	}
}
