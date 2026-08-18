package fw

import (
	"strings"
	"testing"

	"sentry-agent/internal/event"
)

func TestParseFWLineNftables(t *testing.T) {
	line := "SENTRY_FW:input:drop IN=eth0 OUT= MAC=01:02:03:04:05:06:07:08:09:0a:0b:0c:08:00 " +
		"SRC=203.0.113.5 DST=10.0.0.2 LEN=40 PROTO=TCP SPT=50022 DPT=22 SYN URGP=0"
	ev, ok := ParseFWLine(line, "SENTRY_FW:")
	if !ok {
		t.Fatal("应匹配")
	}
	if ev.Chain != "input" || ev.Action != "drop" {
		t.Errorf("Chain=%q Action=%q, 期望 input/drop", ev.Chain, ev.Action)
	}
	if ev.Proto != event.ProtoTCP {
		t.Errorf("Proto = %d, 期望 6", ev.Proto)
	}
	if ev.SrcIP != 0xCB007105 || ev.SrcPort != 50022 {
		t.Errorf("SrcIP=%x SrcPort=%d, 期望 cb007105/50022", ev.SrcIP, ev.SrcPort)
	}
	if ev.DstIP != 0x0A000002 || ev.DstPort != 22 {
		t.Errorf("DstIP=%x DstPort=%d, 期望 a000002/22", ev.DstIP, ev.DstPort)
	}
	if ev.Raw != line {
		t.Error("Raw 应保留原始行（短行不触发 VS-09 截断，口径同 ssh Detail）")
	}
}

// TestParseFWLineRawTruncated（VS-09，DEV-P1-001）：超长输入行 Raw 存储层截断 512 rune，
// 与 ssh Detail 截断口径对齐（消除存储完整保留 vs 展示截断的不对称放大）。
func TestParseFWLineRawTruncated(t *testing.T) {
	long := "SENTRY_FW:input:drop IN=eth0 OUT= " + strings.Repeat("SEG", 300) + " SRC=203.0.113.5 DST=10.0.0.2 LEN=40 PROTO=TCP SPT=50022 DPT=22 SYN URGP=0"
	ev, ok := ParseFWLine(long, "SENTRY_FW:")
	if !ok {
		t.Fatal("应匹配")
	}
	if got := len([]rune(ev.Raw)); got != 512 {
		t.Errorf("Raw rune 长度 = %d, 期望 512（VS-09 截断）", got)
	}
	if len(ev.Raw) == len(long) {
		t.Error("Raw 未被截断")
	}
}

func TestParseFWLineIptablesRejectUDP(t *testing.T) {
	line := "SENTRY_FW:input:reject IN=eth0 OUT= MAC=aa:bb SRC=198.51.100.7 DST=10.0.0.2 LEN=60 " +
		"PROTO=UDP SPT=12345 DPT=53"
	ev, ok := ParseFWLine(line, "SENTRY_FW:")
	if !ok {
		t.Fatal("应匹配")
	}
	if ev.Action != "reject" {
		t.Errorf("Action = %q, 期望 reject", ev.Action)
	}
	if ev.Proto != event.ProtoUDP || ev.DstPort != 53 {
		t.Errorf("Proto=%d DstPort=%d, 期望 17/53", ev.Proto, ev.DstPort)
	}
}

func TestParseFWLineICMP(t *testing.T) {
	line := "SENTRY_FW:input:drop IN=eth0 OUT= SRC=203.0.113.9 DST=10.0.0.2 LEN=84 PROTO=ICMP TYPE=8 CODE=0"
	ev, ok := ParseFWLine(line, "SENTRY_FW:")
	if !ok {
		t.Fatal("应匹配")
	}
	if ev.Proto != event.ProtoICMP {
		t.Errorf("Proto = %d, 期望 1", ev.Proto)
	}
	// 口径：ICMP 无端口，保持 0。
	if ev.SrcPort != 0 || ev.DstPort != 0 {
		t.Errorf("ICMP 端口应为 0，实际 %d/%d", ev.SrcPort, ev.DstPort)
	}
}

func TestParseFWLineNoPrefix(t *testing.T) {
	line := "IN=eth0 OUT= SRC=203.0.113.1 DST=10.0.0.2 PROTO=TCP SPT=1 DPT=2"
	if _, ok := ParseFWLine(line, "SENTRY_FW:"); ok {
		t.Error("无前缀行不应匹配")
	}
}

func TestParseFWLineMalformed(t *testing.T) {
	// 前缀存在但无 SRC/DST 键（如其他日志恰含 SENTRY_FW 字样）→ 判定为噪声，ok=false。
	line := "SENTRY_FW:garbage-no-kv"
	if _, ok := ParseFWLine(line, "SENTRY_FW:"); ok {
		t.Error("无 SRC/DST 键的行应返回 ok=false（噪声防护）")
	}
	// 仅 SRC 键（IPv6 场景键存在但转换失败）仍应通过。
	line6 := "SENTRY_FW:input:drop SRC=2001:db8::1 DST=2001:db8::2 PROTO=TCP"
	ev, ok := ParseFWLine(line6, "SENTRY_FW:")
	if !ok {
		t.Fatal("含 SRC/DST 键的 IPv6 行应通过")
	}
	if ev.SrcIP != 0 || ev.DstIP != 0 {
		t.Error("IPv6 地址应转为 0（已知限制）")
	}
}

func TestProtoMap(t *testing.T) {
	if protoByName["tcp"] != 0 {
		t.Error("协议名应大小写无关后匹配")
	}
	if protoByName["TCP"] != event.ProtoTCP {
		t.Error("TCP 映射错误")
	}
}

// TestParseFWLinePreroutingInbound：raw PREROUTING 入站 LOG 前缀解析——
// SENTRY_FW:PREROUTING:inbound → Chain=PREROUTING Action=inbound（区别于 drop/reject 语义）。
func TestParseFWLinePreroutingInbound(t *testing.T) {
	line := "SENTRY_FW:PREROUTING:inbound IN=eth0 OUT= MAC=01:02:03:04:05:06:07:08:09:0a:0b:0c:08:00 " +
		"SRC=182.136.147.244 DST=172.17.39.111 LEN=40 PROTO=TCP SPT=50022 DPT=22 SYN URGP=0"
	ev, ok := ParseFWLine(line, "SENTRY_FW:")
	if !ok {
		t.Fatal("应匹配")
	}
	if ev.Chain != "PREROUTING" || ev.Action != "inbound" {
		t.Errorf("Chain=%q Action=%q, 期望 PREROUTING/inbound", ev.Chain, ev.Action)
	}
	if ev.SrcIP != 0xB68893F4 || ev.DstIP != 0xAC11276F {
		t.Errorf("SrcIP=%x DstIP=%x, 期望 b68893f4/ac11276f", ev.SrcIP, ev.DstIP)
	}
	if ev.DstPort != 22 {
		t.Errorf("DstPort = %d, 期望 22", ev.DstPort)
	}
}
