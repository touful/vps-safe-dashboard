// 采集层来源过滤单元测试（DEV-031 优化②，B.2.5）。
package fw

import (
	"net"
	"testing"

	"sentry-agent/internal/event"
)

// u32IP 将点分十进制转为 uint32（测试辅助）。
func u32IP(t *testing.T, s string) uint32 {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("非法 IP: %s", s)
	}
	return event.IPv4ToUint32(ip)
}

// mustCIDRs 预编译默认网段（测试辅助）。
func mustCIDRs(t *testing.T) []net.IPNet {
	t.Helper()
	ns, err := ParseCIDRs(nil)
	if err != nil {
		t.Fatal(err)
	}
	return ns
}

// TestIsInternalIPv4 网段边界判定（B.2.5：逐网段边界用例）。
func TestIsInternalIPv4(t *testing.T) {
	ns := mustCIDRs(t)
	cases := []struct {
		name string
		ip   string
		want bool
	}{
		// 127.0.0.0/8 回环
		{"回环 127.0.0.1", "127.0.0.1", true},
		{"回环 127.255.255.255", "127.255.255.255", true},
		{"回环外 128.0.0.1", "128.0.0.1", false},
		// 10.0.0.0/8 RFC1918
		{"10.0.0.1", "10.0.0.1", true},
		{"10.255.255.255", "10.255.255.255", true},
		{"10 段外 11.0.0.1", "11.0.0.1", false},
		// 172.16.0.0/12 RFC1918（覆盖 NPM 容器 172.19.0.2）
		{"172.16.0.1", "172.16.0.1", true},
		{"172.19.0.2（NPM 容器）", "172.19.0.2", true},
		{"172.31.255.255", "172.31.255.255", true},
		{"172.15.255.255", "172.15.255.255", false},
		{"172.32.0.1", "172.32.0.1", false},
		// 192.168.0.0/16 RFC1918
		{"192.168.0.1", "192.168.0.1", true},
		{"192.168.255.255", "192.168.255.255", true},
		{"192.169.0.1", "192.169.0.1", false},
		// 100.64.0.0/10 CGNAT（覆盖阿里云 100.100.30.25）
		{"100.64.0.1", "100.64.0.1", true},
		{"100.100.30.25（阿里云内网）", "100.100.30.25", true},
		{"100.127.255.255", "100.127.255.255", true},
		{"100.128.0.1", "100.128.0.1", false},
		// 169.254.0.0/16 链路本地
		{"169.254.0.1", "169.254.0.1", true},
		{"169.253.0.1", "169.253.0.1", false},
		// 224.0.0.0/4 组播
		{"224.0.0.1", "224.0.0.1", true},
		{"239.255.255.255", "239.255.255.255", true},
		{"240.0.0.1", "240.0.0.1", false},
		// 公网
		{"203.0.113.5（公网）", "203.0.113.5", false},
		{"8.8.8.8（公网）", "8.8.8.8", false},
		{"0.0.0.0（IPv6 行零值）", "0.0.0.0", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsInternalIPv4(u32IP(t, c.ip), ns); got != c.want {
				t.Errorf("IsInternalIPv4(%s) = %v, 期望 %v", c.ip, got, c.want)
			}
		})
	}
}

// TestIsInternalSrc 默认语义双态（reviewer R-01a：仅按 SRC 判定）：
// SRC 内网→过滤；SRC 公网→保留（无论 DST 内外，覆盖 forward 链外部→容器形态）。
func TestIsInternalSrc(t *testing.T) {
	ns := mustCIDRs(t)
	srcInternal := event.FirewallEvent{SrcIP: u32IP(t, "172.19.0.2"), DstIP: u32IP(t, "203.0.113.5")}
	srcPublicDstInternal := event.FirewallEvent{SrcIP: u32IP(t, "203.0.113.5"), DstIP: u32IP(t, "172.19.0.2")}
	srcPublic := event.FirewallEvent{SrcIP: u32IP(t, "203.0.113.5"), DstIP: u32IP(t, "198.51.100.7")}
	ipv6Line := event.FirewallEvent{SrcIP: 0, DstIP: 0} // IPv6 行（IP 转 uint32 为 0）

	if !IsInternalSrc(srcInternal, ns) {
		t.Error("SRC 内网应过滤（默认语义）")
	}
	if IsInternalSrc(srcPublicDstInternal, ns) {
		t.Error("SRC 公网 DST 内网应保留（forward 链外部→容器真实威胁）")
	}
	if IsInternalSrc(srcPublic, ns) {
		t.Error("公网 SRC 应保留")
	}
	if IsInternalSrc(ipv6Line, ns) {
		t.Error("SRC=0（IPv6 行）应保留（无法判定，保守）")
	}
}

// TestIsInternalEither 扩展模式（fw.filter_dst_internal=true）：SRC 或 DST 任一命中即过滤。
func TestIsInternalEither(t *testing.T) {
	ns := mustCIDRs(t)
	srcPublicDstInternal := event.FirewallEvent{SrcIP: u32IP(t, "203.0.113.5"), DstIP: u32IP(t, "172.19.0.2")}
	srcInternalDstPublic := event.FirewallEvent{SrcIP: u32IP(t, "10.0.0.5"), DstIP: u32IP(t, "203.0.113.5")}
	srcPublic := event.FirewallEvent{SrcIP: u32IP(t, "203.0.113.5"), DstIP: u32IP(t, "198.51.100.7")}
	ipv6Line := event.FirewallEvent{SrcIP: 0, DstIP: 0}

	if !IsInternalEither(srcPublicDstInternal, ns) {
		t.Error("扩展模式：外部→内网目的应过滤")
	}
	if !IsInternalEither(srcInternalDstPublic, ns) {
		t.Error("扩展模式：SRC 内网应过滤")
	}
	if IsInternalEither(srcPublic, ns) {
		t.Error("公网双向应保留")
	}
	if IsInternalEither(ipv6Line, ns) {
		t.Error("IPv6 行（双 0）应保留")
	}
}

// TestFwFilterShouldDrop 接线层判定（含开关语义）。
func TestFwFilterShouldDrop(t *testing.T) {
	ns := mustCIDRs(t)
	evInternalSrc := event.FirewallEvent{SrcIP: u32IP(t, "172.19.0.2"), DstIP: u32IP(t, "203.0.113.5")}
	evExtToIntDst := event.FirewallEvent{SrcIP: u32IP(t, "203.0.113.5"), DstIP: u32IP(t, "172.19.0.2")}
	evPublic := event.FirewallEvent{SrcIP: u32IP(t, "203.0.113.5"), DstIP: u32IP(t, "198.51.100.7")}

	// ExcludeInternal=false → 全量记录（不过滤）。
	off := FwFilter{ExcludeInternal: false, CIDRs: ns}
	if off.ShouldDrop(evInternalSrc) {
		t.Error("exclude_internal=false 不应过滤")
	}
	// 空 CIDRs → 保守不过滤。
	emptyCIDR := FwFilter{ExcludeInternal: true, CIDRs: nil}
	if emptyCIDR.ShouldDrop(evInternalSrc) {
		t.Error("空 CIDRs 不应过滤（保守）")
	}
	// 默认模式（FilterDstInternal=false）。
	fDefault := FwFilter{ExcludeInternal: true, FilterDstInternal: false, CIDRs: ns}
	if !fDefault.ShouldDrop(evInternalSrc) {
		t.Error("默认模式：SRC 内网应过滤")
	}
	if fDefault.ShouldDrop(evExtToIntDst) {
		t.Error("默认模式：SRC 公网 DST 内网应保留")
	}
	if fDefault.ShouldDrop(evPublic) {
		t.Error("默认模式：公网应保留")
	}
	// 扩展模式（FilterDstInternal=true）。
	fExt := FwFilter{ExcludeInternal: true, FilterDstInternal: true, CIDRs: ns}
	if !fExt.ShouldDrop(evExtToIntDst) {
		t.Error("扩展模式：外部→内网目的应过滤")
	}
}

// TestParseCIDRs 自定义网段解析（B.2.3：空=内置默认；非法报错）。
func TestParseCIDRs(t *testing.T) {
	// 空输入 → 内置默认列表。
	ns, err := ParseCIDRs(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(ns) != len(defaultInternalCIDRs) {
		t.Errorf("默认网段数 = %d, 期望 %d", len(ns), len(defaultInternalCIDRs))
	}
	ns2, err := ParseCIDRs([]string{})
	if err != nil || len(ns2) != len(defaultInternalCIDRs) {
		t.Errorf("空列表应回退默认: len=%d err=%v", len(ns2), err)
	}
	// 自定义覆盖。
	ns3, err := ParseCIDRs([]string{"172.19.0.0/16"})
	if err != nil || len(ns3) != 1 {
		t.Fatalf("自定义网段解析失败: %v", err)
	}
	if !IsInternalIPv4(u32IP(t, "172.19.1.1"), ns3) {
		t.Error("自定义网段应生效")
	}
	if IsInternalIPv4(u32IP(t, "172.20.1.1"), ns3) {
		t.Error("自定义网段外不应命中")
	}
	// 非法格式。
	if _, err := ParseCIDRs([]string{"10.0.0.0"}); err == nil {
		t.Error("非法 CIDR（无掩码）应报错")
	}
	if _, err := ParseCIDRs([]string{"not-a-cidr"}); err == nil {
		t.Error("非法 CIDR 应报错")
	}
}

// TestParseExcludeIPs 排除 IP 列表解析（DEV-039 用户需求2：空=不排除；非法报错）。
func TestParseExcludeIPs(t *testing.T) {
	// 空输入 → nil（不排除）。
	ips, err := ParseExcludeIPs(nil)
	if err != nil || len(ips) != 0 {
		t.Errorf("空输入应返回空列表: len=%d err=%v", len(ips), err)
	}
	ips2, err := ParseExcludeIPs([]string{})
	if err != nil || len(ips2) != 0 {
		t.Errorf("空列表应返回空: len=%d err=%v", len(ips2), err)
	}
	// 合法 IPv4。
	ips3, err := ParseExcludeIPs([]string{"182.136.147.161", "203.0.113.5"})
	if err != nil || len(ips3) != 2 {
		t.Fatalf("合法 IP 解析失败: %v", err)
	}
	if !containsIPv4(u32IP(t, "182.136.147.161"), ips3) {
		t.Error("182.136.147.161 应命中排除列表")
	}
	if containsIPv4(u32IP(t, "8.8.8.8"), ips3) {
		t.Error("未配置 IP 不应命中")
	}
	// 非法格式。
	if _, err := ParseExcludeIPs([]string{"not-an-ip"}); err == nil {
		t.Error("非法 IP 应报错")
	}
	if _, err := ParseExcludeIPs([]string{"2001:db8::1"}); err == nil {
		t.Error("IPv6 应报错（当前仅支持 IPv4）")
	}
}

// TestFwFilterShouldDropExcludeIPs 排除指定来源 IP 判定（DEV-039 用户需求2）：
// 命中 exclude_ips 的 SRC 丢弃；与 ExcludeInternal 开关独立。
func TestFwFilterShouldDropExcludeIPs(t *testing.T) {
	ns := mustCIDRs(t)
	exIPs, _ := ParseExcludeIPs([]string{"182.136.147.161"})
	evOperator := event.FirewallEvent{SrcIP: u32IP(t, "182.136.147.161"), DstIP: u32IP(t, "172.17.39.111")}
	evOther := event.FirewallEvent{SrcIP: u32IP(t, "203.0.113.5"), DstIP: u32IP(t, "172.17.39.111")}
	evInternal := event.FirewallEvent{SrcIP: u32IP(t, "172.19.0.2"), DstIP: u32IP(t, "203.0.113.5")}
	ipv6Line := event.FirewallEvent{SrcIP: 0, DstIP: 0}

	// exclude_internal=false 时仍排除操作方 IP（开关独立）。
	off := FwFilter{ExcludeInternal: false, CIDRs: ns, ExcludeIPs: exIPs}
	if !off.ShouldDrop(evOperator) {
		t.Error("exclude_internal=false 时操作方 IP 仍应排除")
	}
	if off.ShouldDrop(evOther) {
		t.Error("非排除 IP 不应被排除")
	}
	// 默认模式（exclude_internal=true）：操作方 IP 排除 + 内网 SRC 过滤。
	fDefault := FwFilter{ExcludeInternal: true, FilterDstInternal: false, CIDRs: ns, ExcludeIPs: exIPs}
	if !fDefault.ShouldDrop(evOperator) {
		t.Error("默认模式：操作方 IP 应排除")
	}
	if !fDefault.ShouldDrop(evInternal) {
		t.Error("默认模式：内网 SRC 应过滤")
	}
	if fDefault.ShouldDrop(evOther) {
		t.Error("默认模式：其他公网 SRC 应保留")
	}
	// IPv6 行（SrcIP=0）保守保留。
	if fDefault.ShouldDrop(ipv6Line) {
		t.Error("IPv6 行（SrcIP=0）应保留")
	}
	// 空 ExcludeIPs → 不排除。
	noEx := FwFilter{ExcludeInternal: true, CIDRs: ns, ExcludeIPs: nil}
	if noEx.ShouldDrop(evOperator) {
		t.Error("空 ExcludeIPs 不应排除操作方 IP")
	}
}
