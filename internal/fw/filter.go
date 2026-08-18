// 采集层来源语义过滤（DEV-031 优化②，B.2）。
// 定位：过滤放在采集层（fw.go handleLine 发送前）而非展示层——过滤后 summary 计数、
// TOP 端口/源、时间线、CSV 导出、WS 推送全链路自动干净（DRY，无需改 API/前端消费点）。
// 判定规则（运营官 D.4 裁定 3）：默认仅按 SRC 内网过滤；fw.filter_dst_internal=true
// 为扩展模式（外部→内网目的也过滤）。SrcIP==0（IPv6 行或解析失败）保守保留。
package fw

import (
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"sentry-agent/internal/event"
)

// defaultInternalCIDRs 内置默认内网网段列表（B.2.2：任务书列举 + 合理补充）。
// 注意：不含 0.0.0.0/8——该段为"本网络"保留段，无真实来源语义；
// IPv6 行（SrcIP/DstIP 均为 0）由守卫保证安全（判定前置 ip != 0，见
// IsInternalSrc/IsInternalEither），即使 CIDRs 含 0.0.0.0/8 也不会误杀
// （AUDIT-005 A-09：修正过时注释——守卫已保证 IPv6 行安全）。
var defaultInternalCIDRs = []string{
	"127.0.0.0/8",    // 回环
	"10.0.0.0/8",     // RFC 1918
	"172.16.0.0/12",  // RFC 1918（覆盖 NPM 容器 172.19.0.2）
	"192.168.0.0/16", // RFC 1918
	"100.64.0.0/10",  // CGNAT（覆盖阿里云内网 100.100.30.25）
	"169.254.0.0/16", // 链路本地
	"224.0.0.0/4",    // 组播
}

// FwFilter 采集层过滤配置（由 config.FWCfg 编译而来；零值 = 不过滤，保守全量）。
type FwFilter struct {
	// ExcludeInternal 是否排除内网/自身来源事件（fw.exclude_internal，默认 true）。
	ExcludeInternal bool
	// FilterDstInternal 扩展模式：外部→内网目的事件也过滤（fw.filter_dst_internal，默认 false）。
	FilterDstInternal bool
	// CIDRs 内网网段（fw.internal_cidrs 预编译；空列表 = 使用内置默认列表）。
	CIDRs []net.IPNet
	// ExcludeIPs 排除指定来源 IP（fw.exclude_ips 预编译，DEV-039 用户需求2：
	// 操作方/可信 IP 白名单排除；命中 SRC 的事件在采集层丢弃）。
	ExcludeIPs []net.IP
	// DynamicExcludeIPs 动态白名单（DEV-042 SSH 成功登录自动学习）：指向共享
	// atomic.Pointer（存 []net.IP）。FwFilter 值复制后仍共享同一指针——学习器经
	// SetDynamicExcludeIPs 更新，所有副本的 ShouldDrop 判定可见。nil = 未启用动态白名单。
	DynamicExcludeIPs *atomic.Pointer[[]net.IP]
}

// SetDynamicExcludeIPs 更新动态白名单（DEV-042 SSH 成功登录自动学习）。
// 首次调用初始化共享槽位；后续调用原子替换（学习器并发安全）。
// 注意：须在 FwFilter 值复制（如传入 RunFwParser）之前调用，确保副本共享同一槽位。
func (f *FwFilter) SetDynamicExcludeIPs(ips []net.IP) {
	if f.DynamicExcludeIPs == nil {
		f.DynamicExcludeIPs = &atomic.Pointer[[]net.IP]{}
	}
	f.DynamicExcludeIPs.Store(&ips)
}

// ShouldDrop 判定事件是否应在采集层丢弃（解析成功后、入队前调用）。
func (f FwFilter) ShouldDrop(ev event.FirewallEvent) bool {
	// DEV-039 用户需求2：排除指定来源 IP（操作方/可信 IP）——优先于内网判定，
	// 与 ExcludeInternal 开关独立（exclude_internal=false 时仍排除操作方 IP）。
	// DEV-042：动态白名单（SSH 成功登录学习）与静态 exclude_ips 合并判定。
	if ev.SrcIP != 0 {
		if len(f.ExcludeIPs) > 0 && containsIPv4(ev.SrcIP, f.ExcludeIPs) {
			return true
		}
		if f.DynamicExcludeIPs != nil {
			if p := f.DynamicExcludeIPs.Load(); p != nil && len(*p) > 0 && containsIPv4(ev.SrcIP, *p) {
				return true
			}
		}
	}
	if !f.ExcludeInternal || len(f.CIDRs) == 0 {
		return false
	}
	if f.FilterDstInternal {
		// 扩展模式：SRC 或 DST 任一命中内网即过滤。
		return IsInternalEither(ev, f.CIDRs)
	}
	// 默认模式：仅 SRC 判定（DST 不参与，保留 forward 链外部→内网目的的真实威胁）。
	return IsInternalSrc(ev, f.CIDRs)
}

// containsIPv4 判定 IPv4（uint32）是否命中排除 IP 列表（精确匹配，无掩码）。
func containsIPv4(ip uint32, ips []net.IP) bool {
	for _, n := range ips {
		if n.To4() != nil && event.IPv4ToUint32(n) == ip {
			return true
		}
	}
	return false
}

// IsInternalSrc 默认语义：仅判定 SRC 是否内网来源（B.2.2 判定规则，reviewer R-01a）。
// SrcIP==0（IPv6 行/解析失败）无法判定 → 返回 false（保守保留，避免误杀真实威胁）。
func IsInternalSrc(ev event.FirewallEvent, cidrs []net.IPNet) bool {
	if ev.SrcIP == 0 {
		return false
	}
	return IsInternalIPv4(ev.SrcIP, cidrs)
}

// IsInternalEither 扩展模式专用：SRC 或 DST 任一命中内网即过滤
// （fw.filter_dst_internal=true 时启用；默认不启用）。
func IsInternalEither(ev event.FirewallEvent, cidrs []net.IPNet) bool {
	if IsInternalSrc(ev, cidrs) {
		return true
	}
	if ev.DstIP != 0 && IsInternalIPv4(ev.DstIP, cidrs) {
		return true
	}
	return false
}

// IsInternalIPv4 判定 IPv4（uint32）是否命中任一内网网段（掩码与运算，无 net.IP 分配）。
func IsInternalIPv4(ip uint32, cidrs []net.IPNet) bool {
	for _, n := range cidrs {
		ones, bits := n.Mask.Size()
		if bits != 32 {
			continue
		}
		mask := ^uint32(0) << (32 - ones)
		base := event.IPv4ToUint32(n.IP)
		if (ip & mask) == (base & mask) {
			return true
		}
	}
	return false
}

// ParseCIDRs 校验并预编译 CIDR 列表；空输入返回内置默认列表（B.2.3）。
func ParseCIDRs(cidrs []string) ([]net.IPNet, error) {
	if len(cidrs) == 0 {
		cidrs = defaultInternalCIDRs
	}
	out := make([]net.IPNet, 0, len(cidrs))
	for _, s := range cidrs {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("非法 CIDR %q: %w", s, err)
		}
		out = append(out, *n)
	}
	return out, nil
}

// ParseExcludeIPs 校验并预编译排除 IP 列表（DEV-039 用户需求2）。
// 仅接受 IPv4 点分十进制（与 config.Validate 一致）；空输入返回 nil（不排除）。
func ParseExcludeIPs(ips []string) ([]net.IP, error) {
	out := make([]net.IP, 0, len(ips))
	for _, s := range ips {
		ip := net.ParseIP(s)
		if ip == nil || ip.To4() == nil {
			return nil, fmt.Errorf("非法 IPv4 地址 %q", s)
		}
		out = append(out, ip.To4())
	}
	return out, nil
}

// filterStats 过滤留痕统计（B.2.2：限频 system_event info 留痕累计过滤数）。
type filterStats struct {
	dropped atomic.Uint64
	rep     *event.RateLimiter // 1 小时限频（防高频告警风暴）
}

func newFilterStats() *filterStats {
	return &filterStats{rep: event.NewRateLimiter(time.Hour)}
}

// drop 记录一次过滤并限频留痕。
func (fs *filterStats) drop(sys chan<- event.SystemEvent) {
	n := fs.dropped.Add(1)
	fs.rep.Report(sys, "fw", "info",
		fmt.Sprintf("已过滤内网/自身流量事件累计 %d 条（fw.exclude_internal 生效）", n))
}
