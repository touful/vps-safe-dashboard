package fw

import (
	"regexp"
	"strconv"
	"strings"

	"sentry-agent/internal/event"
)

// reFWKV 提取内核日志行中的键值对（SRC/DST/PROTO/SPT/DPT）。
var reFWKV = regexp.MustCompile(`\b(SRC|DST|PROTO|SPT|DPT)=([^\s]+)`)

// protoByName 协议名 → 协议号映射。
var protoByName = map[string]uint8{
	"TCP":   event.ProtoTCP,
	"UDP":   event.ProtoUDP,
	"ICMP":  event.ProtoICMP,
	"SCTP":  132,
	"GRE":   47,
	"ICMPV6": 58,
}

// ParseFWLine 解析一行 SENTRY_FW 前缀的内核日志行（纯函数，可单测）。
// 行格式（方案 6.5.3 前缀 + 内核 LOG 输出）：
//
//	SENTRY_FW:input:drop IN=eth0 OUT= MAC=... SRC=1.2.3.4 DST=5.6.7.8 LEN=40 PROTO=TCP SPT=1234 DPT=22
//
// 返回 ok=false 表示行不含 prefix 或关键字段缺失（无 SRC/DST 键的行视为噪声，
// 防止其他含前缀字样日志混入；调用方按策略忽略/限频告警）。
// VS-09（DEV-P1-001，AUD-VPS-001）：Raw 存储层截断与 SSH detail 对齐（Truncate512，
// rune 安全 512 字符）——消除"存储完整保留 vs 展示 60 字符截断"的不对称放大
// （DB 行大小攻击者半可控；内核 LOG 行实际 200-300 字节，正常场景不触发截断）。
func ParseFWLine(line, prefix string) (event.FirewallEvent, bool) {
	idx := strings.Index(line, prefix)
	if idx < 0 {
		return event.FirewallEvent{}, false
	}
	ev := event.FirewallEvent{Raw: event.Truncate512(line)}
	// 前缀之后紧跟 "<链>:<动作> "（部署脚本写入的 prefix 形如 "SENTRY_FW:input:drop "）。
	rest := strings.TrimSpace(line[idx+len(prefix):])
	tag := strings.Fields(rest)
	if len(tag) == 0 {
		return event.FirewallEvent{}, false
	}
	if seg := strings.Split(tag[0], ":"); len(seg) == 2 {
		ev.Chain, ev.Action = seg[0], seg[1]
	} else {
		ev.Action = tag[0] // 前缀后无 "<链>:<动作>" 结构时整段作为动作兜底
	}
	// 提取键值对（遍历全部匹配，最后一次匹配生效；内核日志键不重复）。
	hasAddr := false // SRC/DST 键至少一个存在才认定为有效防火墙事件
	for _, m := range reFWKV.FindAllStringSubmatch(line, -1) {
		if len(m) != 3 {
			continue
		}
		key, val := m[1], m[2]
		switch key {
		case "SRC":
			ev.SrcIP = ipToUint32(val)
			hasAddr = true // 键存在即有效（IPv6 地址转 uint32 为 0，但事件仍保留）
		case "DST":
			ev.DstIP = ipToUint32(val)
			hasAddr = true
		case "PROTO":
			if p, ok := protoByName[strings.ToUpper(val)]; ok {
				ev.Proto = p
			}
		case "SPT":
			ev.SrcPort = atou16(val)
		case "DPT":
			ev.DstPort = atou16(val)
		}
	}
	if !hasAddr {
		return event.FirewallEvent{}, false
	}
	// DPT 口径（方案 3.4 强制）：攻击端口统计只允许使用 DPT 字段；
	// SSH 认证日志中的 port 是客户端源端口，禁止混用。ICMP 无端口字段，保持 0。
	return ev, true
}

// ipToUint32 解析点分十进制 IPv4；IPv6 或非法时返回 0（FirewallEvent 无 IPv6 字段，
// 已知限制：IPv6 源/目的地址的防火墙事件 IP 字段为 0，M1 记录）。
func ipToUint32(s string) uint32 {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return 0
	}
	var v uint32
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return 0
		}
		v = v<<8 | uint32(n)
	}
	return v
}

// atou16 解析无符号 16 位端口；失败返回 0。
func atou16(s string) uint16 {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0
	}
	return uint16(n)
}
