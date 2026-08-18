package honeypot

import (
	"context"
	"encoding/binary"
	"net"
	"strings"

	"sentry-agent/internal/event"
)

// handleRDP RDP 握手模拟（ITU-T X.224 / MS-RDPBCGR）。
// 流程：客户端 X.224 Connection Request（0x2E，含 "Cookie: mstshash=xxx" 提示）→
// 回 Connection Confirm（0x2F）→ 客户端随后发起 MCS Connect Initial 并进入
// TLS 加密通道——后续凭据无法解析（RDP 凭据加密，TLS 握手不可见）。
// 捕获：pre-auth 信息（cookie/mstshash 中的用户名提示）+ Extra 注明
// "RDP 凭据加密，无法捕获"（诚实降级：该协议设计目标即记录连接尝试 + 说明限制）。
func handleRDP(ctx context.Context, conn net.Conn, srcIP uint32, rec func(event.CredEvent)) {
	// X.224 Connection Request：TPKT 头（3 字节 len + 1 字节 0）+ X.224 CR。
	// TPKT 头：version(1)=3 + reserved(1)=0 + length(2)。
	var tpkt [4]byte
	if _, err := readFullN(conn, tpkt[:]); err != nil {
		return
	}
	if tpkt[0] != 3 {
		return // 非 TPKT（畸形/非 RDP）
	}
	tpktLen := int(binary.BigEndian.Uint16(tpkt[2:4]))
	if tpktLen < 11 || tpktLen > 65536 {
		return
	}
	cr := make([]byte, tpktLen-4)
	if _, err := readFullN(conn, cr); err != nil {
		return
	}
	// X.224 CR 结构（MS-RDPBCGR 2.2.1.1）：
	// cr[0]=LI(0x0E) cr[1]=0xE0(CR) cr[2:4]=dst-ref cr[4:6]=src-ref cr[6]=class(0x00)
	// cr[7:]=variable part（"Cookie: mstshash=xxx\r\n"）。
	if len(cr) < 7 || cr[1] != 0xE0 {
		return
	}
	// Cookie 提取："Cookie: mstshash=xxx\r\n"（早期 RDP 客户端在 CR 中携带，
	// 用于负载均衡会话亲和；mstshash 为用户名的哈希提示——用户名不可直接还原，
	// 如实记录为 pre-auth 线索）。
	cookie := extractRDCCookie(cr)

	// 凭据记录：username 留空（无法捕获），cookie 线索 + 限制说明入 Extra。
	extra := "RDP 凭据加密（TLS 通道），无法捕获；pre-auth 连接尝试"
	if cookie != "" {
		extra += "；cookie=" + cookie
	}
	rec(event.CredEvent{Extra: extra})

	// 回 X.224 Connection Confirm（0x2F）：TPKT + X.224 CC（MS-RDPBCGR 2.2.1.2）。
	// X.224 CC 结构：LI(1)=6 + PDUTYPE(1)=0xD0 + dst-ref(2) + src-ref(2) + class(1)
	// （R-12 reviewer 整改：原实现 0xD0 提前占位 LI，结构错位）。
	cc := []byte{
		3, 0, 0, 0x0B, // TPKT: version 3, len 11
		0x06, 0xD0, // X.224 CC: LI=6, PDU type=0xD0(CC)
		0x00, 0x00, // dst-ref（回显客户端 src-ref）
		0x00, 0x00, // src-ref
		0x00, // class 0
	}
	// dst-ref 回显客户端 Connection Request 的 src-ref（cr[4:6]）。
	if len(cr) >= 6 {
		cc[7] = cr[4]
		cc[8] = cr[5]
	}
	cc[2] = 0
	cc[3] = byte(len(cc))
	_, _ = conn.Write(cc)
	// 客户端随后的 MCS Connect Initial / TLS 握手不再解析（诚实降级），断开连接。
}

// extractRDCCookie 从 Connection Request 提取 "Cookie: mstshash=xxx\r\n" 文本。
func extractRDCCookie(cr []byte) string {
	// cookie 从 cr[7] 开始（LI(1) + type(1) + dst-ref(2) + src-ref(2) + class(1)），
	// 以 "\r\n" 终止（无显式长度字段）。
	if len(cr) < 8 {
		return ""
	}
	s := string(cr[7:])
	if i := strings.Index(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	// 兼容 "Cookie: mstshash=..." 与纯 mstshash 值。
	if i := strings.Index(s, "mstshash="); i >= 0 {
		s = s[i+len("mstshash="):]
	}
	// 截断控制字符与超长（安全显示）。
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7E {
			return -1
		}
		return r
	}, s)
	if len(s) > 128 {
		s = s[:128]
	}
	return s
}
