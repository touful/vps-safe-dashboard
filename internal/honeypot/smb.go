package honeypot

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"net"

	"sentry-agent/internal/event"
)

// handleSMB SMB2 认证握手模拟（MS-SMB2 + MS-NLMP）。
// 流程：Negotiate Request → 回 Negotiate Response（含 NTLMSSP CHALLENGE 与
// 8 字节 ServerChallenge）→ Session Setup Request（NTLMSSP AUTH）→
// 解析 Domain/User（UTF-16LE 明文）+ NtChallengeResponse（NTLMv2 hash，不可逆）→
// 记录 username + hash（Extra 注明 "NTLMv2 hash"）→ 回 STATUS_LOGON_FAILURE (0xC000006D)。
// 不实现完整 SMB2 会话：捕获认证凭据后即拒绝，不响应后续命令。
// 包格式（SMB2 头 64 字节）：ProtocolId(4)="\xfeSMB" + StructureSize(2) +
// CreditCharge(2) + Status(4) + Command(2) + Credit(2) + Flags(4) +
// NextCommand(4) + MessageId(8) + ... + HeaderPadding(16) + ...
func handleSMB(ctx context.Context, conn net.Conn, srcIP uint32, rec func(event.CredEvent)) {
	for {
		// SMB2 头：ProtocolId 4 字节 "\xfeSMB"。
		var pid [4]byte
		if _, err := readFullN(conn, pid[:]); err != nil {
			return
		}
		if string(pid[:]) != "\xfeSMB" {
			return // 非 SMB2（SMB1 或畸形）：不处理
		}
		hdr := make([]byte, 60) // 剩余头（共 64 字节）
		if _, err := readFullN(conn, hdr); err != nil {
			return
		}
		// 头布局（hdr 从 StructureSize 起，即完整头偏移 4 处）：
		// StructureSize(2) + CreditCharge(2) + Status(4) + Command(2) + Credit(2) +
		// Flags(4) + NextCommand(4) + MessageId(8) + Reserved(4) +
		// TreeId(4) + SessionId(8) + Signature(16) = 60 字节。
		cmd := binary.LittleEndian.Uint16(hdr[8:10])
		msgID := binary.LittleEndian.Uint64(hdr[20:28])
		// 读消息体（NextCommand 为 0 时剩余数据即本消息 payload；SMB2 无显式总长——
		// 由结构体长度字段决定，此处按命令类型读取）。
		switch cmd {
		case 0x0000: // SMB2 NEGOTIATE
			_, ok := readSMB2Body(conn, hdr)
			if !ok {
				return
			}
			// 回 Negotiate Response（NTLMSSP CHALLENGE）。
			resp := buildSMB2NegotiateResponse(msgID)
			if err := writeAll2(conn, resp); err != nil {
				return
			}
		case 0x0001: // SMB2 SESSION_SETUP
			body, ok := readSMB2Body(conn, hdr)
			if !ok {
				return
			}
			// SESSION_SETUP body：StructureSize(2)=25 + Flags(1) + SecurityMode(1) +
			// Capabilities(4) + Channel(4) + SecurityBufferOffset(2) + SecurityBufferLength(2)
			// + PreviousSessionId(8) + Buffer[...]（NTLMSSP）。
			if len(body) < 24 {
				return
			}
			secOff := int(binary.LittleEndian.Uint16(body[12:14]))
			secLen := int(binary.LittleEndian.Uint16(body[14:16]))
			// SecurityBufferOffset 相对完整 SMB2 消息（含 64 字节头）计；
			// body 切片不含头，故切片内偏移 = secOff - 64。
			if secOff < 64 || secOff+secLen > 64+len(body) {
				return // 偏移越界（畸形防御）
			}
			ntlm := body[secOff-64 : secOff-64+secLen]
			user, domain, ntResp, ok := parseNTLMSSPAuth(ntlm)
			if !ok {
				continue // 非 AUTH（如 NEGOTIATE 消息）：等待下一包
			}
			// 凭据记录：Domain\User 明文 + NTLMv2 Response hash（不可逆）。
			username := user
			if domain != "" {
				username = domain + "\\" + user
			}
			rec(event.CredEvent{
				Username: username,
				Password: ntResp,
				Extra:    "NTLMv2 Response hash（NTProofStr+SHA-256 链，不可逆）",
			})
			// STATUS_LOGON_FAILURE (0xC000006D)。
			if err := writeSMB2Error(conn, 0x0001, 0xC000006D); err != nil {
				return
			}
			return
		default:
			return // 其他命令（TREE_CONNECT 等）：认证已结束或路径异常，关闭
		}
	}
}

// readSMB2Body 读取 SMB2 消息剩余数据（含 64 字节头在内的完整帧）。
// SMB2 无显式帧长——以连接剩余数据作为本消息体（蜜罐场景单帧往返，
// 无 SMB2 复合消息（NextCommand=0），此近似成立）。
func readSMB2Body(conn net.Conn, hdr []byte) ([]byte, bool) {
	// 保守读取：客户端发送的完整请求帧通常一次到达；无总长字段时
	// 采用"读取全部剩余数据"策略（读超时兜底 30s）。
	// 简化：依赖框架连接超时——此处尝试读取剩余（可能阻塞至超时）。
	// 改为按 SMB2 头 StructureSize 提供的 body 起点判定：
	// NEGOTIATE 与 SESSION_SETUP 的请求无后续可选大字段，读取剩余即可。
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, false
	}
	if n == 0 {
		return nil, false
	}
	// 注意：本次 Read 可能只读到部分（TCP 分片）——蜜罐场景攻击脚本单帧发送，
	// 一次 Read 即可；残余数据由下一轮循环丢弃（协议流程已结束）。
	return buf[:n], true
}

// buildSMB2NegotiateResponse 构造 SMB2 Negotiate Response + NTLMSSP CHALLENGE。
// 参考 MS-SMB2 2.2.4：Negotiate Response 结构（经典结构 64 字节头 + 65 字节体 + 安全缓冲）。
// msgID 回显请求的 MessageId（客户端靠它关联请求/响应）。
func buildSMB2NegotiateResponse(msgID uint64) []byte {
	// 安全缓冲：NTLMSSP CHALLENGE（MS-NLMP 2.2.1.2）。
	// Signature(8)="NTLMSSP\0" + MessageType(4)=2 + TargetNameFields(8) +
	// NegotiateFlags(4) + ServerChallenge(8) + Reserved(8) + TargetInfoFields(8) + Version(8)。
	challenge := make([]byte, 0, 56+16)
	challenge = append(challenge, []byte("NTLMSSP\x00")...)
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], 2)
	challenge = append(challenge, tmp[:]...)
	// TargetNameFields：Len(2) + MaxLen(2) + Offset(4)（本响应无 TargetName）。
	challenge = append(challenge, 0, 0, 0, 0, 0, 0, 0, 0)
	// NegotiateFlags：NEGOTIATE_EXTENDED_SESSIONSECURITY(0x00080000) |
	// NEGOTIATE_NTLM(0x200) | NEGOTIATE_ALWAYS_SIGN(0x8000) | UNICODE(0x1)。
	binary.LittleEndian.PutUint32(tmp[:], 0x00088201)
	challenge = append(challenge, tmp[:]...)
	// ServerChallenge（8 字节固定伪随机）。
	challenge = append(challenge, []byte("HPCHALNG")...)
	// Reserved(8)。
	challenge = append(challenge, 0, 0, 0, 0, 0, 0, 0, 0)
	// TargetInfoFields：Len(2) + MaxLen(2) + Offset(4)（无 TargetInfo）。
	challenge = append(challenge, 0, 0, 0, 0, 0, 0, 0, 0)
	// Version(8)：Windows 伪版本（major 6, minor 1, build 7601, revision）。
	challenge = append(challenge, 6, 1, 0, 0, 0, 0, 0, 0)

	// Negotiate Response 主体（SMB2_NEGOTIATE_RESPONSE，MS-SMB2 2.2.4）：
	// StructureSize(2)=65 + SecurityMode(2) + DialectRevision(2) + Reserved(2) +
	// ServerGuid(16) + Capabilities(4) + MaxTransactSize(4) + MaxReadSize(4) +
	// MaxWriteSize(4) + SystemTime(8) + ServerStartTime(8) +
	// SecurityBufferOffset(2) + SecurityBufferLength(2) + Reserved(2) +
	// (NegotiateContext 区，经典模式省略)。
	nb := make([]byte, 0, 65+len(challenge))
	nb = append(nb, 65, 0)                 // StructureSize
	nb = append(nb, 0x01, 0x00)            // SecurityMode: SIGNING_ENABLED
	nb = append(nb, 0x10, 0x02)            // DialectRevision: SMB 2.1（广泛兼容）
	nb = append(nb, 0, 0)                  // Reserved
	nb = append(nb, []byte("SENTRYH0N3YP0T!!")...) // ServerGuid（16 字节）
	nb = append(nb, 0, 0, 0, 0) // Capabilities
	nb = append(nb, 0x00, 0x10, 0x00, 0x00) // MaxTransactSize 4MB
	nb = append(nb, 0x00, 0x10, 0x00, 0x00) // MaxReadSize
	nb = append(nb, 0x00, 0x10, 0x00, 0x00) // MaxWriteSize
	nb = append(nb, 0, 0, 0, 0, 0, 0, 0, 0) // SystemTime
	nb = append(nb, 0, 0, 0, 0, 0, 0, 0, 0) // ServerStartTime
	// SecurityBufferOffset = 126（64 头 + 62 体；SMB 2.1 Negotiate Response
	// 实际字段 62 字节，StructureSize 字段声明 64 属协议历史遗留）。
	secOff := 64 + 62
	var sbo [2]byte
	binary.LittleEndian.PutUint16(sbo[:], uint16(secOff))
	nb = append(nb, sbo[:]...)
	var sbl [2]byte
	binary.LittleEndian.PutUint16(sbl[:], uint16(len(challenge)))
	nb = append(nb, sbl[:]...)
	nb = append(nb, 0, 0) // Reserved

	// 组装完整消息：SMB2 头 + 体 + 安全缓冲。
	out := make([]byte, 0, 64+len(nb)+len(challenge))
	// 头：\xfeSMB + StructureSize(2)=64 + CreditCharge(2)=0 + Status(4)=0 +
	// Command(2)=0x0000(Negotiate) + Credit(2)=1 + Flags(4)=0 +
	// NextCommand(4)=0 + MessageId(8)=0 + Reserved(4)=0 + TreeId(4)=0 +
	// SessionId(8)=0 + Signature(16)=0。
	out = append(out, []byte("\xfeSMB")...)
	out = append(out, 64, 0)
	out = append(out, 0, 0)
	out = append(out, 0, 0, 0, 0) // Status
	out = append(out, 0x00, 0x00) // Command = NEGOTIATE
	out = append(out, 1, 0)       // Credit
	out = append(out, 0, 0, 0, 0) // Flags
	out = append(out, 0, 0, 0, 0) // NextCommand
	var mi [8]byte
	binary.LittleEndian.PutUint64(mi[:], msgID)
	out = append(out, mi[:]...)               // MessageId（回显请求）
	out = append(out, 0, 0, 0, 0)             // Reserved
	out = append(out, 0, 0, 0, 0)             // TreeId
	out = append(out, 0, 0, 0, 0, 0, 0, 0, 0) // SessionId
	out = append(out, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0) // Signature 16
	out = append(out, nb...)
	out = append(out, challenge...)
	return out
}

// parseNTLMSSPAuth 解析 NTLMSSP AUTH 消息（MS-NLMP 2.2.1.3，type 3）。
// 返回 (user, domain, NtChallengeResponse hex, 是否 AUTH)。
func parseNTLMSSPAuth(b []byte) (string, string, string, bool) {
	if len(b) < 12 || string(b[:8]) != "NTLMSSP\x00" {
		return "", "", "", false
	}
	msgType := binary.LittleEndian.Uint32(b[8:12])
	if msgType != 3 {
		return "", "", "", false // 非 AUTH（如 NEGOTIATE type1）：调用方等待下一包
	}
	if len(b) < 64 {
		return "", "", "", false
	}
	// 字段表（各 8 字节：Len(2) + MaxLen(2) + Offset(4)）：
	// LmChallengeResponse @12 / NtChallengeResponse @20 / DomainName @28 /
	// UserName @36 / Workstation @44 / EncryptedRandomSessionKey @52。
	field := func(pos int) (int, int) {
		l := int(binary.LittleEndian.Uint16(b[pos : pos+2]))
		o := int(binary.LittleEndian.Uint32(b[pos+4 : pos+8]))
		return o, l
	}
	domOff, domLen := field(28)
	userOff, userLen := field(36)
	ntOff, ntLen := field(20)
	// 字段数据在消息末尾数据区（offset 从消息起始）。
	user := utf16leToString(b, userOff, userLen)
	domain := utf16leToString(b, domOff, domLen)
	ntResp := ""
	if ntLen > 0 && ntOff+ntLen <= len(b) {
		ntResp = hex.EncodeToString(b[ntOff : ntOff+ntLen])
	}
	if user == "" && ntResp == "" {
		return "", "", "", false
	}
	return user, domain, ntResp, true
}

// utf16leToString 将消息内 UTF-16LE 字段转为字符串（截断 NUL）。
func utf16leToString(b []byte, off, ln int) string {
	if off < 0 || ln < 0 || off+ln > len(b) || ln%2 != 0 {
		return ""
	}
	runes := make([]rune, 0, ln/2)
	for i := 0; i+1 < ln; i += 2 {
		u := binary.LittleEndian.Uint16(b[off+i : off+i+2])
		if u == 0 {
			break
		}
		runes = append(runes, rune(u))
	}
	return string(runes)
}

// writeSMB2Error 发送 SMB2 Error Response（SMB2_ERROR_RESPONSE：
// StructureSize(2)=9 + ErrorContextCount(1) + Reserved(1) + ByteCount(4)=0 + ErrorData）。
// 头中 Status 置错误码，Command 回显。
func writeSMB2Error(conn net.Conn, command uint16, status uint32) error {
	out := make([]byte, 0, 64+9)
	out = append(out, []byte("\xfeSMB")...)
	out = append(out, 64, 0) // StructureSize
	out = append(out, 0, 0)  // CreditCharge
	var st [4]byte
	binary.LittleEndian.PutUint32(st[:], status)
	out = append(out, st[:]...)
	var cm [2]byte
	binary.LittleEndian.PutUint16(cm[:], command)
	out = append(out, cm[:]...)
	out = append(out, 1, 0) // Credit
	out = append(out, 0, 0, 0, 0, 0, 0, 0, 0) // Flags + NextCommand
	out = append(out, 0, 0, 0, 0, 0, 0, 0, 0) // MessageId
	out = append(out, 0, 0, 0, 0, 0, 0, 0, 0) // Reserved + TreeId
	out = append(out, 0, 0, 0, 0, 0, 0, 0, 0) // SessionId
	out = append(out, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0) // Signature
	// Error Response 体。
	out = append(out, 9, 0) // StructureSize
	out = append(out, 0)    // ErrorContextCount
	out = append(out, 0)    // Reserved
	out = append(out, 0, 0, 0, 0) // ByteCount
	return writeAll2(conn, out)
}
