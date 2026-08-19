package honeypot

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"unicode/utf16"

	"sentry-agent/internal/event"
)

// TestMySQLCapture mysql 完整握手：greeting → HandshakeResponse41 → 凭据（hash）+ ERR 1045。
func TestMySQLCapture(t *testing.T) {
	credCh := make(chan event.CredEvent, 16)
	_, addrs := startTestServer(t, []string{"mysql"}, credCh, nil)
	c := dialProto(t, addrs, "mysql")

	// 读 HandshakeV10：4 头（3 字节 len + 1 序号）+ payload（protocol 10 + version NUL + ...）。
	var ghdr [4]byte
	if _, err := io.ReadFull(c, ghdr[:]); err != nil {
		t.Fatal(err)
	}
	gLen := int(binary.LittleEndian.Uint32(append(ghdr[:3], 0)))
	greeting := make([]byte, gLen)
	if _, err := io.ReadFull(c, greeting); err != nil {
		t.Fatal(err)
	}
	if greeting[0] != 10 {
		t.Fatalf("protocol version = %d, 期望 10", greeting[0])
	}
	if !strings.Contains(string(greeting), "mysql_native_password") {
		t.Fatal("greeting 缺少 auth plugin 名")
	}

	// HandshakeResponse41：caps(4) + maxpacket(4) + charset(1) + reserved(23) +
	// username NUL + [1 字节 len + auth-response]（CLIENT_SECURE_CONNECTION）。
	resp := make([]byte, 0, 256)
	var tmp [4]byte
	// caps: CLIENT_PROTOCOL_41(0x200) | CLIENT_SECURE_CONNECTION(0x8000)
	binary.LittleEndian.PutUint32(tmp[:], 0x8200)
	resp = append(resp, tmp[:]...)
	binary.LittleEndian.PutUint32(tmp[:], 1<<20) // max packet
	resp = append(resp, tmp[:]...)
	resp = append(resp, 45) // charset
	resp = append(resp, make([]byte, 23)...) // reserved
	resp = append(resp, []byte("root\x00")...) // username
	resp = append(resp, 20) // auth-response 长度（mysql_native_password 20 字节）
	resp = append(resp, []byte("0123456789ABCDEFGHIJ")...) // 伪 SHA1 摘要
	// 报文头：len(3) + seq(1)。
	pkt := make([]byte, 0, 4+len(resp))
	pkt = append(pkt, byte(len(resp)), byte(len(resp)>>8), byte(len(resp)>>16), 1)
	pkt = append(pkt, resp...)
	if _, err := c.Write(pkt); err != nil {
		t.Fatal(err)
	}

	ev := recvCred(t, credCh)
	if ev.Proto != "mysql" || ev.Username != "root" {
		t.Fatalf("凭据事件 = %+v", ev)
	}
	if ev.Password != "303132333435363738394142434445464748494a" {
		t.Fatalf("auth-response hex = %q", ev.Password)
	}
	if !strings.Contains(ev.Extra, "不可逆") {
		t.Fatalf("extra 应注明不可逆: %q", ev.Extra)
	}
	// ERR 1045 响应。
	var ehdr [4]byte
	if _, err := io.ReadFull(c, ehdr[:]); err != nil {
		t.Fatal(err)
	}
	eLen := int(binary.LittleEndian.Uint32(append(ehdr[:3], 0)))
	ebody := make([]byte, eLen)
	if _, err := io.ReadFull(c, ebody); err != nil {
		t.Fatal(err)
	}
	if ebody[0] != 0xFF {
		t.Fatalf("期望 ERR 包, got 0x%02X", ebody[0])
	}
	if binary.LittleEndian.Uint16(ebody[1:3]) != 1045 {
		t.Fatalf("错误码 = %d, 期望 1045", binary.LittleEndian.Uint16(ebody[1:3]))
	}
}

// TestMongoDBCapture mongodb OP_MSG saslStart：payload.user 明文 + nonce + ok:0 拒绝。
func TestMongoDBCapture(t *testing.T) {
	credCh := make(chan event.CredEvent, 16)
	_, addrs := startTestServer(t, []string{"mongodb"}, credCh, nil)
	c := dialProto(t, addrs, "mongodb")

	// 构造 saslStart 命令 BSON：
	// { saslStart: Int32(1), mechanism: "SCRAM-SHA-256",
	//   payload: Binary({user:"admin", rnonce:"abc123"}),
	//   options: {} }
	payloadDoc := buildBSONDoc(
		bsonElemString("user", "admin"),
		bsonElemString("rnonce", "abc123"),
	)
	cmdDoc := buildBSONDoc(
		bsonElemInt32("saslStart", 1),
		bsonElemString("mechanism", "SCRAM-SHA-256"),
		bsonElemBinary("payload", payloadDoc),
		bsonElemEmptyDoc("options"),
	)
	// OP_MSG：头 + flags(4) + kind(1) + body。
	msg := make([]byte, 0, 16+5+len(cmdDoc))
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], uint32(16+5+len(cmdDoc)))
	msg = append(msg, tmp[:]...)
	binary.LittleEndian.PutUint32(tmp[:], 7) // requestID
	msg = append(msg, tmp[:]...)
	binary.LittleEndian.PutUint32(tmp[:], 0) // responseTo
	msg = append(msg, tmp[:]...)
	binary.LittleEndian.PutUint32(tmp[:], 2013) // OP_MSG
	msg = append(msg, tmp[:]...)
	msg = append(msg, 0, 0, 0, 0) // flags
	msg = append(msg, 0)          // kind 0
	msg = append(msg, cmdDoc...)
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}

	ev := recvCred(t, credCh)
	if ev.Proto != "mongodb" || ev.Username != "admin" {
		t.Fatalf("凭据事件 = %+v", ev)
	}
	if !strings.Contains(ev.Extra, "SCRAM") || !strings.Contains(ev.Extra, "abc123") {
		t.Fatalf("extra 应含 SCRAM 与 nonce: %q", ev.Extra)
	}
	if ev.Password != "" {
		t.Fatalf("SCRAM 无明文密码, Password 应为空: %q", ev.Password)
	}
	// 读 OP_MSG 响应（ok:0）。
	var rhdr [16]byte
	if _, err := io.ReadFull(c, rhdr[:]); err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(rhdr[12:16]) != 2013 {
		t.Fatalf("响应 opCode = %d, 期望 OP_MSG 2013", binary.LittleEndian.Uint32(rhdr[12:16]))
	}
	rLen := int(binary.LittleEndian.Uint32(rhdr[:4]))
	rbody := make([]byte, rLen-16)
	if _, err := io.ReadFull(c, rbody); err != nil {
		t.Fatal(err)
	}
	if len(rbody) < 5 || rbody[4] != 0 {
		t.Fatalf("响应异常: % x", rbody[:8])
	}
}

// TestMongoDBOPQuery 兼容 OP_QUERY（旧版客户端）saslStart。
func TestMongoDBOPQuery(t *testing.T) {
	credCh := make(chan event.CredEvent, 16)
	_, addrs := startTestServer(t, []string{"mongodb"}, credCh, nil)
	c := dialProto(t, addrs, "mongodb")

	payloadDoc := buildBSONDoc(bsonElemString("user", "legacy"))
	cmdDoc := buildBSONDoc(
		bsonElemInt32("saslStart", 1),
		bsonElemBinary("payload", payloadDoc),
	)
	// OP_QUERY：头 + flags(4) + collection NUL + skip(4) + return(4) + query BSON。
	body := make([]byte, 0)
	body = append(body, 0, 0, 0, 0) // flags
	body = append(body, []byte("admin.$cmd\x00")...)
	body = append(body, 0, 0, 0, 0) // skip
	body = append(body, 0, 0, 0, 0) // return
	body = append(body, cmdDoc...)
	msg := make([]byte, 0, 16+len(body))
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], uint32(16+len(body)))
	msg = append(msg, tmp[:]...)
	binary.LittleEndian.PutUint32(tmp[:], 8)
	msg = append(msg, tmp[:]...)
	binary.LittleEndian.PutUint32(tmp[:], 0)
	msg = append(msg, tmp[:]...)
	binary.LittleEndian.PutUint32(tmp[:], 2004) // OP_QUERY
	msg = append(msg, tmp[:]...)
	msg = append(msg, body...)
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	ev := recvCred(t, credCh)
	if ev.Username != "legacy" {
		t.Fatalf("OP_QUERY 凭据 = %+v", ev)
	}
}

// TestMSSQLCapture mssql Prelogin + LOGIN7：用户名明文 + TDS 密码字段 + ERROR 18456。
func TestMSSQLCapture(t *testing.T) {
	credCh := make(chan event.CredEvent, 16)
	_, addrs := startTestServer(t, []string{"mssql"}, credCh, nil)
	c := dialProto(t, addrs, "mssql")

	// 1. Prelogin 请求（版本选项；蜜罐解析选项表后回 Prelogin Response）。
	pre := make([]byte, 0, 8+12)
	pre = append(pre, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00) // VERSION token + offset 10 + len 6
	pre = append(pre, 0x00, 0x00, 0x00, 0x00)             // terminator
	pre = append(pre, 0x07, 0x04, 0x00, 0x00, 0x00, 0x00) // 伪版本数据
	if err := writeTDSPacket(c, 0x12, pre); err != nil {
		t.Fatal(err)
	}
	// 读 Prelogin Response（类型 0x04）。
	pkt, err := readTDSPacket(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkt) == 0 || pkt[0] != 0x04 {
		t.Fatalf("Prelogin 响应类型 = %v", pkt[0])
	}

	// 2. LOGIN7：固定头 36 + offset 表（5 项）+ 变长数据。
	// 注意：offset 表须在全部 append 完成后写入（先 append 后写表，
	// 否则 append 扩容会覆盖表内容）。
	// 用户名按 TDS 规范 UTF-16LE 编码（R-02 整改后蜜罐按规范解码，ASCII 构造
	// 会产生双字节乱码）。
	host := []byte("PC1")
	user := []byte{'s', 0, 'a', 0} // "sa" UTF-16LE
	pass := []byte{0x01, 0xA4, 0x02, 0xA3} // TDS 混淆密码示例（XOR 0xA5 语义）
	dataOff := 36 + 5*4
	login := make([]byte, 0, 512)
	login = append(login, 0, 0, 0, 0) // Length 占位
	login = append(login, 0x04, 0x00, 0x00, 0x74) // TDSVersion 7.4
	login = append(login, 0, 0, 0x10, 0x00)       // PacketSize 4096
	login = append(login, 0, 0, 0, 0, 0, 0, 0, 0) // ClientProgVer + ClientPID
	login = append(login, 0, 0, 0, 0)             // ConnectionID
	login = append(login, 0, 0, 0, 0)             // OptionFlags1-3 + TypeFlags
	login = append(login, 0, 0, 0, 0, 0, 0, 0, 0) // ClientTimeZone + ClientLCID
	login = append(login, make([]byte, 5*4)...)   // offset 表占位（20 字节）
	login = append(login, host...)
	login = append(login, user...)
	login = append(login, pass...)
	// 全部数据就绪后写 offset 表。
	putU16 := func(b []byte, off int, v uint16) { binary.BigEndian.PutUint16(b[off:off+2], v) }
	putU16(login, 36, uint16(dataOff))
	putU16(login, 38, uint16(len(host)))
	putU16(login, 40, uint16(dataOff+len(host)))
	putU16(login, 42, uint16(len(user)))
	putU16(login, 44, uint16(dataOff+len(host)+len(user)))
	putU16(login, 46, uint16(len(pass)))
	putU16(login, 48, 0) // AppName off 0
	putU16(login, 50, 0)
	putU16(login, 52, 0) // ServerName off 0
	putU16(login, 54, 0)
	binary.BigEndian.PutUint32(login[:4], uint32(len(login)))
	if err := writeTDSPacket(c, 0x10, login); err != nil {
		t.Fatal(err)
	}

	ev := recvCred(t, credCh)
	if ev.Proto != "mssql" || ev.Username != "sa" {
		t.Fatalf("凭据事件 = %+v", ev)
	}
	if !strings.Contains(ev.Password, "01a402a3") {
		t.Fatalf("TDS 密码字段 hex = %q", ev.Password)
	}
	if !strings.Contains(ev.Extra, "TDS") {
		t.Fatalf("extra 应注明 TDS: %q", ev.Extra)
	}
	// ERROR 18456 响应。token 布局：0xAA(1) + length(2) + number(4) + state(1) + class(1) + msg。
	pkt, err = readTDSPacket(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkt) < 2 || pkt[0] != 0x04 || pkt[1] != 0xAA {
		t.Fatalf("错误响应异常: type=%v token=%v", pkt[0], pkt[1])
	}
	if binary.BigEndian.Uint32(pkt[4:8]) != 18456 {
		t.Fatalf("错误码 = %d, 期望 18456", binary.BigEndian.Uint32(pkt[4:8]))
	}
}

// TestSMB2Capture smb2 Negotiate + Session Setup（NTLMSSP AUTH）：Domain\User + NTLMv2 hash。
func TestSMB2Capture(t *testing.T) {
	credCh := make(chan event.CredEvent, 16)
	_, addrs := startTestServer(t, []string{"smb"}, credCh, nil)
	c := dialProto(t, addrs, "smb")

	// 1. Negotiate 请求：64 头 + 36 固定 + dialects。
	neg := make([]byte, 0, 64+36+4)
	neg = append(neg, []byte("\xfeSMB")...)
	neg = append(neg, 64, 0) // StructureSize
	neg = append(neg, 0, 0)  // CreditCharge
	neg = append(neg, 0, 0, 0, 0) // Status
	neg = append(neg, 0x00, 0x00) // Command = NEGOTIATE
	neg = append(neg, 1, 0)       // Credit
	neg = append(neg, 0, 0, 0, 0) // Flags
	neg = append(neg, 0, 0, 0, 0) // NextCommand
	neg = append(neg, 1, 0, 0, 0, 0, 0, 0, 0) // MessageId = 1
	neg = append(neg, 0, 0, 0, 0, 0, 0, 0, 0) // Reserved + TreeId
	neg = append(neg, 0, 0, 0, 0, 0, 0, 0, 0) // SessionId
	neg = append(neg, make([]byte, 16)...)     // Signature
	// 36 固定：StructureSize(2)=36 + DialectCount(2) + SecurityMode(2) + Reserved(2) +
	// Capabilities(4) + ClientGuid(16) + SecurityMode(4 空) + Dialects[...]
	neg = append(neg, 36, 0)      // StructureSize
	neg = append(neg, 1, 0)       // DialectCount
	neg = append(neg, 1, 0)       // SecurityMode
	neg = append(neg, 0, 0)       // Reserved
	neg = append(neg, 0, 0, 0, 0) // Capabilities
	neg = append(neg, make([]byte, 16)...) // ClientGuid
	neg = append(neg, 0x10, 0x02) // Dialect SMB 2.1
	if _, err := c.Write(neg); err != nil {
		t.Fatal(err)
	}
	// 读 Negotiate Response（验证含 NTLMSSP CHALLENGE）。
	var rpid [4]byte
	if _, err := io.ReadFull(c, rpid[:]); err != nil {
		t.Fatal(err)
	}
	if string(rpid[:]) != "\xfeSMB" {
		t.Fatalf("响应 ProtocolId = %q", rpid[:])
	}
	rhdr := make([]byte, 60)
	if _, err := io.ReadFull(c, rhdr); err != nil {
		t.Fatal(err)
	}
	rbody := make([]byte, 62+56) // 响应体（62 SMB 2.1 结构 + 56 NTLMSSP CHALLENGE）
	if _, err := io.ReadFull(c, rbody); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rbody), "NTLMSSP") {
		t.Fatal("Negotiate Response 缺 NTLMSSP CHALLENGE")
	}
	// H-03 回归断言：ServerGuid 为中性 16 字节（不得含 SENTRY/HONEYPOT 标识）。
	// SMB2_NEGOTIATE_RESPONSE 布局：StructureSize(2)+SecurityMode(2)+
	// DialectRevision(2)+Reserved(2) → ServerGuid(16) @8-24。
	if got := string(rbody[8:24]); got != "1234567890ABCDEF" {
		t.Fatalf("ServerGuid = %q, 期望 1234567890ABCDEF（H-03：中性值）", got)
	}

	// 2. Session Setup + NTLMSSP AUTH。
	auth := buildNTLMSSPAuth("attacker", "WORKGROUP")
	ss := make([]byte, 0, 64+24+len(auth))
	ss = append(ss, []byte("\xfeSMB")...)
	ss = append(ss, 64, 0)
	ss = append(ss, 0, 0)
	ss = append(ss, 0, 0, 0, 0) // Status
	ss = append(ss, 0x01, 0x00) // Command = SESSION_SETUP
	ss = append(ss, 1, 0)
	ss = append(ss, 0, 0, 0, 0) // Flags
	ss = append(ss, 0, 0, 0, 0) // NextCommand
	ss = append(ss, 2, 0, 0, 0, 0, 0, 0, 0) // MessageId = 2
	ss = append(ss, 0, 0, 0, 0)             // Reserved
	ss = append(ss, 0, 0, 0, 0)             // TreeId
	ss = append(ss, 0, 0, 0, 0, 0, 0, 0, 0) // SessionId
	ss = append(ss, make([]byte, 16)...)    // Signature
	// SESSION_SETUP 请求体：StructureSize(2)=25 + Flags(1) + SecurityMode(1) +
	// Capabilities(4) + Channel(4) + SecBufOff(2) + SecBufLen(2) + PrevSessionId(8) + Buffer。
	ss = append(ss, 25, 0) // StructureSize
	ss = append(ss, 0)     // Flags
	ss = append(ss, 1)     // SecurityMode
	ss = append(ss, 0, 0, 0, 0) // Capabilities
	ss = append(ss, 0, 0, 0, 0) // Channel
	var sbo [2]byte
	binary.LittleEndian.PutUint16(sbo[:], uint16(64+24))
	ss = append(ss, sbo[:]...)
	var sbl [2]byte
	binary.LittleEndian.PutUint16(sbl[:], uint16(len(auth)))
	ss = append(ss, sbl[:]...)
	ss = append(ss, 0, 0, 0, 0, 0, 0, 0, 0) // PreviousSessionId
	ss = append(ss, auth...)
	if _, err := c.Write(ss); err != nil {
		t.Fatal(err)
	}

	ev := recvCred(t, credCh)
	if ev.Proto != "smb" || ev.Username != "WORKGROUP\\attacker" {
		t.Fatalf("凭据事件 = %+v", ev)
	}
	if !strings.Contains(ev.Extra, "NTLMv2") {
		t.Fatalf("extra 应注明 NTLMv2: %q", ev.Extra)
	}
	if ev.Password == "" {
		t.Fatal("NtChallengeResponse hash 不应为空")
	}
	// 读 STATUS_LOGON_FAILURE 响应。
	var shdr [8]byte
	if _, err := io.ReadFull(c, shdr[:]); err != nil {
		t.Fatal(err)
	}
	if string(shdr[:4]) != "\xfeSMB" {
		t.Fatalf("响应 ProtocolId = %q", shdr[:4])
	}
	rest := make([]byte, 60)
	if _, err := io.ReadFull(c, rest); err != nil {
		t.Fatal(err)
	}
	status := binary.LittleEndian.Uint32(rest[0:4])
	if status != 0xC000006D {
		t.Fatalf("Status = 0x%08X, 期望 STATUS_LOGON_FAILURE", status)
	}
}

// TestSMB2CaptureEmoji DEV-ARCH-002 A3：UTF-16 代理对（非 BMP 字符）正确解码。
// 旧实现 utf16leToString 按 code unit 直映（rune(u16)），emoji 等非 BMP 字符失真；
// 改用 unicode/utf16.Decode 后代理对正确合并为单个 rune。
func TestSMB2CaptureEmoji(t *testing.T) {
	credCh := make(chan event.CredEvent, 16)
	_, addrs := startTestServer(t, []string{"smb"}, credCh, nil)
	c := dialProto(t, addrs, "smb")
	defer c.Close()

	// 1. Negotiate 请求 → 读 Negotiate Response（64 头 + 62 体 + 56 NTLMSSP CHALLENGE）。
	if _, err := c.Write(buildSMB2NegotiateFrame()); err != nil {
		t.Fatal(err)
	}
	rbuf := make([]byte, 64+62+56)
	if _, err := io.ReadFull(c, rbuf); err != nil {
		t.Fatal(err)
	}

	// 2. Session Setup + NTLMSSP AUTH（用户名含 emoji 代理对 U+1F600）。
	auth := buildNTLMSSPAuth("😀attacker", "WORKGROUP")
	if _, err := c.Write(buildSMB2SessionSetupFrame(auth)); err != nil {
		t.Fatal(err)
	}

	ev := recvCred(t, credCh)
	want := "WORKGROUP\\😀attacker"
	if ev.Username != want {
		t.Fatalf("用户名解码 = %q, 期望 %q（代理对应正确合并为单个 rune）", ev.Username, want)
	}
}

// TestRDPCapture rdp Connection Request（cookie）→ Connection Confirm → 诚实降级记录。
func TestRDPCapture(t *testing.T) {
	credCh := make(chan event.CredEvent, 16)
	_, addrs := startTestServer(t, []string{"rdp"}, credCh, nil)
	c := dialProto(t, addrs, "rdp")

	// X.224 Connection Request（TPKT + CR + cookie）。
	cookie := []byte("Cookie: mstshash=admin\r\n")
	cr := make([]byte, 0, 11+len(cookie))
	cr = append(cr, 0x0E, 0xE0)       // LI + PDU type (CR)
	cr = append(cr, 0, 0, 0, 0)       // dst-ref + src-ref
	cr = append(cr, 0x00)             // class
	cr = append(cr, cookie...)        // variable part（cookie）
	var tmp [2]byte
	tpkt := make([]byte, 0, 4+len(cr))
	tpkt = append(tpkt, 3, 0)
	binary.BigEndian.PutUint16(tmp[:], uint16(4+len(cr)))
	tpkt = append(tpkt, tmp[:]...)
	tpkt = append(tpkt, cr...)
	if _, err := c.Write(tpkt); err != nil {
		t.Fatal(err)
	}

	ev := recvCred(t, credCh)
	if ev.Proto != "rdp" {
		t.Fatalf("凭据事件 = %+v", ev)
	}
	if !strings.Contains(ev.Extra, "无法捕获") {
		t.Fatalf("extra 应注明限制: %q", ev.Extra)
	}
	if !strings.Contains(ev.Extra, "admin") {
		t.Fatalf("extra 应含 cookie: %q", ev.Extra)
	}
	// Connection Confirm（TPKT + X.224 CC：LI=6 + 0xD0，R-12 整改后结构）。
	var cc [4]byte
	if _, err := io.ReadFull(c, cc[:]); err != nil {
		t.Fatal(err)
	}
	if cc[0] != 3 || cc[3] < 7 {
		t.Fatalf("CC 头异常: % x", cc)
	}
	ccBody := make([]byte, int(cc[3])-4)
	if _, err := io.ReadFull(c, ccBody); err != nil {
		t.Fatal(err)
	}
	if ccBody[0] != 0x06 {
		t.Fatalf("期望 X.224 LI=6, got 0x%02X", ccBody[0])
	}
	if ccBody[1] != 0xD0 {
		t.Fatalf("期望 X.224 CC (0xD0), got 0x%02X", ccBody[1])
	}
	// dst-ref 应回显客户端 src-ref（测试构造为 0）。
	if ccBody[2] != 0 || ccBody[3] != 0 {
		t.Fatalf("dst-ref 回显异常: % x", ccBody[2:4])
	}
}

// TestMemcachedCapture memcached 无认证：命令概览记录 + 最小响应。
func TestMemcachedCapture(t *testing.T) {
	credCh := make(chan event.CredEvent, 16)
	_, addrs := startTestServer(t, []string{"memcached"}, credCh, nil)
	c := dialProto(t, addrs, "memcached")
	br := bufio.NewReader(c)
	_, _ = c.Write([]byte("get flag\r\n"))
	if s, err := br.ReadString('\n'); err != nil || s != "ERROR\r\n" {
		t.Fatalf("响应 = %q err=%v", s, err)
	}
	ev := recvCred(t, credCh)
	if ev.Proto != "memcached" {
		t.Fatalf("凭据事件 = %+v", ev)
	}
	if !strings.Contains(ev.Extra, "无认证") || !strings.Contains(ev.Extra, "get") {
		t.Fatalf("extra 应含无认证与命令: %q", ev.Extra)
	}
	if ev.Username != "" || ev.Password != "" {
		t.Fatalf("memcached 不应有凭据字段: %+v", ev)
	}
}

// ---- BSON 构造工具（测试用） ----

func bsonElemInt32(name string, v int32) []byte {
	var b []byte
	b = append(b, 0x10)
	b = append(b, []byte(name)...)
	b = append(b, 0)
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], uint32(v))
	b = append(b, tmp[:]...)
	return b
}

func bsonElemString(name, val string) []byte {
	var b []byte
	b = append(b, 0x02)
	b = append(b, []byte(name)...)
	b = append(b, 0)
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], uint32(len(val)+1))
	b = append(b, tmp[:]...)
	b = append(b, []byte(val)...)
	b = append(b, 0)
	return b
}

func bsonElemBinary(name string, doc []byte) []byte {
	var b []byte
	b = append(b, 0x05)
	b = append(b, []byte(name)...)
	b = append(b, 0)
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], uint32(len(doc)))
	b = append(b, tmp[:]...)
	b = append(b, 0) // subtype 0 = generic binary
	b = append(b, doc...)
	return b
}

func bsonElemEmptyDoc(name string) []byte {
	var b []byte
	b = append(b, 0x03)
	b = append(b, []byte(name)...)
	b = append(b, 0)
	b = append(b, 5, 0, 0, 0, 0) // { }
	return b
}

func buildBSONDoc(elems ...[]byte) []byte {
	total := 4 + 1
	for _, e := range elems {
		total += len(e)
	}
	var b []byte
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], uint32(total))
	b = append(b, tmp[:]...)
	for _, e := range elems {
		b = append(b, e...)
	}
	b = append(b, 0)
	return b
}

// buildNTLMSSPAuth 构造 NTLMSSP AUTH 消息（type 3，UTF-16LE 字段 + 伪 NTLMv2 Response）。
func buildNTLMSSPAuth(user, domain string) []byte {
	// DEV-ARCH-002 A3：utf16.Encode 正确编码代理对（与 utf16leToString 解码对称；
	// 旧实现 uint16(r) 直映对非 BMP 字符失真）。
	u16 := func(s string) []byte {
		var b []byte
		for _, u := range utf16.Encode([]rune(s)) {
			var tmp [2]byte
			binary.LittleEndian.PutUint16(tmp[:], u)
			b = append(b, tmp[:]...)
		}
		return b
	}
	userB := u16(user)
	domainB := u16(domain)
	ntResp := make([]byte, 32) // 伪 NTLMv2 Response（16 NTProofStr + 16 hash）
	for i := range ntResp {
		ntResp[i] = byte(i)
	}
	// 字段数据区偏移：AUTH 头 = Signature(8) + MessageType(4) + 6 字段表(48) +
	// NegotiateFlags(4) + Version(8) + MIC(16) = 88 字节。
	lmOff := 88
	ntOff := lmOff
	domOff := ntOff + len(ntResp)
	userOff := domOff + len(domainB)
	wkOff := userOff + len(userB)
	// 头部（无 Workstation/Key 数据，offset 指向末尾）。
	b := make([]byte, 0, 88+len(ntResp)+len(domainB)+len(userB))
	b = append(b, []byte("NTLMSSP\x00")...)
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], 3)
	b = append(b, tmp[:]...)
	field := func(off, ln int) {
		var f [8]byte
		binary.LittleEndian.PutUint16(f[:2], uint16(ln))
		binary.LittleEndian.PutUint16(f[2:4], uint16(ln))
		binary.LittleEndian.PutUint32(f[4:8], uint32(off))
		b = append(b, f[:]...)
	}
	field(lmOff, 0)           // LmChallengeResponse
	field(ntOff, len(ntResp)) // NtChallengeResponse
	field(domOff, len(domainB))
	field(userOff, len(userB))
	field(wkOff, 0) // Workstation
	field(wkOff, 0) // EncryptedRandomSessionKey
	binary.LittleEndian.PutUint32(tmp[:], 0x00088201)
	b = append(b, tmp[:]...)          // NegotiateFlags
	b = append(b, 6, 1, 0, 0, 0, 0, 0, 0) // Version
	b = append(b, make([]byte, 16)...)    // MIC
	b = append(b, ntResp...)
	b = append(b, domainB...)
	b = append(b, userB...)
	return b
}

// TestMySQLStrictParse 严格解析 HandshakeV10 布局（R-01 公式核对）：
// 按结构字段顺序推进（version 变长），验证 auth_plugin_data_len 公式、
// 20 字节 salt、插件名、caps 无 SSL 位。
func TestMySQLStrictParse(t *testing.T) {
	credCh := make(chan event.CredEvent, 16)
	_, addrs := startTestServer(t, []string{"mysql"}, credCh, nil)
	c := dialProto(t, addrs, "mysql")
	defer c.Close()

	var ghdr [4]byte
	if _, err := io.ReadFull(c, ghdr[:]); err != nil {
		t.Fatal(err)
	}
	gLen := int(binary.LittleEndian.Uint32(append(ghdr[:3], 0)))
	greeting := make([]byte, gLen)
	if _, err := io.ReadFull(c, greeting); err != nil {
		t.Fatal(err)
	}
	if greeting[0] != 10 {
		t.Fatalf("protocol version = %d, 期望 10", greeting[0])
	}
	// 按结构顺序推进：version(NUL) → connection_id(4) → part1(8) → filler(1)
	// → caps_lower(2) → charset(1) → status(2) → caps_upper(2) → data_len(1)
	// → reserved(10) → part2 → plugin_name(NUL)。
	pos := 1
	vEnd := bytes.IndexByte(greeting[pos:], 0)
	if vEnd < 0 {
		t.Fatal("server version 缺 NUL 终止")
	}
	// H-03 回归断言：version 为中性 "8.0.35"（不得含 honeypot/sentry 蜜罐标识）。
	if got := string(greeting[pos : pos+vEnd]); got != "8.0.35" {
		t.Fatalf("server version = %q, 期望 8.0.35（H-03：去蜜罐标识）", got)
	}
	pos += vEnd + 1 // 跳过 version（含 NUL）
	if pos+4+8+1+2+1+2+2+1+10 > len(greeting) {
		t.Fatalf("greeting 过短（%d 字节）", len(greeting))
	}
	pos += 4                                     // connection_id
	part1 := greeting[pos : pos+8]               // auth-plugin-data-part1
	// H-03 回归断言：salt 为中性 20 字节（part1 "FixedSrv"，不得含蜜罐标识）。
	if got := string(part1); got != "FixedSrv" {
		t.Fatalf("auth-plugin-data-part1 = %q, 期望 FixedSrv（H-03：中性 salt）", got)
	}
	pos += 8 + 1                                 // part1 + filler
	capsLower := binary.LittleEndian.Uint16(greeting[pos : pos+2])
	pos += 2 + 1 + 2                             // caps_lower + charset + status
	capsUpper := binary.LittleEndian.Uint16(greeting[pos : pos+2])
	pos += 2
	caps := uint32(capsLower) | uint32(capsUpper)<<16
	if caps&0x0800 != 0 {
		t.Fatalf("caps 含 CLIENT_SSL(0x0800): 0x%08X（置位会诱导客户端先发 SSLRequest）", caps)
	}
	if caps&0x0200 == 0 {
		t.Fatalf("caps 缺 CLIENT_PROTOCOL_41(0x0200): 0x%08X", caps)
	}
	// auth_plugin_data_len：20 salt + 1 NUL；part2 长度公式 = max(13, len-8)-1。
	dataLen := int(greeting[pos])
	pos++ // data_len
	if dataLen != 21 {
		t.Fatalf("auth_plugin_data_len = %d, 期望 21", dataLen)
	}
	pos += 10 // reserved
	part2Len := dataLen - len(part1) - 1
	if part2Len != 12 {
		t.Fatalf("part2 长度 = %d, 期望 12（公式 max(13, len-8)-1）", part2Len)
	}
	part2 := greeting[pos : pos+part2Len]
	salt := make([]byte, 0, 20)
	salt = append(salt, part1...)
	salt = append(salt, part2...)
	if len(salt) != 20 {
		t.Fatalf("salt 长度 = %d, 期望 20", len(salt))
	}
	// 插件名：part2 后 NUL 终止。
	nameStart := pos + part2Len + 1
	nameEnd := bytes.IndexByte(greeting[nameStart:], 0)
	if nameEnd < 0 {
		t.Fatal("greeting 缺插件名 NUL 终止")
	}
	if got := string(greeting[nameStart : nameStart+nameEnd]); got != "mysql_native_password" {
		t.Fatalf("auth 插件名 = %q, 期望 mysql_native_password", got)
	}
}

// TestMSSQLPreloginOffsets 校验 Prelogin Response 选项表布局（R-03 reviewer 整改）：
// 选项表 15 字节 + 1 字节对齐 = 16，数据区从偏移 16 起；ENCRYPTION 值 0x00（OFF）。
func TestMSSQLPreloginOffsets(t *testing.T) {
	resp := buildPreloginResponse()
	// 总长：16（选项表+pad）+ 8（VERSION）+ 1（ENCRYPTION）+ 尾部对齐 3 = 28。
	if len(resp) != 28 {
		t.Fatalf("Prelogin Response 长度 = %d, 期望 28", len(resp))
	}
	// VERSION 项：token 0x00 @0 + offset @1 + length @3。
	if resp[0] != 0x00 {
		t.Fatalf("VERSION token = 0x%02X", resp[0])
	}
	if off := binary.BigEndian.Uint16(resp[1:3]); off != 16 {
		t.Fatalf("VERSION 数据偏移 = %d, 期望 16（选项表 15+1 后）", off)
	}
	if ln := binary.BigEndian.Uint16(resp[3:5]); ln != 8 {
		t.Fatalf("VERSION 数据长度 = %d, 期望 8", ln)
	}
	// ENCRYPTION 项：token 0x01 @5 + offset @6 + length @8。
	if resp[5] != 0x01 {
		t.Fatalf("ENCRYPTION token = 0x%02X", resp[5])
	}
	if off := binary.BigEndian.Uint16(resp[6:8]); off != 24 {
		t.Fatalf("ENCRYPTION 数据偏移 = %d, 期望 24", off)
	}
	if ln := binary.BigEndian.Uint16(resp[8:10]); ln != 1 {
		t.Fatalf("ENCRYPTION 数据长度 = %d, 期望 1", ln)
	}
	// 终止项 @10（5 字节全 0）+ pad @15。
	for i := 10; i < 16; i++ {
		if resp[i] != 0 {
			t.Fatalf("选项表终止/对齐区 @%d = 0x%02X, 期望 0", i, resp[i])
		}
	}
	// 数据区：VERSION 8 字节（TDS 7.4 伪版本）@16；ENCRYPTION @24 = 0x00（OFF）。
	if resp[16] != 0x07 || resp[17] != 0x04 {
		t.Fatalf("VERSION 数据异常: % x", resp[16:24])
	}
	if resp[24] != 0x00 {
		t.Fatalf("ENCRYPTION 值 = 0x%02X, 期望 0x00（OFF，诱导客户端走明文后续流程）", resp[24])
	}
}

// TestSMB2FragmentedFrames R-10 场景：SMB2 帧 TCP 分片发送（NEGOTIATE 分 3 段、
// SESSION_SETUP 分 2 段），验证蜜罐按结构长度字段完整读取并捕获凭据。
func TestSMB2FragmentedFrames(t *testing.T) {
	credCh := make(chan event.CredEvent, 16)
	_, addrs := startTestServer(t, []string{"smb"}, credCh, nil)
	c := dialProto(t, addrs, "smb")

	// 1. Negotiate 帧分 3 段发送。
	neg := buildSMB2NegotiateFrame()
	for _, seg := range splitSegments(neg, 3) {
		if _, err := c.Write(seg); err != nil {
			t.Fatal(err)
		}
	}
	// 读 Negotiate Response（验证含 NTLMSSP CHALLENGE）。
	var rpid [4]byte
	if _, err := io.ReadFull(c, rpid[:]); err != nil {
		t.Fatal(err)
	}
	if string(rpid[:]) != "\xfeSMB" {
		t.Fatalf("响应 ProtocolId = %q", rpid[:])
	}
	rhdr := make([]byte, 60)
	if _, err := io.ReadFull(c, rhdr); err != nil {
		t.Fatal(err)
	}
	rbody := make([]byte, 62+56) // 响应体（62 SMB 2.1 结构 + 56 NTLMSSP CHALLENGE）
	if _, err := io.ReadFull(c, rbody); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rbody), "NTLMSSP") {
		t.Fatal("Negotiate Response 缺 NTLMSSP CHALLENGE")
	}

	// 2. Session Setup 帧分 2 段发送。
	auth := buildNTLMSSPAuth("attacker", "WORKGROUP")
	ss := buildSMB2SessionSetupFrame(auth)
	for _, seg := range splitSegments(ss, 2) {
		if _, err := c.Write(seg); err != nil {
			t.Fatal(err)
		}
	}
	ev := recvCred(t, credCh)
	if ev.Proto != "smb" || ev.Username != "WORKGROUP\\attacker" {
		t.Fatalf("凭据事件 = %+v", ev)
	}
	if !strings.Contains(ev.Extra, "NTLMv2") {
		t.Fatalf("extra 应注明 NTLMv2: %q", ev.Extra)
	}
	// 读 STATUS_LOGON_FAILURE 响应。
	var shdr [8]byte
	if _, err := io.ReadFull(c, shdr[:]); err != nil {
		t.Fatal(err)
	}
	if string(shdr[:4]) != "\xfeSMB" {
		t.Fatalf("响应 ProtocolId = %q", shdr[:4])
	}
	rest := make([]byte, 60)
	if _, err := io.ReadFull(c, rest); err != nil {
		t.Fatal(err)
	}
	if status := binary.LittleEndian.Uint32(rest[0:4]); status != 0xC000006D {
		t.Fatalf("Status = 0x%08X, 期望 STATUS_LOGON_FAILURE", status)
	}
}

// buildSMB2NegotiateFrame 构造 SMB2 Negotiate 请求帧（SMB 2.1，单 dialect）。
func buildSMB2NegotiateFrame() []byte {
	neg := make([]byte, 0, 64+30)
	neg = append(neg, []byte("\xfeSMB")...)
	neg = append(neg, 64, 0) // StructureSize
	neg = append(neg, 0, 0)  // CreditCharge
	neg = append(neg, 0, 0, 0, 0) // Status
	neg = append(neg, 0x00, 0x00) // Command = NEGOTIATE
	neg = append(neg, 1, 0)       // Credit
	neg = append(neg, 0, 0, 0, 0) // Flags
	neg = append(neg, 0, 0, 0, 0) // NextCommand
	neg = append(neg, 1, 0, 0, 0, 0, 0, 0, 0) // MessageId = 1
	neg = append(neg, 0, 0, 0, 0, 0, 0, 0, 0) // Reserved + TreeId
	neg = append(neg, 0, 0, 0, 0, 0, 0, 0, 0) // SessionId
	neg = append(neg, make([]byte, 16)...)     // Signature
	neg = append(neg, 36, 0)      // StructureSize（声明值，固定实际 28）
	neg = append(neg, 1, 0)       // DialectCount
	neg = append(neg, 1, 0)       // SecurityMode
	neg = append(neg, 0, 0)       // Reserved
	neg = append(neg, 0, 0, 0, 0) // Capabilities
	neg = append(neg, make([]byte, 16)...) // ClientGuid
	neg = append(neg, 0x10, 0x02) // Dialect SMB 2.1
	return neg
}

// buildSMB2SessionSetupFrame 构造 SMB2 Session Setup 请求帧（含 NTLMSSP AUTH 缓冲）。
func buildSMB2SessionSetupFrame(auth []byte) []byte {
	ss := make([]byte, 0, 64+24+len(auth))
	ss = append(ss, []byte("\xfeSMB")...)
	ss = append(ss, 64, 0) // StructureSize
	ss = append(ss, 0, 0)  // CreditCharge
	ss = append(ss, 0, 0, 0, 0) // Status
	ss = append(ss, 0x01, 0x00) // Command = SESSION_SETUP
	ss = append(ss, 1, 0)       // Credit
	ss = append(ss, 0, 0, 0, 0) // Flags
	ss = append(ss, 0, 0, 0, 0) // NextCommand
	ss = append(ss, 2, 0, 0, 0, 0, 0, 0, 0) // MessageId = 2
	ss = append(ss, 0, 0, 0, 0)             // Reserved
	ss = append(ss, 0, 0, 0, 0)             // TreeId
	ss = append(ss, 0, 0, 0, 0, 0, 0, 0, 0) // SessionId
	ss = append(ss, make([]byte, 16)...)    // Signature
	ss = append(ss, 25, 0) // StructureSize（声明值，固定实际 24）
	ss = append(ss, 0)     // Flags
	ss = append(ss, 1)     // SecurityMode
	ss = append(ss, 0, 0, 0, 0) // Capabilities
	ss = append(ss, 0, 0, 0, 0) // Channel
	var sbo [2]byte
	binary.LittleEndian.PutUint16(sbo[:], uint16(64+24))
	ss = append(ss, sbo[:]...)
	var sbl [2]byte
	binary.LittleEndian.PutUint16(sbl[:], uint16(len(auth)))
	ss = append(ss, sbl[:]...)
	ss = append(ss, 0, 0, 0, 0, 0, 0, 0, 0) // PreviousSessionId
	ss = append(ss, auth...)
	return ss
}

// splitSegments 将数据切分为 n 段（前 n-1 段等长，末段含余量）——模拟 TCP 分片。
func splitSegments(b []byte, n int) [][]byte {
	if n <= 1 {
		return [][]byte{b}
	}
	chunk := (len(b) + n - 1) / n
	var out [][]byte
	for len(b) > 0 {
		if len(b) <= chunk {
			out = append(out, b)
			break
		}
		out = append(out, b[:chunk])
		b = b[chunk:]
	}
	return out
}

// TestMSSQLUserNameClamp H-04（audit Minor）：超长 UserName 时 ERROR 响应
// 用户名钳制 256 字节——token length 字段（uint16）不得回绕（畸形响应）。
func TestMSSQLUserNameClamp(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	longUser := strings.Repeat("u", 3000) // 3KB 超长用户名
	go func() {
		_ = writeTDSLoginFailed(c1, longUser)
		_ = c1.Close()
	}()
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(c2, hdr); err != nil {
		t.Fatal(err)
	}
	plen := int(binary.BigEndian.Uint16(hdr[2:4]))
	if plen < 8 {
		t.Fatalf("TDS 包长异常: %d", plen)
	}
	payload := make([]byte, plen-8)
	if _, err := io.ReadFull(c2, payload); err != nil {
		t.Fatal(err)
	}
	// token 布局：0xAA(1) + length(2) + number(4) + state(1) + class(1) + msg。
	if payload[0] != 0xAA {
		t.Fatalf("token = 0x%02X", payload[0])
	}
	bodyLen := int(binary.BigEndian.Uint16(payload[1:3]))
	if bodyLen <= 0 || bodyLen > len(payload)-3 {
		t.Fatalf("token length 回绕/越界: %d（payload 剩余 %d）", bodyLen, len(payload)-3)
	}
	msg := payload[3+4+1+1 : 3+bodyLen]
	if len(msg) > 4096 {
		t.Fatalf("错误消息过长: %d", len(msg))
	}
	// 消息内含钳制后的用户名（256 字节）而非完整 3000 字节。
	if !strings.Contains(string(msg), strings.Repeat("u", 256)) {
		t.Fatal("响应消息未按 256 字节钳制用户名")
	}
	if strings.Contains(string(msg), strings.Repeat("u", 3000)) {
		t.Fatal("响应消息含完整超长用户名")
	}
}
