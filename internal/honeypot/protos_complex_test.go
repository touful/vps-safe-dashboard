package honeypot

import (
	"bufio"
	"encoding/binary"
	"strings"
	"testing"

	"sentry-agent/internal/event"
)

// TestMySQLCapture mysql 完整握手：greeting → HandshakeResponse41 → 凭据（hash）+ ERR 1045。
func TestMySQLCapture(t *testing.T) {
	credCh := make(chan event.CredEvent, 16)
	_, addrs := startTestServer(t, []string{"mysql"}, credCh, nil)
	c := dialProto(t, addrs, "mysql")

	// 读 HandshakeV10：4 头（3 字节 len + 1 序号）+ payload（protocol 10 + version NUL + ...）。
	var ghdr [4]byte
	if _, err := readFullN(c, ghdr[:]); err != nil {
		t.Fatal(err)
	}
	gLen := int(binary.LittleEndian.Uint32(append(ghdr[:3], 0)))
	greeting := make([]byte, gLen)
	if _, err := readFullN(c, greeting); err != nil {
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
	if _, err := readFullN(c, ehdr[:]); err != nil {
		t.Fatal(err)
	}
	eLen := int(binary.LittleEndian.Uint32(append(ehdr[:3], 0)))
	ebody := make([]byte, eLen)
	if _, err := readFullN(c, ebody); err != nil {
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
	if _, err := readFullN(c, rhdr[:]); err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(rhdr[12:16]) != 2013 {
		t.Fatalf("响应 opCode = %d, 期望 OP_MSG 2013", binary.LittleEndian.Uint32(rhdr[12:16]))
	}
	rLen := int(binary.LittleEndian.Uint32(rhdr[:4]))
	rbody := make([]byte, rLen-16)
	if _, err := readFullN(c, rbody); err != nil {
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
	host := []byte("PC1")
	user := []byte("sa")
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
	if _, err := readFullN(c, rpid[:]); err != nil {
		t.Fatal(err)
	}
	if string(rpid[:]) != "\xfeSMB" {
		t.Fatalf("响应 ProtocolId = %q", rpid[:])
	}
	rhdr := make([]byte, 60)
	if _, err := readFullN(c, rhdr); err != nil {
		t.Fatal(err)
	}
	rbody := make([]byte, 62+56) // 响应体（62 SMB 2.1 结构 + 56 NTLMSSP CHALLENGE）
	if _, err := readFullN(c, rbody); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rbody), "NTLMSSP") {
		t.Fatal("Negotiate Response 缺 NTLMSSP CHALLENGE")
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
	if _, err := readFullN(c, shdr[:]); err != nil {
		t.Fatal(err)
	}
	if string(shdr[:4]) != "\xfeSMB" {
		t.Fatalf("响应 ProtocolId = %q", shdr[:4])
	}
	rest := make([]byte, 60)
	if _, err := readFullN(c, rest); err != nil {
		t.Fatal(err)
	}
	status := binary.LittleEndian.Uint32(rest[0:4])
	if status != 0xC000006D {
		t.Fatalf("Status = 0x%08X, 期望 STATUS_LOGON_FAILURE", status)
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
	// Connection Confirm（TPKT + 0xD0）。
	var cc [4]byte
	if _, err := readFullN(c, cc[:]); err != nil {
		t.Fatal(err)
	}
	if cc[0] != 3 || cc[3] < 7 {
		t.Fatalf("CC 头异常: % x", cc)
	}
	ccBody := make([]byte, int(cc[3])-4)
	if _, err := readFullN(c, ccBody); err != nil {
		t.Fatal(err)
	}
	if ccBody[0] != 0xD0 {
		t.Fatalf("期望 X.224 CC (0xD0), got 0x%02X", ccBody[0])
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
	u16 := func(s string) []byte {
		var b []byte
		for _, r := range s {
			var tmp [2]byte
			binary.LittleEndian.PutUint16(tmp[:], uint16(r))
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
