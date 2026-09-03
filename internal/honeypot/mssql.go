package honeypot

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"unicode/utf16"

	"sentry-agent/internal/event"
)

// handleMSSQL SQL Server 登录握手模拟（TDS 7.x，
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/）。
// 流程：Prelogin（0x12）→ 回 Prelogin Response → LOGIN7（0x10）→
// 解析 UserName（明文）+ Password（TDS 混淆字段：UTF-16LE 明文每字节半字节交换后
// XOR 0xA5——可逆混淆非加密）→ 还原明文记录（还原失败回退 hex 摘要）→ 回 ERROR 18456 拒绝。
// TDS 包格式：type(1) + status(1) + length(2) + SPID(2) + packetID(1) + window(1) + 数据。
func handleMSSQL(ctx context.Context, conn net.Conn, srcIP uint32, rec func(event.CredEvent)) {
	for {
		pkt, err := readTDSPacket(conn)
		if err != nil {
			return
		}
		if len(pkt) < 1 {
			continue
		}
		switch pkt[0] {
		case 0x12: // Prelogin：回标准 Prelogin Response（版本 + 加密选项）
			// 选项解析：选项表（offset(2) + length(2) 对，以 offset=0 结束）；
			// 蜜罐仅需回最小 Prelogin Response（VERSION + ENCRYPTION=0x01 OFF）。
			resp := buildPreloginResponse()
			if err := writeTDSPacket(conn, 0x04, resp); err != nil {
				return
			}
		case 0x10: // LOGIN7
			user, obf, ok := parseLogin7(pkt[1:])
			if !ok {
				continue
			}
			// 凭据记录：username 明文 + password 还原（TDS 混淆可逆——见 deobfuscateTDSPassword）。
			// 还原成功记明文（字典可直接使用）；失败（畸形/非可打印，非标准客户端）回退 hex 摘要。
			if pass, deobfOK := deobfuscateTDSPassword(obf); deobfOK {
				rec(event.CredEvent{
					Username: user,
					Password: pass,
					Extra:    "TDS 混淆密码已还原明文（nibble-swap + XOR 0xA5 可逆混淆）",
				})
			} else {
				rec(event.CredEvent{
					Username: user,
					Password: hex.EncodeToString(obf),
					Extra:    "TDS 混淆密码还原失败（非可打印/畸形），记录 hex 摘要",
				})
			}
			// ERROR 18456（登录失败）。
			if err := writeTDSLoginFailed(conn, user); err != nil {
				return
			}
			return
		case 0x02: // Attention/取消：结束。
			return
		default:
			// 其他包类型（RPC/批量等）：不解析，继续等待（超时兜底）。
		}
	}
}

// readTDSPacket 读取单个 TDS 包（含 8 字节头），返回 payload。
// 多包消息（status 0x01 表示还有后续包）由调用方决定——LOGIN7 单包场景足够。
func readTDSPacket(conn net.Conn) ([]byte, error) {
	var hdr [8]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(hdr[2:4]))
	if length < 8 || length > 65536 {
		return nil, nil // 畸形长度（防御）
	}
	payload := make([]byte, length-8)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}
	// 返回 type 前缀（调用方按 pkt[0] 分支）。
	out := make([]byte, 0, 1+len(payload))
	out = append(out, hdr[0])
	out = append(out, payload...)
	return out, nil
}

// writeTDSPacket 写 TDS 包（type + status + length + SPID + packetID + window + payload）。
func writeTDSPacket(conn net.Conn, pktType byte, payload []byte) error {
	buf := make([]byte, 0, 8+len(payload))
	buf = append(buf, pktType)
	buf = append(buf, 0x01) // status: EOM（单包）
	var tmp [2]byte
	binary.BigEndian.PutUint16(tmp[:], uint16(8+len(payload)))
	buf = append(buf, tmp[:]...)
	buf = append(buf, 0, 0) // SPID
	buf = append(buf, 0x01) // packetID
	buf = append(buf, 0x00) // window
	buf = append(buf, payload...)
	_, err := conn.Write(buf)
	return err
}

// buildPreloginResponse 构造最小 Prelogin Response（MS-TDS 2.2.1.1）。
// 选项表（token + offset + length 三元组，offset 从消息起始计算）：
//
//	VERSION（token 0x00，8 字节伪 TDS 版本）
//	ENCRYPTION（token 0x01，1 字节 = 0x00 OFF——诱导客户端走明文后续流程）
//
// 选项表 15 字节（5+5+5）+ 1 字节对齐 pad = 16 字节，数据区从偏移 16 开始。
func buildPreloginResponse() []byte {
	const verOff = 16
	resp := make([]byte, 0, 32)
	// 选项表：VERSION 项（5 字节：token + offset(2) + length(2)）。
	resp = append(resp, 0x00) // token
	var off [2]byte
	binary.BigEndian.PutUint16(off[:], verOff)
	resp = append(resp, off[:]...)
	resp = append(resp, 0x00, 0x08) // length 8
	// ENCRYPTION 项。
	resp = append(resp, 0x01) // token
	binary.BigEndian.PutUint16(off[:], verOff+8)
	resp = append(resp, off[:]...)
	resp = append(resp, 0x00, 0x01) // length 1
	// 终止项（token 0 + offset 0 + length 0，5 字节）。
	resp = append(resp, 0x00, 0x00, 0x00, 0x00, 0x00)
	// 对齐填充到 16 字节（1 字节 pad）。
	resp = append(resp, 0x00)
	// 数据区：VERSION 8 字节（TDS 7.4 伪版本）。
	resp = append(resp, 0x07, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	// ENCRYPTION 1 字节（MS-TDS 2.2.1.1：0x00=OFF，诱导明文后续流程）。
	resp = append(resp, 0x00)
	// 尾部对齐到双字（25 → 28）。
	for len(resp)%4 != 0 {
		resp = append(resp, 0x00)
	}
	return resp
}

// parseLogin7 解析 LOGIN7 消息（MS-TDS 2.2.6.3）。
// 固定头 36 字节 + 变长数据；offset 表从固定头后开始（字段按序：
// HostName UserName Password AppName ServerName ...）。
// 返回 (username, password 混淆字节, 是否解析成功)。
func parseLogin7(data []byte) (string, []byte, bool) {
	if len(data) < 36 {
		return "", nil, false
	}
	// Length(4) TDSVersion(4) PacketSize(4) ClientProgVer(4) ClientPID(4)
	// ConnectionID(4) OptionFlags1-3(3) TypeFlags(1) ClientTimeZone(4) ClientLCID(4)
	// = 36 字节；变长字段 offset 表紧随其后（每字段 4 字节：offset(2)+length(2)）。
	const fixedLen = 36
	// 字段 0=HostName, 1=UserName, 2=Password, 3=AppName, 4=ServerName, ...
	// 至少需要 3 个字段项（Host/User/Pass）才能取到用户名与密码。
	if len(data) < fixedLen+12 {
		return "", nil, false
	}
	user := ""
	var obf []byte
	for i := 0; i < 5; i++ {
		base := fixedLen + i*4
		if base+4 > len(data) {
			break
		}
		off := int(binary.BigEndian.Uint16(data[base : base+2]))
		ln := int(binary.BigEndian.Uint16(data[base+2 : base+4]))
		if ln == 0 || off+ln > len(data) {
			continue
		}
		val := data[off : off+ln]
		switch i {
		case 1: // UserName（UTF-16LE，双字节编码——按规范解码，R-02 reviewer 整改）
			user = utf16leToString(val, 0, ln)
		case 2: // Password（TDS 混淆字节，还原见 deobfuscateTDSPassword）
			obf = make([]byte, ln)
			copy(obf, val)
		}
	}
	if user == "" && obf == nil {
		return "", nil, false
	}
	return user, obf, true
}

// deobfuscateTDSPassword 还原 TDS LOGIN7 密码混淆字段。
// 混淆算法（[MS-TDS] 2.2.6.3）：UTF-16LE 明文 → 每字节半字节交换（高/低 4 位互换）
// → XOR 0xA5。可逆混淆（非加密哈希），与 impacket encryptPassword（impacket/tds.py，
// 0.13.1）交叉验证一致。
// 成功条件：非空、偶数长度（完整 UTF-16 码元）且每个码元均为 ASCII 可打印
// （0x20-0x7E，\t 例外）。ASCII 白名单是保守取舍：垃圾字节还原后常产生高位
// Unicode 乱码码元（缅甸文/楔形文字等，低字节控制位被高字节抬入合法区），
// 非 ASCII 白名单无法稳定区分乱码与真实密码；爆破字典实际构成几乎全为 ASCII，
// 牺牲极罕见的非 ASCII 密码换取字典纯净。不满足则返回 false，调用方回退
// hex 摘要记录（防非标准客户端垃圾数据伪装成"明文"污染字典）。
func deobfuscateTDSPassword(obf []byte) (string, bool) {
	if len(obf) == 0 || len(obf)%2 != 0 {
		return "", false
	}
	raw := make([]byte, len(obf))
	for i, b := range obf {
		// 逆序解混淆：先 XOR 0xA5 再半字节交换（swap 与 XOR 0xA5 不可交换——
		// 0xA5 半字节不对称，顺序反了会得到错误明文；测试向量与 impacket 交叉验证）。
		x := b ^ 0xA5
		raw[i] = (x&0x0F)<<4 | (x&0xF0)>>4
	}
	u := make([]uint16, len(raw)/2)
	for i := 0; i < len(raw); i += 2 {
		code := uint16(raw[i]) | uint16(raw[i+1])<<8
		if (code < 0x20 && code != '\t') || code > 0x7E {
			return "", false
		}
		u[i/2] = code
	}
	return string(utf16.Decode(u)), true
}

// writeTDSLoginFailed 发送 TDS ERROR token（0xAA）消息：错误 18456（登录失败）。
func writeTDSLoginFailed(conn net.Conn, user string) error {
	// H-04（audit Minor）：响应消息内用户名钳制 256 字节——攻击者发送超长
	// UserName 时避免 msg 超 64KB 导致 TDS length 字段 uint16 回绕（畸形响应）。
	if len(user) > 256 {
		user = user[:256]
	}
	// EDB message: 0xAA + length(2) + number(4) + state(1) + class(1) + msgText(VarChar)
	msg := "Login failed for user '" + user + "'. (Microsoft SQL Server, Error: 18456)"
	token := make([]byte, 0, 2+4+1+1+len(msg)+1)
	token = append(token, 0xAA)
	var tmp [2]byte
	binary.BigEndian.PutUint16(tmp[:], uint16(4+1+1+len(msg)+1)) // 后续字节数
	token = append(token, tmp[:]...)
	var num [4]byte
	binary.BigEndian.PutUint32(num[:], 18456)
	token = append(token, num[:]...)
	token = append(token, 1)  // state
	token = append(token, 14) // class（14 = 登录）
	token = append(token, []byte(msg)...)
	token = append(token, 0) // VarChar 终止
	return writeTDSPacket(conn, 0x04, token)
}
