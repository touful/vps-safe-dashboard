package honeypot

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"net"

	"sentry-agent/internal/event"
)

// handleMySQL MySQL 认证握手模拟（MySQL 客户端/服务端协议，
// https://dev.mysql.com/doc/dev/mysql-server/latest/PAGE_PROTOCOL.html）。
// 捕获路径：服务端 HandshakeV10（协议版本 10 + 20 字节 salt）→ 客户端
// HandshakeResponse41（用户名明文 + auth-response（密码 hash，不可逆））→
// 记录 username + auth-response hex（Extra 注明不可逆）→ 回 ERR 1045 拒绝。
// 无法捕获明文密码（mysql_native_password 为 SHA1 链不可逆），如实记录。
// 布线要点（R-01 reviewer 整改，对齐协议公式）：
//   - auth-plugin-data 恰 20 字节（part1 8 + part2 12）；
//   - auth_plugin_data_len = 21（20 salt + 1 NUL）；
//   - 能力位不含 CLIENT_SSL（蜜罐无 TLS，置位会诱导客户端先发 SSLRequest）；
//   - 消息序号按握手机制递增（greeting seq=0 → 客户端响应 seq=1 → ERR seq=2）。
func handleMySQL(ctx context.Context, conn net.Conn, srcIP uint32, rec func(event.CredEvent)) {
	// 1. HandshakeV10（报文头 4 字节：len + seq）。
	// 字段布局（PAGE_PROTOCOL）：protocol_version(1) | server_version(NUL) |
	// connection_id(4) | auth_plugin_data_part1(8) | filler(1) | caps_lower(2) |
	// charset(1) | status(2) | caps_upper(2) | auth_plugin_data_len(1) |
	// reserved(10) | auth_plugin_data_part2(max(13, len-8)-1=12) | auth_plugin_name(NUL)
	salt := []byte("FixedSrvSalt00112233") // 恰好 20 字节（part1 "FixedSrv" 8 + part2 "Salt00112233" 12）；
	// H-03：中性伪随机串（原 "sentryH0n3yp0tS4lt12" 含蜜罐标识，攻击者可据 banner 特征规避）
	greeting := []byte{10} // protocol version 10（version 字段紧随其后 NUL 终止）
	version := []byte("8.0.35\x00") // 伪装版本串（H-03：去 "honeypot" 后缀标识；仅诱导客户端继续认证，非真实信息）
	greeting = append(greeting, version...)
	var connID [4]byte
	binary.LittleEndian.PutUint32(connID[:], 0xDEADBEEF) // 固定 connection id（伪装）
	greeting = append(greeting, connID[:]...)
	greeting = append(greeting, salt[:8]...)
	greeting = append(greeting, 0) // filler
	// capability flags（低位 2 字节 LE）：0xF700 = 0xFF00 清除 CLIENT_SSL(0x0800)——
	// 蜜罐无 TLS，置 SSL 位会诱导客户端先发 SSLRequest 导致握手路径错乱（R-01 整改）。
	// 保留 PROTOCOL_41(0x200)/SECURE_CONNECTION(0x8000)/LONG_FLAG 等位。
	greeting = append(greeting, 0x00, 0xF7) // caps_lower（LE 0xF700，不含 SSL 位 0x0800）
	greeting = append(greeting, 45)         // charset: utf8mb4_general_ci
	greeting = append(greeting, 0x02, 0x00) // status flags: SERVER_STATUS_AUTOCOMMIT
	greeting = append(greeting, 0x77, 0x77) // caps_upper（LE 0x7777：置位 bit16/17/18/20/21/22/24/25/26/28/29/30，
	// 含 CLIENT_CONNECT_ATTRS(0x100000) 等高位；bit19 PLUGIN_AUTH 未置——插件名已由
	// auth_plugin_name 字段声明，客户端不依赖该位）
	greeting = append(greeting, 21)         // auth_plugin_data_len = 21（20 salt + 1 NUL）
	greeting = append(greeting, make([]byte, 10)...) // reserved
	greeting = append(greeting, salt[8:]...)         // auth_plugin_data_part2（12 字节）
	greeting = append(greeting, 0)                   // salt 串 NUL 终止
	greeting = append(greeting, []byte("mysql_native_password\x00")...) // auth plugin
	if err := writeMySQLPacket(conn, 0, greeting); err != nil {
		return
	}

	// 2. HandshakeResponse41（报文头 4 字节：3 字节长度 + 1 序号）。
	hdr := make([]byte, 4)
	if _, err := readFullN(conn, hdr); err != nil {
		return
	}
	pktLen := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16 // 3 字节小端长度
	if pktLen < 4 || pktLen > 1<<20 {
		return // 畸形长度（防御）
	}
	payload := make([]byte, pktLen)
	if _, err := readFullN(conn, payload); err != nil {
		return
	}
	// 解析：capabilities(4) + max_packet(4) + charset(1) + reserved(23) →
	// username（NUL 终止）→ auth response（1 字节长度 + 数据）。
	if len(payload) < 32 {
		return
	}
	caps := binary.LittleEndian.Uint32(payload[:4])
	rest := payload[32:]
	userEnd := -1
	for i, b := range rest {
		if b == 0 {
			userEnd = i
			break
		}
	}
	if userEnd < 0 {
		return
	}
	user := string(rest[:userEnd])
	authResp := ""
	pos := userEnd + 1
	if caps&0x00008000 != 0 { // CLIENT_SECURE_CONNECTION：1 字节长度 + auth-response
		if pos < len(rest) {
			al := int(rest[pos])
			pos++
			if pos+al <= len(rest) {
				authResp = hex.EncodeToString(rest[pos : pos+al])
			}
		}
	}

	// 3. 凭据记录（auth-response 为 mysql_native_password SHA1 链，不可逆——如实记录）。
	if user != "" || authResp != "" {
		rec(event.CredEvent{
			Username: user,
			Password: authResp,
			Extra:    "mysql_native_password 密码 hash（SHA1 链，不可逆）",
		})
	}

	// 4. ERR 1045（ER_ACCESS_DENIED_ERROR）拒绝。序号递增：greeting=0、客户端=1、ERR=2。
	errMsg := []byte("Access denied for user '" + user + "'@'host' (using password: YES)")
	errPkt := make([]byte, 0, 1+2+1+5+len(errMsg))
	errPkt = append(errPkt, 0xFF) // ERR packet
	var ecode [2]byte
	binary.LittleEndian.PutUint16(ecode[:], 1045)
	errPkt = append(errPkt, ecode[:]...)
	errPkt = append(errPkt, '#')
	errPkt = append(errPkt, []byte("28000")...) // SQLSTATE
	errPkt = append(errPkt, errMsg...)
	_ = writeMySQLPacket(conn, 2, errPkt)
}

// writeMySQLPacket 写 MySQL 报文（3 字节长度 + 1 字节序号 + payload）。
func writeMySQLPacket(conn net.Conn, seq byte, payload []byte) error {
	if len(payload) > 0xFFFFFF {
		payload = payload[:0xFFFFFF] // 防御截断（蜜罐响应均远小于此）
	}
	buf := make([]byte, 0, 4+len(payload))
	buf = append(buf, byte(len(payload)), byte(len(payload)>>8), byte(len(payload)>>16), seq)
	buf = append(buf, payload...)
	_, err := conn.Write(buf)
	return err
}
