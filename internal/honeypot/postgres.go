package honeypot

import (
	"context"
	"encoding/binary"
	"net"

	"sentry-agent/internal/event"
)

// handlePostgres PostgreSQL 登录握手模拟（前端协议 v3，参考
// https://www.postgresql.org/docs/current/protocol-message-formats.html 与
// https://www.postgresql.org/docs/current/protocol-flow.html#PROTOCOL-FLOW-START-UP）。
// 捕获路径：客户端发送 StartupMessage（含 user 参数明文）→ 服务端回
// AuthenticationCleartextPassword（诱导明文密码）→ 客户端回 PasswordMessage
// （p 消息，明文）→ 记录 CredEvent → 回 ErrorResponse 拒绝（password authentication failed）。
// 消息格式：
//   StartupMessage:           Int32 len | Int32 196608(3.0) | key\0value\0... | \0
//   AuthenticationCleartextPassword (R): Byte 'R' | Int32 len=8 | Int32 code=3
//   PasswordMessage (p):      Byte 'p' | Int32 len | password\0
//   ErrorResponse (E):        Byte 'E' | Int32 len | (Byte type + String)* | \0
func handlePostgres(ctx context.Context, conn net.Conn, srcIP uint32, rec func(event.CredEvent)) {
	// 1. StartupMessage：长度（含自身 4 字节）+ 协议版本 + 参数对 + 终止 0。
	var hdr [8]byte
	if _, err := readFullN(conn, hdr[:4]); err != nil {
		return
	}
	msgLen := int(binary.BigEndian.Uint32(hdr[:4]))
	if msgLen < 8 || msgLen > 65536 {
		return // 畸形长度（防御）
	}
	body := make([]byte, msgLen-4)
	if _, err := readFullN(conn, body); err != nil {
		return
	}
	protoVer := binary.BigEndian.Uint32(body[:4])
	if protoVer != 196608 { // 3.0；SSLRequest(80877103)/GSSENCRequest 非认证路径，直接关闭
		return
	}
	// 参数对解析（key\0value\0... 以 \0 终止）。
	user := parseStartupParams(body[4:])

	// 2. 回 AuthenticationCleartextPassword（R 消息，code=3）——诱导明文密码。
	// 注：真实服务在 md5/scram 场景回 R code=5/10，明文密码场景回 code=3；
	// 蜜罐选择 code=3 以最大化捕获明文密码。
	rMsg := []byte{'R', 0, 0, 0, 8, 0, 0, 0, 3}
	if _, err := conn.Write(rMsg); err != nil {
		return
	}

	// 3. PasswordMessage（p 消息：type 'p' + len + password\0）。
	var phdr [5]byte
	if _, err := readFullN(conn, phdr[:5]); err != nil {
		return
	}
	if phdr[0] != 'p' {
		return // 客户端未按预期发密码（如直接取消/关闭），放弃本次捕获
	}
	pLen := int(binary.BigEndian.Uint32(phdr[1:5]))
	if pLen < 1 || pLen > 65536 {
		return
	}
	pbuf := make([]byte, pLen)
	if _, err := readFullN(conn, pbuf); err != nil {
		return
	}
	pass := string(pbuf[:len(pbuf)-1]) // 末尾 \0 剥离

	// 4. 凭据记录（username 来自 StartupMessage 明文，密码为明文捕获）。
	rec(event.CredEvent{Username: user, Password: pass})

	// 5. ErrorResponse 拒绝（FATAL：password authentication failed）。
	eMsg := buildPGError("FATAL", `password authentication failed for user "`+user+`"`)
	_, _ = conn.Write(eMsg)
}

// parseStartupParams 解析 StartupMessage 参数区（key\0value\0...\0 终止）。
func parseStartupParams(b []byte) string {
	user := ""
	for i := 0; i < len(b); {
		// 参数对以双 0 终止。
		if b[i] == 0 {
			break
		}
		keyEnd := i
		for keyEnd < len(b) && b[keyEnd] != 0 {
			keyEnd++
		}
		if keyEnd >= len(b) {
			break
		}
		key := string(b[i:keyEnd])
		valEnd := keyEnd + 1
		for valEnd < len(b) && b[valEnd] != 0 {
			valEnd++
		}
		if valEnd >= len(b) {
			break
		}
		val := string(b[keyEnd+1 : valEnd])
		if key == "user" {
			user = val
		}
		i = valEnd + 1
	}
	return user
}

// buildPGError 构造 PostgreSQL ErrorResponse 消息（字段：S severity、M message）。
func buildPGError(severity, message string) []byte {
	var b []byte
	b = append(b, 'E')
	// 长度占位（4 字节），最后回填。
	lenPos := len(b)
	b = append(b, 0, 0, 0, 0)
	b = append(b, 'S')
	b = append(b, []byte(severity)...)
	b = append(b, 0)
	b = append(b, 'M')
	b = append(b, []byte(message)...)
	b = append(b, 0)
	b = append(b, 0) // 终止
	binary.BigEndian.PutUint32(b[lenPos:], uint32(len(b)-lenPos))
	return b
}

// readFullN 从连接读取固定长度字节（与 bufio 版 readFull 区分：直读 conn）。
func readFullN(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
