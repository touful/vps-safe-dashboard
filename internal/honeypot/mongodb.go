package honeypot

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"

	"sentry-agent/internal/event"
)

// handleMongoDB MongoDB 认证握手模拟（Wire Protocol，
// https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/）。
// 支持 OP_QUERY（旧版，opCode 2004）与 OP_MSG（新版，opCode 2013）。
// 认证路径：saslStart/saslContinue 命令（SCRAM-SHA-1/256）——
// 解析命令文档中 payload（binary）子文档的 user 字段（明文）→ 记录
// username + client nonce（Extra 注明 SCRAM 不可逆）→ 回 {ok:0, errmsg:"Authentication failed"}。
// 无法捕获明文密码（SCRAM 盐化哈希不可逆），如实记录。
func handleMongoDB(ctx context.Context, conn net.Conn, srcIP uint32, rec func(event.CredEvent)) {
	credCount := 0 // 单连接凭据记录计数（D-A：超 credsPerConnLimit 后忽略后续）
	for {
		// 消息头：messageLength(4) + requestID(4) + responseTo(4) + opCode(4)。
		var hdr [16]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return
		}
		msgLen := int(binary.LittleEndian.Uint32(hdr[:4]))
		reqID := binary.LittleEndian.Uint32(hdr[4:8]) // 请求 ID（响应 responseTo 回显，R-11）
		opCode := binary.LittleEndian.Uint32(hdr[12:16])
		if msgLen < 16 || msgLen > 1<<20 {
			return // 畸形长度（防御）
		}
		body := make([]byte, msgLen-16)
		if _, err := io.ReadFull(conn, body); err != nil {
			return
		}

		var cmdDoc []byte // 命令 BSON 文档
		switch opCode {
		case 2004: // OP_QUERY：flags(4) + fullCollectionName(NUL) + skip(4) + return(4) + query(BSON)
			if len(body) < 12 {
				continue
			}
			nameEnd := 4
			for nameEnd < len(body) && body[nameEnd] != 0 {
				nameEnd++
			}
			if nameEnd+9 > len(body) {
				continue
			}
			cmdDoc = body[nameEnd+1+8:]
		case 2013: // OP_MSG：flags(4) + section kind(1) + BSON body
			if len(body) < 5 {
				continue
			}
			cmdDoc = body[5:] // section kind 0x00 = body（单 section）
		default:
			// 其他 opCode（OP_COMPRESSED 等）：不解析，等超时断开。
			continue
		}

		cmd, user, rnonce, ok := parseMongoCommand(cmdDoc)
		if !ok {
			continue // 非认证命令（ping/hello/isMaster 等）：静默忽略
		}
		// 凭据记录：user 明文 + client nonce（SCRAM 不可逆，如实记录）。
		if credCount < credsPerConnLimit {
			extra := "SCRAM 认证（" + cmd + "），密码经盐化哈希不可逆"
			if rnonce != "" {
				extra += "；client nonce=" + rnonce
			}
			rec(event.CredEvent{Username: user, Extra: extra})
		}
		credCount++
		// 回 {ok: 0, errmsg: "Authentication failed"}（拒绝继续）。
		resp := buildMongoReply("Authentication failed")
		if err := writeMongoMsg(conn, resp, reqID); err != nil {
			return
		}
	}
}

// parseMongoCommand 解析命令 BSON 文档：识别 saslStart/saslContinue，
// 提取 payload 子文档的 user 与 rnonce 字段。
// 返回 (命令名, user, rnonce, 是否为认证命令)。
func parseMongoCommand(doc []byte) (string, string, string, bool) {
	// BSON 文档：int32 totalSize + elements；元素 = type(1) + name(NUL) + value。
	if len(doc) < 4 {
		return "", "", "", false
	}
	total := int(binary.LittleEndian.Uint32(doc[:4]))
	if total < 4 || total > len(doc) {
		return "", "", "", false
	}
	cmd := ""
	user := ""
	rnonce := ""
	isAuth := false
	pos := 4
	for pos < total-1 { // 末尾 0x00 终止符
		typ := doc[pos]
		pos++
		nameEnd := pos
		for nameEnd < total && doc[nameEnd] != 0 {
			nameEnd++
		}
		if nameEnd >= total {
			break
		}
		name := string(doc[pos:nameEnd])
		pos = nameEnd + 1
		valEnd, err := skipBSONValue(doc, pos, typ)
		if err != nil {
			break
		}
		switch {
		case name == "saslStart" || name == "saslContinue":
			if typ == 0x10 { // int32 命令标志
				isAuth = true
				cmd = name
			}
		case name == "payload" && typ == 0x05: // binary：子文档（SCRAM client-first-message）
			// binary: len(4) + subtype(1) + data
			if pos+5 <= len(doc) {
				bLen := int(binary.LittleEndian.Uint32(doc[pos : pos+4]))
				sub := doc[pos+4]
				if sub == 0 && pos+5+bLen <= len(doc) {
					subUser, subNonce := parseScramPayload(doc[pos+5 : pos+5+bLen])
					if subUser != "" {
						user = subUser
					}
					if subNonce != "" {
						rnonce = subNonce
					}
				}
			}
		case name == "mechanism" && typ == 0x02:
			// 机制字符串（SCRAM-SHA-1/256）：记录到 extra 由调用方拼接，此处仅确认认证。
		}
		pos = valEnd
	}
	if !isAuth {
		return "", "", "", false
	}
	return cmd, user, rnonce, true
}

// parseScramPayload 解析 SCRAM client-first-message BSON（user/rnonce 字段明文）。
func parseScramPayload(doc []byte) (string, string) {
	if len(doc) < 4 {
		return "", ""
	}
	total := int(binary.LittleEndian.Uint32(doc[:4]))
	if total < 4 || total > len(doc) {
		return "", ""
	}
	user, rnonce := "", ""
	pos := 4
	for pos < total-1 {
		typ := doc[pos]
		pos++
		nameEnd := pos
		for nameEnd < total && doc[nameEnd] != 0 {
			nameEnd++
		}
		if nameEnd >= total {
			break
		}
		name := string(doc[pos:nameEnd])
		pos = nameEnd + 1
		valEnd, err := skipBSONValue(doc, pos, typ)
		if err != nil {
			break
		}
		if typ == 0x02 { // string：len(4) + data + \0
			sLen := int(binary.LittleEndian.Uint32(doc[pos : pos+4]))
			if pos+4+sLen <= len(doc) {
				val := string(doc[pos+4 : pos+4+sLen-1])
				switch name {
				case "user":
					user = val
				case "rnonce":
					rnonce = val
				}
			}
		}
		pos = valEnd
	}
	return user, rnonce
}

// skipBSONValue 跳过 BSON 值，返回值结束位置（不含下一个元素 type）。
// 支持最小类型集：double(0x01)/string(0x02)/document(0x03)/binary(0x05)/
// bool(0x08)/int32(0x10)/int64(0x12)/datetime(0x09)/null(0x0A)/regex(0x0B)/
// javascript(0x0D)/timestamp(0x11)/decimal(0x13)；其余按未知类型跳过。
func skipBSONValue(doc []byte, pos int, typ byte) (int, error) {
	if pos >= len(doc) {
		return pos, errShortBSON
	}
	switch typ {
	case 0x01: // double
		return pos + 8, nil
	case 0x02: // string
		if pos+4 > len(doc) {
			return pos, errShortBSON
		}
		n := int(binary.LittleEndian.Uint32(doc[pos : pos+4]))
		if pos+4+n > len(doc) || n < 1 {
			return pos, errShortBSON
		}
		return pos + 4 + n, nil
	case 0x03, 0x04: // document / array
		if pos+4 > len(doc) {
			return pos, errShortBSON
		}
		n := int(binary.LittleEndian.Uint32(doc[pos : pos+4]))
		if pos+n > len(doc) || n < 4 {
			return pos, errShortBSON
		}
		return pos + n, nil
	case 0x05: // binary
		if pos+5 > len(doc) {
			return pos, errShortBSON
		}
		n := int(binary.LittleEndian.Uint32(doc[pos : pos+4]))
		if pos+5+n > len(doc) {
			return pos, errShortBSON
		}
		return pos + 5 + n, nil
	case 0x08: // bool
		return pos + 1, nil
	case 0x09: // datetime
		return pos + 8, nil
	case 0x0A: // null
		return pos, nil
	case 0x0B: // regex（cstring 对）
		for pos < len(doc) && doc[pos] != 0 {
			pos++
		}
		pos++
		for pos < len(doc) && doc[pos] != 0 {
			pos++
		}
		return pos + 1, nil
	case 0x10: // int32
		return pos + 4, nil
	case 0x11: // timestamp
		return pos + 8, nil
	case 0x12: // int64
		return pos + 8, nil
	case 0x13: // decimal128
		return pos + 16, nil
	case 0x0D: // javascript code
		if pos+4 > len(doc) {
			return pos, errShortBSON
		}
		n := int(binary.LittleEndian.Uint32(doc[pos : pos+4]))
		if pos+4+n > len(doc) || n < 1 {
			return pos, errShortBSON
		}
		return pos + 4 + n, nil
	default:
		return pos, errShortBSON // 未知类型：放弃解析（防御）
	}
}

// errShortBSON BSON 数据不足（畸形输入防御）。
var errShortBSON = &bsonShortError{}

type bsonShortError struct{}

func (e *bsonShortError) Error() string { return "BSON 数据不足" }

// buildMongoReply 构造 OP_REPLY 文档（合法 BSON：{ok: 0, errmsg: "..."}——
// 真实客户端可正确解析并中止认证（ok=0 即认证失败语义））。
// 注意：最终 wire 响应由 writeMongoMsg 重写为 OP_MSG 并回填 responseTo。
func buildMongoReply(errmsg string) []byte {
	doc := buildBSONAuthFail(errmsg)
	msg := make([]byte, 0, 16+len(doc))
	var hdr [16]byte
	binary.LittleEndian.PutUint32(hdr[:4], uint32(16+len(doc))) // messageLength
	binary.LittleEndian.PutUint32(hdr[12:16], 1)                 // OP_REPLY
	msg = append(msg, hdr[:]...)
	msg = append(msg, doc...)
	return msg
}

// buildBSONAuthFail 构造认证失败 BSON 文档：{ok: Int32(0), errmsg: "..."}。
func buildBSONAuthFail(errmsg string) []byte {
	// element: type(1) + name(NUL) + value
	// ok: type 0x10 (int32) + "ok\0" + int32 0
	// errmsg: type 0x02 (string) + "errmsg\0" + int32(len) + data\0
	errLen := len(errmsg) + 1
	total := 4 + (1 + 3 + 4) + (1 + 7 + 4 + errLen) + 1
	doc := make([]byte, 0, total)
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], uint32(total))
	doc = append(doc, tmp[:]...)
	doc = append(doc, 0x10) // int32
	doc = append(doc, 'o', 'k', 0)
	doc = append(doc, 0, 0, 0, 0) // ok = 0
	doc = append(doc, 0x02)       // string
	doc = append(doc, 'e', 'r', 'r', 'm', 's', 'g', 0)
	binary.LittleEndian.PutUint32(tmp[:], uint32(errLen))
	doc = append(doc, tmp[:]...)
	doc = append(doc, errmsg...)
	doc = append(doc, 0) // string 终止
	doc = append(doc, 0) // 文档终止
	return doc
}

// writeMongoMsg 写 MongoDB 消息：将 OP_REPLY 重写为 OP_MSG（2013）响应
// （现代驱动认证路径仅认 OP_MSG）；responseTo 回填请求 ID（R-11 reviewer 整改：
// 校验 responseTo 的驱动才能正确关联认证失败语义）。
func writeMongoMsg(conn net.Conn, msg []byte, reqID uint32) error {
	if len(msg) < 16 {
		return nil
	}
	out := make([]byte, 0, len(msg)+5)
	var hdr [16]byte
	binary.LittleEndian.PutUint32(hdr[:4], uint32(len(msg)+5))
	binary.LittleEndian.PutUint32(hdr[8:12], reqID) // responseTo = 请求 ID
	binary.LittleEndian.PutUint32(hdr[12:16], 2013) // OP_MSG
	out = append(out, hdr[:]...)
	out = append(out, 0, 0, 0, 0)   // flags
	out = append(out, 0)            // section kind 0 = body
	out = append(out, msg[16:]...)  // BSON doc
	// writeAll2 已由标准库 io.Copy 取代（DEV-ARCH-002 A2：bytes.Reader 实现
	// WriteTo，io.Copy 直连 conn.Write 循环；短写返回 io.ErrShortWrite → 蜜罐
	// 响应路径断开——net.Conn 短写概率极低，失败路径方向与旧实现一致）。
	_, err := io.Copy(conn, bytes.NewReader(out))
	return err
}
