package honeypot

import (
	"bufio"
	"context"
	"io"
	"net"
	"strconv"
	"strings"

	"sentry-agent/internal/event"
)

// handleRedis Redis 认证握手模拟（RESP 协议，https://redis.io/docs/reference/protocol-spec/）。
// 捕获路径：
//   - AUTH <password>       → 记录（username 留空，redis 无用户概念）
//   - AUTH <user> <password> → 记录（ACL 用户格式）
//   - HELLO 3 [AUTH u p]     → HELLO 带 AUTH 参数时解析记录；回 -ERR 最小响应
// 响应全部为拒绝（-ERR），不执行任何命令、不返回真实信息（INFO/CONFIG 等回 -ERR）。
// 解析：优先 RESP 数组（*N\r\n$len\r\n...）；首字节非 '*' 时按 inline 命令行
// （空格分词，兼容 telnet 式攻击脚本）。
func handleRedis(ctx context.Context, conn net.Conn, srcIP uint32, rec func(event.CredEvent)) {
	br := bufio.NewReader(conn)
	credCount := 0 // 单连接凭据记录计数（D-A：超 credsPerConnLimit 后忽略后续）
	for {
		cmd, args, err := readRESPCommand(br)
		if err != nil {
			return
		}
		switch cmd {
		case "AUTH":
			var user, pass string
			switch len(args) {
			case 1:
				pass = args[0] // AUTH <password>
			case 2:
				user, pass = args[0], args[1] // AUTH <user> <password>
			default:
				_, _ = conn.Write([]byte("-ERR wrong number of arguments for 'auth' command\r\n"))
				continue
			}
			// 凭据记录（明文捕获；redis 无用户概念时 username 留空）。
			if credCount < credsPerConnLimit {
				rec(event.CredEvent{Username: user, Password: pass})
			}
			credCount++
			_, _ = conn.Write([]byte("-ERR invalid password\r\n"))
		case "HELLO":
			// HELLO 3 AUTH <user> <pass>：带 AUTH 参数时尝试捕获（redis-cli 升级握手路径）。
			if len(args) >= 4 && strings.EqualFold(args[1], "AUTH") {
				if credCount < credsPerConnLimit {
					rec(event.CredEvent{Username: args[2], Password: args[3],
						Extra: "HELLO 3 AUTH 参数"})
				}
				credCount++
			}
			// 最小响应：不回真实 server 信息；客户端 HELLO 失败后通常回退 AUTH 命令。
			_, _ = conn.Write([]byte("-ERR unknown command 'HELLO'\r\n"))
		case "QUIT":
			_, _ = conn.Write([]byte("+OK\r\n"))
			return
		default:
			// INFO/CONFIG/GET 等一律最小拒绝（蜜罐不返回真实信息）。
			_, _ = conn.Write([]byte("-ERR unknown command\r\n"))
		}
	}
}

// readRESPCommand 读取一条 RESP 命令：RESP 数组 → (命令, 参数列表)；
// 非 '*' 首字节回退 inline 命令行解析。
// 参考 RESP2 格式：*N\r\n$len\r\n<data>\r\n...；返回 err 表示连接关闭/协议畸形。
func readRESPCommand(br *bufio.Reader) (string, []string, error) {
	first, err := br.ReadByte()
	if err != nil {
		return "", nil, err
	}
	if first != '*' {
		// inline 命令：整行空格分词（Redis inline command 兼容）。
		// 首字节已消费——退回后整行读取。
		if err := br.UnreadByte(); err != nil {
			return "", nil, err
		}
		line, err := readLine(br)
		if err != nil {
			return "", nil, err
		}
		parts := strings.Fields(line)
		if len(parts) == 0 {
			return "", nil, nil // 空行：调用方按未知命令处理
		}
		cmd := strings.ToUpper(parts[0])
		rest := parts[1:]
		// 大小写归一化（AUTH/HELLO 等命令名不区分大小写）。
		return cmd, rest, nil
	}
	// RESP 数组：*N\r\n
	count, err := readRESPInt(br)
	if err != nil {
		return "", nil, err
	}
	if count <= 0 || count > 64 {
		return "", nil, nil // 畸形数组（0/负/超限）：按未知命令处理
	}
	elements := make([]string, 0, count)
	for i := 0; i < count; i++ {
		elem, err := readRESPBulk(br)
		if err != nil {
			return "", nil, err
		}
		elements = append(elements, elem)
	}
	if len(elements) == 0 {
		return "", nil, nil
	}
	return strings.ToUpper(elements[0]), elements[1:], nil
}

// readRESPInt 读取 RESP 整数行（*N / $len 前缀的 N）。
func readRESPInt(br *bufio.Reader) (int, error) {
	line, err := readLine(br)
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(line)
	if err != nil || n < 0 || n > 65536 {
		return 0, nil // 畸形：按 0 处理（调用方走未知命令路径）
	}
	return n, nil
}

// readRESPBulk 读取 RESP bulk string（$len\r\n<data>\r\n；len 上限 64KB 防放大）。
// 注意：须先消费 '$' 类型字节（RESP 元素前缀），再读长度行与数据。
func readRESPBulk(br *bufio.Reader) (string, error) {
	typ, err := br.ReadByte()
	if err != nil {
		return "", err
	}
	if typ != '$' {
		return "", nil // 非 bulk 元素（畸形输入防御）：按空串处理
	}
	n, err := readRESPInt(br)
	if err != nil {
		return "", err
	}
	if n > 65536 {
		return "", nil // 超限：截断（畸形输入防御）
	}
	buf := make([]byte, n+2) // +2 覆盖 \r\n
	if _, err := io.ReadFull(br, buf); err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}


