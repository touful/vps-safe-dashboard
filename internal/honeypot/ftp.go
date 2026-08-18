package honeypot

import (
	"bufio"
	"context"
	"net"
	"strings"

	"sentry-agent/internal/event"
)

// handleFTP FTP 认证握手模拟（RFC 959）。
// 流程：220 横幅 → 循环解析客户端命令：
//   USER <name>    → 331 Password required（暂存用户名）
//   PASS <pass>    → 记录 CredEvent（用户名取自上次 USER）→ 530 Login incorrect（支持重试多组）
//   QUIT           → 221 关闭
//   SYST/其他      → 502 Command not implemented（最小响应，不泄露真实系统信息）
// 行协议：\r\n 结尾文本行；多行命令不解析（命令概览级）。
func handleFTP(ctx context.Context, conn net.Conn, srcIP uint32, rec func(event.CredEvent)) {
	if _, err := conn.Write([]byte("220 FTP Server ready\r\n")); err != nil {
		return
	}
	br := bufio.NewReader(conn)
	var pendingUser string // 最近一次 USER 命令的用户名（PASS 后清空）
	credCount := 0         // 单连接凭据记录计数（D-A：超 credsPerConnLimit 后忽略后续）
	for {
		line, err := readLine(br)
		if err != nil {
			return
		}
		cmd, arg := splitCommand(line)
		switch cmd {
		case "USER":
			pendingUser = arg
			if _, err := conn.Write([]byte("331 Password required\r\n")); err != nil {
				return
			}
		case "PASS":
			// 凭据记录（明文捕获；无 USER 直接 PASS 时用户名留空）。
			if credCount < credsPerConnLimit {
				rec(event.CredEvent{Username: pendingUser, Password: arg})
			}
			credCount++
			pendingUser = ""
			if _, err := conn.Write([]byte("530 Login incorrect\r\n")); err != nil {
				return
			}
		case "QUIT":
			_, _ = conn.Write([]byte("221 Goodbye\r\n"))
			return
		case "":
			// 空行/纯回车：忽略（RFC 959 允许空行）。
			continue
		default:
			// 最小响应：不实现 PASV/PORT/LIST 等真实功能（蜜罐不执行命令）。
			if _, err := conn.Write([]byte("502 Command not implemented\r\n")); err != nil {
				return
			}
		}
	}
}

// splitCommand 拆分 FTP 命令行：命令（大写）+ 参数。
func splitCommand(line string) (cmd, arg string) {
	line = strings.TrimSpace(line)
	if i := strings.IndexAny(line, " \t"); i >= 0 {
		return strings.ToUpper(line[:i]), strings.TrimSpace(line[i+1:])
	}
	return strings.ToUpper(line), ""
}
