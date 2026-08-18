package honeypot

import (
	"bufio"
	"context"
	"net"
	"strings"

	"sentry-agent/internal/event"
)

// handleMemcached memcached 文本协议交互模拟（协议规范：
// https://github.com/memcached/memcached/blob/master/doc/protocol.txt）。
// 关键事实：memcached 协议无认证机制（无 USER/PASS 概念）——无法捕获凭据。
// 捕获能力（诚实降级）：记录连接 + 首条命令概览（Extra 注明"协议无认证"），
// username/password 留空。响应统一回 "ERROR"（蜜罐不执行任何命令、不返回真实数据）。
func handleMemcached(ctx context.Context, conn net.Conn, srcIP uint32, rec func(event.CredEvent)) {
	br := bufio.NewReader(conn)
	// 记录首条命令（命令概览：get/set/delete/stats/version/flush_all 等）。
	// H-01 修复：readLine 有界读取（原 ReadString 无换行持续输入内存无界）。
	line, err := readLine(br)
	if err != nil {
		return
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	cmdName := strings.Fields(line)[0]
	// 命令概览截断（超长防御）。
	if len(line) > 256 {
		line = line[:256]
	}
	// 凭据记录：协议无认证，username/password 留空，Extra 记录命令概览。
	rec(event.CredEvent{
		Extra: "协议无认证机制，无法捕获凭据；命令概览: " + cmdName + " (" + line + ")",
	})
	// 最小响应（不回真实数据；客户端继续发命令时同样拒绝）。
	_, _ = conn.Write([]byte("ERROR\r\n"))
	// 剩余交互：循环读丢弃（防客户端发送大量命令刷连接——框架 30s 超时兜底）。
	buf := make([]byte, 512)
	for {
		if _, err := br.Read(buf); err != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}
