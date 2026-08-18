package honeypot

import (
	"bufio"
	"context"
	"net"
	"strings"

	"sentry-agent/internal/event"
)

// telnetBanner 伪装的 telnet 横幅（仅文本伪装，不执行任何命令）。
// 设计：常见扫描器（如默认口令爆破脚本）以 banner 判断目标系统后尝试
// root/admin 等默认口令；横幅仅用于诱导认证流程，不含真实系统信息。
const telnetBanner = "Ubuntu 22.04.3 LTS\r\n"

// handleTelnet telnet 登录握手模拟（RFC 854）。
// 流程：横幅 → 循环（最多 loginRoundsMax 轮）：
//   发 "login: " → 收用户名 → 发 "Password: " → 收密码 → 记录 CredEvent
//   → 发 "Login incorrect" → 继续下一轮；客户端断开/超时结束。
// 不实现 TELNET 选项协商（IAC 序列）：真实客户端通常先发 IAC DO/DONT 协商，
// 扫描器/脚本通常直接发 login 行；对 IAC 字节（0xFF）按普通行数据丢弃处理。
func handleTelnet(ctx context.Context, conn net.Conn, srcIP uint32, rec func(event.CredEvent)) {
	if _, err := conn.Write([]byte(telnetBanner)); err != nil {
		return
	}
	br := bufio.NewReader(conn)
	for round := 0; round < loginRoundsMax; round++ {
		if _, err := conn.Write([]byte("login: ")); err != nil {
			return
		}
		user, err := readLine(br)
		if err != nil {
			return
		}
		if _, err := conn.Write([]byte("Password: ")); err != nil {
			return
		}
		pass, err := readLine(br)
		if err != nil {
			return
		}
		// 凭据记录（明文捕获；敏感内容仅落 cred_events 本地库）。
		rec(event.CredEvent{Username: user, Password: pass})
		if _, err := conn.Write([]byte("Login incorrect\r\n")); err != nil {
			return
		}
	}
}

// readLine 读取一行（\n 结尾），剥离 \r\n，去除行内 TELNET 控制序列。
// IAC（0xFF）协商：0xFF + command(1) + option(1) 三字节整体剥离
// （R-13 reviewer 整改：原实现仅丢 0xFF，选项残留进用户名）。
// 行长度上限 4KB（防单行内存放大；超限截断按当前行处理）。
func readLine(br *bufio.Reader) (string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		// 已读到部分数据时仍返回（客户端不发 \n 直接断开的场景）；
		// 无数据时返回错误。
		if len(line) == 0 {
			return "", err
		}
	}
	line = strings.TrimRight(line, "\r\n")
	// 字节级扫描剥离 IAC 序列（0xFF 后两字节一并丢弃；结尾残缺 IAC 一并丢弃）。
	out := make([]byte, 0, len(line))
	for i := 0; i < len(line); i++ {
		if line[i] == 0xFF {
			i += 2 // 跳过 command + option（IAC 三字节序列）
			continue
		}
		out = append(out, line[i])
	}
	line = string(out)
	// 截断保护：超长行按 4KB 截断（其余丢弃）。
	if len(line) > 4096 {
		line = line[:4096]
	}
	return line, nil
}
