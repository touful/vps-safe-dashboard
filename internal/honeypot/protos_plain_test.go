package honeypot

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"sentry-agent/internal/event"
)

// dialProto 连接指定协议蜜罐端口。
func dialProto(t *testing.T, addrs map[string]string, proto string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addrs[proto], time.Second)
	if err != nil {
		t.Fatalf("连接 %s 蜜罐失败: %v", proto, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// recvCred 从 credCh 接收一条凭据事件（带超时）。
func recvCred(t *testing.T, credCh chan event.CredEvent) event.CredEvent {
	t.Helper()
	select {
	case ev := <-credCh:
		return ev
	case <-time.After(2 * time.Second):
		t.Fatal("超时未收到凭据事件")
		return event.CredEvent{}
	}
}

// TestTelnetCapture telnet 完整登录流：banner → login/password → 凭据捕获。
func TestTelnetCapture(t *testing.T) {
	credCh := make(chan event.CredEvent, 16)
	_, addrs := startTestServer(t, []string{"telnet"}, credCh, nil)
	c := dialProto(t, addrs, "telnet")
	br := bufio.NewReader(c)

	// 读 banner。
	if _, err := br.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	// login: 提示。
	if s, _ := br.ReadString(' '); s != "login: " {
		t.Fatalf("login 提示 = %q", s)
	}
	_, _ = c.Write([]byte("admin\r\n"))
	if s, _ := br.ReadString(' '); s != "Password: " {
		t.Fatalf("Password 提示 = %q", s)
	}
	_, _ = c.Write([]byte("p@ss123\r\n"))
	// Login incorrect 回复。
	if s, _ := br.ReadString('\n'); s != "Login incorrect\r\n" {
		t.Fatalf("拒绝文案 = %q", s)
	}
	ev := recvCred(t, credCh)
	if ev.Proto != "telnet" || ev.Username != "admin" || ev.Password != "p@ss123" {
		t.Fatalf("凭据事件 = %+v", ev)
	}
	if ev.SrcIP == 0 {
		t.Fatal("SrcIP 不应为 0（回环连接）")
	}
}

// TestTelnetMultiRound telnet 多轮登录（每 IP 限 5 轮）：第 2 轮仍可捕获。
func TestTelnetMultiRound(t *testing.T) {
	credCh := make(chan event.CredEvent, 16)
	_, addrs := startTestServer(t, []string{"telnet"}, credCh, nil)
	c := dialProto(t, addrs, "telnet")
	br := bufio.NewReader(c)
	_, _ = br.ReadString('\n')
	// 第 1 轮。
	_, _ = br.ReadString(' ')
	_, _ = c.Write([]byte("root\r\n"))
	_, _ = br.ReadString(' ')
	_, _ = c.Write([]byte("pass1\r\n"))
	_, _ = br.ReadString('\n')
	// 第 2 轮。
	if s, _ := br.ReadString(' '); s != "login: " {
		t.Fatalf("第 2 轮 login 提示 = %q", s)
	}
	_, _ = c.Write([]byte("root\r\n"))
	_, _ = br.ReadString(' ')
	_, _ = c.Write([]byte("pass2\r\n"))
	_, _ = br.ReadString('\n')
	ev1 := recvCred(t, credCh)
	ev2 := recvCred(t, credCh)
	if ev1.Password != "pass1" || ev2.Password != "pass2" {
		t.Fatalf("多轮捕获失败: %+v %+v", ev1, ev2)
	}
}

// TestFTPCapture ftp 完整认证流 + 重试多组。
func TestFTPCapture(t *testing.T) {
	credCh := make(chan event.CredEvent, 16)
	_, addrs := startTestServer(t, []string{"ftp"}, credCh, nil)
	c := dialProto(t, addrs, "ftp")
	br := bufio.NewReader(c)
	// 220 横幅。
	if s, _ := br.ReadString('\n'); s != "220 FTP Server ready\r\n" {
		t.Fatalf("横幅 = %q", s)
	}
	// USER → 331。
	_, _ = c.Write([]byte("USER anonymous\r\n"))
	if s, _ := br.ReadString('\n'); s != "331 Password required\r\n" {
		t.Fatalf("USER 回复 = %q", s)
	}
	// PASS → 530 + 凭据。
	_, _ = c.Write([]byte("PASS guest@example.com\r\n"))
	if s, _ := br.ReadString('\n'); s != "530 Login incorrect\r\n" {
		t.Fatalf("PASS 回复 = %q", s)
	}
	ev := recvCred(t, credCh)
	if ev.Proto != "ftp" || ev.Username != "anonymous" || ev.Password != "guest@example.com" {
		t.Fatalf("凭据事件 = %+v", ev)
	}
	// 重试第二组凭据。
	_, _ = c.Write([]byte("USER admin\r\n"))
	_, _ = br.ReadString('\n')
	_, _ = c.Write([]byte("PASS admin123\r\n"))
	_, _ = br.ReadString('\n')
	ev2 := recvCred(t, credCh)
	if ev2.Username != "admin" || ev2.Password != "admin123" {
		t.Fatalf("第二组凭据 = %+v", ev2)
	}
	// QUIT。
	_, _ = c.Write([]byte("QUIT\r\n"))
	if s, _ := br.ReadString('\n'); s != "221 Goodbye\r\n" {
		t.Fatalf("QUIT 回复 = %q", s)
	}
}

// TestFTPUnknownCommand 未知命令最小响应（不泄露真实信息）。
func TestFTPUnknownCommand(t *testing.T) {
	credCh := make(chan event.CredEvent, 16)
	_, addrs := startTestServer(t, []string{"ftp"}, credCh, nil)
	c := dialProto(t, addrs, "ftp")
	br := bufio.NewReader(c)
	_, _ = br.ReadString('\n')
	_, _ = c.Write([]byte("SYST\r\n"))
	if s, _ := br.ReadString('\n'); s != "502 Command not implemented\r\n" {
		t.Fatalf("SYST 回复 = %q", s)
	}
}

// TestRedisAuthCapture redis RESP 数组 AUTH 捕获。
func TestRedisAuthCapture(t *testing.T) {
	credCh := make(chan event.CredEvent, 16)
	_, addrs := startTestServer(t, []string{"redis"}, credCh, nil)
	c := dialProto(t, addrs, "redis")
	br := bufio.NewReader(c)

	// RESP2: *2\r\n$4\r\nAUTH\r\n$6\r\nsecret\r\n
	_, _ = c.Write([]byte("*2\r\n$4\r\nAUTH\r\n$6\r\nsecret\r\n"))
	if s, _ := br.ReadString('\n'); s != "-ERR invalid password\r\n" {
		t.Fatalf("AUTH 回复 = %q", s)
	}
	ev := recvCred(t, credCh)
	if ev.Proto != "redis" || ev.Username != "" || ev.Password != "secret" {
		t.Fatalf("凭据事件 = %+v", ev)
	}

	// AUTH user pass（ACL 格式）。
	_, _ = c.Write([]byte("*3\r\n$4\r\nAUTH\r\n$4\r\nuser\r\n$8\r\npass1234\r\n"))
	_, _ = br.ReadString('\n')
	ev2 := recvCred(t, credCh)
	if ev2.Username != "user" || ev2.Password != "pass1234" {
		t.Fatalf("ACL AUTH 凭据 = %+v", ev2)
	}
}

// TestRedisInlineAuth 兼容 inline 命令格式（telnet 式攻击脚本）。
func TestRedisInlineAuth(t *testing.T) {
	credCh := make(chan event.CredEvent, 16)
	_, addrs := startTestServer(t, []string{"redis"}, credCh, nil)
	c := dialProto(t, addrs, "redis")
	br := bufio.NewReader(c)
	_, _ = c.Write([]byte("AUTH hunter2\r\n"))
	if s, _ := br.ReadString('\n'); s != "-ERR invalid password\r\n" {
		t.Fatalf("inline AUTH 回复 = %q", s)
	}
	ev := recvCred(t, credCh)
	if ev.Password != "hunter2" {
		t.Fatalf("inline 凭据 = %+v", ev)
	}
}

// TestRedisHelloAuth HELLO 3 AUTH 参数解析。
func TestRedisHelloAuth(t *testing.T) {
	credCh := make(chan event.CredEvent, 16)
	_, addrs := startTestServer(t, []string{"redis"}, credCh, nil)
	c := dialProto(t, addrs, "redis")
	br := bufio.NewReader(c)
	// HELLO 3 AUTH default pw12345（RESP 数组）。
	_, _ = c.Write([]byte("*5\r\n$5\r\nHELLO\r\n$1\r\n3\r\n$4\r\nAUTH\r\n$7\r\ndefault\r\n$7\r\npw12345\r\n"))
	_, _ = br.ReadString('\n')
	ev := recvCred(t, credCh)
	if ev.Username != "default" || ev.Password != "pw12345" || ev.Extra == "" {
		t.Fatalf("HELLO AUTH 凭据 = %+v", ev)
	}
}

// TestRedisUnknownCommand INFO 等命令最小拒绝（不返回真实信息）。
func TestRedisUnknownCommand(t *testing.T) {
	credCh := make(chan event.CredEvent, 16)
	_, addrs := startTestServer(t, []string{"redis"}, credCh, nil)
	c := dialProto(t, addrs, "redis")
	br := bufio.NewReader(c)
	_, _ = c.Write([]byte("INFO\r\n"))
	if s, _ := br.ReadString('\n'); s != "-ERR unknown command\r\n" {
		t.Fatalf("INFO 回复 = %q", s)
	}
}

// TestPostgresCapture postgres 完整握手：StartupMessage → R(3) → p 消息 → 凭据 + E 拒绝。
func TestPostgresCapture(t *testing.T) {
	credCh := make(chan event.CredEvent, 16)
	_, addrs := startTestServer(t, []string{"postgres"}, credCh, nil)
	c := dialProto(t, addrs, "postgres")

	// StartupMessage：len + 196608 + user\0postgres\0database\0test\0 + 终止 \0。
	params := []byte("user\x00postgres\x00database\x00test\x00")
	startup := make([]byte, 0, 8+len(params)+1)
	startup = append(startup, 0, 0, 0, 0) // len 占位
	startup = append(startup, 0, 3, 0, 0) // 196608 = 0x00030000（协议版本 3.0）
	startup = append(startup, params...)
	startup = append(startup, 0)
	binary.BigEndian.PutUint32(startup[:4], uint32(len(startup)))
	_, _ = c.Write(startup)

	// 读 R 消息（AuthenticationCleartextPassword：R + len 8 + code 3）。
	var rbuf [9]byte
	if _, err := readFullN(c, rbuf[:]); err != nil {
		t.Fatal(err)
	}
	if rbuf[0] != 'R' || binary.BigEndian.Uint32(rbuf[5:9]) != 3 {
		t.Fatalf("R 消息异常: % x", rbuf)
	}

	// PasswordMessage：p + len + "cleartext\0"。
	pass := []byte("cleartext\x00")
	pmsg := make([]byte, 0, 1+4+len(pass))
	pmsg = append(pmsg, 'p', 0, 0, 0, byte(len(pass)))
	pmsg = append(pmsg, pass...)
	// len 字段占 4 字节：修正。
	binary.BigEndian.PutUint32(pmsg[1:5], uint32(len(pass)))
	_, _ = c.Write(pmsg)

	ev := recvCred(t, credCh)
	if ev.Proto != "postgres" || ev.Username != "postgres" || ev.Password != "cleartext" {
		t.Fatalf("凭据事件 = %+v", ev)
	}
	// ErrorResponse：E 消息（FATAL）。PG 协议 length 字段从自身开始计数，
	// body 长度 = elen - 4。
	var ehdr [5]byte
	if _, err := readFullN(c, ehdr[:]); err != nil {
		t.Fatal(err)
	}
	if ehdr[0] != 'E' {
		t.Fatalf("期望 E 消息, got %q", ehdr[0])
	}
	elen := int(binary.BigEndian.Uint32(ehdr[1:5]))
	ebody := make([]byte, elen-4)
	if _, err := readFullN(c, ebody); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(ebody), "SFATAL\x00M") {
		t.Fatalf("错误字段异常: %q", ebody[:16])
	}
}

// TestReadLineBounded H-01（audit Blocker）：10MB 无换行输入必须在上限内截断
// 返回——readLine 有界读取，杜绝远程无认证 OOM DoS（原 ReadString 持续累积内存）。
func TestReadLineBounded(t *testing.T) {
	big := make([]byte, 10<<20) // 10MB 无换行
	for i := range big {
		big[i] = 'a'
	}
	br := bufio.NewReader(bytes.NewReader(big))
	line, err := readLine(br)
	if err != nil {
		t.Fatalf("readLine 超长输入出错: %v", err)
	}
	// 内存有界：raw 行截断于 maxLineLen，IAC 剥离后按 4KB 记录截断。
	if len(line) != 4096 {
		t.Fatalf("超长行返回长度 = %d, 期望 4096（4KB 记录截断）", len(line))
	}
	// 对照：带换行的正常行不受影响。
	br2 := bufio.NewReader(strings.NewReader("admin\n"))
	l2, err := readLine(br2)
	if err != nil || l2 != "admin" {
		t.Fatalf("正常行解析 = %q err=%v", l2, err)
	}
}

// TestFTPSingleConnCredLimit D-A（audit Major）：ftp 单连接 PASS 洪泛
// （20 组）最多落库 credsPerConnLimit=10 条——批量注入不污染统计与存储。
func TestFTPSingleConnCredLimit(t *testing.T) {
	credCh := make(chan event.CredEvent, 64)
	_, addrs := startTestServer(t, []string{"ftp"}, credCh, nil)
	c := dialProto(t, addrs, "ftp")
	br := bufio.NewReader(c)
	if s, err := br.ReadString('\n'); err != nil || !strings.HasPrefix(s, "220") {
		t.Fatalf("banner = %q err=%v", s, err)
	}
	for i := 0; i < 20; i++ {
		_, _ = c.Write([]byte("USER u\r\n"))
		if _, err := br.ReadString('\n'); err != nil { // 331
			t.Fatal(err)
		}
		_, _ = c.Write([]byte("PASS p\r\n"))
		if _, err := br.ReadString('\n'); err != nil { // 530
			t.Fatal(err)
		}
	}
	// 统计落库条数（等待处理完毕）。
	deadline := time.Now().Add(2 * time.Second)
	n := 0
	for {
		select {
		case <-credCh:
			n++
		default:
			if time.Now().After(deadline) {
				if n != credsPerConnLimit {
					t.Fatalf("凭据条数 = %d, 期望恰好 %d", n, credsPerConnLimit)
				}
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
}

// TestMalformedCredsNotRecorded D-A（audit Major）：畸形凭据（含控制字节）
// 不落库——框架层 validCredText 过滤批量注入噪声。
func TestMalformedCredsNotRecorded(t *testing.T) {
	credCh := make(chan event.CredEvent, 16)
	_, addrs := startTestServer(t, []string{"ftp"}, credCh, nil)
	c := dialProto(t, addrs, "ftp")
	br := bufio.NewReader(c)
	if s, err := br.ReadString('\n'); err != nil || !strings.HasPrefix(s, "220") {
		t.Fatalf("banner = %q err=%v", s, err)
	}
	// 用户名/密码含控制字节（\x00、\x01）——畸形，不应落库。
	_, _ = c.Write([]byte("USER bad\x00user\r\n"))
	_, _ = br.ReadString('\n') // 331
	_, _ = c.Write([]byte("PASS bad\x01pass\r\n"))
	_, _ = br.ReadString('\n') // 530
	// 正常凭据（验证过滤不影响合法捕获）。
	_, _ = c.Write([]byte("USER good\r\n"))
	_, _ = br.ReadString('\n')
	_, _ = c.Write([]byte("PASS ok123\r\n"))
	_, _ = br.ReadString('\n')
	ev := recvCred(t, credCh)
	if ev.Username != "good" || ev.Password != "ok123" {
		t.Fatalf("正常凭据 = %+v（畸形凭据应被过滤）", ev)
	}
	// 畸形凭据不得再产生事件。
	select {
	case ev := <-credCh:
		t.Fatalf("畸形凭据未被过滤: %+v", ev)
	case <-time.After(500 * time.Millisecond):
	}
}
