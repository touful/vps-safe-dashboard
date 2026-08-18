package conn

import (
	"testing"

	"sentry-agent/internal/event"
)

func TestParseSSOutput(t *testing.T) {
	content := `Netid  State   Recv-Q Send-Q  Local Address:Port   Peer Address:Port  Process
tcp    ESTAB   0      0       10.0.0.2:22          10.0.0.1:50542      users:(("sshd",pid=1234,fd=3))
tcp    LISTEN  0      4096    0.0.0.0:22           0.0.0.0:*           
udp    ESTAB   0      0       10.0.0.2:53          10.0.0.1:54321      users:(("dnsmasq",pid=999,fd=5))
`
	conns, err := ParseSSOutput(content)
	if err != nil {
		t.Fatalf("ParseSSOutput 报错: %v", err)
	}
	if len(conns) != 3 {
		t.Fatalf("连接数 = %d, 期望 3", len(conns))
	}
	// tcp ESTAB：入站连接场景（本机 10.0.0.2:22 被 10.0.0.1:50542 连接）
	// 方向语义：Local（本机侧）→ Dst，Peer（远端）→ Src。
	if conns[0].Proto != event.ProtoTCP || conns[0].State != "ESTAB" {
		t.Errorf("conns[0] proto/state 错误: %d/%s", conns[0].Proto, conns[0].State)
	}
	if conns[0].DstIP != 0x0A000002 || conns[0].DstPort != 22 {
		t.Errorf("conns[0] 本机侧（Dst）地址错误: %x:%d", conns[0].DstIP, conns[0].DstPort)
	}
	if conns[0].SrcIP != 0x0A000001 || conns[0].SrcPort != 50542 {
		t.Errorf("conns[0] 远端（Src）地址错误: %x:%d", conns[0].SrcIP, conns[0].SrcPort)
	}
	if conns[0].Pid != 1234 {
		t.Errorf("conns[0] Pid = %d, 期望 1234", conns[0].Pid)
	}
	// tcp LISTEN 通配地址
	if conns[1].State != "LISTEN" || conns[1].DstIP != 0 || conns[1].DstPort != 22 {
		t.Errorf("conns[1] LISTEN 解析错误: %s %x:%d", conns[1].State, conns[1].DstIP, conns[1].DstPort)
	}
	if conns[1].Pid != -1 {
		t.Errorf("conns[1] 无进程信息时 Pid 应为 -1，实际 %d", conns[1].Pid)
	}
	// udp
	if conns[2].Proto != event.ProtoUDP || conns[2].DstPort != 53 || conns[2].SrcPort != 54321 {
		t.Errorf("conns[2] UDP 解析错误: %d %d %d", conns[2].Proto, conns[2].DstPort, conns[2].SrcPort)
	}
	if conns[2].Pid != 999 {
		t.Errorf("conns[2] Pid = %d, 期望 999", conns[2].Pid)
	}
}

// TestParseSSOutputDirection：攻击场景方向语义断言（强制项）。
// 外部源 203.0.113.5 连接本机 10.0.0.2:22：Src 必须为攻击者、Dst 必须为本机被攻击端口。
func TestParseSSOutputDirection(t *testing.T) {
	content := "tcp   ESTAB  0  0  10.0.0.2:22  203.0.113.5:50022  users:((\"sshd\",pid=1234,fd=3))\n"
	conns, err := ParseSSOutput(content)
	if err != nil {
		t.Fatalf("报错: %v", err)
	}
	if len(conns) != 1 {
		t.Fatalf("连接数 = %d, 期望 1", len(conns))
	}
	c := conns[0]
	if c.SrcIP != 0xCB007105 || c.SrcPort != 50022 {
		t.Errorf("攻击者（Src）错误: %x:%d, 期望 cb007105:50022", c.SrcIP, c.SrcPort)
	}
	if c.DstIP != 0x0A000002 || c.DstPort != 22 {
		t.Errorf("被攻击侧（Dst）错误: %x:%d, 期望 a000002:22", c.DstIP, c.DstPort)
	}
}

func TestParseSSOutputIPv6Skipped(t *testing.T) {
	content := "tcp   ESTAB  0  0  [::1]:8080  [::1]:50000"
	conns, err := ParseSSOutput(content)
	if err != nil {
		t.Fatalf("报错: %v", err)
	}
	if len(conns) != 0 {
		t.Errorf("IPv6 行应被跳过，实际 %d 条", len(conns))
	}
}

func TestSnapKeyUniqueness(t *testing.T) {
	a := event.SnapConn{Proto: 6, SrcIP: 0x0A000002, SrcPort: 22, DstIP: 0x0A000001, DstPort: 50542}
	b := event.SnapConn{Proto: 6, SrcIP: 0x0A000001, SrcPort: 50542, DstIP: 0x0A000002, DstPort: 22}
	if snapKey(a) == snapKey(b) {
		t.Error("不同五元组 key 不应相同")
	}
	if snapKey(a) != snapKey(a) {
		t.Error("相同五元组 key 应相同")
	}
}
