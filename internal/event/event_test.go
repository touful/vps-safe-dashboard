package event

import (
	"net"
	"testing"
	"time"
)

// event 包纯函数最小单测，补齐可测纯函数口径缺口。

func TestIPv4ToUint32(t *testing.T) {
	cases := []struct {
		name string
		ip   net.IP
		want uint32
	}{
		{"点分十进制", net.ParseIP("192.168.1.1"), 0xc0a80101},
		{"0.0.0.0", net.ParseIP("0.0.0.0"), 0},
		{"255.255.255.255", net.ParseIP("255.255.255.255"), 0xffffffff},
		{"IPv6 返回 0", net.ParseIP("2001:db8::1"), 0},
		{"nil 返回 0", nil, 0},
		{"非法串返回 nil", net.ParseIP("not-an-ip"), 0}, // ParseIP 失败返回 nil，To4 亦 nil
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IPv4ToUint32(c.ip); got != c.want {
				t.Fatalf("IPv4ToUint32(%v) = %d, want %d", c.ip, got, c.want)
			}
		})
	}
}

func TestUint32ToIPv4(t *testing.T) {
	cases := []struct {
		v    uint32
		want string
	}{
		{0xc0a80101, "192.168.1.1"},
		{0, "0.0.0.0"},
		{0xffffffff, "255.255.255.255"},
		{0x0a000001, "10.0.0.1"},
	}
	for _, c := range cases {
		if got := Uint32ToIPv4(c.v); got != c.want {
			t.Fatalf("Uint32ToIPv4(%d) = %q, want %q", c.v, got, c.want)
		}
	}
}

// 往返一致性：IPv4ToUint32 与 Uint32ToIPv4 互逆。
func TestIPv4RoundTrip(t *testing.T) {
	for _, s := range []string{"1.2.3.4", "10.0.0.1", "<LAN_IP>", "8.8.8.8"} {
		v := IPv4ToUint32(net.ParseIP(s))
		if got := Uint32ToIPv4(v); got != s {
			t.Fatalf("round trip %s -> %d -> %s 不一致", s, v, got)
		}
	}
}

func TestTruncate512(t *testing.T) {
	short := "短行"
	if got := Truncate512(short); got != short {
		t.Fatalf("短行不应截断: %q", got)
	}
	// 恰好 512 rune 不截断
	exact := string(make([]rune, 512))
	if got := Truncate512(exact); len([]rune(got)) != 512 {
		t.Fatalf("512 rune 行不应截断，实际 %d", len([]rune(got)))
	}
	// 513 rune 截断为 512（rune 安全，不破坏 UTF-8）
	long := string(make([]rune, 600))
	got := Truncate512(long)
	if len([]rune(got)) != 512 {
		t.Fatalf("600 rune 行应截断为 512，实际 %d", len([]rune(got)))
	}
	// 含中文的多字节字符截断不产生非法 UTF-8（600 rune > 512 触发截断）
	cn := ""
	for i := 0; i < 600; i++ {
		cn += "安"
	}
	got2 := Truncate512(cn)
	if len([]rune(got2)) != 512 {
		t.Fatalf("中文行截断 rune 数错误: %d", len([]rune(got2)))
	}
}

func TestNewRateLimiterAndReport(t *testing.T) {
	sys := make(chan SystemEvent, 10)
	rl := NewRateLimiter(0) // limit=0：每次均可上报
	if rl == nil {
		t.Fatal("NewRateLimiter 返回 nil")
	}
	rl.Report(sys, "ssh", "info", "msg1")
	select {
	case e := <-sys:
		if e.Source != "ssh" || e.Level != "info" || e.Message != "msg1" {
			t.Fatalf("事件字段错误: %+v", e)
		}
	default:
		t.Fatal("limit=0 时应成功上报")
	}
	// limit=1h：连续上报被限频丢弃
	rl2 := NewRateLimiter(time.Hour)
	rl2.Report(sys, "ssh", "info", "a")
	rl2.Report(sys, "ssh", "info", "b")
	select {
	case e := <-sys:
		if e.Message != "a" {
			t.Fatalf("首条应上报，实际 %q", e.Message)
		}
	default:
		t.Fatal("首条应上报")
	}
	select {
	case e := <-sys:
		t.Fatalf("限频期内不应上报第二条，实际收到 %q", e.Message)
	default:
		// 期望丢弃
	}
}

func TestReportSysNilChannel(t *testing.T) {
	// nil channel 不 panic
	ReportSys(nil, "x", "info", "msg")
}

// TestReportSysFullChannel：通道满时丢弃且不阻塞。
func TestReportSysFullChannel(t *testing.T) {
	sys := make(chan SystemEvent, 1)
	sys <- SystemEvent{TS: 1, Source: "pre", Level: "info", Message: "pre"}
	// 通道已满：ReportSys 应丢弃新事件（select default），不阻塞调用方。
	ReportSys(sys, "ssh", "warn", "dropped")
	if len(sys) != 1 {
		t.Fatalf("通道满时不应入队，实际长度 %d", len(sys))
	}
	e := <-sys
	if e.Source != "pre" {
		t.Fatalf("应保留原事件，实际 %+v", e)
	}
}

// TestMicrosToUnix 微秒时间戳解析（DEV-AUDIT-001 P1-5：ssh/fw 共用解析合并后
// 语义保持：纯数字串 → 微秒/1e6；空串/非数字 → ok=false，回退由调用方决定）。
func TestMicrosToUnix(t *testing.T) {
	cases := []struct {
		in   string
		want int64
		ok   bool
	}{
		{"", 0, false},
		{"abc123", 0, false},
		{"123abc", 0, false},
		{"1786870000000000", 1786870000, true},
		{"0", 0, true},
	}
	for _, c := range cases {
		got, ok := MicrosToUnix(c.in)
		if ok != c.ok || got != c.want {
			t.Fatalf("MicrosToUnix(%q) = (%d, %v), 期望 (%d, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}
