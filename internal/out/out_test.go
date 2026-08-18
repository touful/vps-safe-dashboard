package out

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"sentry-agent/internal/event"
)

// TEST-001 整改（reviewer R-01）：out 包 conv* 纯函数最小单测，补齐可测纯函数口径缺口。

func TestConvResource(t *testing.T) {
	v := convResource(event.ResourceSample{
		TS: 100, CPUPercent: 12.5, MemUsedMB: 1024.5, MemPercent: 33.3,
		DiskUsedMB: 5000.25, DiskPercent: 66.6, NetRxBps: 12345, NetTxBps: 67890,
	})
	r, ok := v.(resourceOut)
	if !ok {
		t.Fatalf("类型错误: %T", v)
	}
	if r.TS != 100 || r.CPUPercent != 12.5 || r.MemUsedMB != 1024.5 || r.MemPercent != 33.3 ||
		r.DiskUsedMB != 5000.25 || r.DiskPercent != 66.6 || r.NetRxBps != 12345 || r.NetTxBps != 67890 {
		t.Fatalf("字段映射错误: %+v", r)
	}
}

func TestConvConnIPv4(t *testing.T) {
	v := convConn(event.ConnEvent{
		TS: 200, EvType: event.EvNew, Proto: event.ProtoTCP,
		SrcIP: 0xc0a80101, SrcPort: 1234, DstIP: 0x0a000001, DstPort: 80,
		Packets: 10, Bytes: 1000, Mark: 7,
	})
	c, ok := v.(connOut)
	if !ok {
		t.Fatalf("类型错误: %T", v)
	}
	if c.SrcIP != "192.168.1.1" || c.DstIP != "10.0.0.1" || c.SrcPort != 1234 || c.DstPort != 80 ||
		c.EvType != 1 || c.Proto != 6 || c.Packets != 10 || c.Bytes != 1000 || c.Mark != 7 {
		t.Fatalf("字段映射错误: %+v", c)
	}
	if c.SrcIP6 != "" || c.DstIP6 != "" {
		t.Fatalf("IPv4 时 IPv6 字段应为空: %+v", c)
	}
}

func TestConvConnIPv6(t *testing.T) {
	v := convConn(event.ConnEvent{
		TS: 201, EvType: event.EvDestroy, Proto: event.ProtoUDP,
		SrcIP6: "2001:db8::1", DstIP6: "2001:db8::2", SrcPort: 5000, DstPort: 53,
	})
	c, ok := v.(connOut)
	if !ok {
		t.Fatalf("类型错误: %T", v)
	}
	if c.SrcIP6 != "2001:db8::1" || c.DstIP6 != "2001:db8::2" {
		t.Fatalf("IPv6 字段映射错误: %+v", c)
	}
	if c.SrcIP != "0.0.0.0" || c.DstIP != "0.0.0.0" { // IPv6 时 uint32 为 0
		t.Fatalf("IPv6 时 IP 字段应为 0.0.0.0: %+v", c)
	}
}

func TestConvSSH(t *testing.T) {
	v := convSSH(event.SSHAttempt{
		TS: 300, SrcIP: 0xcb007105, Username: "root", AuthMethod: "password",
		Result: event.ResultFail, Fingerprint: "SHA256:abc", Detail: "line",
	})
	s, ok := v.(sshOut)
	if !ok {
		t.Fatalf("类型错误: %T", v)
	}
	if s.SrcIP != "203.0.113.5" || s.Username != "root" || s.AuthMethod != "password" ||
		s.Result != 0 || s.Fingerprint != "SHA256:abc" || s.Detail != "line" || s.TS != 300 {
		t.Fatalf("字段映射错误: %+v", s)
	}
}

func TestConvFW(t *testing.T) {
	v := convFW(event.FirewallEvent{
		TS: 400, Chain: "input", Action: "drop", Proto: event.ProtoTCP,
		SrcIP: 0xc0a80101, SrcPort: 9999, DstIP: 0xc0a80102, DstPort: 22, Raw: "raw line",
	})
	f, ok := v.(fwOut)
	if !ok {
		t.Fatalf("类型错误: %T", v)
	}
	if f.Chain != "input" || f.Action != "drop" || f.Proto != 6 ||
		f.SrcIP != "192.168.1.1" || f.SrcPort != 9999 || f.DstIP != "192.168.1.2" || f.DstPort != 22 ||
		f.Raw != "raw line" {
		t.Fatalf("字段映射错误: %+v", f)
	}
}

func TestConvF2B(t *testing.T) {
	v := convF2B(event.BanEvent{TS: 500, IP: 0x0a000001, Type: "ban", Jail: "sshd"})
	b, ok := v.(f2bOut)
	if !ok {
		t.Fatalf("类型错误: %T", v)
	}
	if b.IP != "10.0.0.1" || b.Type != "ban" || b.Jail != "sshd" || b.TS != 500 {
		t.Fatalf("字段映射错误: %+v", b)
	}
}

// tsOf 各事件类型统一提取 TS。
func TestTsOf(t *testing.T) {
	if got := tsOf(event.ResourceSample{TS: 1}); got != 1 {
		t.Fatalf("ResourceSample ts = %d", got)
	}
	if got := tsOf(event.ConnEvent{TS: 2}); got != 2 {
		t.Fatalf("ConnEvent ts = %d", got)
	}
	if got := tsOf(event.OverrunInfo{TS: 3}); got != 3 {
		t.Fatalf("OverrunInfo ts = %d", got)
	}
	if got := tsOf(event.SSHAttempt{TS: 4}); got != 4 {
		t.Fatalf("SSHAttempt ts = %d", got)
	}
	if got := tsOf(event.FirewallEvent{TS: 5}); got != 5 {
		t.Fatalf("FirewallEvent ts = %d", got)
	}
	if got := tsOf(event.BanEvent{TS: 6}); got != 6 {
		t.Fatalf("BanEvent ts = %d", got)
	}
	if got := tsOf(event.SystemEvent{TS: 7}); got != 7 {
		t.Fatalf("SystemEvent ts = %d", got)
	}
}

// ===== M2 新增：两阶段排空协议测试（auditor M-02） =====

// TestRunDrainNoLoss 验证两阶段排空协议：ctx 取消瞬间生产者仍未退出（wg 未释放）时，
// 在途事件不丢失（consume 先等 producers.Wait() 再 drain）。
func TestRunDrainNoLoss(t *testing.T) {
	ch := event.NewChannels(16)
	var producers sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	var buf bytes.Buffer
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = Run(ctx, &buf, ch, &producers, nil)
	}()

	const n = 5
	producers.Add(1)
	go func() {
		defer producers.Done()
		for i := 0; i < n; i++ {
			ch.Conn <- event.ConnEvent{TS: int64(i), EvType: event.EvNew, Proto: event.ProtoTCP,
				SrcIP: 0xCB007105, SrcPort: 50022, DstIP: 0x0A000002, DstPort: 22}
		}
		// 在途窗口：所有 send 完成后仍保持生产者未退出 200ms，
		// 验证排空会等待 producers.Wait() 而非立即 drain。
		time.Sleep(200 * time.Millisecond)
	}()

	// 等待部分事件进入缓冲后立即取消（触发排空路径）。
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("out.Run 未在超时内退出（疑似死锁）")
	}

	got := strings.Count(buf.String(), `"channel":"conn"`)
	if got != n {
		t.Errorf("排空后 conn 事件数 = %d, 期望 %d（两阶段排空失败，存在丢失）", got, n)
	}
}

// TestRunNormalFlow 常规消费路径：ctx 取消前事件正常输出。
func TestRunNormalFlow(t *testing.T) {
	ch := event.NewChannels(16)
	var producers sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	var buf bytes.Buffer
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = Run(ctx, &buf, ch, &producers, nil)
	}()
	producers.Add(1)
	go func() {
		defer producers.Done()
		ch.System <- event.SystemEvent{TS: 1, Source: "test", Level: "info", Message: "hello"}
		time.Sleep(50 * time.Millisecond)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(buf.String(), `"hello"`) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if !strings.Contains(buf.String(), `"hello"`) {
		t.Error("system 事件未输出")
	}
	if !strings.Contains(buf.String(), `"channel":"system"`) {
		t.Error("system 通道标记缺失")
	}
}
