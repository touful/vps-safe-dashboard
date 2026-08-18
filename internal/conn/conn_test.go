package conn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/florianl/go-conntrack"

	"sentry-agent/internal/config"
	"sentry-agent/internal/event"
)

// 构造 go-conntrack 的 Con 对象辅助函数（仅测试用）。
func tuple(src, dst string, proto uint8, sport, dport uint16) *conntrack.IPTuple {
	s, d := net.ParseIP(src), net.ParseIP(dst)
	return &conntrack.IPTuple{
		Src: &s, Dst: &d,
		Proto: &conntrack.ProtoTuple{Number: &proto, SrcPort: &sport, DstPort: &dport},
	}
}

func u32(v uint32) *uint32 { return &v }
func u16(v uint16) *uint16 { return &v }
func u8(v uint8) *uint8    { return &v }
func u64(v uint64) *uint64 { return &v }

func TestConnEventFromConIPv4TCPNew(t *testing.T) {
	c := conntrack.Con{
		Info:          &conntrack.InfoSource{NetlinkGroup: conntrack.NetlinkCtNew},
		Origin:        tuple("203.0.113.5", "10.0.0.2", event.ProtoTCP, 50022, 22),
		CounterOrigin: &conntrack.Counter{Packets: u64(3), Bytes: u64(120)},
		Mark:          u32(0x1),
	}
	ev, ok := connEventFromCon(c)
	if !ok {
		t.Fatal("应转换成功")
	}
	if ev.EvType != event.EvNew {
		t.Errorf("EvType = %d, 期望 1", ev.EvType)
	}
	if ev.Proto != event.ProtoTCP || ev.SrcIP != 0xCB007105 || ev.DstIP != 0x0A000002 {
		t.Errorf("五元组错误: proto=%d src=%x dst=%x", ev.Proto, ev.SrcIP, ev.DstIP)
	}
	if ev.SrcPort != 50022 || ev.DstPort != 22 {
		t.Errorf("端口错误: %d/%d", ev.SrcPort, ev.DstPort)
	}
	if ev.Packets != 3 || ev.Bytes != 120 {
		t.Errorf("计数错误: %d/%d", ev.Packets, ev.Bytes)
	}
	if ev.Mark != 1 {
		t.Errorf("Mark = %d, 期望 1", ev.Mark)
	}
	if ev.SrcIP6 != "" || ev.DstIP6 != "" {
		t.Error("IPv4 事件不应有 IPv6 字段")
	}
}

func TestConnEventFromConIPv6(t *testing.T) {
	c := conntrack.Con{
		Info:   &conntrack.InfoSource{NetlinkGroup: conntrack.NetlinkCtUpdate},
		Origin: tuple("2001:db8::1", "2001:db8::2", event.ProtoTCP, 443, 22),
	}
	ev, ok := connEventFromCon(c)
	if !ok {
		t.Fatal("应转换成功")
	}
	if ev.EvType != event.EvUpdate {
		t.Errorf("EvType = %d, 期望 2", ev.EvType)
	}
	if ev.SrcIP6 != "2001:db8::1" || ev.DstIP6 != "2001:db8::2" {
		t.Errorf("IPv6 字段错误: %q/%q", ev.SrcIP6, ev.DstIP6)
	}
	if ev.SrcIP != 0 || ev.DstIP != 0 {
		t.Error("IPv6 事件 IPv4 字段应为 0")
	}
}

func TestConnEventFromConICMP(t *testing.T) {
	c := conntrack.Con{
		Info:   &conntrack.InfoSource{NetlinkGroup: conntrack.NetlinkCtDestroy},
		Origin: tuple("203.0.113.9", "10.0.0.2", event.ProtoICMP, 0, 0),
	}
	ev, ok := connEventFromCon(c)
	if !ok {
		t.Fatal("应转换成功")
	}
	if ev.EvType != event.EvDestroy {
		t.Errorf("EvType = %d, 期望 3", ev.EvType)
	}
	if ev.Proto != event.ProtoICMP {
		t.Errorf("Proto = %d, 期望 1", ev.Proto)
	}
	// 口径：ICMP 端口为 0（即使原 tuple 带端口也清零）。
	if ev.SrcPort != 0 || ev.DstPort != 0 {
		t.Errorf("ICMP 端口应为 0: %d/%d", ev.SrcPort, ev.DstPort)
	}
}

func TestConnEventFromConIncomplete(t *testing.T) {
	// 缺五元组（Origin nil / Proto nil）→ ok=false，不 panic。
	var cases = []conntrack.Con{
		{},
		{Origin: &conntrack.IPTuple{}},
		{Origin: &conntrack.IPTuple{Proto: &conntrack.ProtoTuple{}}},
	}
	for i, c := range cases {
		if _, ok := connEventFromCon(c); ok {
			t.Errorf("case %d 应返回 ok=false", i)
		}
	}
}

func TestConnEventFromConNilPointers(t *testing.T) {
	// 可选字段为 nil（无计数器/无 mark）→ 零值，不 panic。
	s, d := net.ParseIP("203.0.113.5"), net.ParseIP("10.0.0.2")
	proto := uint8(event.ProtoTCP)
	c := conntrack.Con{
		Info:   &conntrack.InfoSource{NetlinkGroup: conntrack.NetlinkCtNew},
		Origin: &conntrack.IPTuple{Src: &s, Dst: &d, Proto: &conntrack.ProtoTuple{Number: &proto}},
	}
	ev, ok := connEventFromCon(c)
	if !ok {
		t.Fatal("应转换成功")
	}
	if ev.Packets != 0 || ev.Bytes != 0 || ev.Mark != 0 {
		t.Error("nil 可选字段应为零值")
	}
}

func TestDiffSnapshots(t *testing.T) {
	sc := func(proto uint8, sip uint32, sport uint16, dip uint32, dport uint16, state string) event.SnapConn {
		return event.SnapConn{Proto: proto, SrcIP: sip, SrcPort: sport, DstIP: dip, DstPort: dport, State: state}
	}
	a := sc(event.ProtoTCP, 0x0A000002, 22, 0x0A000001, 50542, "ESTAB")
	b := sc(event.ProtoTCP, 0x0A000002, 22, 0x0A000001, 50543, "ESTAB")
	prev := map[string]event.SnapConn{snapKey(a): a}
	cur := map[string]event.SnapConn{
		snapKey(a): sc(event.ProtoTCP, 0x0A000002, 22, 0x0A000001, 50542, "TIME_WAIT"), // 状态变化
		snapKey(b): b,                                                                  // 新增
	}
	evs := diffSnapshots(prev, cur, 1700000000)
	got := map[int]int{}
	for _, e := range evs {
		got[e.EvType]++
		if e.TS != 1700000000 {
			t.Error("事件 TS 应为入参")
		}
	}
	// 1 个 NEW（b）+ 1 个 UPDATE（a 状态变化）；a 未消失。
	if got[event.EvNew] != 1 || got[event.EvUpdate] != 1 || got[event.EvDestroy] != 0 {
		t.Errorf("事件分布错误: %v", got)
	}
	// 全部消失 → 2 个 DESTROY。
	evs2 := diffSnapshots(cur, map[string]event.SnapConn{}, 1)
	if len(evs2) != 2 {
		t.Errorf("消失事件数 = %d, 期望 2", len(evs2))
	}
}

// TestConnStartTracker 启动失败计数状态机（B.4.3）：
// 连续 3 次启动类失败 → giveUp；运行类错误清零计数；混合序列。
func TestConnStartTracker(t *testing.T) {
	var tr connStartTracker
	// 连续 3 次启动失败 → 第 3 次 giveUp。
	if giveUp, fails := tr.record(true); giveUp || fails != 1 {
		t.Fatalf("第 1 次启动失败: giveUp=%v fails=%d, 期望 false/1", giveUp, fails)
	}
	if giveUp, fails := tr.record(true); giveUp || fails != 2 {
		t.Fatalf("第 2 次启动失败: giveUp=%v fails=%d, 期望 false/2", giveUp, fails)
	}
	if giveUp, fails := tr.record(true); !giveUp || fails != 3 {
		t.Fatalf("第 3 次启动失败应 giveUp: giveUp=%v fails=%d", giveUp, fails)
	}

	// 运行类错误清零计数（主通道曾成功启动，之后运行期错误不累计启动失败）。
	tr = connStartTracker{}
	tr.record(true) // 1 次启动失败
	tr.record(true) // 2 次启动失败
	if giveUp, fails := tr.record(false); giveUp || fails != 0 {
		t.Fatalf("运行类错误应清零: giveUp=%v fails=%d, 期望 false/0", giveUp, fails)
	}
	// 清零后重新计数。
	if giveUp, _ := tr.record(true); giveUp {
		t.Fatal("清零后首次启动失败不应 giveUp")
	}
	if giveUp, fails := tr.record(true); giveUp || fails != 2 {
		t.Fatalf("清零后第 2 次: giveUp=%v fails=%d, 期望 false/2", giveUp, fails)
	}
}

// TestConnStartErrorWrap 启动类错误包装可被 errors.As 识别（外层分类依据）。
func TestConnStartErrorWrap(t *testing.T) {
	err := &connStartError{err: fmt.Errorf("打开 conntrack netlink 失败: %v", errors.New("permission denied"))}
	var se *connStartError
	if !errors.As(err, &se) {
		t.Fatal("connStartError 应可被 errors.As 识别")
	}
	if !strings.Contains(err.Error(), "conntrack netlink") {
		t.Errorf("错误文案应透传根因: %v", err)
	}
	// 普通错误不应被识别为启动类。
	if errors.As(errors.New("netlink 监听循环终止"), &se) {
		t.Fatal("普通错误不应被分类为启动类")
	}
}

// mockOnce 构造可注入的 once 执行器（测试辅助）。
func mockOnce(fn func() error) func(context.Context, config.ConntrackCfg, int, chan<- event.ConnEvent, chan<- event.OverrunInfo, chan<- event.SystemEvent, *atomic.Uint64) error {
	return func(context.Context, config.ConntrackCfg, int, chan<- event.ConnEvent, chan<- event.OverrunInfo, chan<- event.SystemEvent, *atomic.Uint64) error {
		return fn()
	}
}

// TestRunConntrackLoopGiveUp（B.4.5）：Open 失败 ×3 → 第 3 次后放弃主通道，
// 返回错误由 main 切换 B5 降级；告警文案含降级语义。
func TestRunConntrackLoopGiveUp(t *testing.T) {
	ctx := context.Background()
	sys := make(chan event.SystemEvent, 16)
	once := mockOnce(func() error {
		return &connStartError{err: fmt.Errorf("打开 conntrack netlink 失败: %v", errors.New("operation not permitted"))}
	})
	// 退避 2s→4s：3 次启动失败总等待 = 2+4 = 6s（可接受）。
	start := time.Now()
	err := runConntrackLoop(ctx, config.ConntrackCfg{}, 2048, nil, nil, sys, nil, once)
	if err == nil {
		t.Fatal("连续 3 次启动失败应返回错误（触发降级）")
	}
	if !strings.Contains(err.Error(), "放弃主通道") {
		t.Errorf("错误应含放弃主通道语义: %v", err)
	}
	// 3 次失败 = 2 条重启告警（第 3 次直接返回，不告警）+ 3 次等待（2+4s）。
	if time.Since(start) < 5*time.Second {
		t.Errorf("应经历退避等待（>=5s），实际 %v", time.Since(start))
	}
	// 告警文案含"放弃并降级"提示。
	found := false
	for i := 0; i < len(sys); i++ {
		ev := <-sys
		if strings.Contains(ev.Message, "放弃并降级") {
			found = true
		}
	}
	if !found {
		t.Error("重启告警应含'连续 N 次后放弃并降级'提示")
	}
}

// TestRunConntrackLoopRuntimeReset（B.4.3）：运行类错误清零启动失败计数——
// 启动失败×2 后出现运行类错误（主通道曾成功），再启动失败×2 仍不放弃。
func TestRunConntrackLoopRuntimeReset(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sys := make(chan event.SystemEvent, 16)
	calls := 0
	once := mockOnce(func() error {
		calls++
		switch calls {
		case 1, 2, 4, 5:
			return &connStartError{err: fmt.Errorf("打开 conntrack netlink 失败: %v", errors.New("denied"))}
		case 3:
			return errors.New("netlink 监听循环终止（运行类）") // 运行类：清零计数
		default:
			cancel() // 第 6 次前取消，退出循环
			return nil
		}
	})
	err := runConntrackLoop(ctx, config.ConntrackCfg{}, 2048, nil, nil, sys, nil, once)
	if err != nil {
		t.Fatalf("运行类错误清零后不应放弃主通道，实际: %v", err)
	}
	if calls != 6 {
		t.Errorf("调用次数 = %d, 期望 6（2 失败 + 1 运行 + 2 失败 + 1 取消）", calls)
	}
}

// TestRunConntrackLoopCtxCancel ctx 取消即退出（nil）。
func TestRunConntrackLoopCtxCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	once := mockOnce(func() error { return nil })
	if err := runConntrackLoop(ctx, config.ConntrackCfg{}, 2048, nil, nil, nil, nil, once); err != nil {
		t.Errorf("ctx 取消应返回 nil: %v", err)
	}
}
