// SSH 成功登录自动白名单学习测试（DEV-042）。
// 覆盖：启动立即学习、轮询增量更新、查询失败留痕不退出、ctx 取消退出、等待 filter 就绪。
package fw

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"sentry-agent/internal/event"
)

// mockSSHIPSource 模拟成功登录 IP 数据源（可注入错误、可动态追加 IP）。
type mockSSHIPSource struct {
	mu   sync.Mutex
	ips  []uint32
	err  error
	call int
}

func (m *mockSSHIPSource) QuerySuccessfulSSHIPs(ctx context.Context, windowDays int) ([]uint32, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.call++
	return m.ips, m.err
}

// waitDynamicIPs 轮询等待动态白名单达到期望 IP 数（带超时）。
func waitDynamicIPs(t *testing.T, filter *FwFilter, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		p := filter.DynamicExcludeIPs.Load()
		if p != nil && len(*p) == want {
			return
		}
		if time.Now().After(deadline) {
			var cur []net.IP
			if p := filter.DynamicExcludeIPs.Load(); p != nil {
				cur = *p
			}
			t.Fatalf("等待动态白名单 %d 个 IP 超时，当前 %v", want, cur)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestRunSSHLearnerInitial 启动立即学习（验收标准 4）：filter 就绪后立即加载成功登录 IP。
func TestRunSSHLearnerInitial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	src := &mockSSHIPSource{ips: []uint32{u32IP(t, "182.136.147.244")}}
	filter := &FwFilter{}
	filter.SetDynamicExcludeIPs(nil)
	ready := make(chan *FwFilter, 1)
	ready <- filter
	sys := make(chan event.SystemEvent, 8)
	done := make(chan struct{})
	go func() {
		_ = RunSSHLearner(ctx, src, 30, time.Hour, ready, sys)
		close(done)
	}()

	waitDynamicIPs(t, filter, 1)
	p := filter.DynamicExcludeIPs.Load()
	if event.IPv4ToUint32((*p)[0]) != u32IP(t, "182.136.147.244") {
		t.Errorf("动态白名单 = %v, 期望 [182.136.147.244]", *p)
	}
	// 学习留痕（info）。
	select {
	case ev := <-sys:
		if ev.Source != "fw" || ev.Level != "info" {
			t.Errorf("留痕字段错误: %+v", ev)
		}
	case <-time.After(time.Second):
		t.Error("学习留痕未上报")
	}
	cancel()
	<-done
}

// TestRunSSHLearnerPolling 轮询增量更新（验收标准 5）：新成功登录 IP 自动加入白名单。
func TestRunSSHLearnerPolling(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	src := &mockSSHIPSource{ips: []uint32{u32IP(t, "182.136.147.244")}}
	filter := &FwFilter{}
	filter.SetDynamicExcludeIPs(nil)
	ready := make(chan *FwFilter, 1)
	ready <- filter
	sys := make(chan event.SystemEvent, 16)
	done := make(chan struct{})
	go func() {
		_ = RunSSHLearner(ctx, src, 30, 50*time.Millisecond, ready, sys)
		close(done)
	}()

	waitDynamicIPs(t, filter, 1)
	// 模拟新成功登录 IP 出现（操作方 IP 变化：161 → 244 同 C 段不同尾数）。
	src.mu.Lock()
	src.ips = append(src.ips, u32IP(t, "182.136.147.161"))
	src.mu.Unlock()
	waitDynamicIPs(t, filter, 2)
	cancel()
	<-done
}

// TestRunSSHLearnerQueryError 查询失败仅限频留痕不退出（下轮重试）。
func TestRunSSHLearnerQueryError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	src := &mockSSHIPSource{err: errors.New("db 不可用")}
	filter := &FwFilter{}
	filter.SetDynamicExcludeIPs(nil)
	ready := make(chan *FwFilter, 1)
	ready <- filter
	sys := make(chan event.SystemEvent, 8)
	done := make(chan struct{})
	go func() {
		_ = RunSSHLearner(ctx, src, 30, 50*time.Millisecond, ready, sys)
		close(done)
	}()

	select {
	case ev := <-sys:
		if ev.Source != "fw" || ev.Level != "warn" {
			t.Errorf("留痕字段错误: %+v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("查询失败 warn 留痕未上报")
	}
	// 学习器不应退出（继续运行）。
	select {
	case <-done:
		t.Fatal("查询失败不应导致学习器退出")
	case <-time.After(200 * time.Millisecond):
	}
	cancel()
	<-done
}

// TestRunSSHLearnerCtxDone ctx 取消后学习器退出。
func TestRunSSHLearnerCtxDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	src := &mockSSHIPSource{ips: []uint32{}}
	filter := &FwFilter{}
	filter.SetDynamicExcludeIPs(nil)
	ready := make(chan *FwFilter, 1)
	ready <- filter
	sys := make(chan event.SystemEvent, 8)
	done := make(chan struct{})
	go func() {
		_ = RunSSHLearner(ctx, src, 30, time.Hour, ready, sys)
		close(done)
	}()

	// 等待首次学习完成（空列表也更新槽位）。
	waitDynamicIPs(t, filter, 0)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ctx 取消后学习器未退出")
	}
}

// TestRunSSHLearnerWaitFilter filter 未就绪时学习器阻塞等待，投递后开始学习。
func TestRunSSHLearnerWaitFilter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	src := &mockSSHIPSource{ips: []uint32{u32IP(t, "182.136.147.244")}}
	ready := make(chan *FwFilter, 1) // 不立即投递 filter
	sys := make(chan event.SystemEvent, 8)
	done := make(chan struct{})
	go func() {
		_ = RunSSHLearner(ctx, src, 30, time.Hour, ready, sys)
		close(done)
	}()

	// 学习器应阻塞等待 filter 就绪（不退出）。
	select {
	case <-done:
		t.Fatal("filter 未就绪时学习器不应退出")
	case <-time.After(200 * time.Millisecond):
	}
	// 投递 filter（模拟 fw producer 创建后投递）。
	filter := &FwFilter{}
	filter.SetDynamicExcludeIPs(nil)
	ready <- filter
	waitDynamicIPs(t, filter, 1)
	cancel()
	<-done
}
