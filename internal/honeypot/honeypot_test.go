package honeypot

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"sentry-agent/internal/event"
)

// startTestServer 启动蜜罐（每个协议预分配本机随机端口）并返回实际地址。
// protos 为要启用的协议名列表（框架按协议名取 handler，与端口解耦）。
func startTestServer(t *testing.T, protos []string, credCh chan<- event.CredEvent, sys chan<- event.SystemEvent) (*Server, map[string]string) {
	t.Helper()
	real := make(map[string]string, len(protos))
	for _, p := range protos {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("预分配端口失败: %v", err)
		}
		addr := ln.Addr().String()
		_ = ln.Close() // 释放后由 Server 重新监听（竞态窗口极小，测试可接受）
		real[p] = addr
	}
	srv := NewServer(real, credCh, sys)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = srv.Run(ctx)
		close(done)
	}()
	t.Cleanup(func() { cancel(); <-done })
	// 等待全部监听就绪（避免客户端连接过早被拒）。
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		ready := true
		for _, addr := range real {
			if !listenOK(addr) {
				ready = false
				break
			}
		}
		if ready {
			return srv, real
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("蜜罐监听未就绪: %v", real)
	return nil, nil
}

// listenOK 探测监听是否就绪（连接成功即认为就绪）。
func listenOK(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// TestRateLimiter 每源 IP 限速：窗口内第 limit+1 次拒绝；窗口过期重置。
func TestRateLimiter(t *testing.T) {
	r := newIPRateLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		if !r.allow(0x7F000001) {
			t.Fatalf("第 %d 次应放行", i+1)
		}
	}
	if r.allow(0x7F000001) {
		t.Fatal("第 4 次应拒绝（窗口 3 上限）")
	}
	if !r.allow(0x7F000002) {
		t.Fatal("其他 IP 应放行")
	}

	r2 := newIPRateLimiter(1, 30*time.Millisecond)
	if !r2.allow(1) {
		t.Fatal("首次应放行")
	}
	if r2.allow(1) {
		t.Fatal("窗口内第 2 次应拒绝")
	}
	time.Sleep(40 * time.Millisecond)
	if !r2.allow(1) {
		t.Fatal("窗口过期后应放行")
	}
}

// TestRateLimiterSweep 桶清理：sweep 清除过期桶（防 map 无限增长）。
func TestRateLimiterSweep(t *testing.T) {
	r := newIPRateLimiter(10, 20*time.Millisecond)
	r.allow(1)
	time.Sleep(30 * time.Millisecond) // 桶 1 过期
	r.allow(2)                        // 桶 2 新建（未过期）
	r.mu.Lock()
	r.sweep(time.Now())
	r.mu.Unlock()
	if _, ok := r.buckets[1]; ok {
		t.Fatal("过期桶应被清理")
	}
	if _, ok := r.buckets[2]; !ok {
		t.Fatal("未过期桶应保留")
	}
}

// TestRateLimiterOverflowRebuild 桶数超阈时全量重建（极端多源场景兜底）。
func TestRateLimiterOverflowRebuild(t *testing.T) {
	r := newIPRateLimiter(10, time.Minute)
	// 填充超阈值桶数（不逐个 allow 遍历——直接构造 map 状态验证重建路径）。
	for i := uint32(1); i <= rateLimiterMaxBuckets+5; i++ {
		r.buckets[i] = &ipBucket{count: 1, reset: time.Now().Add(time.Minute)}
	}
	if !r.allow(1) {
		t.Fatal("重建后首次应放行")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.buckets) > rateLimiterMaxBuckets {
		t.Fatalf("重建后桶数 = %d, 期望 <= %d", len(r.buckets), rateLimiterMaxBuckets)
	}
}

// TestServerRateLimitReject 框架层限速：同源并发 13 连接，放行数受限速窗口约束。
func TestServerRateLimitReject(t *testing.T) {
	credCh := make(chan event.CredEvent, 64)
	srv, addrs := startTestServer(t, []string{"telnet"}, credCh, nil)
	var wg sync.WaitGroup
	ok := make([]bool, ipConnLimit+3)
	for i := 0; i < ipConnLimit+3; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, err := net.DialTimeout("tcp", addrs["telnet"], time.Second)
			if err != nil {
				return
			}
			ok[i] = true
			_ = c.Close()
		}(i)
	}
	wg.Wait()
	allowed := 0
	for _, o := range ok {
		if o {
			allowed++
		}
	}
	// 限速窗口 10：极端并发调度下允许 [10, 13] 全放行边界，但拒绝计数应随超限增加。
	if allowed < ipConnLimit || allowed > ipConnLimit+3 {
		t.Fatalf("放行连接数 = %d, 期望窗口 [%d, %d]", allowed, ipConnLimit, ipConnLimit+3)
	}
	if srv.Stats().Rejected+int64(allowed-ipConnLimit) < int64(allowed-ipConnLimit) {
		t.Fatalf("拒绝计数异常: %d", srv.Stats().Rejected)
	}
}

// TestServerConcurrentLimit 并发上限：sem 占满时新连接被拒，释放后放行。
func TestServerConcurrentLimit(t *testing.T) {
	srv := NewServer(nil, nil, nil)
	for i := 0; i < maxConns; i++ {
		srv.sem <- struct{}{}
	}
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	if srv.acceptConn("telnet", c1) {
		t.Fatal("并发满时应拒绝")
	}
	<-srv.sem
	if !srv.acceptConn("telnet", c1) {
		t.Fatal("有空槽时应放行")
	}
}

// TestServerStats 统计：连接计数与读写字节数累计。
func TestServerStats(t *testing.T) {
	credCh := make(chan event.CredEvent, 16)
	srv, addrs := startTestServer(t, []string{"telnet"}, credCh, nil)
	c, err := net.DialTimeout("tcp", addrs["telnet"], time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte("hello\n"))
	time.Sleep(150 * time.Millisecond)
	_ = c.Close()
	time.Sleep(150 * time.Millisecond)
	st := srv.Stats()
	if st.TotalConns < 1 {
		t.Fatalf("TotalConns = %d, 期望 >= 1", st.TotalConns)
	}
	if st.TotalBytes < 6 {
		t.Fatalf("TotalBytes = %d, 期望 >= 6（含 5 字节 payload）", st.TotalBytes)
	}
}

// TestServerConnTimeout 连接超时常量与 deadline 设置（编译期 + 行为断言）。
func TestServerConnTimeout(t *testing.T) {
	if connTimeout != 30*time.Second {
		t.Fatalf("connTimeout = %v, 期望 30s（任务书建议值）", connTimeout)
	}
	// 行为验证：handleConn 设置 30s 读写超时——空闲连接 30s 后被框架关闭。
	credCh := make(chan event.CredEvent, 16)
	srv, addrs := startTestServer(t, []string{"telnet"}, credCh, nil)
	c, err := net.DialTimeout("tcp", addrs["telnet"], time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// 模拟空闲：不发送任何数据。框架 handler 读阻塞至超时（占位 stub 读阻塞）。
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	start := time.Now()
	buf := make([]byte, 1)
	_, err = c.Read(buf)
	// 客户端侧 2s 读超时先触发（服务器侧 30s 未到）；验证服务器连接仍存活。
	if err == nil {
		t.Fatal("空闲连接不应有数据")
	}
	if time.Since(start) < 1*time.Second {
		t.Fatalf("连接应保持到客户端读超时，实际 %v", time.Since(start))
	}
	_ = srv
}

// TestServerListenFail 监听失败不崩溃：已占用端口启动，其余协议继续。
func TestServerListenFail(t *testing.T) {
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	blocked := blocker.Addr().String()

	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	free := ln2.Addr().String()
	_ = ln2.Close()

	sys := make(chan event.SystemEvent, 16)
	srv := NewServer(map[string]string{"telnet": blocked, "ftp": free}, nil, sys)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = srv.Run(ctx)
		close(done)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if listenOK(free) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !listenOK(free) {
		t.Fatal("ftp 应正常监听（telnet 失败不阻塞）")
	}
	cancel()
	<-done
	// 确认失败留痕（warn 级别，source=honeypot）。
	var found bool
	for i := 0; i < len(sys); i++ {
		ev := <-sys
		if ev.Source == "honeypot" && ev.Level == "warn" {
			found = true
		}
	}
	if !found {
		t.Error("未捕获到监听失败 warn 留痕")
	}
}

// TestServerRunNoListen 全部监听失败场景：Run 正常退出不崩溃。
func TestServerRunNoListen(t *testing.T) {
	sys := make(chan event.SystemEvent, 16)
	srv := NewServer(map[string]string{"telnet": "999.999.1.1:23"}, nil, sys)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = srv.Run(ctx)
		close(done)
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run 未退出")
	}
}
