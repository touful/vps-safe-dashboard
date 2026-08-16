package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"sentry-agent/internal/event"
	"sentry-agent/internal/out"
)

// newTestStore 创建临时目录上的 Store（不启动 Run）。
func newTestStore(t *testing.T, ch *out.Channels, producers *sync.WaitGroup) *Store {
	t.Helper()
	dir := t.TempDir()
	st, err := NewStore(filepath.Join(dir, "state.db"), filepath.Join(dir, "archive"),
		1000, 500, 6, 90, ch, producers)
	if err != nil {
		t.Fatalf("NewStore 失败: %v", err)
	}
	return st
}

// TestStoreSchema 建库后表结构齐全（方案 4.2 DDL）。
func TestStoreSchema(t *testing.T) {
	ch := out.NewChannels(16)
	st := newTestStore(t, ch, &sync.WaitGroup{})
	defer st.Close()

	for _, table := range []string{"resources", "connections", "ssh_attempts", "firewall_events", "ban_events", "system_events", "meta"} {
		var name string
		err := st.db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&name)
		if err != nil {
			t.Errorf("表 %s 不存在: %v", table, err)
		}
	}
	// WAL 模式生效。
	var mode string
	if err := st.db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil {
		t.Fatalf("查询 journal_mode 失败: %v", err)
	}
	if mode != "wal" {
		t.Errorf("journal_mode = %s, 期望 wal", mode)
	}
}

// TestWriteBatch 各事件类型批量写入正确。
func TestWriteBatch(t *testing.T) {
	ch := out.NewChannels(16)
	st := newTestStore(t, ch, &sync.WaitGroup{})
	defer st.Close()

	items := []eventItem{
		{kind: "resource", v: event.ResourceSample{TS: 100, CPUPercent: 1.5, MemUsedMB: 10, MemPercent: 5, DiskUsedMB: 20, DiskPercent: 8, NetRxBps: 100, NetTxBps: 50}},
		{kind: "conn", v: event.ConnEvent{TS: 101, EvType: event.EvNew, Proto: event.ProtoTCP, SrcIP: 0xCB007105, SrcPort: 50022, DstIP: 0x0A000002, DstPort: 22, Packets: 1, Bytes: 40, Mark: 1}},
		{kind: "ssh", v: event.SSHAttempt{TS: 102, SrcIP: 0xCB007105, Username: "root", AuthMethod: "password", Result: 0, Detail: "x"}},
		{kind: "fw", v: event.FirewallEvent{TS: 103, Chain: "input", Action: "drop", Proto: event.ProtoTCP, SrcIP: 0xCB007105, SrcPort: 50022, DstIP: 0x0A000002, DstPort: 22, Raw: "SENTRY_FW:input:drop IN=lo"}},
		{kind: "f2b", v: event.BanEvent{TS: 104, IP: 0xCB007105, Type: "ban", Jail: "sshd"}},
		{kind: "system", v: event.SystemEvent{TS: 105, Source: "test", Level: "info", Message: "m"}},
		{kind: "overrun", v: event.OverrunInfo{TS: 106, Dropped: 3}},
	}
	if err := st.writeBatch(items); err != nil {
		t.Fatalf("writeBatch 失败: %v", err)
	}
	// overrun 落 system_events（R-10 留痕）。
	counts := map[string]int64{
		"resources": 1, "connections": 1, "ssh_attempts": 1,
		"firewall_events": 1, "ban_events": 1,
	}
	for table, want := range counts {
		var n int64
		if err := st.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
			t.Fatalf("查询 %s 失败: %v", table, err)
		}
		if n != want {
			t.Errorf("%s 行数 = %d, 期望 %d", table, n, want)
		}
	}
	var sysN int64
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM system_events`).Scan(&sysN); err != nil {
		t.Fatal(err)
	}
	if sysN != 2 {
		t.Errorf("system_events 行数 = %d, 期望 2（system + overrun）", sysN)
	}
}

// TestWriteBatchIPv6 IPv6 连接落库（方案 4.1：IPv6 存 TEXT）。
func TestWriteBatchIPv6(t *testing.T) {
	ch := out.NewChannels(16)
	st := newTestStore(t, ch, &sync.WaitGroup{})
	defer st.Close()
	items := []eventItem{
		{kind: "conn", v: event.ConnEvent{TS: 1, EvType: event.EvNew, Proto: event.ProtoTCP,
			SrcIP: 0, SrcPort: 443, DstIP: 0, DstPort: 22, SrcIP6: "2001:db8::1", DstIP6: "2001:db8::2"}},
	}
	if err := st.writeBatch(items); err != nil {
		t.Fatalf("writeBatch 失败: %v", err)
	}
	var src6, dst6 string
	if err := st.db.QueryRow(`SELECT src_ip6, dst_ip6 FROM connections LIMIT 1`).Scan(&src6, &dst6); err != nil {
		t.Fatal(err)
	}
	if src6 != "2001:db8::1" || dst6 != "2001:db8::2" {
		t.Errorf("IPv6 字段错误: %q/%q", src6, dst6)
	}
}

// TestStoreRunDrainNoLoss 端到端：Run 消费 + 两阶段关闭，落库行数与发送数一致（零丢失）。
func TestStoreRunDrainNoLoss(t *testing.T) {
	ch := out.NewChannels(64)
	var producers sync.WaitGroup
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	st, err := NewStore(dbPath, filepath.Join(dir, "archive"), 500, 10, 6, 90, ch, &producers)
	if err != nil {
		t.Fatalf("NewStore 失败: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		if err := st.Run(ctx); err != nil {
			t.Errorf("Run 失败: %v", err)
		}
		_ = st.Close()
	}()

	const n = 30
	producers.Add(1)
	go func() {
		defer producers.Done()
		for i := 0; i < n; i++ {
			ch.Conn <- event.ConnEvent{TS: int64(i), EvType: event.EvNew, Proto: event.ProtoTCP,
				SrcIP: 1, SrcPort: 100, DstIP: 2, DstPort: 22}
		}
		time.Sleep(150 * time.Millisecond) // 在途窗口（cancel 后仍未 Done）
	}()

	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case <-runDone:
	case <-time.After(10 * time.Second):
		t.Fatal("Store.Run 未在超时内退出（疑似死锁）")
	}

	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var got int64
	if err := db.QueryRow(`SELECT COUNT(*) FROM connections`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != n {
		t.Errorf("落库行数 = %d, 期望 %d（两阶段关闭零丢失失败）", got, n)
	}
}

// TestRequestArchiveQueue 归档请求队列投递。
func TestRequestArchiveQueue(t *testing.T) {
	ch := out.NewChannels(16)
	st := newTestStore(t, ch, &sync.WaitGroup{})
	defer st.Close()
	if err := st.RequestArchive("2026-07"); err != nil {
		t.Errorf("RequestArchive 失败: %v", err)
	}
	if len(st.archiveReq) != 1 {
		t.Errorf("队列长度 = %d, 期望 1", len(st.archiveReq))
	}
}

// TestBatchLatency 千行批量写入延迟（V3 目标：<50ms/批，方案 4.5/11.2）。
func TestBatchLatency(t *testing.T) {
	ch := out.NewChannels(16)
	st := newTestStore(t, ch, &sync.WaitGroup{})
	defer st.Close()

	const n = 1000
	items := make([]eventItem, 0, n)
	for i := 0; i < n; i++ {
		items = append(items, eventItem{kind: "conn", v: event.ConnEvent{
			TS: int64(i), EvType: event.EvNew, Proto: event.ProtoTCP,
			SrcIP: 0xCB007105, SrcPort: uint16(1000 + i), DstIP: 0x0A000002, DstPort: 22,
		}})
	}
	start := time.Now()
	if err := st.writeBatch(items); err != nil {
		t.Fatalf("writeBatch 失败: %v", err)
	}
	elapsed := time.Since(start)
	t.Logf("1000 行批量写入耗时: %v", elapsed)
	if elapsed > 50*time.Millisecond {
		t.Errorf("批延迟 %v 超过目标 50ms（V3 预算）", elapsed)
	}
	var got int64
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM connections`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != n {
		t.Errorf("行数 = %d, 期望 %d", got, n)
	}
}
