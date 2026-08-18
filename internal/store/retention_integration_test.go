// AUDIT-005 A-01 集成测试：大库启动（25 万行超期）+ 并发写（模拟高流量）场景，
// 验证启动期 retention 清理不阻塞写路径、事件零丢失、超期存量全部清理。
package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"sentry-agent/internal/event"
)

// waitRetentionDone 轮询 meta.last_retention_ts（独立只读连接，避免与 Run 写线程竞争）。
func waitRetentionDone(t *testing.T, dbPath string, timeout time.Duration) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+url.PathEscape(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var last string
		err := db.QueryRow(`SELECT value FROM meta WHERE key = 'last_retention_ts'`).Scan(&last)
		if err == nil && last != "" {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("retention 首轮清理未在超时内完成（last_retention_ts 未出现）")
}

// TestRunRetentionStartupConcurrentWrites（AUDIT-005 A-01 集成测试）：
// 大库启动（25 万行超期数据）+ 并发写（模拟高流量）场景，验证：
//
//	① 启动期清理不阻塞写路径——清理完成时已有事件落库（旧实现 select 前同步清理
//	   期间 0 落库，通道积压满后 conntrack hook 阻塞 → netlink 缓冲积压 → ENOBUFS
//	   溢出丢事件）；
//	② 全部发送事件零丢失落库；
//	③ 超期存量全部清理。
//
// 区分新旧行为的真实机制：生产者发送带超时（sendErr）——旧实现清理期间通道满，
// 生产者阻塞超过超时即失败；断言①（清理完成时已落库）为辅助观测。已知边界：
// 极快机器上清理耗时可能 < 超时值，旧实现可能通过全部断言（测试有效性边界，记录）。
func TestRunRetentionStartupConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	ch := event.NewChannels(64) // 小容量模拟真实 4096 满场景（更易暴露阻塞）
	var producers sync.WaitGroup
	st, err := NewStore(dbPath, filepath.Join(dir, "archive"),
		200, 50, 6, 7, 60, 90, ch, &producers)
	if err != nil {
		t.Fatalf("NewStore 失败: %v", err)
	}
	defer st.Close()

	// 预插 25 万行超期数据（事务批量插入加速）。
	old := nowSec() - 30*86400
	if _, err := st.db.Exec("BEGIN"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 250000; i++ {
		if _, err := st.db.Exec(`INSERT INTO connections (ts, ev_type, proto, src_ip, src_port, dst_ip, dst_port) VALUES (?,?,?,?,?,?,?)`,
			old, 1, 6, 1, 1, 2, 22); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.db.Exec("COMMIT"); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		if err := st.Run(ctx); err != nil {
			t.Errorf("Run 失败: %v", err)
		}
	}()

	// 并发写：模拟高流量（生产者发送带超时，阻塞即失败——区分新旧行为的核心断言）。
	const n = 2000
	producers.Add(1)
	sendErr := make(chan error, 1)
	go func() {
		defer producers.Done()
		for i := 0; i < n; i++ {
			ev := event.ConnEvent{TS: nowSec(), EvType: event.EvNew, Proto: event.ProtoTCP,
				SrcIP: 1, SrcPort: uint16(1000 + i), DstIP: 2, DstPort: 22}
			select {
			case ch.Conn <- ev:
			case <-ctx.Done():
				sendErr <- fmt.Errorf("ctx 取消时仅发送 %d/%d 条", i, n)
				return
			case <-time.After(3 * time.Second):
				sendErr <- fmt.Errorf("生产者发送第 %d 条阻塞超过 3s（启动期清理阻塞写路径）", i)
				return
			}
		}
		sendErr <- nil
	}()

	// 等待首轮清理完成（meta.last_retention_ts 出现）。
	waitRetentionDone(t, dbPath, 60*time.Second)

	// ① 清理完成时已有事件落库（辅助观测：旧实现同步清理期间 0 落库）。
	ro, err := sql.Open("sqlite", "file:"+url.PathEscape(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	var flushed int64
	if err := ro.QueryRow(`SELECT COUNT(*) FROM connections WHERE ts >= ?`, nowSec()-3600).Scan(&flushed); err != nil {
		t.Fatal(err)
	}
	if flushed == 0 {
		t.Error("清理完成时保留期内 0 行落库——启动期清理阻塞写路径（AUDIT-005 A-01 未整改）")
	}

	// 等待生产者发送完成（无阻塞超时）。
	if err := <-sendErr; err != nil {
		t.Fatal(err)
	}

	cancel()
	select {
	case <-runDone:
	case <-time.After(15 * time.Second):
		t.Fatal("Run 未在超时内退出（疑似死锁）")
	}

	// ② 零丢失验证：保留期内行数 = 发送数。
	var kept int64
	if err := ro.QueryRow(`SELECT COUNT(*) FROM connections WHERE ts >= ?`, nowSec()-3600).Scan(&kept); err != nil {
		t.Fatal(err)
	}
	if kept != n {
		t.Errorf("保留期内行数 = %d, 期望 %d（启动期事件丢失）", kept, n)
	}
	// ③ 超期存量全部清理。
	var stale int64
	if err := ro.QueryRow(`SELECT COUNT(*) FROM connections WHERE ts < ?`, nowSec()-3600).Scan(&stale); err != nil {
		t.Fatal(err)
	}
	if stale != 0 {
		t.Errorf("超期存量 = %d, 期望 0（25 万行未清理）", stale)
	}
}
