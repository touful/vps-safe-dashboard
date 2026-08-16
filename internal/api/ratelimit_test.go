package api

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestTokenBucket 令牌桶基本语义：初始满桶、消耗、耗尽拒绝、时间恢复。
func TestTokenBucket(t *testing.T) {
	b := newTokenBucket(1, 3) // 1 rps / burst 3
	// 初始满桶：连续 3 个允许。
	for i := 0; i < 3; i++ {
		if !b.allow() {
			t.Fatalf("第 %d 次应允许（满桶 3）", i+1)
		}
	}
	// 桶空：立即第 4 次拒绝（未到补充时间窗）。
	if b.allow() {
		t.Error("桶空后应立即拒绝")
	}
	// 时间恢复：1.1s 后补充 ~1 令牌，应允许 1 次。
	time.Sleep(1100 * time.Millisecond)
	if !b.allow() {
		t.Error("1.1s 后应补充至少 1 令牌")
	}
	if b.allow() {
		t.Error("补充 1 令牌后仅允许 1 次（剩余 0）")
	}
}

// TestTokenBucketCap 令牌封顶：长时间空闲后桶不超 burst 容量。
func TestTokenBucketCap(t *testing.T) {
	b := newTokenBucket(10, 5) // 10 rps / burst 5
	time.Sleep(1100 * time.Millisecond)
	// 空闲 1.1s 补充 11 令牌，封顶 5 → 恰好允许 5 次，第 6 次拒绝。
	for i := 0; i < 5; i++ {
		if !b.allow() {
			t.Fatalf("第 %d 次应允许（封顶 5）", i+1)
		}
	}
	if b.allow() {
		t.Error("封顶后第 6 次应拒绝")
	}
}

// TestTokenBucketConcurrent 并发安全冒烟：N goroutine 并发消费，通过总数不超过
// burst + 并发期间补充量；且并发下无 panic/竞态（go test -race 下运行）。
func TestTokenBucketConcurrent(t *testing.T) {
	b := newTokenBucket(1000, 10) // 高补充速率，主要验证并发正确性
	const n = 50
	var wg sync.WaitGroup
	var okCount atomic.Int64
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if b.allow() {
				okCount.Add(1)
			}
		}()
	}
	wg.Wait()
	if okCount.Load() < 1 || okCount.Load() > 10 {
		t.Errorf("并发通过数 = %d, 期望 1~10（burst 10 内）", okCount.Load())
	}
}
