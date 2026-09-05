package logstream

import (
	"context"
	"errors"
	"os/exec"
	"sync"
	"testing"
	"time"
)

// TestRunRestarted 流死亡限频自动重启（审计 M-1）：
// 首次死亡必留痕；1 分钟窗口内的后续死亡不重复留痕；ctx 取消后正常退出且不再重启。
func TestRunRestarted(t *testing.T) {
	oldBase := restartBaseBackoff
	oldMax := restartMaxBackoff
	restartBaseBackoff = 10 * time.Millisecond
	restartMaxBackoff = 20 * time.Millisecond
	defer func() {
		restartBaseBackoff = oldBase
		restartMaxBackoff = oldMax
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	reports := 0
	starts := 0
	// fake run：前两次立即报错（模拟流死亡），第三次起阻塞至 ctx 取消（模拟正常流）。
	run := func(ctx context.Context, cmd *exec.Cmd, name string, onLine func([]byte)) error {
		mu.Lock()
		starts++
		n := starts
		mu.Unlock()
		if n <= 2 {
			return errors.New("test 流提前结束")
		}
		<-ctx.Done()
		return nil
	}
	done := make(chan error, 1)
	go func() {
		done <- runRestarted(ctx, "test",
			func() *exec.Cmd { return exec.Command("true") },
			func([]byte) {},
			func(string) { mu.Lock(); reports++; mu.Unlock() },
			run)
	}()

	deadline := time.Now().Add(3 * time.Second)
	for {
		mu.Lock()
		s, r := starts, reports
		mu.Unlock()
		if s >= 3 {
			if r != 1 {
				t.Fatalf("留痕限频不符预期：两次死亡（间隔远小于 1 分钟）应仅首次留痕，got %d 条", r)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("未按预期重启：starts=%d reports=%d", s, r)
		}
		time.Sleep(5 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("ctx 取消后应返回 nil，got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ctx 取消后未退出")
	}
	mu.Lock()
	defer mu.Unlock()
	if starts != 3 {
		t.Errorf("ctx 取消后不应再重启：starts=%d（want 3）", starts)
	}
}
