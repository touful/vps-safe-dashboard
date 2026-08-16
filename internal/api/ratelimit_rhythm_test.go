package api

import (
	"fmt"
	"testing"
	"time"
)

// TestTokenBucketPageRhythm 模拟页面真实轮询节奏（DEV-P1-001 偶发 429 复现实验）：
// 轮间隔采用浏览器实测真实值（performance 实测 R1→R2=5006ms、R2→R3=4993ms、
// R3→R4=5004ms，后续 ~5000ms）；R1/R2 完整轮（3 heavy）、R3 节流轮（1 heavy）、
// R4~R7 完整轮（3 heavy），同轮 heavy 请求间隔 ~1ms。验证桶在页面节奏下不亏空。
func TestTokenBucketPageRhythm(t *testing.T) {
	b := newTokenBucket(1, 3) // heavy 桶：1 rps / burst 3
	rounds := []struct {
		name    string
		heavy   int
		nextGap time.Duration // 到下一轮的间隔（实测真实值）
	}{
		{"R1", 3, 5006 * time.Millisecond},
		{"R2", 3, 4993 * time.Millisecond},
		{"R3(节流)", 1, 5004 * time.Millisecond},
		{"R4", 3, 5000 * time.Millisecond},
		{"R5", 3, 5000 * time.Millisecond},
		{"R6", 3, 5000 * time.Millisecond},
		{"R7", 3, 0},
	}
	rejected := 0
	for _, rd := range rounds {
		for i := 0; i < rd.heavy; i++ {
			if !b.allow() {
				rejected++
				t.Logf("%s 第 %d 个 heavy 被拒", rd.name, i+1)
			}
			time.Sleep(time.Millisecond) // 同轮请求间隔 ~1ms
		}
		if rd.nextGap > 0 {
			time.Sleep(rd.nextGap)
		}
	}
	t.Logf("页面节奏模拟：7 轮共 19 个 heavy 请求，拒绝 %d 个", rejected)
	if rejected > 0 {
		t.Errorf("页面节奏下出现 %d 个拒绝（稳态 0.6rps 消耗 < 1rps 补充，不应拒绝）", rejected)
	}
}

// TestTokenBucketBurstReject 攻击者突发验证：burst 3 下第 4 个连续请求被拒。
func TestTokenBucketBurstReject(t *testing.T) {
	b := newTokenBucket(1, 3)
	for i := 0; i < 3; i++ {
		if !b.allow() {
			t.Fatalf("第 %d 个应允许", i+1)
		}
	}
	if b.allow() {
		t.Fatal("第 4 个应被拒（burst 3）")
	}
	_ = fmt.Sprintf // 保持 fmt 依赖（日志格式化）
}
