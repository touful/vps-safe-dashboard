package api

import (
	"math"
	"sync"
	"time"
)

// tokenBucket 简单令牌桶（VS-04 API 速率限制，DEV-P1-001）。
// 实现：Mutex 保护 + 时间窗按秒补充令牌；无第三方依赖（golang.org/x/time 不在白名单，
// 遵守"无新依赖"约束，任务书 VS-04）。语义为标准令牌桶：
//   - 容量 burst，初始满桶；
//   - 每次 allow 消耗 1 个令牌，令牌不足返回 false；
//   - 每经过 dt 秒补充 rate*dt 个令牌，封顶 burst。
//
// 并发安全：全部方法经互斥锁串行化（简单可靠优先，Q3 任务无极端吞吐要求）。
type tokenBucket struct {
	mu     sync.Mutex
	rate   float64 // 每秒补充令牌数
	burst  float64 // 桶容量（最大突发请求数）
	tokens float64 // 当前可用令牌
	last   time.Time
}

// newTokenBucket 创建令牌桶（rate/burst 须为正数，调用方保证配置校验已通过）。
func newTokenBucket(rate, burst float64) *tokenBucket {
	now := time.Now()
	return &tokenBucket{rate: rate, burst: burst, tokens: burst, last: now}
}

// allow 尝试消耗一个令牌；成功返回 true，桶空返回 false。
func (b *tokenBucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	// 补充自上次请求以来累积的令牌（封顶 burst，避免长时间空闲后瞬间灌满）。
	b.tokens = math.Min(b.burst, b.tokens+now.Sub(b.last).Seconds()*b.rate)
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}
