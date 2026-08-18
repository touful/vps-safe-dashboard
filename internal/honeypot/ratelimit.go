package honeypot

import (
	"sync"
	"time"
)

// ipRateLimiter 每源 IP 固定窗口限速器（防单源连接风暴 DoS）。
// 语义：同一窗口（默认 1 分钟）内单 IP 最多 limit 次 allow；窗口过期自动重置。
// 存储治理：allow 调用时惰性清理过期桶 + 桶数超阈值时全量清理（防恶意多源
// 伪造源 IP 场景下 map 无限增长——蜜罐场景攻击者源 IP 真实可追，阈值兜底）。
type ipRateLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	buckets map[uint32]*ipBucket
	// calls 自上次全量清理以来的 allow 调用计数（触发全量清理节流）。
	calls int
}

// ipBucket 单 IP 窗口计数。
type ipBucket struct {
	count int
	reset time.Time
}

// newIPRateLimiter 创建限速器（limit=每窗口连接数上限，window=窗口时长）。
func newIPRateLimiter(limit int, window time.Duration) *ipRateLimiter {
	return &ipRateLimiter{
		limit:   limit,
		window:  window,
		buckets: make(map[uint32]*ipBucket),
	}
}

// allow 判断该 IP 当前是否允许接入：窗口内未超限返回 true 并计数。
func (r *ipRateLimiter) allow(ip uint32) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	b, ok := r.buckets[ip]
	if !ok || now.After(b.reset) {
		// 新窗口：重置计数（旧桶复用，避免删除重建）。
		if b == nil {
			b = &ipBucket{}
			r.buckets[ip] = b
		}
		b.count = 0
		b.reset = now.Add(r.window)
	}
	if b.count >= r.limit {
		return false
	}
	b.count++
	// 惰性治理：每 1024 次调用触发一次过期桶清理；桶数超阈值时全量清理
	// （超阈场景多为扫描器轮换源 IP，清理后旧桶重建，正确性不受影响）。
	r.calls++
	if r.calls%1024 == 0 || len(r.buckets) > rateLimiterMaxBuckets {
		r.sweep(now)
	}
	return true
}

// sweep 清理过期桶（调用方持锁）。
func (r *ipRateLimiter) sweep(now time.Time) {
	for ip, b := range r.buckets {
		if now.After(b.reset) {
			delete(r.buckets, ip)
		}
	}
	if len(r.buckets) > rateLimiterMaxBuckets {
		// 极端场景兜底：过期清理后仍超阈——按 reset 时间删除最早一批
		// （简化：仅清空重建；蜜罐单进程内存 map 上限 10000 桶 + 每桶 ~80B，
		// 实际峰值约 1MB，重建代价可忽略）。
		r.buckets = make(map[uint32]*ipBucket, rateLimiterMaxBuckets)
	}
}
