package api

import (
	"golang.org/x/time/rate"
)

// tokenBucket 简单令牌桶（VS-04 API 速率限制，DEV-P1-001）。
// DEV-ARCH-002 E12：内部实现由手写令牌桶替换为 golang.org/x/time/rate.Limiter
// （官方维护、语义等价：容量 burst 初始满桶、每次 Allow 消耗 1 令牌、按 rate 惰性补充）。
// 保留 tokenBucket 薄封装以最小化调用点改动（newTokenBucket/allow API 不变，
// 测试与 api.go 调用点零改动）。
type tokenBucket struct {
	lim *rate.Limiter
}

// newTokenBucket 创建令牌桶（rate/burst 须为正数，调用方保证配置校验已通过）。
// 参数名 rps 避免遮蔽 golang.org/x/time/rate 包名。
func newTokenBucket(rps, burst float64) *tokenBucket {
	return &tokenBucket{lim: rate.NewLimiter(rate.Limit(rps), int(burst))}
}

// allow 尝试消耗一个令牌；成功返回 true，桶空返回 false。
func (b *tokenBucket) allow() bool {
	return b.lim.Allow()
}
