// Package util 提供跨采集模块复用的无业务语义小工具（周期任务骨架等）。
package util

import (
	"context"
	"time"
)

// Periodic 周期任务骨架：runImmediately 为 true 时启动立即执行一次 fn，
// 之后每 interval 触发一次，直至 ctx 取消返回。
// fn(now) 接收本次触发时刻（需要时间戳的调用方直接使用，避免函数内重复取时）。
// 适用"启动立即执行一次 + ticker for-select"的纯周期场景；
// 分钟粒度时刻匹配（archive.RunArchiver/geoip updater）与 timer 链调度
// （store retention）语义不同，不适用本骨架。
func Periodic(ctx context.Context, interval time.Duration, runImmediately bool, fn func(now time.Time)) {
	if runImmediately {
		fn(time.Now())
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			fn(now)
		}
	}
}
