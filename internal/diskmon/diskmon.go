// Package diskmon 实现磁盘水位监控（方案 7.3 三级告警）。
// diskMonitor 协程每 5 分钟检查归档目录所在分区使用率：
//   - >= emergency（95%）：error 级告警（最高优先级，R-09）
//   - >= critical（90%）：warn 级告警（归档跳过阈值，与 archive.ShouldSkipArchive 衔接）
//   - >= warn（80%）：info/warn 级提示
//
// 分级告警写 system_events，限频防风暴；水位回落至阈值以下时写恢复事件。
package diskmon

import (
	"context"
	"fmt"
	"time"

	"sentry-agent/internal/diskutil"
	"sentry-agent/internal/event"
	"sentry-agent/internal/util"
)

// Level 水位分级。
type Level int

const (
	LevelOK Level = iota
	LevelWarn
	LevelCritical
	LevelEmergency
)

// Classify 按阈值判定水位分级（纯函数，可单测）。
// 输入：使用率百分比与 warn/critical/emergency 阈值（配置校验已保证 warn < critical < emergency）。
func Classify(usagePercent float64, warn, critical, emergency int) Level {
	switch {
	case usagePercent >= float64(emergency):
		return LevelEmergency
	case usagePercent >= float64(critical):
		return LevelCritical
	case usagePercent >= float64(warn):
		return LevelWarn
	}
	return LevelOK
}

// RunDiskMonitor 磁盘水位检查协程（方案 2.3.2 diskMonitor，每 5 分钟）。
// 分级告警写 system_events（限频：同级别 10 分钟内不重复，避免风暴）；
// 水位从非 OK 回落至 OK 时写恢复事件。
// 首轮 checkOnce 返回 level 并同步 lastLevel/lastReport，
// 避免首轮告警后第一个 ticker 周期重复报同级别告警。
func RunDiskMonitor(ctx context.Context, interval time.Duration, dir string, warn, critical, emergency int, sys chan<- event.SystemEvent) error {
	// DEV-ARCH-002 D11：直连 diskutil.UsagePercent（原经 archive.DiskUsagePercent
	// 间接转发，消除不必要依赖链）。
	return RunDiskMonitorWithUsage(ctx, interval, func() (float64, error) {
		return diskutil.UsagePercent(dir)
	}, warn, critical, emergency, sys)
}

// RunDiskMonitorWithUsage 可注入使用率函数的变体（单测用 mock 水位）。
func RunDiskMonitorWithUsage(ctx context.Context, interval time.Duration, usageFn func() (float64, error), warn, critical, emergency int, sys chan<- event.SystemEvent) error {
	var lastLevel Level = LevelOK
	// 限频：每级别 10 分钟内最多一条（按级别独立计时）。
	lastReport := map[Level]time.Time{}
	// 首轮立即检查（M-03：同步 lastLevel/lastReport，防重复告警）。
	// 首轮与周期轮语义不同：首轮只同步状态并上报非 OK 级，不触发
	// "级别回落恢复"与"同级别限频"判定；首轮读取失败仅留痕，后续轮次
	// 进入完整状态机（与原实现逐行为一致）。
	first := true
	util.Periodic(ctx, interval, true, func(now time.Time) {
		usage, err := usageFn()
		if err != nil {
			event.ReportSys(sys, "disk", "warn", "磁盘水位检查失败: "+err.Error())
			first = false
			return
		}
		level := Classify(usage, warn, critical, emergency)
		if first {
			first = false
			lastLevel = level
			if lastLevel != LevelOK {
				report(sys, lastLevel, usage)
				lastReport[lastLevel] = now
			}
			return
		}
		if level != lastLevel {
			// 级别变化（升级或回落）：立即上报。
			report(sys, level, usage)
			if level == LevelOK {
				event.ReportSys(sys, "disk", "info", "磁盘水位已回落至正常")
			}
			lastLevel = level
			lastReport[level] = now
			return
		}
		// 同级别持续：限频上报。
		if level != LevelOK && now.Sub(lastReport[level]) >= 10*time.Minute {
			report(sys, level, usage)
			lastReport[level] = now
		}
	})
	return nil
}

// report 按级别输出告警事件。
func report(sys chan<- event.SystemEvent, level Level, usage float64) {
	switch level {
	case LevelWarn:
		event.ReportSys(sys, "disk", "warn", fmt.Sprintf("磁盘使用率 %.1f%%（warn 阈值）", usage))
	case LevelCritical:
		event.ReportSys(sys, "disk", "warn", fmt.Sprintf("磁盘使用率 %.1f%%（critical，归档将跳过）", usage))
	case LevelEmergency:
		event.ReportSys(sys, "disk", "error", fmt.Sprintf("磁盘使用率 %.1f%%（emergency，最高优先级）", usage))
	}
}

// 注：checkOnce 已删除——首轮检查逻辑并入 RunDiskMonitorWithUsage
// 且同步 lastLevel/lastReport，无需独立封装。
