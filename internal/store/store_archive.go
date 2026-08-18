package store

import (
	"fmt"
	"time"

	"sentry-agent/internal/archive"
	"sentry-agent/internal/event"
)

// execArchive 在写线程内同步执行归档（方案 3.9：RequestArchive 投递写线程执行）。
// 期间普通事件继续进入 pending 积压（不阻塞、不丢失）。
//
// 归档是写线程内的长操作（导出+压缩），期间写线程停摆、
// 通道背压传导至采集端。方案 3.9 已约定 critical 水位跳过归档——此处落实最小形态：
//  1. 执行前检查归档目录所在分区磁盘水位（critical 90% 或 statfs 失败 → 跳过并告警）；
//  2. 归档开始/完成/失败均写 system_event 留痕（含耗时），故障可观测。
//
// M3 磁盘水位模块完整实现后与本逻辑深度衔接。
//
// 留痕统一在本函数内完成（开始 info / 完成 info 含耗时 / 失败 error 含耗时），
// 调用方（Run 主循环）不再重复上报。
func (s *Store) execArchive(month string) error {
	// 磁盘水位检查（critical 跳过；statfs 失败保守跳过）。
	// 阈值来自配置 disk.critical_percent（R-01：与 diskmon 共用同一配置源）。
	usage, err := archive.DiskUsagePercent(s.archiveDir)
	if archive.ShouldSkipArchive(usage, err == nil, s.archiveCriticalPct) {
		detail := fmt.Sprintf("磁盘使用率 %.1f%%", usage)
		if err != nil {
			detail = "磁盘水位检查失败: " + err.Error()
		}
		event.ReportSys(s.ch.System, "archiver", "warn",
			fmt.Sprintf("归档 %s 跳过（%s，磁盘 critical 水位，方案 7.3）", month, detail))
		return nil
	}

	start := time.Now()
	event.ReportSys(s.ch.System, "archiver", "info", "归档开始: "+month)
	if err := archive.ArchiveMonthDB(s.db, s.archiveDir, month, s.gzipLevel); err != nil {
		event.ReportSys(s.ch.System, "archiver", "error",
			fmt.Sprintf("归档失败: %s（耗时 %v）: %v", month, time.Since(start).Round(time.Millisecond), err))
		return fmt.Errorf("归档 %s 失败: %w", month, err)
	}
	event.ReportSys(s.ch.System, "archiver", "info",
		fmt.Sprintf("归档完成: %s（耗时 %v）", month, time.Since(start).Round(time.Millisecond)))
	return nil
}
