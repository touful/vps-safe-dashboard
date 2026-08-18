//go:build linux

package api

import (
	"sentry-agent/internal/diskutil"
)

// diskUsagePercent 返回 dir 所在分区使用率（0-100；API summary 展示用）。
// DEV-AUDIT-001 P1-5：statfs 实现统一收敛至 diskutil（错误语义不变）。
func diskUsagePercent(dir string) (float64, error) {
	return diskutil.UsagePercent(dir)
}
