//go:build linux

package archive

import (
	"sentry-agent/internal/diskutil"
)

// DiskUsagePercent 返回 dir 所在文件系统的使用率（0-100）。
// 归档执行前的水位检查（方案 7.3：critical 90% 时跳过归档）。
// 注：statfs 实现统一收敛至 diskutil（对外 API 与错误语义不变）。
func DiskUsagePercent(dir string) (float64, error) {
	return diskutil.UsagePercent(dir)
}
