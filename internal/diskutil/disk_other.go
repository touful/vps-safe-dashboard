//go:build !linux

package diskutil

import "fmt"

// Usage 非 Linux 平台占位实现（保证 Windows 可编译/测试；不用于运行）。
func Usage(dir string) (uint64, uint64, error) {
	return 0, 0, fmt.Errorf("diskutil.Usage 不支持 Linux 以外的平台")
}

// UsagePercent 非 Linux 平台占位实现。
func UsagePercent(dir string) (float64, error) {
	return 0, fmt.Errorf("diskutil.UsagePercent 不支持 Linux 以外的平台")
}
