//go:build !linux

package api

import "fmt"

// diskUsagePercent 非 Linux 占位（Windows 开发环境返回 -1 语义错误）。
func diskUsagePercent(dir string) (float64, error) {
	return 0, fmt.Errorf("diskUsagePercent 仅支持 Linux")
}
