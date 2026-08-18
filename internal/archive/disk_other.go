//go:build !linux

package archive

import "fmt"

// DiskUsagePercent 非 Linux 平台占位实现（保证 Windows 本地可编译）。
// 注意：Windows 上执行归档时本函数返回 error，
// execArchive 的 ShouldSkipArchive(statfsOK=false) 会保守跳过归档（warn 留痕可观测）——
// 即 Windows 开发环境归档功能禁用，属可接受的降级行为；归档在 Linux 生产环境运行。
func DiskUsagePercent(dir string) (float64, error) {
	return 0, fmt.Errorf("DiskUsagePercent 仅支持 Linux（Windows 归档禁用）")
}
