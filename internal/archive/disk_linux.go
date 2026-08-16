//go:build linux

package archive

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// DiskUsagePercent 返回 dir 所在文件系统的使用率（0-100）。
// 归档执行前的水位检查（A-02，方案 7.3：critical 90% 时跳过归档）。
func DiskUsagePercent(dir string) (float64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, fmt.Errorf("statfs %s 失败: %w", dir, err)
	}
	blockSize := uint64(st.Bsize)
	total := st.Blocks * blockSize
	if total == 0 {
		return 0, fmt.Errorf("分区总块数为 0")
	}
	used := total - st.Bfree*blockSize
	return float64(used) / float64(total) * 100, nil
}
