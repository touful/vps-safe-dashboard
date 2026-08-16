//go:build linux

package api

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// diskUsagePercent 返回 dir 所在分区使用率（0-100；API summary 展示用）。
func diskUsagePercent(dir string) (float64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, err
	}
	blockSize := uint64(st.Bsize)
	total := st.Blocks * blockSize
	if total == 0 {
		return 0, fmt.Errorf("分区总块数为 0")
	}
	return float64(total-st.Bfree*blockSize) / float64(total) * 100, nil
}
