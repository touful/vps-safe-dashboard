// Package diskutil 提供磁盘使用率/空间统计（statfs 封装）。
// api/archive/collect 三包重复的 statfs 实现统一收敛于此；
// 纯叶子包，不依赖其他内部包。
package diskutil

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// ErrZeroTotal 分区总块数为 0（异常文件系统；调用方按各自场景决定错误文案）。
var ErrZeroTotal = errors.New("分区总块数为 0")

// Usage 返回 dir 所在文件系统的总/可用字节（statfs，Bfree 口径）。
// statfs 失败返回包装错误；total 为 0 时返回 ErrZeroTotal。
func Usage(dir string) (total, free uint64, err error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, 0, fmt.Errorf("statfs %s 失败: %w", dir, err)
	}
	blockSize := uint64(st.Bsize)
	total = st.Blocks * blockSize
	if total == 0 {
		return 0, 0, ErrZeroTotal
	}
	return total, st.Bfree * blockSize, nil
}

// UsagePercent 返回 dir 所在文件系统的使用率（0-100）。
// 口径与归档水位检查一致（Bfree）；错误语义同 Usage。
func UsagePercent(dir string) (float64, error) {
	total, free, err := Usage(dir)
	if err != nil {
		return 0, err
	}
	return float64(total-free) / float64(total) * 100, nil
}
