//go:build linux

package collect

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"sentry-agent/internal/diskutil"
)

// diskUsage 计算根分区（挂载点 "/"）的已用空间（MB）与使用率（0-100）。
// 实现：/proc/self/mountinfo 确认根挂载存在并取挂载点，再对挂载点 statfs 获取块计数
// （方案 3.1 允许的路径：/proc/self/mountinfo + statfs）。
// 注意：statfs 必须作用于挂载点路径（如 "/"），不能作用于挂载源设备文件
// （对 /dev/sdX 这类设备文件 statfs 返回 devtmpfs 的统计，数据无意义）。
// DEV-AUDIT-001 P1-5：statfs 实现统一收敛至 diskutil（错误消息与语义不变）。
func diskUsage() (usedMB float64, percent float64, err error) {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return 0, 0, err
	}
	mountPoint, err := findRootMount(string(data))
	if err != nil {
		return 0, 0, err
	}
	total, free, err := diskutil.Usage(mountPoint)
	if err != nil {
		if errors.Is(err, diskutil.ErrZeroTotal) {
			return 0, 0, fmt.Errorf("根分区总块数为 0")
		}
		return 0, 0, err
	}
	used := total - free
	return float64(used) / 1024 / 1024, float64(used) / float64(total) * 100, nil
}

// findRootMount 从 mountinfo 内容中找到挂载点 "/" 的记录，返回其挂载点路径。
// mountinfo 行格式：id parent major:minor root mount_point options ... - fstype source superopts
// 纯函数，可单测。
func findRootMount(content string) (string, error) {
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			continue
		}
		// 第 5 个字段（索引 4）为挂载点。
		if fields[4] == "/" {
			return fields[4], nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("mountinfo 中未找到根挂载记录")
}
