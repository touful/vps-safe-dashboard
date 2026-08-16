//go:build !linux

package collect

import "fmt"

// diskUsage 非 Linux 平台占位实现（保证 Windows 本地可编译/测试，运行期不调用）。
func diskUsage() (float64, float64, error) {
	return 0, 0, fmt.Errorf("diskUsage 仅支持 Linux")
}
