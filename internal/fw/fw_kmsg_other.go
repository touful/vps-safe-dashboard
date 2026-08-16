//go:build !linux

package fw

import (
	"context"
	"fmt"
)

// kmsgReadLoop 非 Linux 平台占位实现（保证 Windows 本地可编译/测试，运行期不调用）。
func kmsgReadLoop(ctx context.Context, onLine func(string)) error {
	return fmt.Errorf("kmsg 读取仅支持 Linux")
}
