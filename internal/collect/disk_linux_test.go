//go:build linux

package collect

import (
	"strings"
	"testing"
)

func TestFindRootMount(t *testing.T) {
	content := `82 67 8:48 / / rw,relatime shared:1 - ext4 /dev/sdd rw,discard,errors=remount-ro
85 82 0:29 / /proc rw,nosuid,nodev,noexec,relatime shared:3 - proc proc rw
86 82 0:30 / /sys rw,nosuid,nodev,noexec,relatime shared:4 - sysfs sysfs rw
`
	mp, err := findRootMount(content)
	if err != nil {
		t.Fatalf("findRootMount 报错: %v", err)
	}
	if mp != "/" {
		t.Errorf("根挂载点 = %q, 期望 /", mp)
	}
}

func TestFindRootMountMissing(t *testing.T) {
	content := "85 82 0:29 / /proc rw - proc proc rw\n"
	if _, err := findRootMount(content); err == nil {
		t.Error("缺少根挂载记录时应报错")
	}
}

func TestFindRootMountTruncatedLine(t *testing.T) {
	// 短行（字段不足）应跳过不 panic。
	content := "short line\n82 67 8:48 / / rw,relatime - ext4 /dev/sdd\n"
	mp, err := findRootMount(content)
	if err != nil {
		t.Fatalf("报错: %v", err)
	}
	if mp != "/" || !strings.Contains(content, "ext4") {
		t.Error("解析结果不符")
	}
}
