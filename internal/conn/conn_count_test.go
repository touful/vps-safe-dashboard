package conn

import (
	"os"
	"path/filepath"
	"testing"
)

// TestReadConntrackCount（现场核查结论 8）：count 文件读取路径——
// 正常数字、带空白、非数字内容、文件缺失均不崩溃（缺失返回 -1 供调用方回退 ss 口径）。
func TestReadConntrackCount(t *testing.T) {
	dir := t.TempDir()

	t.Run("正常数字", func(t *testing.T) {
		p := filepath.Join(dir, "count1")
		if err := os.WriteFile(p, []byte("31"), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := readConntrackCount(p); got != 31 {
			t.Errorf("readConntrackCount = %d, 期望 31", got)
		}
	})

	t.Run("带换行空白", func(t *testing.T) {
		p := filepath.Join(dir, "count2")
		if err := os.WriteFile(p, []byte("  128\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := readConntrackCount(p); got != 128 {
			t.Errorf("readConntrackCount = %d, 期望 128（TrimSpace）", got)
		}
	})

	t.Run("零值", func(t *testing.T) {
		p := filepath.Join(dir, "count3")
		if err := os.WriteFile(p, []byte("0"), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := readConntrackCount(p); got != 0 {
			t.Errorf("readConntrackCount = %d, 期望 0", got)
		}
	})

	t.Run("非数字内容", func(t *testing.T) {
		p := filepath.Join(dir, "count4")
		if err := os.WriteFile(p, []byte("not-a-number"), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := readConntrackCount(p); got != -1 {
			t.Errorf("readConntrackCount = %d, 期望 -1（解析失败）", got)
		}
	})

	t.Run("文件缺失", func(t *testing.T) {
		if got := readConntrackCount(filepath.Join(dir, "missing")); got != -1 {
			t.Errorf("readConntrackCount = %d, 期望 -1（不可读）", got)
		}
	})
}
