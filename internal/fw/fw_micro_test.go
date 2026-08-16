package fw

import (
	"testing"
	"time"
)

// TestJournalMicroTS journal 微秒时间戳解析（TEST-003 reviewer R-01：补齐 §2.2 纳入函数）。
// journalMicroTS 语义：纯数字串 → 微秒/1e6（Unix 秒）；空串/非数字 → 当前时间。
func TestJournalMicroTS(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want int64
	}{
		{"零", "0", 0},
		{"正常微秒", "1786630928000000", 1786630928},
		{"整秒", "1000000", 1},
		{"不足一秒截断", "999999", 0},
		{"多位数", "<WSL_ROOT_PASSWORD>7890<WSL_ROOT_PASSWORD>", <WSL_ROOT_PASSWORD>7890},
		{"前导零", "00000000001000000", 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := journalMicroTS(c.in); got != c.want {
				t.Errorf("journalMicroTS(%q) = %d, 期望 %d", c.in, got, c.want)
			}
		})
	}
	// 错误路径：空串/非数字 → 返回当前时间（前后 2s 窗口）。
	before := time.Now().Unix()
	got := journalMicroTS("")
	after := time.Now().Unix()
	if got < before-2 || got > after+2 {
		t.Errorf("空串回退时间越界: %d（窗口 %d~%d）", got, before-2, after+2)
	}
	got2 := journalMicroTS("abc123")
	if got2 < before-2 || got2 > after+2 {
		t.Errorf("非数字回退时间越界: %d（窗口 %d~%d）", got2, before-2, after+2)
	}
}
