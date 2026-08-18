//go:build linux

package fw

import "testing"

// TestKmsgSeq kmsg 记录 SEQUENCE 解析（D-09，tester 覆盖率缺口）。
// 记录格式：PRIORITY,SEQUENCE,TIMESTAMP,FLAGS;MESSAGE
func TestKmsgSeq(t *testing.T) {
	cases := []struct {
		name   string
		record []byte
		want   uint64
		wantOK bool
	}{
		{"标准格式", []byte("6,123,456789,-;SENTRY_FW:input:drop IN=eth0"), 123, true},
		{"大序号", []byte("4,4294967295,1,-;x"), 4294967295, true},
		{"多位数", []byte("1,999999,2,-;y"), 999999, true},
		{"回绕后新序号（边界）", []byte("6,0,3,-;z"), 0, true},
		{"无逗号", []byte("12345"), 0, false},
		{"仅优先级无序号", []byte("6,"), 0, false},
		{"非数字序号", []byte("6,abc,1,-;x"), 0, false},
		{"空记录", []byte(""), 0, false},
		{"无分号消息（格式仍应解析序号）", []byte("6,42,1,-"), 42, true},
		// 溢出回绕（uint64 最大值+1 截断）与序号后无逗号。
		{"序号溢出回绕", []byte("6,18446744073709551616,1,-;x"), 0, true}, // 溢出截断为 0
		{"序号后无逗号", []byte("6,123"), 123, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := kmsgSeq(c.record)
			if ok != c.wantOK {
				t.Fatalf("ok = %v, 期望 %v", ok, c.wantOK)
			}
			if ok && got != c.want {
				t.Errorf("seq = %d, 期望 %d", got, c.want)
			}
		})
	}
}
