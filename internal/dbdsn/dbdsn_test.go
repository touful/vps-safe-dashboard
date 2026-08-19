package dbdsn

import (
	"strings"
	"testing"
)

// TestReadWritePragmas（DEV-ARCH-002 R-04）：主库读写 DSN 含全部 4 个 pragma。
func TestReadWritePragmas(t *testing.T) {
	dsn := ReadWrite("/var/lib/sentry-agent/state.db")
	for _, want := range []string{
		"journal_mode(WAL)",
		"synchronous(NORMAL)",
		"busy_timeout(5000)",
		"foreign_keys(1)",
	} {
		if !strings.Contains(dsn, want) {
			t.Errorf("ReadWrite DSN 缺 pragma %q: %s", want, dsn)
		}
	}
	if !strings.HasPrefix(dsn, "file:") {
		t.Errorf("ReadWrite DSN 应以 file: 开头: %s", dsn)
	}
}

// TestReadWriteEscape（DEV-ARCH-002 R-04）：路径特殊字符转义与 ReadOnly 对称。
func TestReadWriteEscape(t *testing.T) {
	if got := ReadWrite("q?.db"); !strings.Contains(got, "q%3F.db") {
		t.Errorf("ReadWrite 路径 '?' 未转义: %s", got)
	}
}
