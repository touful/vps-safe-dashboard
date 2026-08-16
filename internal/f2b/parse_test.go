package f2b

import (
	"testing"
	"time"
)

func TestParseF2BLine(t *testing.T) {	cases := []struct {
		name   string
		line   string
		wantOK bool
		wantIP uint32
		wantT  string
		wantJ  string
	}{
		{
			name: "Ban",
			line: "2023-01-01 00:00:00,123 fail2ban.actions [2912]: NOTICE  [sshd] Ban 203.0.113.5",
			wantOK: true, wantIP: 0xCB007105, wantT: "ban", wantJ: "sshd",
		},
		{
			name: "Unban",
			line: "2023-01-01 00:00:01,456 fail2ban.actions [2912]: NOTICE  [sshd] Unban 203.0.113.5",
			wantOK: true, wantIP: 0xCB007105, wantT: "unban", wantJ: "sshd",
		},
		{
			name: "Found",
			line: "2023-01-01 00:00:02,789 fail2ban.filter  [2912]: INFO    [sshd] Found 198.51.100.7",
			wantOK: true, wantIP: 0xC6336407, wantT: "found", wantJ: "sshd",
		},
		{
			name: "Ban with failures suffix",
			line: "2023-01-01 00:00:03,000 fail2ban.actions [2912]: NOTICE  [sshd] Ban 198.51.100.8 (5 failures)",
			wantOK: true, wantIP: 0xC6336408, wantT: "ban", wantJ: "sshd",
		},
		{
			name: "Other jail",
			line: "2023-01-01 00:00:04,000 fail2ban.actions [2912]: NOTICE  [postfix-smtp] Ban 203.0.113.9",
			wantOK: true, wantIP: 0xCB007109, wantT: "ban", wantJ: "postfix-smtp",
		},
		{
			name:   "Noise line",
			line:   "2023-01-01 00:00:05,000 fail2ban.server [2912]: INFO    Starting server",
			wantOK: false,
		},
		{
			name:   "IPv6 ban skipped",
			line:   "2023-01-01 00:00:06,000 fail2ban.actions [2912]: NOTICE  [sshd] Ban 2001:db8::1",
			wantOK: false,
		},
		{
			name:   "Empty",
			line:   "",
			wantOK: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := ParseF2BLine(c.line, 1700000000)
			if ok != c.wantOK {
				t.Fatalf("ok = %v, 期望 %v", ok, c.wantOK)
			}
			if !ok {
				return
			}
			if got.IP != c.wantIP {
				t.Errorf("IP = %x, 期望 %x", got.IP, c.wantIP)
			}
			if got.Type != c.wantT {
				t.Errorf("Type = %q, 期望 %q", got.Type, c.wantT)
			}
			if got.Jail != c.wantJ {
				t.Errorf("Jail = %q, 期望 %q", got.Jail, c.wantJ)
			}
			if got.TS != 1700000000 {
				t.Errorf("TS = %d, 期望 1700000000", got.TS)
			}
		})
	}
}

// TestParseF2BTime 行首时间戳解析（auditor m-01）。
func TestParseF2BTime(t *testing.T) {
	ts, ok := ParseF2BTime("2026-08-13 00:00:00,123 fail2ban.actions [2912]: NOTICE  [sshd] Ban 1.2.3.4")
	if !ok {
		t.Fatal("应解析成功")
	}
	want := time.Date(2026, 8, 13, 0, 0, 0, 0, time.Local).Unix()
	if ts != want {
		t.Errorf("ts = %d, 期望 %d", ts, want)
	}
	if _, ok := ParseF2BTime("not-a-date line"); ok {
		t.Error("非日期前缀不应解析成功")
	}
	if _, ok := ParseF2BTime(""); ok {
		t.Error("空行不应解析成功")
	}
	if _, ok := ParseF2BTime("2026-13-99 00:00:00"); ok {
		t.Error("非法日期不应解析成功")
	}
}
