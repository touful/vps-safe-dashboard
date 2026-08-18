package ssh

import (
	"testing"
	"time"

	"sentry-agent/internal/event"
)

// 覆盖方案 3.3 要求的所有行模式。
func TestParseSSHLineAllPatterns(t *testing.T) {
	cases := []struct {
		name     string
		line     string
		wantOK   bool
		wantUser string
		wantIP   uint32
		wantRes  int
		wantMeth string
		wantFP   string
	}{
		{
			name:   "Failed password",
			line:   "Failed password for root from 203.0.113.5 port 50022 ssh2",
			wantOK: true, wantUser: "root", wantIP: 0xCB007105, wantRes: event.ResultFail, wantMeth: "password",
		},
		{
			name:   "Failed password invalid user",
			line:   "Failed password for invalid user admin from 203.0.113.9 port 50123 ssh2",
			wantOK: true, wantUser: "admin", wantIP: 0xCB007109, wantRes: event.ResultFail, wantMeth: "password",
		},
		{
			name:   "Accepted password",
			line:   "Accepted password for alice from 198.51.100.7 port 45210 ssh2",
			wantOK: true, wantUser: "alice", wantIP: 0xC6336407, wantRes: event.ResultOK, wantMeth: "password",
		},
		{
			name:   "Accepted publickey with fingerprint",
			line:   "Accepted publickey for deploy from 198.51.100.8 port 45211 ssh2: RSA SHA256:abcdef<WSL_ROOT_PASSWORD>7890",
			wantOK: true, wantUser: "deploy", wantIP: 0xC6336408, wantRes: event.ResultOK,
			wantMeth: "publickey", wantFP: "SHA256:abcdef<WSL_ROOT_PASSWORD>7890",
		},
		{
			name:   "Failed publickey",
			line:   "Failed publickey for user2 from 203.0.113.10 port 50033 ssh2: ECDSA SHA256:xyz987",
			wantOK: true, wantUser: "user2", wantIP: 0xCB00710A, wantRes: event.ResultFail,
			wantMeth: "publickey", wantFP: "SHA256:xyz987",
		},
		{
			name:   "Invalid user",
			line:   "Invalid user guest from 203.0.113.11 port 50044",
			wantOK: true, wantUser: "guest", wantIP: 0xCB00710B, wantRes: event.ResultFail,
		},
		{
			name:   "Connection closed by authenticating user",
			line:   "Connection closed by authenticating user root 203.0.113.12 port 50055 [preauth]",
			wantOK: true, wantUser: "root", wantIP: 0xCB00710C, wantRes: event.ResultUnknown,
		},
		{
			name:   "Maximum auth attempts exceeded with user",
			line:   "error: maximum authentication attempts exceeded for root from 203.0.113.13 port 50066 ssh2",
			wantOK: true, wantUser: "root", wantIP: 0xCB00710D, wantRes: event.ResultFail,
		},
		{
			name:   "Maximum auth attempts exceeded without user",
			line:   "error: maximum authentication attempts exceeded from 203.0.113.14 port 50077 ssh2",
			wantOK: true, wantUser: "", wantIP: 0xCB00710E, wantRes: event.ResultFail,
		},
		{
			name:   "rsyslog prefixed line",
			line:   "Jan  1 12:00:00 vps sshd[1234]: Failed password for root from 203.0.113.15 port 50088 ssh2",
			wantOK: true, wantUser: "root", wantIP: 0xCB00710F, wantRes: event.ResultFail, wantMeth: "password",
		},
		{
			name:   "Unrelated line",
			line:   "Server listening on 0.0.0.0 port 22.",
			wantOK: false,
		},
		{
			name:   "Empty line",
			line:   "",
			wantOK: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := ParseSSHLine(c.line, 1700000000)
			if ok != c.wantOK {
				t.Fatalf("ok = %v, 期望 %v", ok, c.wantOK)
			}
			if !ok {
				return
			}
			if got.Username != c.wantUser {
				t.Errorf("username = %q, 期望 %q", got.Username, c.wantUser)
			}
			if got.SrcIP != c.wantIP {
				t.Errorf("SrcIP = %x, 期望 %x", got.SrcIP, c.wantIP)
			}
			if got.Result != c.wantRes {
				t.Errorf("Result = %d, 期望 %d", got.Result, c.wantRes)
			}
			if got.AuthMethod != c.wantMeth {
				t.Errorf("AuthMethod = %q, 期望 %q", got.AuthMethod, c.wantMeth)
			}
			if got.Fingerprint != c.wantFP {
				t.Errorf("Fingerprint = %q, 期望 %q", got.Fingerprint, c.wantFP)
			}
			if got.TS != 1700000000 {
				t.Errorf("TS = %d, 期望 1700000000", got.TS)
			}
		})
	}
}

func TestParseSSHLineDetailTruncated(t *testing.T) {
	long := "Failed password for root from 203.0.113.5 port 50022 ssh2 " + string(make([]rune, 600))
	got, ok := ParseSSHLine(long, 1)
	if !ok {
		t.Fatal("应匹配")
	}
	if len([]rune(got.Detail)) != 512 {
		t.Errorf("Detail 长度 = %d, 期望 512", len([]rune(got.Detail)))
	}
}

func TestParseSyslogTimestamp(t *testing.T) {
	// 标准行首时间戳。
	ts, ok := parseSyslogTimestamp("Aug 13 12:30:00 vps sshd[1234]: Failed password for root from 1.2.3.4 port 22")
	if !ok {
		t.Fatal("应解析成功")
	}
	now := time.Now()
	want := time.Date(now.Year(), time.August, 13, 12, 30, 0, 0, time.Local).Unix()
	if ts != want {
		t.Errorf("ts = %d, 期望 %d", ts, want)
	}
	// 单数字日期（"Aug  5" 格式）。
	if _, ok := parseSyslogTimestamp("Aug  5 01:02:03 host sshd[1]: x"); !ok {
		t.Error("单数字日期应解析成功")
	}
	// 非 syslog 行。
	if _, ok := parseSyslogTimestamp("Failed password for root from 1.2.3.4 port 22"); ok {
		t.Error("无时间戳前缀的行不应解析成功")
	}
	if _, ok := parseSyslogTimestamp(""); ok {
		t.Error("空行不应解析成功")
	}
	// 跨年回退：解析时间晚于当前超过 24h 时应减一年。
	future := time.Now().Add(48 * time.Hour)
	fake := future.Format("Jan _2 15:04:05") + " host sshd[1]: x"
	ts2, ok := parseSyslogTimestamp(fake)
	if !ok {
		t.Fatal("未来时间戳应解析成功")
	}
	if time.Unix(ts2, 0).Year() != now.Year()-1 {
		t.Errorf("跨年回退失败: %v", time.Unix(ts2, 0))
	}
}
