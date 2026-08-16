package ssh

import (
	"net"
	"regexp"
	"time"

	"sentry-agent/internal/event"
)

// ParseSSHLine 解析一行 SSH 认证日志（纯函数，可单测）。
// 覆盖方案 3.3 要求的所有行模式；ts 为日志事件时间（Unix 秒，由调用方提供）。
// 返回 ok=false 表示行不属于可识别模式（调用方限频记录 system_event）。
//
// 行前缀归一化：rsyslog 文本行带 "Jan 01 00:00:00 host sshd[123]: " 前缀，
// journald 的 MESSAGE 字段无前缀；先剥离前者再匹配消息模式。
func ParseSSHLine(line string, ts int64) (event.SSHAttempt, bool) {
	msg := stripPrefix(line)
	for _, p := range sshPatterns {
		m := p.re.FindStringSubmatch(msg)
		if m == nil {
			continue
		}
		attempt := event.SSHAttempt{
			TS:         ts,
			Username:   m[p.idxUser],
			AuthMethod: p.method,
			Result:     p.result,
			Detail:     event.Truncate512(line),
		}
		if p.idxFingerprint >= 0 && m[p.idxFingerprint] != "" {
			attempt.Fingerprint = m[p.idxFingerprint]
		}
		if ip := net.ParseIP(m[p.idxIP]); ip != nil {
			attempt.SrcIP = event.IPv4ToUint32(ip)
			// 已知限制：IPv6 源地址登录尝试的 SrcIP 为 0（SSHAttempt 无 IPv6 字段，
			// M1 记录；VPS 场景 IPv4 为主，M2 DDL 如需 IPv6 支持再扩展）。
		}
		return attempt, true
	}
	return event.SSHAttempt{}, false
}

// sshPattern 一条 SSH 日志匹配规则。
type sshPattern struct {
	re             *regexp.Regexp
	method         string
	result         int
	idxUser        int
	idxIP          int
	idxFingerprint int
}

// rePrefix 剥离 rsyslog 行首时间/主机/进程前缀。
var rePrefix = regexp.MustCompile(`^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+sshd\[\d+\]:\s*`)

// stripPrefix 返回剥离 syslog 前缀后的消息体；无前缀时原样返回。
func stripPrefix(line string) string {
	return rePrefix.ReplaceAllString(line, "")
}

// parseSyslogTimestamp 解析 syslog 行首时间戳（格式 "Jan 02 15:04:05"，如 "Aug 13 12:30:00"）。
// 返回 Unix 秒；无法解析返回 ok=false。跨年处理：解析结果晚于当前时间超过 24h 时按上年推算
// （syslog 无年份字段，M1 采用此推断；M2 若需精确跨年可扩展）。
func parseSyslogTimestamp(line string) (int64, bool) {
	if len(line) < 15 || line[3] != ' ' {
		return 0, false
	}
	t, err := time.ParseInLocation("Jan _2 15:04:05", line[:15], time.Local)
	if err != nil {
		return 0, false
	}
	now := time.Now()
	t = time.Date(now.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.Local)
	if t.After(now.Add(24 * time.Hour)) {
		t = t.AddDate(-1, 0, 0) // 跨年日志（如 1 月日志在 12 月读取）
	}
	return t.Unix(), true
}

// sshPatterns 全部可识别模式（顺序即优先级：invalid user 变体必须先于普通 Failed password）。
// 指纹提取：publickey 行格式 "ssh2: <算法> <指纹>"，取指纹 token。
var sshPatterns = []sshPattern{
	{
		re:     regexp.MustCompile(`^Failed password for invalid user (\S+) from (\S+) port (\d+)`),
		method: "password", result: event.ResultFail,
		idxUser: 1, idxIP: 2, idxFingerprint: -1,
	},
	{
		re:     regexp.MustCompile(`^Failed password for (\S+) from (\S+) port (\d+)`),
		method: "password", result: event.ResultFail,
		idxUser: 1, idxIP: 2, idxFingerprint: -1,
	},
	{
		re:     regexp.MustCompile(`^Accepted password for (\S+) from (\S+) port (\d+)`),
		method: "password", result: event.ResultOK,
		idxUser: 1, idxIP: 2, idxFingerprint: -1,
	},
	{
		re:     regexp.MustCompile(`^Accepted publickey for (\S+) from (\S+) port (\d+) ssh2: \S+ (\S+)`),
		method: "publickey", result: event.ResultOK,
		idxUser: 1, idxIP: 2, idxFingerprint: 4,
	},
	{
		re:     regexp.MustCompile(`^Failed publickey for (\S+) from (\S+) port (\d+) ssh2: \S+ (\S+)`),
		method: "publickey", result: event.ResultFail,
		idxUser: 1, idxIP: 2, idxFingerprint: 4,
	},
	{
		re:     regexp.MustCompile(`^Invalid user (\S+) from (\S+) port (\d+)`),
		method: "", result: event.ResultFail,
		idxUser: 1, idxIP: 2, idxFingerprint: -1,
	},
	{
		re:     regexp.MustCompile(`^Connection closed by authenticating user (\S+) (\S+) port (\d+)`),
		method: "", result: event.ResultUnknown,
		idxUser: 1, idxIP: 2, idxFingerprint: -1,
	},
	{
		// error: maximum authentication attempts exceeded (for <user> 可缺省) from <ip> port <p>
		re:     regexp.MustCompile(`^error: maximum authentication attempts exceeded(?: for (\S+))? from (\S+) port (\d+)`),
		method: "", result: event.ResultFail,
		idxUser: 1, idxIP: 2, idxFingerprint: -1,
	},
}
