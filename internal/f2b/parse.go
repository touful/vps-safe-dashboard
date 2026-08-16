package f2b

import (
	"net"
	"regexp"
	"strings"
	"time"

	"sentry-agent/internal/event"
)

// reF2B 匹配 fail2ban 事件行：提取 jail 名、动作（Ban/Unban/Found）与 IPv4 地址。
// 行示例：
//
//	2023-01-01 00:00:00,123 fail2ban.actions [2912]: NOTICE  [sshd] Ban 192.168.1.1
//	2023-01-01 00:00:00,123 fail2ban.filter  [2912]: INFO    [sshd] Found 192.168.1.1
//	2023-01-01 00:00:00,123 fail2ban.actions [2912]: NOTICE  [sshd] Unban 192.168.1.1
//
// 注意：Ban/Unban 动作行中可能出现 "Ban 1.2.3.4 (5 failures)" 尾部说明，此处只取 IP。
var reF2B = regexp.MustCompile(`\[([A-Za-z0-9_.-]+)\]\s+(Ban|Unban|Found)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)

// ParseF2BLine 解析单行 fail2ban 日志（纯函数，可单测）。
// 返回 ok=false 表示行不含 Ban/Unban/Found 事件。
// 已知限制：fail2ban 亦可封禁 IPv6 地址（如 "Ban 2001:db8::1"），BanEvent.IP 为
// uint32 仅承载 IPv4；IPv6 封禁事件不产出（M1 记录，VPS 场景 IPv4 为主，M2 需要时扩展）。
func ParseF2BLine(line string, ts int64) (event.BanEvent, bool) {
	m := reF2B.FindStringSubmatch(line)
	if m == nil {
		return event.BanEvent{}, false
	}
	ip := net.ParseIP(m[3])
	if ip == nil {
		return event.BanEvent{}, false
	}
	return event.BanEvent{
		TS:   ts,
		IP:   event.IPv4ToUint32(ip),
		Type: strings.ToLower(m[2]),
		Jail: m[1],
	}, true
}

// ParseF2BTime 解析 fail2ban 日志行首时间戳（格式 "YYYY-MM-DD HH:MM:SS,mmm"，纯函数，可单测）。
// 返回 Unix 秒；无法解析返回 ok=false（调用方回退接收时间）。
func ParseF2BTime(line string) (int64, bool) {
	if len(line) < 19 {
		return 0, false
	}
	t, err := time.ParseInLocation("2006-01-02 15:04:05", line[:19], time.Local)
	if err != nil {
		return 0, false
	}
	return t.Unix(), true
}
