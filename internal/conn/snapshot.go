package conn

import (
	"bufio"
	"context"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"sentry-agent/internal/event"
)

// RunConnSnapshotter 每 interval 执行一次 `ss -tanup` 并解析为当前连接列表（方案 3.2.3）。
// latest 保存最新 *event.ConnSnapshot（atomic.Value），仅供面板"当前连接列表"与"活跃连接数"使用，
// 不落库（全量记录由 conntrack 通道承担）。快照会漏短连接（已知，SEA-001），由 conntrack 补偿。
func RunConnSnapshotter(ctx context.Context, interval time.Duration, latest *atomic.Value, sys chan<- event.SystemEvent) error {
	// 启动即取一次快照，避免首帧为空。
	_ = snapshotOnce(latest, sys)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			_ = snapshotOnce(latest, sys)
		}
	}
}

// snapshotOnce 执行一次 ss 快照并写入 latest。
func snapshotOnce(latest *atomic.Value, sys chan<- event.SystemEvent) error {
	out, err := exec.Command("ss", "-tanup").Output()
	if err != nil {
		event.ReportSys(sys, "conntrack", "warn", "执行 ss -tanup 失败: "+err.Error())
		return err
	}
	conns, err := ParseSSOutput(string(out))
	if err != nil {
		event.ReportSys(sys, "conntrack", "warn", "解析 ss 输出失败: "+err.Error())
		return err
	}
	// 现场核查结论 8：活跃连接数改读 count 文件（/proc/net/nf_conntrack
	// 因 CONFIG_NF_CONNTRACK_PROCFS not set 不存在，sysctl count 文件可读）；
	// 读取失败 Cnt=-1（fallback 等无模块环境预期），API 回退 ss 口径，不告警。
	latest.Store(&event.ConnSnapshot{TS: time.Now().Unix(), Conn: conns, Cnt: readConntrackCount(conntrackCountPath)})
	return nil
}

// ParseSSOutput 解析 `ss -tanup` 输出（纯函数，可单测）。
// 行示例（netid state recv-q send-q Local Peer [process]）：
//
//	tcp   ESTAB 0      0      10.0.0.2:22    10.0.0.1:50542  users:(("sshd",pid=1234,fd=3))
//	udp   ESTAB 0      0      10.0.0.2:53    10.0.0.1:54321  users:(("dnsmasq",pid=999,fd=5))
//
// 方向语义：ss 的 Local 列为本机侧、Peer 列为远端。
// 本模块统一按"本机侧=目的（Dst）、远端=源（Src）"赋值——与 conntrack 事件方向语义对齐，
// 使攻击场景（外部源 → 本机被攻击端口）中攻击者恒为 Src、被攻击端口恒为 Dst。
// 已知限制：ss 输出无连接方向标记，出站连接（本机主动发起）方向会反置；
// 该通道为展示/近似用途（fallback B5 亦基于此），面板标注"近似通道"；
// 入站为主的 VPS 场景语义正确。展示层如需精确方向，由 API 结合本机端口判定（M3）。
//
// 已知限制：IPv6 连接不在快照中（SnapConn 仅含 IPv4 字段，展示通道口径，conntrack 通道补齐）。
func ParseSSOutput(content string) ([]event.SnapConn, error) {
	var out []event.SnapConn
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "Netid") || strings.HasPrefix(line, "State") {
			continue
		}
		if sc, ok := parseSSLine(line); ok {
			out = append(out, sc)
		}
	}
	return out, scanner.Err()
}

// rePid 提取 ss 行尾进程信息中的 pid=NNN。
var rePid = regexp.MustCompile(`pid=(\d+)`)

// parseSSLine 解析单行 ss 输出（纯函数，可单测）。
// 列布局：netid state recv-q send-q local peer [users]（Local 为第 5 列）。
func parseSSLine(line string) (event.SnapConn, bool) {
	fields := strings.Fields(line)
	if len(fields) < 6 {
		return event.SnapConn{}, false
	}
	var sc event.SnapConn
	switch fields[0] {
	case "tcp":
		sc.Proto = event.ProtoTCP
	case "udp":
		sc.Proto = event.ProtoUDP
	default:
		return event.SnapConn{}, false // 仅 TCP/UDP（方案 3.2.3 口径）
	}
	sc.State = fields[1]
	sc.Pid = -1
	// 方向语义：Local（本机侧）→ Dst，Peer（远端）→ Src（见 ParseSSOutput 注释）。
	localIP, localPort, ok1 := parseAddrPort(fields[4])
	peerIP, peerPort, ok2 := parseAddrPort(fields[5])
	if !ok1 || !ok2 {
		return event.SnapConn{}, false
	}
	sc.DstIP, sc.DstPort = localIP, localPort
	sc.SrcIP, sc.SrcPort = peerIP, peerPort
	if m := rePid.FindStringSubmatch(line); len(m) == 2 {
		if pid, err := strconv.Atoi(m[1]); err == nil {
			sc.Pid = pid
		}
	}
	return sc, true
}

// parseAddrPort 解析 "IP:port" 或 "*:22"/"0.0.0.0:*" 形式的地址。
// IPv6（带 []）返回 false（快照展示通道限制）。* 视为 0.0.0.0；port 的 * 视为 0。
func parseAddrPort(s string) (uint32, uint16, bool) {
	idx := strings.LastIndexByte(s, ':')
	if idx < 0 {
		return 0, 0, false
	}
	ipStr, portStr := s[:idx], s[idx+1:]
	if ipStr == "*" {
		ipStr = "0.0.0.0"
	}
	if portStr == "*" {
		portStr = "0"
	}
	ip := net.ParseIP(ipStr)
	if ip == nil || ip.To4() == nil {
		return 0, 0, false
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return 0, 0, false
	}
	return event.IPv4ToUint32(ip), uint16(port), true
}
