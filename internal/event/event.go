// Package event 定义各采集模块的公共事件类型与常量。
// 类型签名与《技术方案》第 3 章伪代码保持一致：所有时间戳统一为 Unix 秒（int64）。
//
// 时间戳口径（auditor n-03 统一说明，M2 落库固化）：
//   - 日志类通道（ssh/fw/f2b）：TS = 日志源时间戳（journal 条目时间戳 / 行首时间解析），
//     源时间戳缺失时回退为处理时刻；
//   - 事件类通道（conn/overrun）：TS = 处理时刻（内核事件无源时间戳语义，netlink 消息
//     不带内核时间，采用接收时刻；误差为处理延迟，毫秒级）；
//   - 资源采样：TS = 采样时刻。
// 全部为 Unix 秒（int64），落库/API/前端一致。
package event

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// 连接事件类型（对应 conntrack 事件类型映射，见方案 3.2）
const (
	EvNew     = 1 // NEW：新连接建立
	EvUpdate  = 2 // UPDATE：连接状态/计数更新
	EvDestroy = 3 // DESTROY：连接销毁
)

// IP 协议号（与 Linux 内核协议常量一致）
const (
	ProtoTCP  = 6
	ProtoUDP  = 17
	ProtoICMP = 1
)

// SSH 认证结果（见方案 3.3）
const (
	ResultFail    = 0 // 失败
	ResultOK      = 1 // 成功
	ResultUnknown = 2 // 无法判定（如 Connection closed 行）
)

// ResourceSample 资源采样（M-01，方案 3.1）。
type ResourceSample struct {
	TS          int64   // Unix 秒
	CPUPercent  float64 // 0-100，两次采样差值/总时间差计算
	MemUsedMB   float64 // 已用内存（含 buffer/cache 口径：MemTotal - MemAvailable）
	MemPercent  float64 // 内存使用率 0-100
	DiskUsedMB  float64 // 根分区已用空间（/proc/self/mountinfo + statfs）
	DiskPercent float64 // 根分区使用率 0-100
	NetRxBps    uint64  // 接收速率，自上次采样差值按间隔折算
	NetTxBps    uint64  // 发送速率，自上次采样差值按间隔折算
}

// ConnEvent 连接事件（M-02 conntrack 通道，方案 3.2）。
// SrcIP/DstIP 为 IPv4 无符号 32 位（方案 3 章说明：IPv4 统一存无符号 32 位整数）。
// IPv6 连接无法压缩进 uint32，补充 SrcIP6/DstIP6 文本字段（与方案 4.1"IPv6 存 TEXT"口径一致，
// 属接口微扩展，M2 落库时对应 TEXT 列）。
type ConnEvent struct {
	TS      int64  // Unix 秒
	EvType  int    // 1=NEW 2=UPDATE 3=DESTROY
	Proto   uint8  // 6=TCP 17=UDP 1=ICMP
	SrcIP   uint32 // IPv4 无符号 32 位
	SrcPort uint16 // ICMP 时为 0
	DstIP   uint32
	DstPort uint16
	SrcIP6  string // IPv6 源地址（IPv4 时为空）
	DstIP6  string // IPv6 目的地址（IPv4 时为空）
	Packets uint64 // acct 开启时有值，否则 0
	Bytes   uint64 // acct 开启时有值，否则 0
	Mark    uint32 // 防火墙 mark，用于识别被标记的连接
}

// OverrunInfo netlink 溢出信息（R-10 留痕，方案 3.2.1）。
type OverrunInfo struct {
	TS      int64  // Unix 秒
	Dropped uint64 // 本次检查周期内的溢出丢弃数
}

// SnapConn ss 快照中的单条连接（展示通道，不落库，方案 3.2.3）。
type SnapConn struct {
	Proto   uint8
	SrcIP   uint32
	SrcPort uint16
	DstIP   uint32
	DstPort uint16
	State   string // LISTEN/ESTABLISHED/TIME_WAIT/...
	Pid     int    // 本机进程（可空，-1 表示未知）
}

// ConnSnapshot ss 快照（最新值经 atomic.Value 共享，供面板读取）。
// Cnt 为 conntrack 当前连接数（nf_conntrack_count，DEV-033：/proc/net/nf_conntrack 因内核
// 编译配置可能不存在，连接数改读 sysctl count 文件）；-1 表示不可读（调用方回退 ss 口径）。
type ConnSnapshot struct {
	TS   int64
	Conn []SnapConn
	Cnt  int64
}

// SSHAttempt SSH 登录尝试（M-03，方案 3.3）。
type SSHAttempt struct {
	TS          int64  // Unix 秒
	SrcIP       uint32 // IPv4 源地址
	Username    string
	AuthMethod  string // password/publickey/keyboard-interactive/...
	Result      int    // 1=成功 0=失败 2=未知
	Fingerprint string // 公钥指纹（SHA256:...），LogLevel VERBOSE 时可得
	Detail      string // 原始日志行（截断 512 字符）
}

// FirewallEvent 防火墙日志事件（M-04，方案 3.4）。
// 口径警示（方案 3.4 与验收 C-03）：攻击端口统计只允许使用 DPT 字段；
// SSH 认证日志中的 port 是客户端源端口，禁止混用。
type FirewallEvent struct {
	TS      int64
	Chain   string // input/forward（从规则前缀映射，见方案 6.5.3）
	Action  string // drop/reject
	Proto   uint8
	SrcIP   uint32
	SrcPort uint16
	DstIP   uint32
	DstPort uint16
	Raw     string // 原始内核日志行（完整保留）
}

// BanEvent fail2ban 事件（M-05，方案 3.5）。
type BanEvent struct {
	TS   int64
	IP   uint32
	Type string // ban/unban/found
	Jail string // fail2ban jail 名（如 sshd）
}

// SystemEvent 采集器自身事件（溢出/降级/告警，方案 4.2 system_events 表口径）。
// Source 取值：collector/conntrack/ssh/fw/f2b/archiver/disk。
type SystemEvent struct {
	TS      int64
	Source  string
	Level   string // info/warn/error
	Message string
}

// IPv4ToUint32 将 net.IP 转为 IPv4 无符号 32 位；非 IPv4 地址返回 0。
func IPv4ToUint32(ip net.IP) uint32 {
	v4 := ip.To4()
	if v4 == nil {
		return 0
	}
	return uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
}

// Uint32ToIPv4 将无符号 32 位整数还原为点分十进制字符串。
func Uint32ToIPv4(v uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// ReportSys 非阻塞上报 system_event（通道满时丢弃，避免阻塞采集主路径）。
// 所有采集模块的告警/降级/溢出留痕统一经此函数出口。
func ReportSys(sys chan<- SystemEvent, source, level, message string) {
	if sys == nil {
		return
	}
	select {
	case sys <- SystemEvent{TS: time.Now().Unix(), Source: source, Level: level, Message: message}:
	default:
	}
}

// Truncate512 将原始日志行截断到 512 字符（rune 安全，方案 3.3 Detail 字段口径）。
func Truncate512(s string) string {
	const max = 512
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max])
}

// RateLimiter 限频上报器（用于无法匹配行等低频告警场景，如方案 3.3：1/分钟）。
type RateLimiter struct {
	mu    sync.Mutex
	last  time.Time
	limit time.Duration
}

// NewRateLimiter 创建限频上报器。
func NewRateLimiter(limit time.Duration) *RateLimiter {
	return &RateLimiter{limit: limit}
}

// Report 限频上报：距上次上报不足 limit 时丢弃本次。
func (r *RateLimiter) Report(sys chan<- SystemEvent, source, level, message string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Since(r.last) < r.limit {
		return
	}
	r.last = time.Now()
	ReportSys(sys, source, level, message)
}
