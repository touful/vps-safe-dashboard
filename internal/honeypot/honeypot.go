// Package honeypot 实现 DEV-HONEY-001 蜜罐假服务（方案 M-B）。
// 对 mysql/redis/memcached/mssql/mongodb/postgres/rdp/smb/telnet/ftp 十种协议的标准端口
// 提供最小认证握手模拟，捕获攻击者尝试登录的用户名/密码（CredEvent → cred_events 表）。
//
// 安全红线（任务书）：
//   - 蜜罐不执行任何命令、不返回真实系统信息（所有响应为伪造的最小握手/拒绝报文）；
//   - 连接治理严格：每连接读写超时（30s）、全局并发上限（200）、每源 IP 限速
//     （10 连接/分钟，超限立即断开）——防 DoS 与资源耗尽；
//   - 凭据仅落本地 SQLite（cred_events），禁止写入日志与 system_events；
//   - system_events 只记录连接/IP/协议（限频防刷屏）。
//
// 已知限制（诚实降级）：rdp 后续 TLS 加密无法解析、memcached 协议无认证机制、
// 加密/哈希协议（mysql/mongodb/mssql/smb）仅能捕获不可逆摘要（Extra 注明 hash 类型）。
package honeypot

import (
	"context"
	"net"
	"strconv"
	"sync"
	"time"

	"sentry-agent/internal/event"
)

// 连接治理常量（任务书建议值定稿；防 DoS 资源面收敛）。
const (
	// connTimeout 单连接读写超时：攻击者长时间挂连不发送数据时回收连接。
	connTimeout = 30 * time.Second
	// maxConns 全局并发连接上限：超出立即断开（防连接耗尽 DoS）。
	maxConns = 200
	// ipConnLimit 每源 IP 连接数上限（固定窗口 ipWindow 内）。
	ipConnLimit = 10
	// ipWindow 每源 IP 限速窗口。
	ipWindow = time.Minute
	// loginRoundsMax telnet 登录轮次上限（防单连接无限循环）。
	loginRoundsMax = 5
	// rateLimiterMaxBuckets IP 限速器活跃桶上限，超过触发惰性清理（防 map 无限增长）。
	rateLimiterMaxBuckets = 10000
)

// protoHandler 单连接协议处理器：完成最小认证握手模拟并调用 rec 记录凭据。
// 约定：conn 生命周期由框架管理（handler 返回后框架统一 Close 与计数）；
// handler 内部读操作应响应 ctx 取消（select 监听 ctx.Done 或依赖连接关闭）。
// rec 已自动填充 TS/Proto/SrcIP，handler 仅需提供 Username/Password/Extra。
type protoHandler func(ctx context.Context, conn net.Conn, srcIP uint32, rec func(event.CredEvent))

// protoHandlers 协议处理器注册表（internal/honeypot 各协议文件实现）。
var protoHandlers = map[string]protoHandler{
	"telnet":    handleTelnet,
	"ftp":       handleFTP,
	"redis":     handleRedis,
	"postgres":  handlePostgres,
	"mysql":     handleMySQL,
	"mongodb":   handleMongoDB,
	"mssql":     handleMSSQL,
	"smb":       handleSMB,
	"rdp":       handleRDP,
	"memcached": handleMemcached,
}

// Stats 蜜罐运行统计（连接治理与容量观测）。
type Stats struct {
	TotalConns int64 // 累计通过治理并开始处理的连接数（限速/并发拒绝不计入）
	Active     int64 // 当前活跃连接数
	TotalBytes int64 // 累计读写字节数
	Rejected   int64 // 被限速/并发上限拒绝的连接数
	CredEvents int64 // 累计捕获凭据事件数
}

// Server 蜜罐服务：配置驱动监听 + 连接治理 + 凭据事件投递。
type Server struct {
	listen map[string]string // 启用协议 → 监听地址（配置注入，运行期只读）
	credCh chan<- event.CredEvent
	sys    chan<- event.SystemEvent
	// addrs 协议 → 实际监听地址（Run 填充；支持 ":0" 自动分配端口，
	// 测试与动态端口场景经 Addrs 回读）。
	addrs map[string]string

	// 治理
	sem chan struct{}   // 全局并发上限信号量（容量 maxConns）
	rl  *ipRateLimiter  // 每源 IP 限速
	rep *event.RateLimiter // system_events 连接留痕限频（1/分钟）

	// 统计
	mu    sync.Mutex
	stats Stats
}

// NewServer 创建蜜罐服务。
// listen 为 协议→监听地址 映射（已由 config.Validate 校验；空串协议跳过；
// 地址 ":0" 表示自动分配端口，实际端口经 Addrs 回读）。
// credCh 为凭据事件通道（event.Channels.Cred，落库）；sys 为 system_events 通道
// （连接/IP/协议留痕，限频）。两者均可为 nil（nil channel 静默丢弃，测试便利）。
func NewServer(listen map[string]string, credCh chan<- event.CredEvent, sys chan<- event.SystemEvent) *Server {
	return &Server{
		listen: listen,
		credCh: credCh,
		sys:    sys,
		addrs:  make(map[string]string, len(listen)),
		sem:    make(chan struct{}, maxConns),
		rl:     newIPRateLimiter(ipConnLimit, ipWindow),
		rep:    event.NewRateLimiter(time.Minute),
	}
}

// Run 运行蜜罐直至 ctx 取消：为每个启用协议启动独立监听 goroutine。
// 单个协议监听失败（端口被占用等）：记录 system_events + 日志，不崩溃，其余协议继续。
func (s *Server) Run(ctx context.Context) error {
	var lns []net.Listener
	var mu sync.Mutex
	var wg sync.WaitGroup     // 监听 goroutine
	var connWG sync.WaitGroup // 在途连接 goroutine（R-07 reviewer 整改：关闭时等待在途连接处理完毕，
	// 避免最长 30s 超时窗口内的凭据事件丢失——先 wg.Wait 再 connWG.Wait，保证 Add 全部完成）
	for proto, addr := range s.listen {
		if addr == "" {
			continue // 空串 = 禁用该协议
		}
		proto, addr := proto, addr
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			event.ReportSys(s.sys, "honeypot", "warn",
				"蜜罐 "+proto+" 监听 "+addr+" 失败（协议禁用，其余继续）: "+err.Error())
			continue
		}
		mu.Lock()
		lns = append(lns, ln)
		s.addrs[proto] = ln.Addr().String()
		mu.Unlock()
		event.ReportSys(s.sys, "honeypot", "info", "蜜罐 "+proto+" 监听 "+ln.Addr().String())
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.serveProto(ctx, proto, ln, &connWG)
		}()
	}
	if len(lns) == 0 {
		event.ReportSys(s.sys, "honeypot", "warn", "蜜罐启用但无任何协议监听成功（检查 honeypot.listen 配置与端口占用）")
	}
	<-ctx.Done()
	mu.Lock()
	for _, ln := range lns {
		_ = ln.Close() // 关闭全部监听：accept 阻塞返回错误，serveProto 感知 ctx 后退出
	}
	mu.Unlock()
	wg.Wait()     // 监听循环全部退出后，再无新连接进入 connWG
	connWG.Wait() // 等待在途连接处理完毕（最长 connTimeout 30s），关闭窗口凭据不丢
	return nil
}

// serveProto 单协议 accept 循环：连接治理（限速/并发）在接入点执行。
// connWG 跟踪在途连接 goroutine（Run 关闭路径等待，见 Run）。
func (s *Server) serveProto(ctx context.Context, proto string, ln net.Listener, connWG *sync.WaitGroup) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			// 瞬时错误（如 EMFILE 抖动）：短暂退避后继续（不崩溃）。
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if !s.acceptConn(proto, conn) {
			continue // 治理拒绝：acceptConn 内已关闭连接并统计
		}
		connWG.Add(1)
		go func() {
			defer connWG.Done()
			s.handleConn(proto, conn)
		}()
	}
}

// acceptConn 连接接入治理：限速检查 → 并发上限检查；任一拒绝立即断开。
// 拒绝路径统计 Rejected（运维可观测防 DoS 面）。
func (s *Server) acceptConn(proto string, conn net.Conn) bool {
	srcIP := remoteIPv4(conn)
	if !s.rl.allow(srcIP) {
		s.mu.Lock()
		s.stats.Rejected++
		s.mu.Unlock()
		_ = conn.Close()
		s.rep.Report(s.sys, "honeypot", "info",
			"限速拒绝 "+proto+" 连接（源 "+event.Uint32ToIPv4(srcIP)+"，超 10 连接/分钟）")
		return false
	}
	select {
	case s.sem <- struct{}{}:
	default:
		s.mu.Lock()
		s.stats.Rejected++
		s.mu.Unlock()
		_ = conn.Close()
		s.rep.Report(s.sys, "honeypot", "warn",
			"并发上限拒绝 "+proto+" 连接（当前活跃达 "+strconv.Itoa(maxConns)+"）")
		return false
	}
	return true
}

// handleConn 单连接处理：超时设置 → 统计 → 协议握手 → 凭据记录。
func (s *Server) handleConn(proto string, conn net.Conn) {
	defer func() {
		<-s.sem
		_ = conn.Close()
		s.mu.Lock()
		s.stats.Active--
		s.mu.Unlock()
	}()

	srcIP := remoteIPv4(conn)
	_ = conn.SetDeadline(time.Now().Add(connTimeout))
	s.mu.Lock()
	s.stats.TotalConns++
	s.stats.Active++
	s.mu.Unlock()
	// system_events 连接留痕（限频 1/分钟，只记连接/IP/协议——红线：不记凭据内容）。
	s.rep.Report(s.sys, "honeypot", "info",
		"蜜罐连接 "+proto+"（源 "+event.Uint32ToIPv4(srcIP)+"）")

	h := protoHandlers[proto]
	if h == nil {
		_ = conn.Close()
		return
	}
	c := &countingConn{Conn: conn}
	h(context.Background(), c, srcIP, func(ev event.CredEvent) {
		ev.TS = time.Now().Unix()
		ev.Proto = proto
		ev.SrcIP = srcIP
		s.emit(ev)
	})
	s.mu.Lock()
	s.stats.TotalBytes += c.in + c.out
	s.mu.Unlock()
}

// emit 投递凭据事件（非阻塞：通道满时丢弃并限频留痕，不阻塞连接处理路径）。
func (s *Server) emit(ev event.CredEvent) {
	select {
	case s.credCh <- ev:
		s.mu.Lock()
		s.stats.CredEvents++
		s.mu.Unlock()
	default:
		s.rep.Report(s.sys, "honeypot", "warn", "蜜罐凭据事件通道已满，丢弃 1 条（防阻塞）")
	}
}

// Stats 返回当前统计快照。
func (s *Server) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

// Addrs 返回 协议→实际监听地址 映射（Run 启动后回读；":0" 自动分配端口场景使用）。
// 未就绪的协议不在映射中（调用方轮询等待）。
func (s *Server) Addrs() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]string, len(s.addrs))
	for k, v := range s.addrs {
		out[k] = v
	}
	return out
}

// remoteIPv4 提取远端 IPv4 地址。
// 已知边界（R-08 reviewer 备注）：非 IPv4（IPv6）返回 0——IPv6 连接共享同一
// 0 值限速桶（每 IP 10 连接/分钟 的全局配额）且 CredEvent.SrcIP 归因失真。
// 任务书为 IPv4 语义（VPS 双栈攻击面主要为 IPv4），IPv6 单独分桶留待后续。
func remoteIPv4(conn net.Conn) uint32 {
	ra := conn.RemoteAddr()
	if ra == nil {
		return 0
	}
	ta, ok := ra.(*net.TCPAddr)
	if !ok {
		return 0
	}
	return event.IPv4ToUint32(ta.IP)
}

// countingConn 计数包装连接（统计读写字节数，TotalBytes 观测用）。
type countingConn struct {
	net.Conn
	in  int64
	out int64
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.in += int64(n)
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.out += int64(n)
	return n, err
}
