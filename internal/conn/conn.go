// Package conn 实现 M-02 连接监听模块：
// conntrack 主通道（netlink 事件订阅）+ ss 快照（展示通道）+ B5 降级近似（conntrack 不可用时）。
package conn

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/florianl/go-conntrack"

	"sentry-agent/internal/config"
	"sentry-agent/internal/event"
)

// netlinkNetfilterProto NETLINK_NETFILTER 协议号（/proc/net/netlink 的 Eth 列）。
const netlinkNetfilterProto = 12

// ctGroupsMask 内核 conntrack 组位掩码（/proc/net/netlink Groups 列）：
// 组 1/2/3（NFNLGRP_CONNTRACK_NEW/UPDATE/DESTROY）对应位 0/1/2。
// go-conntrack 的 JoinGroup 成功后内核置位，DEV-036 订阅验证以此为判据。
const ctGroupsMask = 0x7

// netlinkBufferMax netlink 缓冲扩容上限（R-10：可扩至 8MB）。
const netlinkBufferMax = 8 * 1024 * 1024

// freshnessCheckInterval 事件流新鲜度检查间隔（DEV-036：连接采集自检）。
const freshnessCheckInterval = 10 * time.Minute

// conntrackCountPath nf_conntrack 当前连接数（sysctl 接口，模块加载即存在）。
// DEV-033（DEV-032 现场核查结论 7/8）：nf_conntrack 模块依赖链自动加载（无需 modprobe），
// /proc/net/nf_conntrack 不存在是内核编译配置（CONFIG_NF_CONNTRACK_PROCFS not set）非故障；
// 连接数改读本 count 文件（现场验证 count=31，sysctl 可读）。
const conntrackCountPath = "/proc/sys/net/netfilter/nf_conntrack_count"

// readConntrackCount 读取 conntrack 当前连接数（count 文件）；不可读/解析失败返回 -1
// （调用方回退 ss 口径，DEV-033 结论 8）。
func readConntrackCount(path string) int64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return -1
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return -1
	}
	return n
}

// maxConntrackStartFails 启动失败降级阈值（DEV-031 B.4.3：连续 3 次启动失败放弃主通道）。
const maxConntrackStartFails = 3

// connStartError 启动类错误标记（Open/Register 失败）——区别于运行类错误（netlink
// 监听终止/溢出）：外层对启动类错误连续计数，达阈值即放弃主通道进入 B5 降级。
type connStartError struct{ err error }

func (e *connStartError) Error() string { return e.err.Error() }
func (e *connStartError) Unwrap() error { return e.err }

// connStartTracker 启动失败计数状态机（DEV-031 B.4.3，可单测）。
// 连续 maxConntrackStartFails 次启动类失败 → giveUp=true（放弃主通道）；
// 一次运行类错误（说明主通道曾成功启动）清零计数。
type connStartTracker struct {
	fails int
}

// record 记录一次 runConntrackOnce 返回结果。
// isStartErr=true 表示启动类错误（Open/Register 失败）；返回 giveUp 表示应放弃主通道。
func (t *connStartTracker) record(isStartErr bool) (giveUp bool, fails int) {
	if isStartErr {
		t.fails++
		return t.fails >= maxConntrackStartFails, t.fails
	}
	t.fails = 0 // 主通道曾成功启动，运行期错误不累计启动失败
	return false, 0
}

// RunConntrackListener 订阅内核 conntrack 事件流（M-02 主通道，方案 3.2）。
// sink 为有界 channel（背压：channel 满时阻塞读取 netlink，内核缓冲溢出经 overrun 留痕）；
// overrun 上报 R-10 溢出信息；sys 上报 system_event。
// 返回错误（模块不可用/订阅失败）时，调用方应切换 B5 降级路径。
//
// 健壮性设计（V2 压测实测驱动）：netlink 缓冲溢出（ENOBUFS）时 go-conntrack 库会终止
// receive 循环（监听死亡）；本实现检测到监听终止后自动重启（退避 2s→30s），
// 并在每次重启时尝试扩大缓冲（上限 8MB），避免事件流静默中断。
func RunConntrackListener(ctx context.Context, cfg config.ConntrackCfg, sink chan<- event.ConnEvent, overrun chan<- event.OverrunInfo, sys chan<- event.SystemEvent, counter *atomic.Uint64) error {
	// DEV-033（DEV-032 现场核查结论 7）：nf_conntrack 模块依赖链自动加载（无需 modprobe、
	// 无需 /etc/modules-load.d）；/proc/net/nf_conntrack 不存在是内核编译配置
	// （CONFIG_NF_CONNTRACK_PROCFS not set），与模块可用性无关——因此不做 procfs 存在性
	// 前置检查（旧实现会在此误判"模块不可用"而降级，丢失真实事件流）；可用性由下方
	// netlink Open/Register 直接探测（连续 3 次启动失败自动降级，B.4.3 防御保留）。
	// 启用每流包/字节计数（方案 3.2）：sysctl 写入失败记 warn 不阻塞（包/字节字段为 0）。
	if cfg.EnableAcct {
		if err := os.WriteFile("/proc/sys/net/netfilter/nf_conntrack_acct", []byte("1"), 0o644); err != nil {
			event.ReportSys(sys, "conntrack", "warn", fmt.Sprintf("启用 nf_conntrack_acct 失败（包/字节字段将为 0）: %v", err))
		}
	}
	// 提升系统 netlink 缓冲上限（R-10：8MB 生效前提；rmem_max 默认 212992 会截断 2MB 配置）。
	if err := os.WriteFile("/proc/sys/net/core/rmem_max", []byte(strconv.Itoa(netlinkBufferMax)), 0o644); err != nil {
		event.ReportSys(sys, "conntrack", "warn", fmt.Sprintf("提升 net.core.rmem_max 失败（netlink 缓冲可能受限）: %v", err))
	}

	bufSize := cfg.BufferSizeKB * 1024
	// DEV-031 B.4.3（reviewer R-04 整改）：启动失败连续计数，达阈值放弃主通道——
	// 修复"前置检查通过但 Open/Register 失败（如 NET_ADMIN 缺失）→ 无限重启空转、
	// B5 降级永不触发"的现状缺陷（conn.go 原 55-74）。once 注入便于单测 mock。
	return runConntrackLoop(ctx, cfg, bufSize, sink, overrun, sys, counter, runConntrackOnce)
}

// runConntrackLoop 主通道运行循环（启动失败状态机，可注入 once 供单测 mock）。
// 返回错误语义：ctx 取消 → nil；连续 maxConntrackStartFails 次启动类错误 → 放弃主通道错误
// （调用方切换 B5 降级）；运行类错误 → 无限重启+扩容（R-10 恢复路径）。
func runConntrackLoop(ctx context.Context, cfg config.ConntrackCfg, bufSize int, sink chan<- event.ConnEvent, overrun chan<- event.OverrunInfo, sys chan<- event.SystemEvent, counter *atomic.Uint64, once func(context.Context, config.ConntrackCfg, int, chan<- event.ConnEvent, chan<- event.OverrunInfo, chan<- event.SystemEvent, *atomic.Uint64) error) error {
	backoff := 2 * time.Second
	// A-05（auditor Note）：重启告警限频（5 分钟）——持续溢出场景下重启频繁，
	// 未限频将产生告警风暴淹没 system_events。
	restartRep := event.NewRateLimiter(5 * time.Minute)
	var tracker connStartTracker
	for {
		err := once(ctx, cfg, bufSize, sink, overrun, sys, counter)
		if ctx.Err() != nil {
			return nil
		}
		var se *connStartError
		isStartErr := errors.As(err, &se)
		if giveUp, fails := tracker.record(isStartErr); giveUp {
			return fmt.Errorf("conntrack 主通道连续 %d 次启动失败（Open/Register），放弃主通道并切换 B5 降级: %w", fails, err)
		}
		if isStartErr {
			restartRep.Report(sys, "conntrack", "warn",
				fmt.Sprintf("conntrack 主通道启动失败（第 %d 次，连续 %d 次后放弃并降级），%.0fs 后重试: %v",
					tracker.fails, maxConntrackStartFails, backoff.Seconds(), err))
		} else {
			restartRep.Report(sys, "conntrack", "warn",
				fmt.Sprintf("conntrack 监听异常终止，%.0fs 后自动重启（R-10 恢复路径）: %v", backoff.Seconds(), err))
			// 运行类错误伴随缓冲扩容（上限 8MB，R-10 动态扩容语义；启动类失败与
			// 缓冲溢出无关，不扩容——reviewer R-08）。
			bufSize *= 2
			if bufSize > netlinkBufferMax {
				bufSize = netlinkBufferMax
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

// runConntrackOnce 执行一轮 conntrack 监听；仅在 ctx 取消时返回 nil。
func runConntrackOnce(ctx context.Context, cfg config.ConntrackCfg, bufSize int, sink chan<- event.ConnEvent, overrun chan<- event.OverrunInfo, sys chan<- event.SystemEvent, counter *atomic.Uint64) error {
	nfct, err := conntrack.Open(&conntrack.Config{
		AddConntrackInformation: true, // 需要 Con.Info.NetlinkGroup 区分 NEW/UPDATE/DESTROY
		DisableNSLockThread:     true, // 本进程始终处于目标 netns，关闭 OS 线程锁以降低开销
	})
	if err != nil {
		// 启动类错误（DEV-031 B.4.3）：外层连续计数，达阈值放弃主通道降级。
		return &connStartError{fmt.Errorf("打开 conntrack netlink 失败: %w", err)}
	}
	// DEV-036（CONN-01 根因）：不得在此处 defer nfct.Close()——go-conntrack v0.7.0 的
	// Register 失败路径存在库 bug：register() 在 manageGroups 出错时提前返回，未启动
	// 清理 goroutine，shutdown 通道永不关闭；随后 Close() 永久阻塞在 <-nfct.shutdown，
	// 导致 runConntrackOnce 永不返回——启动错误被吞、无留痕无降级（现场 CONN-01 形态）。
	// 因此 Close 仅在 Register 成功后注册（成功路径清理 goroutine 已启动，Close 正常）。
	// Register 失败时泄漏该 fd：连续 maxConntrackStartFails 轮后降级停止尝试，
	// 泄漏上限 3 个 fd，可接受（换取降级链路可用性）。

	if err := nfct.Con.SetReadBuffer(bufSize); err != nil {
		event.ReportSys(sys, "conntrack", "warn", fmt.Sprintf("设置 netlink 接收缓冲 %d B 失败: %v", bufSize, err))
	}

	// 监听终止信号：库在 netlink 错误（如 ENOBUFS 溢出）时结束 receive 循环并置错误入 errChan；
	// 本 goroutine 收到错误后上报留痕并通知主循环返回（触发外层重启）。
	// 防御（T-01 实测结论）：go-conntrack v0.7.0 的 Close() 会 close(errChan)，
	// 关闭后 receive 返回零值 nil——须用 ok 判断与 nil 防御，防止退出竞态下 e.Error() panic。
	dead := make(chan struct{}, 1)
	errCh := nfct.AttachErrChan()
	go func() {
		select {
		case e, ok := <-errCh:
			if !ok || e == nil {
				return // 通道关闭（正常退出路径），非错误
			}
			event.ReportSys(sys, "conntrack", "error", "netlink 接收错误: "+e.Error())
			select {
			case dead <- struct{}{}:
			default:
			}
		case <-ctx.Done():
		}
	}()

	// 事件到达计数（DEV-036 新鲜度自检基准；hook 每次被调用即递增）。
	var evts atomic.Uint64
	hook := func(c conntrack.Con) int {
		evts.Add(1)
		ev, ok := connEventFromCon(c)
		if !ok {
			return 0
		}
		select {
		case sink <- ev:
		case <-ctx.Done():
			return 1 // 非 0 终止监听循环（库约定）
		}
		return 0
	}
	groups := conntrack.NetlinkCtNew | conntrack.NetlinkCtUpdate | conntrack.NetlinkCtDestroy
	if err := nfct.Register(ctx, conntrack.Conntrack, groups, hook); err != nil {
		// 启动类错误（DEV-031 B.4.3）：同上——Register 失败多为权限/NET_ADMIN 缺失。
		// 注意：不 defer Close（见上方 DEV-036 注释），失败路径直接返回避免库 bug 死锁。
		return &connStartError{fmt.Errorf("注册 conntrack 事件订阅失败: %w", err)}
	}
	// Register 成功后才注册 Close（成功路径库清理 goroutine 已启动，Close 正常返回）。
	defer nfct.Close()

	// DEV-036（CONN-01 修复）：订阅有效性验证——Register 返回 nil 只代表 setsockopt
	// 调用成功，不保证组订阅真正生效（现场 CONN-01：Groups=00000000 无报错无留痕，
	// connections 表冻结）。读取 /proc/net/netlink 核对本进程 NETLINK_NETFILTER 套接字
	// Groups 位：缺失组位 → 判定订阅无效，按启动类错误处理（外层连续计数 → B5 降级留痕）；
	// 读取失败（无法验证）→ warn 留痕但不降级（无证据证明无效，避免误降级）。
	if err := verifySubscription(); err != nil {
		if errors.Is(err, errSubscriptionInvalid) {
			return &connStartError{err}
		}
		event.ReportSys(sys, "conntrack", "warn", "无法验证 netlink 组订阅（继续运行）: "+err.Error())
	}

	// 主通道健康状态留痕（DEV-036：防静默——启动成功必须可见，与失败告警对称）。
	event.ReportSys(sys, "conntrack", "info", "conntrack 主通道启动成功（netlink 订阅 NEW/UPDATE/DESTROY 组，订阅验证通过）")

	// R-10 溢出监控：每 OverrunWarnIntervalS 检查本进程 netfilter 套接字的 Drops 累计差值。
	ticker := time.NewTicker(time.Duration(cfg.OverrunWarnIntervalS) * time.Second)
	defer ticker.Stop()
	// DEV-036 新鲜度自检：每 freshnessCheckInterval 检查事件流是否停滞（订阅静默失效兜底）。
	freshTicker := time.NewTicker(freshnessCheckInterval)
	defer freshTicker.Stop()
	staleRep := event.NewRateLimiter(60 * time.Minute)
	staleWarnRep := event.NewRateLimiter(30 * time.Minute)
	lastDrops := uint64(0)
	first := true
	lastEvts := uint64(0)
	lastCnt := int64(-1)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-dead:
			return fmt.Errorf("netlink 监听循环终止（大概率因缓冲溢出）")
		case <-freshTicker.C:
			// 事件计数未推进 = 停滞；结合 conntrack 表连接数变化判级（见 checkFreshness）。
			checkFreshness(sys, &evts, &lastEvts, &lastCnt, staleRep, staleWarnRep)
		case <-ticker.C:
			if !checkOverrun(ctx, sys, nfct, &bufSize, overrun, counter, &lastDrops, &first) {
				return nil
			}
		}
	}
}

// checkFreshness 新鲜度自检（DEV-036）：事件计数未推进时结合 conntrack 表连接数
// 变化判级——表在动但事件无 → 订阅失效高置信（warn）；表无变化 → 低流量或失效（info）。
// 状态（evts 计数、lastEvts/lastCnt）由调用方持有，本函数无状态（DEV-AUDIT-001 P1-4 提取）。
func checkFreshness(sys chan<- event.SystemEvent, evts *atomic.Uint64, lastEvts *uint64, lastCnt *int64, staleRep, staleWarnRep *event.RateLimiter) {
	curEvts := evts.Load()
	if curEvts == *lastEvts {
		curCnt := readConntrackCount(conntrackCountPath)
		stalled, tableActive := staleVerdict(curEvts, *lastEvts, *lastCnt, curCnt)
		if tableActive {
			staleWarnRep.Report(sys, "conntrack", "warn",
				fmt.Sprintf("conntrack 事件流停滞：%v 无事件但表连接数变化（%d→%d），订阅可能失效", freshnessCheckInterval, *lastCnt, curCnt))
		} else if stalled {
			staleRep.Report(sys, "conntrack", "info",
				fmt.Sprintf("conntrack 事件流 %v 无事件（低流量或订阅失效，当前表连接数 %d）", freshnessCheckInterval, curCnt))
		}
	}
	*lastEvts = curEvts
	*lastCnt = readConntrackCount(conntrackCountPath)
}

// checkOverrun 溢出监控（R-10）：检查本进程 netfilter 套接字 Drops 累计差值，
// 有溢出时留痕 + 累加共享计数 + 投递 overrun 通道（store 单消费者）+ 动态扩容（上限 8MB）。
// 返回 false 表示 ctx 取消（调用方应结束监听循环）；其余情况返回 true（continue 语义）。
// 状态（lastDrops/first/bufSize）由调用方持有，本函数无状态（DEV-AUDIT-001 P1-4 提取）。
func checkOverrun(ctx context.Context, sys chan<- event.SystemEvent, nfct *conntrack.Nfct, bufSize *int, overrun chan<- event.OverrunInfo, counter *atomic.Uint64, lastDrops *uint64, first *bool) bool {
	drops, err := netlinkDrops()
	if err != nil {
		event.ReportSys(sys, "conntrack", "warn", "读取 netlink 溢出计数失败: "+err.Error())
		return true
	}
	if *first {
		*first = false
		*lastDrops = drops
		return true
	}
	diff := drops - *lastDrops // 计数器单调不减，无回绕场景
	*lastDrops = drops
	if diff == 0 {
		return true
	}
	// 溢出留痕（永留存，符合"只记录"精神：记录丢了什么也是记录）。
	event.ReportSys(sys, "conntrack", "warn", fmt.Sprintf("netlink 缓冲溢出，丢弃 %d 条事件（R-10 留痕）", diff))
	// M-01（auditor Minor）：共享 atomic 计数（main 注入，API health 直接读取），
	// overrun 通道保持 store 单消费者（防止双消费者竞争导致计数/留痕减半）。
	if counter != nil {
		counter.Add(diff)
	}
	if overrun != nil {
		select {
		case overrun <- event.OverrunInfo{TS: time.Now().Unix(), Dropped: diff}:
		case <-ctx.Done():
			return false
		}
	}
	// 动态扩容（上限 8MB）；失败维持现状，下轮继续告警。
	if *bufSize < netlinkBufferMax {
		*bufSize *= 2
		if *bufSize > netlinkBufferMax {
			*bufSize = netlinkBufferMax
		}
		if err := nfct.Con.SetReadBuffer(*bufSize); err != nil {
			event.ReportSys(sys, "conntrack", "warn", fmt.Sprintf("扩容 netlink 缓冲至 %d B 失败: %v", *bufSize, err))
		} else {
			event.ReportSys(sys, "conntrack", "info", fmt.Sprintf("netlink 缓冲已扩容至 %d B", *bufSize))
		}
	}
	return true
}

// connEventFromCon 将 go-conntrack 的 Con 转换为业务事件 ConnEvent。
// 返回 ok=false 表示无法提取五元组（跳过该事件，不阻塞流）。
func connEventFromCon(c conntrack.Con) (event.ConnEvent, bool) {
	if c.Origin == nil || c.Origin.Proto == nil || c.Origin.Src == nil || c.Origin.Dst == nil {
		return event.ConnEvent{}, false
	}
	// 防御：Info 为 nil 时按 UPDATE 处理（当前固定 AddConntrackInformation=true 使其必有值，
	// 若未来库行为变化或配置关闭该选项，避免 panic 击穿监听）。
	if c.Info == nil {
		c.Info = &conntrack.InfoSource{NetlinkGroup: conntrack.NetlinkCtUpdate}
	}
	ev := event.ConnEvent{TS: time.Now().Unix()}
	switch c.Info.NetlinkGroup {
	case conntrack.NetlinkCtNew:
		ev.EvType = event.EvNew
	case conntrack.NetlinkCtDestroy:
		ev.EvType = event.EvDestroy
	default:
		ev.EvType = event.EvUpdate
	}
	// IPv4 压缩为 uint32；IPv6 走文本字段（方案 4.1：IPv6 存 TEXT）。
	if ip4 := c.Origin.Src.To4(); ip4 != nil {
		ev.SrcIP = event.IPv4ToUint32(*c.Origin.Src)
	} else {
		ev.SrcIP6 = c.Origin.Src.String()
	}
	if ip4 := c.Origin.Dst.To4(); ip4 != nil {
		ev.DstIP = event.IPv4ToUint32(*c.Origin.Dst)
	} else {
		ev.DstIP6 = c.Origin.Dst.String()
	}
	if c.Origin.Proto.Number != nil {
		ev.Proto = *c.Origin.Proto.Number
	}
	if c.Origin.Proto.SrcPort != nil {
		ev.SrcPort = *c.Origin.Proto.SrcPort
	}
	if c.Origin.Proto.DstPort != nil {
		ev.DstPort = *c.Origin.Proto.DstPort
	}
	// 口径（方案 3.2）：ICMP 时端口为 0（ICMP ID 不进入端口字段）。
	if ev.Proto == event.ProtoICMP {
		ev.SrcPort, ev.DstPort = 0, 0
	}
	if c.CounterOrigin != nil {
		if c.CounterOrigin.Packets != nil {
			ev.Packets = *c.CounterOrigin.Packets
		}
		if c.CounterOrigin.Bytes != nil {
			ev.Bytes = *c.CounterOrigin.Bytes
		}
	}
	if c.Mark != nil {
		ev.Mark = *c.Mark
	}
	return ev, true
}

// netlinkOwnInfo 本进程某个 netlink 套接字的 /proc/net/netlink 统计行信息。
type netlinkOwnInfo struct {
	groups uint32 // Groups 列（订阅组位掩码，仅 Eth=12 关注）
	drops  uint64 // Drops 列（溢出累计）
	inode  uint64
}

// netlinkDrops 统计本进程 NETLINK_NETFILTER 套接字在 /proc/net/netlink 中的累计 Drops。
// 方法：枚举 /proc/self/fd 的 socket inode 集合，匹配 /proc/net/netlink 中 Eth=12 的行，求和 Drops 列。
func netlinkDrops() (uint64, error) {
	infos, err := netlinkOwnInfos(netlinkNetfilterProto)
	if err != nil {
		return 0, err
	}
	var drops uint64
	for _, info := range infos {
		drops += info.drops
	}
	return drops, nil
}

// netlinkOwnInfos 读取 /proc/net/netlink，返回本进程指定协议号套接字的统计行
// （/proc/self/fd inode 集合匹配）。读取失败返回错误。
func netlinkOwnInfos(proto int) ([]netlinkOwnInfo, error) {
	inodes, err := ownSocketInodes()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile("/proc/net/netlink")
	if err != nil {
		return nil, err
	}
	return parseNetlinkOwn(string(data), inodes, proto), nil
}

// parseNetlinkOwn 解析 /proc/net/netlink 文本，过滤指定协议号且 inode 属于本进程的行
// （纯函数，可单测）。列：sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode。
func parseNetlinkOwn(data string, inodes map[uint64]bool, proto int) []netlinkOwnInfo {
	var out []netlinkOwnInfo
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 || fields[0] == "sk" {
			continue
		}
		p, err := strconv.Atoi(fields[1])
		if err != nil || p != proto {
			continue
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil || !inodes[inode] {
			continue
		}
		info := netlinkOwnInfo{inode: inode}
		if g, err := strconv.ParseUint(fields[3], 16, 32); err == nil {
			info.groups = uint32(g)
		}
		if d, err := strconv.ParseUint(fields[8], 10, 64); err == nil {
			info.drops = d
		}
		out = append(out, info)
	}
	return out
}

// errSubscriptionInvalid 订阅验证确定无效（Groups 位缺失）——按启动类错误处理（降级）。
var errSubscriptionInvalid = errors.New("netlink 组订阅验证失败")

// verifySubscription 验证本进程 NETLINK_NETFILTER 组订阅已生效（DEV-036）：
// 读取 /proc/net/netlink，检查本进程套接字 Groups 位是否含全部期望组位（NEW/UPDATE/DESTROY）。
// 返回 errSubscriptionInvalid 表示订阅确定无效（调用方应降级）；其他错误表示无法验证
// （读取失败，调用方仅留痕不降级）。
func verifySubscription() error {
	infos, err := netlinkOwnInfos(netlinkNetfilterProto)
	if err != nil {
		return err
	}
	return verifyGroups(infos)
}

// verifyGroups 核对本进程 netfilter 套接字组位（纯函数，可单测）：
// 无匹配套接字或任一期望组位缺失 → errSubscriptionInvalid。
func verifyGroups(infos []netlinkOwnInfo) error {
	var groups uint32
	for _, info := range infos {
		groups |= info.groups
	}
	if groups&ctGroupsMask != ctGroupsMask {
		return fmt.Errorf("%w: 本进程 NETLINK_NETFILTER 套接字 Groups=%#08x，期望组位 %#08x（NEW/UPDATE/DESTROY 订阅未生效）",
			errSubscriptionInvalid, groups, ctGroupsMask)
	}
	return nil
}

// ownSocketInodes 枚举本进程全部 fd 的 socket inode 集合（/proc/self/fd 的 readlink 目标 "socket:[N]"）。
func ownSocketInodes() (map[uint64]bool, error) {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return nil, err
	}
	inodes := make(map[uint64]bool)
	for _, e := range entries {
		target, err := os.Readlink("/proc/self/fd/" + e.Name())
		if err != nil {
			continue
		}
		if !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
			continue
		}
		num, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]"), 10, 64)
		if err != nil {
			continue
		}
		inodes[num] = true
	}
	return inodes, nil
}

// staleVerdict 事件流停滞判定（DEV-036 新鲜度自检，纯函数可单测）：
// prevEvts/curEvts 为相邻周期的事件计数；prevCnt/curCnt 为相邻周期的 conntrack 表连接数
// （-1 表示不可读）。返回 stalled=事件计数未推进；tableActive=表连接数变化（表有活动）。
func staleVerdict(prevEvts, curEvts uint64, prevCnt, curCnt int64) (stalled, tableActive bool) {
	if curEvts != prevEvts {
		return false, false
	}
	// 事件停滞；表连接数可比且变化 → 表活跃（订阅失效高置信）。
	if prevCnt >= 0 && curCnt >= 0 && prevCnt != curCnt {
		return true, true
	}
	return true, false
}
