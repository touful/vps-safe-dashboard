// Package conn 实现 M-02 连接监听模块：
// conntrack 主通道（netlink 事件订阅）+ ss 快照（展示通道）+ B5 降级近似（conntrack 不可用时）。
package conn

import (
	"context"
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

// netlinkBufferMax netlink 缓冲扩容上限（R-10：可扩至 8MB）。
const netlinkBufferMax = 8 * 1024 * 1024

// RunConntrackListener 订阅内核 conntrack 事件流（M-02 主通道，方案 3.2）。
// sink 为有界 channel（背压：channel 满时阻塞读取 netlink，内核缓冲溢出经 overrun 留痕）；
// overrun 上报 R-10 溢出信息；sys 上报 system_event。
// 返回错误（模块不可用/订阅失败）时，调用方应切换 B5 降级路径。
//
// 健壮性设计（V2 压测实测驱动）：netlink 缓冲溢出（ENOBUFS）时 go-conntrack 库会终止
// receive 循环（监听死亡）；本实现检测到监听终止后自动重启（退避 2s→30s），
// 并在每次重启时尝试扩大缓冲（上限 8MB），避免事件流静默中断。
func RunConntrackListener(ctx context.Context, cfg config.ConntrackCfg, sink chan<- event.ConnEvent, overrun chan<- event.OverrunInfo, sys chan<- event.SystemEvent, counter *atomic.Uint64) error {
	// 前置检查：nf_conntrack 模块已加载（C-05：/proc/net/nf_conntrack 存在）。
	if _, err := os.Stat("/proc/net/nf_conntrack"); err != nil {
		return fmt.Errorf("nf_conntrack 模块不可用（/proc/net/nf_conntrack 不存在）: %w", err)
	}
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
	backoff := 2 * time.Second
	// A-05（auditor Note）：重启告警限频（5 分钟）——持续溢出场景下重启频繁，
	// 未限频将产生告警风暴淹没 system_events。
	restartRep := event.NewRateLimiter(5 * time.Minute)
	for {
		err := runConntrackOnce(ctx, cfg, bufSize, sink, overrun, sys, counter)
		if ctx.Err() != nil {
			return nil
		}
		restartRep.Report(sys, "conntrack", "warn", fmt.Sprintf("conntrack 监听异常终止，%.0fs 后自动重启（R-10 恢复路径）: %v", backoff.Seconds(), err))
		// 重启伴随缓冲扩容（上限 8MB，R-10 动态扩容语义）。
		bufSize *= 2
		if bufSize > netlinkBufferMax {
			bufSize = netlinkBufferMax
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
		return fmt.Errorf("打开 conntrack netlink 失败: %w", err)
	}
	defer nfct.Close()

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

	hook := func(c conntrack.Con) int {
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
		return fmt.Errorf("注册 conntrack 事件订阅失败: %w", err)
	}

	// R-10 溢出监控：每 OverrunWarnIntervalS 检查本进程 netfilter 套接字的 Drops 累计差值。
	ticker := time.NewTicker(time.Duration(cfg.OverrunWarnIntervalS) * time.Second)
	defer ticker.Stop()
	lastDrops := uint64(0)
	first := true
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-dead:
			return fmt.Errorf("netlink 监听循环终止（大概率因缓冲溢出）")
		case <-ticker.C:
			drops, err := netlinkDrops()
			if err != nil {
				event.ReportSys(sys, "conntrack", "warn", "读取 netlink 溢出计数失败: "+err.Error())
				continue
			}
			if first {
				first = false
				lastDrops = drops
				continue
			}
			diff := drops - lastDrops // 计数器单调不减，无回绕场景
			lastDrops = drops
			if diff == 0 {
				continue
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
					return nil
				}
			}
			// 动态扩容（上限 8MB）；失败维持现状，下轮继续告警。
			if bufSize < netlinkBufferMax {
				bufSize *= 2
				if bufSize > netlinkBufferMax {
					bufSize = netlinkBufferMax
				}
				if err := nfct.Con.SetReadBuffer(bufSize); err != nil {
					event.ReportSys(sys, "conntrack", "warn", fmt.Sprintf("扩容 netlink 缓冲至 %d B 失败: %v", bufSize, err))
				} else {
					event.ReportSys(sys, "conntrack", "info", fmt.Sprintf("netlink 缓冲已扩容至 %d B", bufSize))
				}
			}
		}
	}
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

// netlinkDrops 统计本进程 NETLINK_NETFILTER 套接字在 /proc/net/netlink 中的累计 Drops。
// 方法：枚举 /proc/self/fd 的 socket inode 集合，匹配 /proc/net/netlink 中 Eth=12 的行，求和 Drops 列。
func netlinkDrops() (uint64, error) {
	inodes, err := ownSocketInodes()
	if err != nil {
		return 0, err
	}
	data, err := os.ReadFile("/proc/net/netlink")
	if err != nil {
		return 0, err
	}
	var drops uint64
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		// 列：sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode
		if len(fields) < 10 || fields[0] == "sk" {
			continue
		}
		proto, err := strconv.Atoi(fields[1])
		if err != nil || proto != netlinkNetfilterProto {
			continue
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil || !inodes[inode] {
			continue
		}
		d, err := strconv.ParseUint(fields[8], 10, 64)
		if err != nil {
			continue
		}
		drops += d
	}
	return drops, nil
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
