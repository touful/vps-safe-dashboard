// Package out 实现 stdout 结构化输出（M1 落点：采集事件 + system_event 以 JSON 行输出）。
// M2 起此落点由 M-06 存储模块取代；消费的 channel 结构不变，接口平滑替换。
// IP 统一输出点分十进制（方案第 3 章说明：二进制与点分互转由 API 层承担；M1 stdout 即验证出口）。
package out

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"sentry-agent/internal/event"
)

// Channels 聚合各采集通道（与方案 3.6 Store 的入队接口一一对应）。
type Channels struct {
	Resource chan event.ResourceSample
	Conn     chan event.ConnEvent
	Overrun  chan event.OverrunInfo
	SSH      chan event.SSHAttempt
	FW       chan event.FirewallEvent
	F2B      chan event.BanEvent
	System   chan event.SystemEvent
}

// NewChannels 创建有界 channel 集合（方案 2.3.3：默认容量 4096）。
func NewChannels(buf int) *Channels {
	return &Channels{
		Resource: make(chan event.ResourceSample, buf),
		Conn:     make(chan event.ConnEvent, buf),
		Overrun:  make(chan event.OverrunInfo, buf),
		SSH:      make(chan event.SSHAttempt, buf),
		FW:       make(chan event.FirewallEvent, buf),
		F2B:      make(chan event.BanEvent, buf),
		System:   make(chan event.SystemEvent, buf),
	}
}

// line 单行输出结构（JSON 序列化）。
type line struct {
	TS      int64  `json:"ts"`
	Channel string `json:"channel"`
	Ev      any    `json:"ev,omitempty"`
}

// statsLine 统计行（每 60s 输出，供压测观测事件率）。
type statsLine struct {
	TS            int64 `json:"ts"`
	Channel       string `json:"channel"`
	IntervalS     int64 `json:"interval_s"`
	Resource      int64 `json:"resource"`
	Conn          int64 `json:"conn"`
	SSH           int64 `json:"ssh"`
	FW            int64 `json:"fw"`
	F2B           int64 `json:"f2b"`
	System        int64 `json:"system"`
	Overrun       int64 `json:"overrun"`
	SnapshotTS    int64 `json:"snapshot_ts"`
	SnapshotConns int   `json:"snapshot_conns"`
}

// counters 各通道累计计数。
type counters struct {
	resource, conn, overrun, ssh, fw, f2b, system atomic.Int64
}

// SnapshotFn 返回最新 ss 快照的（时间戳, 连接数）；可为 nil。
type SnapshotFn func() (int64, int)

// Run 启动 stdout 输出器：消费全部采集 channel，输出 JSON 行；每 60s 输出统计行。
// producers 为全部采集协程的 WaitGroup——两阶段排空协议（auditor M-02 修复）：
// ctx 取消后先等待所有生产者退出（不再有新的 send），再排空 channel 中在途事件，
// 消除"ctx 取消瞬间生产者最后 send 落在排空完成后"的丢失竞态。
func Run(ctx context.Context, w io.Writer, ch *Channels, producers *sync.WaitGroup, snapshotFn SnapshotFn) error {
	var mu sync.Mutex
	bw := bufio.NewWriterSize(w, 64*1024)
	write := func(v any) {
		b, err := json.Marshal(v)
		if err != nil {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		_, _ = bw.Write(b)
		_ = bw.WriteByte('\n')
		_ = bw.Flush() // 每行 flush：验证期保证数据完整；M2 落库后此路径退役
	}

	var cnt counters
	dones := []<-chan struct{}{
		consume(ctx, producers, ch.Resource, &cnt.resource, write, convResource, "resource"),
		consume(ctx, producers, ch.Conn, &cnt.conn, write, convConn, "conn"),
		consume(ctx, producers, ch.Overrun, &cnt.overrun, write, func(v event.OverrunInfo) any { return v }, "overrun"),
		consume(ctx, producers, ch.SSH, &cnt.ssh, write, convSSH, "ssh"),
		consume(ctx, producers, ch.FW, &cnt.fw, write, convFW, "fw"),
		consume(ctx, producers, ch.F2B, &cnt.f2b, write, convF2B, "f2b"),
		consume(ctx, producers, ch.System, &cnt.system, write, func(v event.SystemEvent) any { return v }, "system"),
	}

	// 统计行（60s 周期）。
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	last := statsLine{TS: time.Now().Unix()}
	for {
		select {
		case <-ctx.Done():
			// 等待全部 consume 排空完成（生产者已随 ctx 退出，drain 后通道内事件写完）。
			for _, d := range dones {
				<-d
			}
			return nil
		case <-ticker.C:
			now := time.Now().Unix()
			cur := statsLine{
				TS: now, Channel: "stats", IntervalS: now - last.TS,
				Resource: cnt.resource.Load(), Conn: cnt.conn.Load(), SSH: cnt.ssh.Load(),
				FW: cnt.fw.Load(), F2B: cnt.f2b.Load(), System: cnt.system.Load(),
				Overrun: cnt.overrun.Load(),
			}
			if snapshotFn != nil {
				cur.SnapshotTS, cur.SnapshotConns = snapshotFn()
			}
			write(cur)
			last = cur
		}
	}
}

// consume 消费单个 channel。两阶段排空协议：ctx 取消后先等待 producers 全部退出
// （确保不再有新 send），再排空 channel 中在途事件，完成后关闭 done 通道。
func consume[T any](ctx context.Context, producers *sync.WaitGroup, src <-chan T, cnt *atomic.Int64, write func(any), conv func(T) any, name string) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case v, ok := <-src:
				if !ok {
					return
				}
				cnt.Add(1)
				write(line{TS: tsOf(v), Channel: name, Ev: conv(v)})
			case <-ctx.Done():
				// 阶段一：等待所有生产者退出（在途 send 全部完成）。
				if producers != nil {
					producers.Wait()
				}
				// 阶段二：排空在途事件（此时不会有新 send，drain 到空即完成）。
				for {
					select {
					case v, ok := <-src:
						if !ok {
							return
						}
						cnt.Add(1)
						write(line{TS: tsOf(v), Channel: name, Ev: conv(v)})
					default:
						return
					}
				}
			}
		}
	}()
	return done
}

// tsOf 提取事件时间戳（全部事件类型统一带 TS 字段）。
func tsOf(v any) int64 {
	switch e := v.(type) {
	case event.ResourceSample:
		return e.TS
	case event.ConnEvent:
		return e.TS
	case event.OverrunInfo:
		return e.TS
	case event.SSHAttempt:
		return e.TS
	case event.FirewallEvent:
		return e.TS
	case event.BanEvent:
		return e.TS
	case event.SystemEvent:
		return e.TS
	}
	return time.Now().Unix()
}

// 以下 conv* 为各事件类型的输出视图（IP 转点分十进制）。

type resourceOut struct {
	TS          int64   `json:"ts"`
	CPUPercent  float64 `json:"cpu_percent"`
	MemUsedMB   float64 `json:"mem_used_mb"`
	MemPercent  float64 `json:"mem_percent"`
	DiskUsedMB  float64 `json:"disk_used_mb"`
	DiskPercent float64 `json:"disk_percent"`
	NetRxBps    uint64  `json:"net_rx_bps"`
	NetTxBps    uint64  `json:"net_tx_bps"`
}

func convResource(v event.ResourceSample) any {
	return resourceOut{
		TS: v.TS, CPUPercent: v.CPUPercent, MemUsedMB: v.MemUsedMB, MemPercent: v.MemPercent,
		DiskUsedMB: v.DiskUsedMB, DiskPercent: v.DiskPercent, NetRxBps: v.NetRxBps, NetTxBps: v.NetTxBps,
	}
}

type connOut struct {
	TS      int64  `json:"ts"`
	EvType  int    `json:"ev_type"` // 1=NEW 2=UPDATE 3=DESTROY
	Proto   uint8  `json:"proto"`
	SrcIP   string `json:"src_ip"`
	SrcPort uint16 `json:"src_port"`
	DstIP   string `json:"dst_ip"`
	DstPort uint16 `json:"dst_port"`
	SrcIP6  string `json:"src_ip6,omitempty"`
	DstIP6  string `json:"dst_ip6,omitempty"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
	Mark    uint32 `json:"mark"`
}

func convConn(v event.ConnEvent) any {
	return connOut{
		TS: v.TS, EvType: v.EvType, Proto: v.Proto,
		SrcIP: event.Uint32ToIPv4(v.SrcIP), SrcPort: v.SrcPort,
		DstIP: event.Uint32ToIPv4(v.DstIP), DstPort: v.DstPort,
		SrcIP6: v.SrcIP6, DstIP6: v.DstIP6,
		Packets: v.Packets, Bytes: v.Bytes, Mark: v.Mark,
	}
}

type sshOut struct {
	TS          int64  `json:"ts"`
	SrcIP       string `json:"src_ip"`
	Username    string `json:"username"`
	AuthMethod  string `json:"auth_method"`
	Result      int    `json:"result"` // 1=成功 0=失败 2=未知
	Fingerprint string `json:"fingerprint"`
	Detail      string `json:"detail"`
}

func convSSH(v event.SSHAttempt) any {
	return sshOut{
		TS: v.TS, SrcIP: event.Uint32ToIPv4(v.SrcIP), Username: v.Username,
		AuthMethod: v.AuthMethod, Result: v.Result, Fingerprint: v.Fingerprint, Detail: v.Detail,
	}
}

type fwOut struct {
	TS      int64  `json:"ts"`
	Chain   string `json:"chain"`
	Action  string `json:"action"`
	Proto   uint8  `json:"proto"`
	SrcIP   string `json:"src_ip"`
	SrcPort uint16 `json:"src_port"`
	DstIP   string `json:"dst_ip"`
	DstPort uint16 `json:"dst_port"`
	Raw     string `json:"raw"`
}

func convFW(v event.FirewallEvent) any {
	return fwOut{
		TS: v.TS, Chain: v.Chain, Action: v.Action, Proto: v.Proto,
		SrcIP: event.Uint32ToIPv4(v.SrcIP), SrcPort: v.SrcPort,
		DstIP: event.Uint32ToIPv4(v.DstIP), DstPort: v.DstPort, Raw: v.Raw,
	}
}

type f2bOut struct {
	TS   int64  `json:"ts"`
	IP   string `json:"ip"`
	Type string `json:"type"` // ban/unban/found
	Jail string `json:"jail"`
}

func convF2B(v event.BanEvent) any {
	return f2bOut{TS: v.TS, IP: event.Uint32ToIPv4(v.IP), Type: v.Type, Jail: v.Jail}
}
