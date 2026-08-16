package conn

import (
	"context"
	"os/exec"
	"strconv"
	"time"

	"sentry-agent/internal/event"
)

// RunFallbackConnListener 实现 B5 降级路径（方案 3.2.4 / 6.2 B5 / R-07）：
// conntrack 通道不可用（模块缺失/嵌套虚拟化/无 NET_ADMIN）时，每 interval 执行一次
// ss -tanup 快照，对比相邻快照差异，近似产出 NEW（新增）/UPDATE（状态变化）/DESTROY（消失）事件。
// 明确语义：近似通道、非全量（快照间隔内发生又消失的短连接无法记录）；
// 降级原因与影响以 system_event 留痕，面板标注"近似通道"由 M3 实现。
func RunFallbackConnListener(ctx context.Context, interval time.Duration, sink chan<- event.ConnEvent, sys chan<- event.SystemEvent) error {
	event.ReportSys(sys, "conntrack", "warn", "conntrack 通道不可用，连接记录降级为 ss 快照 diff 近似模式（B5，非全量）")
	prev := map[string]event.SnapConn{} // key: 五元组 → 快照连接（含状态）
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			out, err := exec.Command("ss", "-tanup").Output()
			if err != nil {
				event.ReportSys(sys, "conntrack", "warn", "降级模式执行 ss -tanup 失败: "+err.Error())
				continue
			}
			conns, err := ParseSSOutput(string(out))
			if err != nil {
				event.ReportSys(sys, "conntrack", "warn", "降级模式解析 ss 输出失败: "+err.Error())
				continue
			}
			cur := make(map[string]event.SnapConn, len(conns))
			for _, c := range conns {
				cur[snapKey(c)] = c
			}
			for _, ev := range diffSnapshots(prev, cur, time.Now().Unix()) {
				if !sendApprox(sink, ctx, ev) {
					return nil
				}
			}
			prev = cur
		}
	}
}

// snapKey 生成五元组 key（协议+两端地址端口）。
func snapKey(c event.SnapConn) string {
	return strconv.Itoa(int(c.Proto)) + ":" + strconv.FormatUint(uint64(c.SrcIP), 10) + ":" +
		strconv.Itoa(int(c.SrcPort)) + ":" + strconv.FormatUint(uint64(c.DstIP), 10) + ":" +
		strconv.Itoa(int(c.DstPort))
}

// diffSnapshots 对比相邻快照，产出近似事件（纯函数，可单测）：
// 新增连接 → NEW；状态变化 → UPDATE；消失连接 → DESTROY。
func diffSnapshots(prev, cur map[string]event.SnapConn, ts int64) []event.ConnEvent {
	var out []event.ConnEvent
	for k, sc := range cur {
		if _, existed := prev[k]; !existed {
			out = append(out, approxEvent(ts, event.EvNew, sc))
		}
	}
	for k, old := range prev {
		sc, still := cur[k]
		if !still {
			out = append(out, approxEvent(ts, event.EvDestroy, old))
		} else if sc.State != old.State {
			out = append(out, approxEvent(ts, event.EvUpdate, sc))
		}
	}
	return out
}

// approxEvent 由快照连接构造近似 ConnEvent（IPv6 不在快照中，字段恒为空）。
func approxEvent(ts int64, evType int, sc event.SnapConn) event.ConnEvent {
	return event.ConnEvent{
		TS: ts, EvType: evType, Proto: sc.Proto,
		SrcIP: sc.SrcIP, SrcPort: sc.SrcPort,
		DstIP: sc.DstIP, DstPort: sc.DstPort,
	}
}

// sendApprox 阻塞发送近似事件（背压），ctx 取消返回 false。
func sendApprox(sink chan<- event.ConnEvent, ctx context.Context, ev event.ConnEvent) bool {
	select {
	case sink <- ev:
		return true
	case <-ctx.Done():
		return false
	}
}
