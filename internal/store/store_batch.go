package store

import (
	"fmt"

	"sentry-agent/internal/event"
)

// eventItem 写入队列中的单条事件（kind 决定目标表）。
type eventItem struct {
	kind string
	v    any
}

// enqueue 将一条事件追加到待写批次（kind 与 insertStmts 键对应；Run 主循环与
// drainInto 共用去重）。
func enqueue(pending *[]eventItem, n *int, kind string, v any) {
	*pending = append(*pending, eventItem{kind: kind, v: v})
	*n++
}

// insertStmts 各表 INSERT 语句（与方案 4.2 DDL 字段一一对应）。
var insertStmts = map[string]string{
	"resource": `INSERT INTO resources
		(ts, cpu_percent, mem_used_mb, mem_percent, disk_used_mb, disk_percent, net_rx_bps, net_tx_bps)
		VALUES (?,?,?,?,?,?,?,?)`,
	"conn": `INSERT INTO connections
		(ts, ev_type, proto, src_ip, src_port, dst_ip, dst_port, packets, bytes, mark, src_ip6, dst_ip6)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
	"ssh": `INSERT INTO ssh_attempts
		(ts, src_ip, username, auth_method, result, fingerprint, detail)
		VALUES (?,?,?,?,?,?,?)`,
	"fw": `INSERT INTO firewall_events
		(ts, chain, action, proto, src_ip, src_port, dst_ip, dst_port, raw)
		VALUES (?,?,?,?,?,?,?,?,?)`,
	"f2b":    `INSERT INTO ban_events (ts, ip, type, jail) VALUES (?,?,?,?)`,
	"system": `INSERT INTO system_events (ts, source, level, message) VALUES (?,?,?,?)`,
	// overrun（R-10 溢出）落 system_events 留痕（source=conntrack, level=warn）。
	"overrun": `INSERT INTO system_events (ts, source, level, message) VALUES (?,?,?,?)`,
	// DEV-HONEY-001：蜜罐凭据捕获。
	"cred": `INSERT INTO cred_events (ts, proto, src_ip, username, password, extra) VALUES (?,?,?,?,?,?)`,
}

// writeBatch 将一批事件写入主库（单事务，BEGIN IMMEDIATE，方案 4.5）。
// 实现注意：手动 BEGIN IMMEDIATE / COMMIT / ROLLBACK（方案要求 IMMEDIATE 防御归档交叉）；
// 事务内直接 Exec（SQLite 对重复语句有内部优化，批量开销可接受）；
// 不使用 db.Prepare 缓存——MaxOpenConns(1) 下事务占用唯一连接后再取连接会死锁。
func (s *Store) writeBatch(items []eventItem) error {
	if len(items) == 0 {
		return nil
	}
	if _, err := s.db.Exec("BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("开启事务失败: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = s.db.Exec("ROLLBACK")
		}
	}()

	for _, it := range items {
		sqlText, ok := insertStmts[it.kind]
		if !ok {
			return fmt.Errorf("未知事件类型: %s", it.kind)
		}
		args, err := itemArgs(it)
		if err != nil {
			return err
		}
		if _, err := s.db.Exec(sqlText, args...); err != nil {
			return fmt.Errorf("插入 %s 失败: %w", it.kind, err)
		}
	}
	if _, err := s.db.Exec("COMMIT"); err != nil {
		return fmt.Errorf("提交事务失败: %w", err)
	}
	committed = true
	return nil
}

// itemArgs 将事件转换为 INSERT 参数（时间戳口径见 event 包注释：统一 Unix 秒）。
// kind 与事件类型不匹配时返回错误（原裸类型断言在类型失配时
// panic，改为带 ok 断言防御——当前调用方 kind/类型严格配对，属防御性缺口封堵）。
func itemArgs(it eventItem) ([]any, error) {
	switch it.kind {
	case "resource":
		v, ok := it.v.(event.ResourceSample)
		if !ok {
			return nil, fmt.Errorf("事件类型与 kind 不匹配: %s", it.kind)
		}
		return []any{v.TS, v.CPUPercent, v.MemUsedMB, v.MemPercent, v.DiskUsedMB, v.DiskPercent, v.NetRxBps, v.NetTxBps}, nil
	case "conn":
		v, ok := it.v.(event.ConnEvent)
		if !ok {
			return nil, fmt.Errorf("事件类型与 kind 不匹配: %s", it.kind)
		}
		return []any{v.TS, v.EvType, int(v.Proto), int(v.SrcIP), v.SrcPort, int(v.DstIP), v.DstPort, v.Packets, v.Bytes, v.Mark, v.SrcIP6, v.DstIP6}, nil
	case "ssh":
		v, ok := it.v.(event.SSHAttempt)
		if !ok {
			return nil, fmt.Errorf("事件类型与 kind 不匹配: %s", it.kind)
		}
		return []any{v.TS, int(v.SrcIP), v.Username, v.AuthMethod, v.Result, v.Fingerprint, v.Detail}, nil
	case "fw":
		v, ok := it.v.(event.FirewallEvent)
		if !ok {
			return nil, fmt.Errorf("事件类型与 kind 不匹配: %s", it.kind)
		}
		return []any{v.TS, v.Chain, v.Action, int(v.Proto), int(v.SrcIP), v.SrcPort, int(v.DstIP), v.DstPort, v.Raw}, nil
	case "f2b":
		v, ok := it.v.(event.BanEvent)
		if !ok {
			return nil, fmt.Errorf("事件类型与 kind 不匹配: %s", it.kind)
		}
		return []any{v.TS, int(v.IP), v.Type, v.Jail}, nil
	case "system":
		v, ok := it.v.(event.SystemEvent)
		if !ok {
			return nil, fmt.Errorf("事件类型与 kind 不匹配: %s", it.kind)
		}
		return []any{v.TS, v.Source, v.Level, v.Message}, nil
	case "overrun":
		v, ok := it.v.(event.OverrunInfo)
		if !ok {
			return nil, fmt.Errorf("事件类型与 kind 不匹配: %s", it.kind)
		}
		msg := fmt.Sprintf("netlink 缓冲溢出，丢弃 %d 条事件（R-10 留痕）", v.Dropped)
		return []any{v.TS, "conntrack", "warn", msg}, nil
	case "cred":
		// DEV-HONEY-001：蜜罐凭据捕获（敏感信息：明文密码仅落本地 SQLite，禁止日志）。
		v, ok := it.v.(event.CredEvent)
		if !ok {
			return nil, fmt.Errorf("事件类型与 kind 不匹配: %s", it.kind)
		}
		return []any{v.TS, v.Proto, int(v.SrcIP), v.Username, v.Password, v.Extra}, nil
	}
	return nil, fmt.Errorf("未知事件类型: %s", it.kind)
}
