// retention 清理实现（B.5.2/B.5.4）。
// 语义变更：主库按保留期保留（默认 7 天可配置），归档机制保留（副本为历史保留通道）。
// 本清理是主库首个 DELETE 路径：采用 ts>0 守卫（保护异常 0 值行）+ 分批 DELETE
// （批间提交，避免长事务锁 WAL）+ 批间让出（调用方注入 yield
// 回调消费一轮通道，维持启动期写吞吐——替代原 5ms Sleep，见 cleanupTable 注释）。
package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"sentry-agent/internal/archive"
	"sentry-agent/internal/event"
)

// retentionBatchSize 每批 DELETE 行数上限（B.5.2：分批提交，避免长事务锁 WAL）。
const retentionBatchSize = 10000

// retentionHourMin 每日清理固定时刻 02:30（运营官 D.4 裁定 4：不配置化，KISS）。
const (
	retentionHour = 2
	retentionMin  = 30
)

// nextRetentionTime 计算下一个清理时刻（02:30；已过今日 02:30 则明日）。
func nextRetentionTime(now time.Time) time.Time {
	next := time.Date(now.Year(), now.Month(), now.Day(), retentionHour, retentionMin, 0, 0, time.Local)
	if !now.Before(next) {
		next = next.AddDate(0, 0, 1)
	}
	return next
}

// cleanupTable 清理单表早于 cutoff 的事件行（纯 SQL 分批 DELETE，可单测）。
// ts > 0 AND ts < cutoff 守卫：保护异常 0 值行（保留，不参与清理）。
// 表名来自 archive.ArchivedTables() 固定清单（非用户输入，无注入面）。
// 分批实现（实现偏差说明）：modernc.org/sqlite v1.56.0 内嵌 SQLite 不支持
// DELETE 语句的 LIMIT 子句（实测语法错误，无论参数化/常量），改用子查询取 id 上限
// 分批删除（每批最多 batchSize 行，批间提交避免长事务锁 WAL，语义与 B.5.2 一致）。
// yield 批间让出回调：每批删除后调用一次，供调用方消费一轮
// 通道维持写吞吐——替代原 5ms Sleep（Sleep 不释放通道消费，大库清理期间通道积压满后
// conntrack hook 阻塞 → netlink 缓冲积压 → ENOBUFS 溢出丢事件）；测试场景传 nil 跳过。
// 返回清理行数；ctx 取消时返回已清理行数 + ctx.Err()（幂等：中断后可重跑）。
func cleanupTable(ctx context.Context, db *sql.DB, table string, cutoff int64, batchSize int, yield func()) (int64, error) {
	var total int64
	for {
		select {
		case <-ctx.Done():
			return total, ctx.Err()
		default:
		}
		// 子查询按 id 升序取前 batchSize 行（确定性分批；id 为主键单调递增）。
		res, err := db.ExecContext(ctx, fmt.Sprintf(
			`DELETE FROM "%s" WHERE ts > 0 AND ts < ? AND id IN (SELECT id FROM "%s" WHERE ts > 0 AND ts < ? ORDER BY id LIMIT ?)`,
			table, table), cutoff, cutoff, batchSize)
		if err != nil {
			return total, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, nil
		}
		total += n
		if yield != nil {
			yield()
		}
	}
}

// runRetentionOnce 执行一轮 retention 清理（写线程内调用；启动首轮 + 每日 02:30 定时）。
// cutoff 按本轮开始时刻快照（不随清理过程漂移，防边界误删）；
// 触发表：archive.ArchivedTables() 全量（meta 不清理）；
// yield 批间让出回调：透传给 cleanupTable，Run 场景消费一轮
// 通道维持写吞吐；测试场景传 nil。
// 留痕：system_event info（合计行数/耗时）+ meta.last_retention_ts（幂等/可观测）。
func (s *Store) runRetentionOnce(ctx context.Context, yield func()) error {
	// 防御：禁用态（<=0）直接返回——Run 已守卫，此处防内部误调用
	// 计算出未来 cutoff（会删 0 行但产生无意义 meta 写入）。
	if s.retentionDays <= 0 {
		return nil
	}
	cutoff := time.Now().AddDate(0, 0, -s.retentionDays).Unix()
	start := time.Now()
	var total int64
	for _, t := range archive.ArchivedTables() {
		n, err := cleanupTable(ctx, s.db, t, cutoff, retentionBatchSize, yield)
		if err != nil {
			return fmt.Errorf("清理表 %s 失败: %w", t, err)
		}
		total += n
	}
	if _, err := s.db.Exec(`INSERT INTO meta(key, value) VALUES('last_retention_ts', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		fmt.Sprintf("%d", time.Now().Unix())); err != nil {
		return fmt.Errorf("记录 last_retention_ts 失败: %w", err)
	}
	event.ReportSys(s.ch.System, "store", "info",
		fmt.Sprintf("retention 清理完成：各表行数合计 %d，耗时 %v（保留 %d 天）", total, time.Since(start).Round(time.Millisecond), s.retentionDays))
	return nil
}

// retentionStep 执行一轮 retention 清理并检查批间让出期间的致命写错误。
// label 用于留痕消息（"首轮"/"定时"）；清理失败仅留痕不退出（清理是容错可重试操作，
// 写路径主职责不受影响）；yieldErr 非 nil 表示批间 flush 失败（写路径致命错误），
// 返回错误终止 Run（DEV-AUDIT-001 P1-4：Run 主循环双分支公共处理提取）。
func (s *Store) retentionStep(ctx context.Context, yield func(), yieldErr *error, label string) error {
	if err := s.runRetentionOnce(ctx, yield); err != nil {
		event.ReportSys(s.ch.System, "store", "error", "retention "+label+"清理失败: "+err.Error())
	}
	if *yieldErr != nil {
		return fmt.Errorf("批量提交失败: %w", *yieldErr)
	}
	return nil
}

// warnRetentionArchiveGap 启动时检测 retention 与归档跨度的空洞语义（B.5.1）。
// 推导：归档执行日对 cutoff 月（now - copy_after_days 所在月）做整月复制，最大年龄 =
// copy_after_days + 30；故 retention_days < copy_after_days + 30 时归档副本必然含空洞。
// 决策：代码不强制联动（避免隐性删除语义），仅启动 warn 提示，由运维按需调整。
func (s *Store) warnRetentionArchiveGap() {
	if s.retentionDays <= 0 || s.retentionDays >= s.copyAfterDays+30 {
		return
	}
	event.ReportSys(s.ch.System, "store", "warn", fmt.Sprintf(
		"db.retention_days=%d 小于归档跨度（archive.copy_after_days+30=%d）：归档副本将包含已清理数据的空洞；如需完整归档，retention_days 应 >= %d，或接受短保留期下归档仅含保留窗口数据",
		s.retentionDays, s.copyAfterDays+30, s.copyAfterDays+31))
}
