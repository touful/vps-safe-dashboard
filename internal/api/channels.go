// P3-3（2026-09）：采集通道健康端点——读侧聚合各表最新入库时间与库概况，
// 反映采集管线是否断流（某表 last_ts 长期停滞 = 对应通道异常线索）。
// 不改采集模块，仅消费既有表数据；retention/db_size/overrun 与 /api/v1/health
// 同口径（dbSizeBytes 单一来源，勿复制 os.Stat 逻辑）。
package api

import (
	"context"
	"net/http"
	"time"
)

// channelTableStatus 单表通道状态行。
type channelTableStatus struct {
	Name   string `json:"name"`
	LastTS int64  `json:"last_ts"`
}

// sysWarningRow 最近告警行（system_events warn/error 口径）。
type sysWarningRow struct {
	TS      int64  `json:"ts"`
	Source  string `json:"source"`
	Level   string `json:"level"`
	Message string `json:"message"`
}

// channelTables 固定 7 表顺序（前端契约按序展示，勿改顺序）。
var channelTables = []string{
	"connections", "ssh_attempts", "firewall_events", "ban_events",
	"cred_events", "resources", "system_events",
}

// hChannels 采集通道健康（GET /api/v1/channels；limitAPI 档，handler 内 3s ctx）。
// 响应：{"now":...,"retention_days":...,"db_size_mb":...,"overrun_total":...,
//        "tables":[{name,last_ts}×7],"recent_warnings":[{ts,source,level,message}≤20]}
// 语义：
//   - tables[].last_ts = 各表 MAX(ts)（空表为 0，COALESCE 兜底 NULL）；
//   - recent_warnings = system_events 最近 20 条 warn/error（ts 降序）；
//   - 任一查询错误 → writeDBErr 500。
func (s *Server) hChannels(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	tables := make([]channelTableStatus, 0, len(channelTables))
	for _, name := range channelTables {
		var last int64
		// 表名仅来自本包常量列表（无用户输入面）；MAX 空表 NULL → 0。
		if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(ts),0) FROM `+name).Scan(&last); err != nil {
			writeDBErr(w, r, err)
			return
		}
		tables = append(tables, channelTableStatus{Name: name, LastTS: last})
	}
	warnings, err := s.recentWarnings(ctx, 20)
	if err != nil {
		writeDBErr(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{
		"now":             time.Now().Unix(),
		"retention_days":  s.retentionDays,
		"db_size_mb":      float64(s.dbSizeBytes()) / 1024 / 1024,
		"overrun_total":   s.overrunCounter.Load(),
		"tables":          tables,
		"recent_warnings": warnings,
	})
}

// recentWarnings 最近 warn/error 系统事件（ts 降序，limit 条；channels 专用查询）。
func (s *Server) recentWarnings(ctx context.Context, limit int) ([]sysWarningRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT ts, source, level, message FROM system_events
		WHERE level IN ('warn','error') ORDER BY ts DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]sysWarningRow, 0) // 空结果输出 []（非 null），m4 口径
	for rows.Next() {
		var w sysWarningRow
		if rows.Scan(&w.TS, &w.Source, &w.Level, &w.Message) == nil {
			out = append(out, w)
		}
	}
	return out, nil
}
