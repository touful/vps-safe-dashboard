// P3-1（2026-09 合并优化批次）：fail2ban 当前封禁名单端点。
// 数据源为内存快照（main 注入取值函数，f2b.QueryBanned 每 60s 刷新），无 SQL 查询，
// 与 /api/v1/bans（ban_events 历史日志表）互补：历史记录 vs 当前在封集合。
package api

import (
	"net/http"

	"sentry-agent/internal/event"
)

// hBansActive 输出 fail2ban 当前封禁名单快照（limitAPI 档：纯内存读，成本极低）。
// 响应：{"ts": <快照时刻 Unix 秒，0=尚无快照>, "count": n, "rows": ["1.2.3.4", ...]}。
// 语义：
//   - f2b 未启用 / 尚未完成首轮查询 / 查询失败期间 → 上一次快照或空名单（rows 恒为数组非 null，
//     对齐 m4 空结果口径）；
//   - 名单来自 fail2ban 自身库的活跃判定（bantime 未过期/永久封禁），非本工具推导；
//   - IPv6 封禁不在名单内（f2b 查询层限制，与 BanEvent.IP 字段口径一致）。
func (s *Server) hBansActive(w http.ResponseWriter, r *http.Request) {
	type out struct {
		TS    int64    `json:"ts"`
		Count int      `json:"count"`
		Rows  []string `json:"rows"`
	}
	var ips []uint32
	var ts int64
	if s.bannedFn != nil {
		ips, ts = s.bannedFn()
	}
	rows := make([]string, 0, len(ips))
	for _, v := range ips {
		rows = append(rows, event.Uint32ToIPv4(v))
	}
	writeJSON(w, 200, out{TS: ts, Count: len(rows), Rows: rows})
}
