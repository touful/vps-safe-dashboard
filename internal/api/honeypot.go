package api

import (
	"context"
	"net/http"
	"time"

	"sentry-agent/internal/event"
)

// honeypotRow 蜜罐凭据捕获行（API 展示口径）。
// 敏感信息：Password 为攻击者提交的尝试凭据（明文协议为明文、加密协议为不可逆摘要），
// API 返回明文——本地单机工具定位（监听默认 127.0.0.1:8080）；前端默认遮蔽展示。
type honeypotRow struct {
	TS       int64  `json:"ts"`
	Proto    string `json:"proto"`
	SrcIP    string `json:"src_ip"`
	Username string `json:"username"`
	Password string `json:"password"`
	Extra    string `json:"extra"`
}

// hHoneypotEvents 蜜罐凭据捕获查询（DEV-HONEY-001）。
// GET /api/v1/honeypot/events?range=1h|24h|7d|30d&proto=mysql&limit=200
// 响应：{"range":"24h","rows":[{ts,proto,src_ip,username,password,extra}]}
// 参数：proto 精确过滤（mysql/redis/...，缺失=全部）；limit 默认 200 上限 500。
// 限流：limitAPI 普通档（蜜罐事件量小）；只读查询（与全部 /api/ 一致）。
func (s *Server) hHoneypotEvents(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	from := rangeSeconds(r)
	limit := parseUintParam(r, "limit", 200)
	if limit > 500 {
		limit = 500
	}
	conds := []string{"ts >= ?"}
	args := []any{from}
	if proto := r.URL.Query().Get("proto"); proto != "" {
		conds = append(conds, "proto = ?")
		args = append(args, proto)
	}
	query := `SELECT ts, proto, src_ip, username, password, extra FROM cred_events
		WHERE ` + joinConds(conds) + ` ORDER BY ts DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		writeErr(w, 500, "查询失败: "+err.Error())
		return
	}
	defer rows.Close()
	var out []honeypotRow
	for rows.Next() {
		var row honeypotRow
		var srcIP int64
		if rows.Scan(&row.TS, &row.Proto, &srcIP, &row.Username, &row.Password, &row.Extra) == nil {
			row.SrcIP = event.Uint32ToIPv4(uint32(srcIP))
			out = append(out, row)
		}
	}
	// range 回显（与既有端点口径一致：非法值回显默认 24h）。
	rng := r.URL.Query().Get("range")
	switch rng {
	case "1h", "24h", "7d", "30d":
	default:
		rng = "24h"
	}
	writeJSON(w, 200, map[string]any{"range": rng, "rows": out})
}

// joinConds 拼接 WHERE 条件（与查询构造分离的小工具；conds 非空）。
func joinConds(conds []string) string {
	out := ""
	for i, c := range conds {
		if i > 0 {
			out += " AND "
		}
		out += c
	}
	return out
}
