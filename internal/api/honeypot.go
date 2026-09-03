package api

import (
	"context"
	"net/http"
	"strings"
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
		WHERE ` + strings.Join(conds, " AND ") + ` ORDER BY ts DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		writeDBErr(w, r, err)
		return
	}
	defer rows.Close()
	// 空结果输出 []（非 null）——前端三态与外部调用方规范性。
	out := make([]honeypotRow, 0)
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

// honeypotCredRow 凭据字典聚合行（DEV-HONEY-002：按 协议+用户名+密码 去重聚合）。
type honeypotCredRow struct {
	Proto    string `json:"proto"`
	Username string `json:"username"`
	Password string `json:"password"`
	Kind     string `json:"kind"` // plaintext（明文，可直接入字典）/ hash（不可逆摘要）/ none（协议无认证）
	Count    int64  `json:"count"`
	FirstTS  int64  `json:"first_ts"`
	LastTS   int64  `json:"last_ts"`
	SrcIPCnt int64  `json:"src_ip_cnt"`
	Extra    string `json:"extra"`
}

// 明文协议集合：password 字段为攻击者提交的明文（telnet/ftp/redis/postgres 捕获即明文；
// mssql TDS 混淆可逆、捕获时已还原——还原失败条目的 extra 含还原失败标注，降级为 hash）。
var credPlaintextProtos = map[string]bool{
	"telnet":   true,
	"ftp":      true,
	"redis":    true,
	"postgres": true,
	"mssql":    true,
}

// 无认证协议：协议本身无凭据概念，无密码可捕获。
var credNoAuthProtos = map[string]bool{
	"rdp":       true,
	"memcached": true,
}

// credKind 凭据条目类型判定（协议级静态分类 + mssql 逐条降级）。
func credKind(proto, extra string) string {
	if credNoAuthProtos[proto] {
		return "none"
	}
	if credPlaintextProtos[proto] {
		if proto == "mssql" && strings.Contains(extra, "还原失败") {
			return "hash" // mssql 非标准客户端（畸形/非可打印）回退 hex 摘要的条目
		}
		return "plaintext"
	}
	return "hash" // mysql（SHA1 链）/ smb（NTLMv2）/ mongodb（SCRAM 证明）均为不可逆摘要
}

// hHoneypotCreds 凭据字典聚合查询（DEV-HONEY-002）。
// GET /api/v1/honeypot/creds?range=1h|24h|7d|30d&proto=mysql&limit=200
// 按 (proto, username, password) GROUP BY 去重聚合，返回尝试次数/首见/最近/源 IP 数，
// 按次数降序；kind 标注明文/摘要/无认证（字典导出与前端展示的筛选依据）。
// limit 默认 200 上限 500（去重后条目数天然有限，500 覆盖绝大多数字典规模）。
func (s *Server) hHoneypotCreds(w http.ResponseWriter, r *http.Request) {
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
	// extra 取 MAX 作代表标注（同组 extra 可能不一——redis AUTH 与 HELLO；
	// kind 判定仅需 mssql 的还原失败标记，MAX 不影响语义）。
	query := `SELECT proto, username, password, MAX(extra), COUNT(*), MIN(ts), MAX(ts),
		COUNT(DISTINCT src_ip) FROM cred_events
		WHERE ` + strings.Join(conds, " AND ") + `
		GROUP BY proto, username, password ORDER BY COUNT(*) DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		writeDBErr(w, r, err)
		return
	}
	defer rows.Close()
	out := make([]honeypotCredRow, 0) // 空结果输出 []（非 null），与 events 端点口径一致
	for rows.Next() {
		var row honeypotCredRow
		if rows.Scan(&row.Proto, &row.Username, &row.Password, &row.Extra,
			&row.Count, &row.FirstTS, &row.LastTS, &row.SrcIPCnt) == nil {
			row.Kind = credKind(row.Proto, row.Extra)
			out = append(out, row)
		}
	}
	rng := r.URL.Query().Get("range")
	switch rng {
	case "1h", "24h", "7d", "30d":
	default:
		rng = "24h"
	}
	writeJSON(w, 200, map[string]any{"range": rng, "rows": out})
}
