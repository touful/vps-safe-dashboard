package api

import (
	"context"
	"encoding/csv"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// hExportCreds 蜜罐凭据字典导出（DEV-HONEY-002，用户裁定 2026-09-02 开放本地导出）。
// GET /api/v1/export/creds?format=csv|pairs|passwords&range=1h|24h|7d|30d[&from+to][&proto=]
//
// 数据口径：cred_events 按 (proto, username, password) 去重聚合（与
// /api/v1/honeypot/creds 同一聚合口径），三格式：
//   - csv       全量审计视图（含摘要/无认证协议条目），表头
//     username,password,protocol,kind,count,first_seen,last_seen,src_ip_count
//   - pairs     爆破字典格式，每行 `username:password`（仅 kind=plaintext 且密码非空，
//     按尝试次数降序；hydra -C / medusa 组合字典格式）
//   - passwords 纯密码列表（仅明文且非空，跨协议去重，按尝试次数降序）
//
// 明文协议：telnet/ftp/redis/postgres（捕获即明文）+ mssql（TDS 混淆可逆，捕获时已还原；
// 还原失败条目自动降级为 hash 不入字典）。mysql/smb/mongodb 为不可逆摘要、rdp/memcached
// 无认证——均不出现在 pairs/passwords，仅见 csv（如实标注 kind）。
//
// 限流：路由注册处 limitHeavy（与 export/csv 同档）；导出为本地敏感数据，文件由用户自行保管。
// 聚合结果为去重条目（天然有限规模，通常 < 数千行），一次性取回内存后写出，无需流式。
func (s *Server) hExportCreds(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	switch format {
	case "csv", "pairs", "passwords":
	default:
		writeErr(w, http.StatusBadRequest, "参数错误：format 须为 csv / pairs / passwords")
		return
	}
	from, to, timeout, ok := parseExportWindow(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	conds := []string{"ts >= ?", "ts <= ?"}
	args := []any{from, to}
	if proto := r.URL.Query().Get("proto"); proto != "" {
		conds = append(conds, "proto = ?")
		args = append(args, proto)
	}
	// 聚合 SQL 单一来源（m4 修复）：与 hHoneypotCreds 共用 credAggQuery。
	query := credAggQuery(strings.Join(conds, " AND "))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		writeDBErr(w, r, err)
		return
	}
	defer rows.Close()
	type credEntry struct {
		proto, username, password, extra string
		count, firstTS, lastTS, srcCnt   int64
	}
	var entries []credEntry
	for rows.Next() {
		var e credEntry
		if rows.Scan(&e.proto, &e.username, &e.password, &e.extra,
			&e.count, &e.firstTS, &e.lastTS, &e.srcCnt) == nil {
			entries = append(entries, e)
		}
	}
	if err := rows.Err(); err != nil {
		writeDBErr(w, r, err)
		return
	}

	stamp := time.Now().Format("20060102_150405")
	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="sentry_creds_`+stamp+`.csv"`)
		cw := csv.NewWriter(w)
		// 写错误处理与 export.go/export_table.go 口径对齐（审计 A7）：写失败经
		// limitWarn 限频留痕（客户端断开等），不再静默忽略。
		if err := cw.Write([]string{"username", "password", "protocol", "kind", "count", "first_seen", "last_seen", "src_ip_count"}); err != nil {
			s.limitWarn.Report(s.sysCh, "api", "warn", "creds 导出写表头失败（客户端可能已断开）")
		}
		for _, e := range entries {
			if err := cw.Write([]string{
				// username/password 为攻击者可控文本，公式注入防护（审计 H-1，见 sanitizeCSVCell）
				sanitizeCSVCell(e.username), sanitizeCSVCell(e.password), e.proto, credKind(e.proto, e.extra),
				strconv.FormatInt(e.count, 10), time.Unix(e.firstTS, 0).Format("2006-01-02 15:04:05"),
				time.Unix(e.lastTS, 0).Format("2006-01-02 15:04:05"), strconv.FormatInt(e.srcCnt, 10),
			}); err != nil {
				s.limitWarn.Report(s.sysCh, "api", "warn", "creds 导出写行失败（客户端可能已断开）")
				break
			}
		}
		cw.Flush()
		if err := cw.Error(); err != nil {
			s.limitWarn.Report(s.sysCh, "api", "warn", "creds 导出 Flush 失败: "+err.Error())
		}
	case "pairs":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="sentry_creds_pairs_`+stamp+`.txt"`)
		for _, e := range entries {
			if credKind(e.proto, e.extra) == "plaintext" && e.password != "" {
				_, _ = w.Write([]byte(e.username + ":" + e.password + "\n"))
			}
		}
	case "passwords":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="sentry_creds_passwords_`+stamp+`.txt"`)
		seen := make(map[string]bool, len(entries))
		for _, e := range entries {
			if credKind(e.proto, e.extra) == "plaintext" && e.password != "" && !seen[e.password] {
				seen[e.password] = true
				_, _ = w.Write([]byte(e.password + "\n"))
			}
		}
	}
}
