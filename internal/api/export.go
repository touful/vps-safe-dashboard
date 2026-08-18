package api

import (
	"context"
	"database/sql"
	"encoding/csv"
	"net/http"
	"strconv"
	"time"

	"sentry-agent/internal/event"
)

// hExportCSV 数据导出（DEV-EXPORT-001）：CSV 三列（攻击者 IP、攻击时间、攻击端口），无表头。
// 数据来源两类全合并（UNION ALL 按时间升序）：
//   - 防火墙 drop：IP=源 IP、时间=事件时间、端口=目标端口 dst_port
//   - SSH 失败尝试：IP=源 IP、时间=事件时间、端口固定 22（result=0 为失败，与 hSummary 口径一致）
//
// DEV-GEO-001：fail2ban 封禁数据随"前端移除封禁展示"一并移出导出（后端 f2b 采集与
// /api/v1/bans 端点保留不动）；攻击来源国家 CSV 走新端点 /api/v1/export/attacks_csv。
//
// 参数二选一：range（1h/24h/7d/30d，复用 rangeSeconds 语义）或 from+to（Unix 秒，含端点，
// 自定义跨度上限 90 天防超长查询）；同时给或都缺 → 400。
// 输出：text/csv + Content-Disposition attachment；流式写（逐行写 ResponseWriter，
// 避免大结果集内存峰值——30d 全量可能数万行）；空数据返回 200 + 空文件（前端提示"无攻击记录"）。
// 限流：路由注册处套 limitHeavy（与 firewall/timeline 一致，1 rps / burst 6）。
func (s *Server) hExportCSV(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	rangeV := q.Get("range")
	fromS, toS := q.Get("from"), q.Get("to")
	hasRange := rangeV != ""
	hasFromTo := fromS != "" || toS != ""
	if hasRange == hasFromTo {
		writeErr(w, http.StatusBadRequest, "参数错误：range 与 from/to 须二选一")
		return
	}
	var from, to int64
	if hasRange {
		from = rangeSeconds(r)
		to = time.Now().Unix()
	} else {
		var err error
		from, err = strconv.ParseInt(fromS, 10, 64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "参数错误：from 须为 Unix 秒")
			return
		}
		to, err = strconv.ParseInt(toS, 10, 64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "参数错误：to 须为 Unix 秒")
			return
		}
		if from > to {
			writeErr(w, http.StatusBadRequest, "参数错误：from 不能晚于 to")
			return
		}
		// span<0 兜底 int64 溢出回绕（from/to 极端值组合使 to-from 溢出为负，
		// 可绕过跨度上限——评审整改）；正常输入下 span>=0 恒成立。
		span := to - from
		if span < 0 || span > 90*86400 {
			writeErr(w, http.StatusBadRequest, "参数错误：自定义时间跨度不能超过 90 天")
			return
		}
	}
	// 超时：30d 视图（或自定义跨度 >7d）放宽至 30s（与 hFirewallTimeline 同模式），其余 5s。
	// 注：span 仅自定义路径定义；range 路径跨度恒 <=30d，超时档由 rangeV 判定。
	timeout := 5 * time.Second
	if (hasRange && rangeV == "30d") || (!hasRange && to-from > 7*86400) {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	// 两源 UNION ALL：子查询统一列（ip INTEGER / ts INTEGER / port INTEGER 或 NULL），
	// 外层按时间升序（再按 ip 稳定排序）。SQLite 动态类型允许 NULL 与 INTEGER 混列。
	query := `SELECT ip, ts, port FROM (
		SELECT src_ip AS ip, ts, dst_port AS port FROM firewall_events
			WHERE action = 'drop' AND ts >= ? AND ts <= ?
		UNION ALL
		SELECT src_ip AS ip, ts, 22 AS port FROM ssh_attempts
			WHERE result = 0 AND ts >= ? AND ts <= ?
	) ORDER BY ts, ip`
	rows, err := s.db.QueryContext(ctx, query, from, to, from, to)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "查询失败: "+err.Error())
		return
	}
	defer rows.Close()
	// CSV 头（查询成功后才写——查询失败须回 500 JSON，不能先写 CSV 头）。
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="sentry_export_`+time.Now().Format("20060102_150405")+`.csv"`)
	cw := csv.NewWriter(w) // 标准库 RFC 4180 转义（含逗号/引号/换行自动加引号）；行尾 \n（UseCRLF 默认 false）
	for rows.Next() {
		var ipV int64
		var ts int64
		var port sql.NullInt64
		if err := rows.Scan(&ipV, &ts, &port); err != nil {
			continue // 单行读取失败跳过该行（CSV 已流式输出，无法回写 500；schema 固定，正常不触发）
		}
		portStr := ""
		if port.Valid {
			portStr = strconv.FormatInt(port.Int64, 10)
		}
		// 行字段：IP 转点分十进制（复用现有转换）、本地时区时间、端口。
		// 写路径错误（缓冲满/客户端断开）停止迭代并留痕。
		// 客户端已断开，后续 rows.Err()/Flush 检查无意义，直接返回（避免再走正常路径）。
		if err := cw.Write([]string{
			event.Uint32ToIPv4(uint32(ipV)),
			time.Unix(ts, 0).Format("2006-01-02 15:04:05"),
			portStr,
		}); err != nil {
			s.limitWarn.Report(s.sysCh, "api", "warn", "导出写入失败: "+err.Error())
			return
		}
	}
	// 迭代后检查 rows.Err()——超时取消/IO 错误时
	// CSV 可能静默截断。中断路径必须先 cw.Flush()：csv.Writer 内部缓冲 4096 字节，
	// 不 Flush 则最后一批已扫描行滞留缓冲，客户端连完整前缀都拿不到；
	// Flush 后检查 cw.Error()——客户端断开等写错误不再被静默吞掉。
	// 两条信息合并为单条留痕（limitWarn 1/分钟限频，分开上报第二条必被确定性丢弃）。
	// CSV 已流式输出（响应头已发），无法回写 500，复用 limitWarn 限频留痕供运维可观测。
	if err := rows.Err(); err != nil {
		cw.Flush()
		werrMsg := ""
		if werr := cw.Error(); werr != nil {
			werrMsg = "；写入=" + werr.Error()
		}
		s.limitWarn.Report(s.sysCh, "api", "warn", "导出中断: 查询="+err.Error()+werrMsg)
		return
	}
	// 正常路径 Flush 后同样检查 cw.Error()（客户端断开留痕）。
	cw.Flush()
	if err := cw.Error(); err != nil {
		s.limitWarn.Report(s.sysCh, "api", "warn", "导出写入失败: "+err.Error())
	}
}
