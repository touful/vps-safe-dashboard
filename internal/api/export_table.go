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

// hExportTable 统一明细导出（GET /api/v1/export/table?type=ssh|fw|hp|conn|bans|sys&窗口参数）。
// 为六类明细表提供带表头的标准 CSV（RFC 4180），补齐"前端只做统计展示、明细走导出"定位：
//   - ssh  ssh_attempts     SSH 登录尝试明细
//   - fw   firewall_events  防火墙事件明细
//   - hp   cred_events      蜜罐凭据捕获明细
//   - conn connections      连接事件明细
//   - bans ban_events       fail2ban 封禁历史
//   - sys  system_events    采集器系统事件
//
// 敏感口径警示：type=hp 含攻击者提交的明文凭据（password 列）——与 /api/v1/export/creds
// 同级敏感数据（用户裁定 2026-09-02 开放本地导出），文件由用户自行保管、禁止外发；
// password/extra 与 fw 的 raw 均为攻击者可控字段，RFC 4180 转义必须完整覆盖
// （含逗号/引号/换行字段自动加引号并双写引号，防 CSV 行列撕裂）。
//
// 参数：type 必填（缺失/非法 → 400，错误信息列出合法值）；时间窗复用 parseExportWindow
// （range=1h|24h|7d|30d 或 from+to Unix 秒，与 export/csv、export/creds 共用，窗口 SQL
// 条件 ts >= ? AND ts <= ? 亦一致）；无 limit 参数——窗口内全量流式（与 hExportCSV 同口径，
// conn 表 30d 可能数十万行）。排序 ORDER BY ts DESC 与查询端点一致。
//
// 流式写出：逐行 Write + 每 500 行 Flush（大结果集避免内存聚合与客户端长时间无数据）；
// 写出阶段错误（客户端断开/写失败）时状态码已发、无法回写 5xx，经 limitWarn 限频留痕
// system channel 供运维可观测（sysCh 未注入时 nil 安全静默丢弃）；
// 参数/窗口/查询阶段错误尚未写响应头，正常回 4xx/5xx JSON。
// 限流：路由注册处 limitHeavy（与既有导出端点同档——流式大导出）。
func (s *Server) hExportTable(w http.ResponseWriter, r *http.Request) {
	typ := r.URL.Query().Get("type")
	spec, ok := exportTableSpecs[typ]
	if !ok {
		writeErr(w, http.StatusBadRequest,
			"参数错误：type 须为 ssh / fw / hp / conn / bans / sys 之一")
		return
	}
	from, to, timeout, ok := parseExportWindow(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, spec.query, from, to)
	if err != nil {
		writeDBErr(w, r, err)
		return
	}
	defer rows.Close()
	// 响应头在查询成功后才写——查询失败须回 500 JSON，不能先发 CSV 头。
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition",
		`attachment; filename="sentry-`+typ+`-`+time.Now().Format("20060102-150405")+`.csv"`)
	// RFC 4180 转义单一来源：标准库 csv.Writer（与 export/csv、export/attacks_csv 一致，
	// 不另造第二份转义实现）。
	cw := csv.NewWriter(w)
	if err := cw.Write(spec.cols); err != nil {
		s.limitWarn.Report(s.sysCh, "api", "warn", "明细导出写入失败: "+err.Error())
		return
	}
	written := 0
	for rows.Next() {
		// 单行 scan 失败跳过该行（CSV 已流式输出无法回写；schema 全列 NOT NULL，正常不触发）。
		rec, err := spec.row(rows)
		if err != nil {
			continue
		}
		if err := cw.Write(rec); err != nil {
			s.limitWarn.Report(s.sysCh, "api", "warn", "明细导出写入失败: "+err.Error())
			return
		}
		// 每 500 行 Flush：conn 大窗口数十万行场景下限制缓冲占用，
		// 且避免客户端（浏览器下载）长时间收不到字节。
		if written++; written%500 == 0 {
			cw.Flush()
			if err := cw.Error(); err != nil {
				s.limitWarn.Report(s.sysCh, "api", "warn", "明细导出写入失败: "+err.Error())
				return
			}
		}
	}
	// 迭代后 rows.Err()：超时取消/IO 错误时 CSV 可能静默截断——状态码已发无法回写 5xx，
	// Flush 尽量交付已扫描前缀；查询与写入两条错误合并单条留痕（limitWarn 1/分钟限频，
	// 分开上报第二条必被确定性丢弃）。
	// 截断标记（审计 A4）：中断时在 CSV 尾部追加 "# EXPORT_TRUNCATED" 注释行，客户端
	// （前端 exportTableCsv）据此检测并向用户告警"导出不完整"，避免截断文件被当真使用。
	if err := rows.Err(); err != nil {
		// 标记行经 cw 写出（绕过 cw 直写 w 会与 cw 内部缓冲乱序）；单字段无逗号，
		// 前端按 blob 尾部前缀 "# EXPORT_TRUNCATED" 检测。写失败无需单独处理
		// （rows.Err 已是主因，下方统一留痕）。
		_ = cw.Write([]string{"# EXPORT_TRUNCATED at " + time.Now().Format(time.RFC3339) + "（导出中断，以上数据不完整）"})
		cw.Flush()
		msg := "明细导出中断: 查询=" + err.Error()
		if werr := cw.Error(); werr != nil {
			msg += "；写入=" + werr.Error()
		}
		s.limitWarn.Report(s.sysCh, "api", "warn", msg)
		return
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		s.limitWarn.Report(s.sysCh, "api", "warn", "明细导出写入失败: "+err.Error())
	}
}

// csvTS Unix 秒 → RFC3339 本地时区（如 2026-09-05T15:30:00+08:00），
// 带时区偏移可被 pandas/Excel 直接解析为时间类型。
func csvTS(ts int64) string { return time.Unix(ts, 0).Format(time.RFC3339) }

// sanitizeCSVCell CSV 公式注入防护（安全审计 H-1，OWASP CSV Injection 惯例）。
// 蜜罐捕获的 username/password 与 SSH username 均为攻击者可控文本，可携带
// = + - @ \t \r 开头的 Excel/LibreOffice 公式（=WEBSERVICE 数据外带、DDE 命令执行
// 尝试）；RFC 4180 转义只处理分隔符与换行，不覆盖此面，且前端 blob 下载不触发
// Protected View。检测到风险前缀时前置单引号，Excel 按文本展示原始值。
// 仅在导出边界调用——入库保留攻击原值（取证口径不变）。
func sanitizeCSVCell(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

// csvIP4 INTEGER 存储的 IPv4 → 点分十进制（uint32 语义，int64 中转 scan 防负值误读）。
func csvIP4(v int64) string { return event.Uint32ToIPv4(uint32(v)) }

// exportTableSpec 单类明细的导出规格（表驱动，六类型共用一个 handler 骨架，避免六段 if 复制）：
// cols 固定表头；query 窗口 SQL（from/to 两个 ? 占位，ORDER BY ts DESC）；row 单行 scan → CSV 字段串。
type exportTableSpec struct {
	cols  []string
	query string
	row   func(rows *sql.Rows) ([]string, error)
}

// exportTableSpecs 六类明细导出规格（key = type 参数值）。
// proto 列口径：event 包仅有协议号常量（ProtoTCP=6/ProtoUDP=17/ProtoICMP=1），
// 无数值→语义名映射；既有查询端点（/api/v1/connections、/api/v1/firewall 的 JSON
// proto 字段）均原样输出整数协议号——本导出保持同口径输出数值，不引入第二套语义映射。
// src_ip6/dst_ip6 为 TEXT 列（IPv4 连接时空串），原样输出。
var exportTableSpecs = map[string]exportTableSpec{
	"ssh": {
		cols: []string{"ts", "src_ip", "username", "auth_method", "result", "fingerprint", "detail"},
		query: `SELECT ts, src_ip, username, auth_method, result, fingerprint, detail
			FROM ssh_attempts WHERE ts >= ? AND ts <= ? ORDER BY ts DESC`,
		row: func(rows *sql.Rows) ([]string, error) {
			var ts, ip, result int64
			var username, auth, fp, detail string
			if err := rows.Scan(&ts, &ip, &username, &auth, &result, &fp, &detail); err != nil {
				return nil, err
			}
			return []string{csvTS(ts), csvIP4(ip), sanitizeCSVCell(username), auth,
				strconv.FormatInt(result, 10), fp, sanitizeCSVCell(detail)}, nil
		},
	},
	"fw": {
		cols: []string{"ts", "chain", "action", "proto", "src_ip", "src_port", "dst_ip", "dst_port", "raw"},
		query: `SELECT ts, chain, action, proto, src_ip, src_port, dst_ip, dst_port, raw
			FROM firewall_events WHERE ts >= ? AND ts <= ? ORDER BY ts DESC`,
		row: func(rows *sql.Rows) ([]string, error) {
			var ts, proto, sip, dip, sport, dport int64
			var chain, action, raw string
			if err := rows.Scan(&ts, &chain, &action, &proto, &sip, &sport, &dip, &dport, &raw); err != nil {
				return nil, err
			}
			return []string{csvTS(ts), chain, action, strconv.FormatInt(proto, 10), csvIP4(sip),
				strconv.FormatInt(sport, 10), csvIP4(dip), strconv.FormatInt(dport, 10), raw}, nil
		},
	},
	// hp 含明文密码（与 /api/v1/export/creds 同级敏感口径，红线见 hExportTable 注释）。
	"hp": {
		cols: []string{"ts", "proto", "src_ip", "username", "password", "extra"},
		query: `SELECT ts, proto, src_ip, username, password, extra
			FROM cred_events WHERE ts >= ? AND ts <= ? ORDER BY ts DESC`,
		row: func(rows *sql.Rows) ([]string, error) {
			var ts, ip int64
			var proto, username, password, extra string
			if err := rows.Scan(&ts, &proto, &ip, &username, &password, &extra); err != nil {
				return nil, err
			}
			return []string{csvTS(ts), proto, csvIP4(ip), sanitizeCSVCell(username),
				sanitizeCSVCell(password), sanitizeCSVCell(extra)}, nil
		},
	},
	"conn": {
		cols: []string{"ts", "ev_type", "proto", "src_ip", "src_port", "dst_ip", "dst_port",
			"packets", "bytes", "mark", "src_ip6", "dst_ip6"},
		query: `SELECT ts, ev_type, proto, src_ip, src_port, dst_ip, dst_port,
			packets, bytes, mark, src_ip6, dst_ip6
			FROM connections WHERE ts >= ? AND ts <= ? ORDER BY ts DESC`,
		row: func(rows *sql.Rows) ([]string, error) {
			var ts, evType, proto, sip, dip, sport, dport, pkts, bytes, mark int64
			var sip6, dip6 string
			if err := rows.Scan(&ts, &evType, &proto, &sip, &sport, &dip, &dport,
				&pkts, &bytes, &mark, &sip6, &dip6); err != nil {
				return nil, err
			}
			return []string{csvTS(ts), strconv.FormatInt(evType, 10), strconv.FormatInt(proto, 10),
				csvIP4(sip), strconv.FormatInt(sport, 10), csvIP4(dip), strconv.FormatInt(dport, 10),
				strconv.FormatInt(pkts, 10), strconv.FormatInt(bytes, 10), strconv.FormatInt(mark, 10),
				sip6, dip6}, nil
		},
	},
	"bans": {
		cols: []string{"ts", "ip", "type", "jail"},
		query: `SELECT ts, ip, type, jail
			FROM ban_events WHERE ts >= ? AND ts <= ? ORDER BY ts DESC`,
		row: func(rows *sql.Rows) ([]string, error) {
			var ts, ip int64
			var typ, jail string
			if err := rows.Scan(&ts, &ip, &typ, &jail); err != nil {
				return nil, err
			}
			return []string{csvTS(ts), csvIP4(ip), typ, jail}, nil
		},
	},
	"sys": {
		cols: []string{"ts", "source", "level", "message"},
		query: `SELECT ts, source, level, message
			FROM system_events WHERE ts >= ? AND ts <= ? ORDER BY ts DESC`,
		row: func(rows *sql.Rows) ([]string, error) {
			var ts int64
			var source, level, message string
			if err := rows.Scan(&ts, &source, &level, &message); err != nil {
				return nil, err
			}
			return []string{csvTS(ts), source, level, message}, nil
		},
	},
}
