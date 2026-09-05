package api

import (
	"context"
	"encoding/csv"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"sentry-agent/internal/event"
)

// GeoLookuper 国家查询接口（*geoip.Reader 实现；测试注入 fake）。
// OK()=false 表示未配置/未加载——API 层 mmdb_ok=false 降级（country 恒 Unknown）。
type GeoLookuper interface {
	OK() bool
	Lookup(net.IP) (code, name string, ok bool)
}

// geoRow 攻击来源 IP 聚合行（SSH 失败口径，DEV-GEO-001）。
type geoRow struct {
	IP          string `json:"ip"`
	CountryCode string `json:"country_code"`
	CountryName string `json:"country_name"`
	Count       int64  `json:"count"`
}

// unknownCountry mmdb 未配置/未命中时的占位值。
const unknownCountry = "Unknown"

// queryGeoRows 查询 SSH 失败（result=0，与 hSummary/hSSHTimeline 同口径）按 src_ip 聚合，
// 逐 IP 经 geo 查询补国家信息。limit 为服务端返回上限（按 count DESC 排序取前 limit）。
func (s *Server) queryGeoRows(ctx context.Context, from int64, limit int) ([]geoRow, bool, error) {
	mmdbOK := s.geo != nil && s.geo.OK()
	rows, err := s.db.QueryContext(ctx, `SELECT src_ip, COUNT(*) AS cnt FROM ssh_attempts
		WHERE ts >= ? AND result = 0 GROUP BY src_ip ORDER BY cnt DESC, src_ip LIMIT ?`, from, limit)
	if err != nil {
		return nil, mmdbOK, err
	}
	defer rows.Close()
	out := make([]geoRow, 0, 64)
	for rows.Next() {
		var srcIP uint32
		var cnt int64
		if rows.Scan(&srcIP, &cnt) != nil {
			continue
		}
		row := geoRow{IP: event.Uint32ToIPv4(srcIP), Count: cnt}
		if mmdbOK {
			ip := net.ParseIP(row.IP)
			if code, name, ok := s.geo.Lookup(ip); ok && code != "" {
				row.CountryCode = code
				row.CountryName = name
			} else {
				row.CountryCode, row.CountryName = unknownCountry, unknownCountry
			}
		} else {
			row.CountryCode, row.CountryName = unknownCountry, unknownCountry
		}
		out = append(out, row)
	}
	// 迭代后 rows.Err()（功能审计 Minor-2）：超时取消/IO 错误时迭代提前终止，
	// 已扫描部分与错误一并返回——导出侧据此追加截断标记，地图侧维持 500（下轮轮询自愈）。
	if err := rows.Err(); err != nil {
		return out, mmdbOK, err
	}
	return out, mmdbOK, nil
}

// filterGeoRows 应用 country（ISO code 精确匹配，含 Unknown）与 min_count 过滤。
// 过滤在 Go 侧进行（SQL 无法处理 mmdb 查询后的国家归属）。
// G-01（M-A 审计遗留，DEV-HONEY-001 顺手修复）：country 参数在 hGeoAttacks/
// hExportAttacksCSV 已 ToUpper（如 "unknown"→"UNKNOWN"），与 unknownCountry 占位值
// "Unknown"（混合大小写）直接比较会漏匹配——此处按大小写不敏感比较（EqualFold）。
func filterGeoRows(rows []geoRow, country string, minCount uint64) []geoRow {
	out := rows[:0]
	for _, row := range rows {
		if country != "" && !strings.EqualFold(row.CountryCode, country) {
			continue
		}
		if minCount > 0 && uint64(row.Count) < minCount {
			continue
		}
		out = append(out, row)
	}
	return out
}

// geoRowsFromReq geo 双 handler（地图 /attacks/geo 与导出 /export/attacks_csv）共用取数前置：
// range → from、country（ToUpper+TrimSpace）、min_count 解析，随后 queryGeoRows（上限 1000 IP 组）
// + filterGeoRows。"地图与导出同口径同筛选"由代码结构强制（两调用方走同一函数，无第二份拷贝）。
func (s *Server) geoRowsFromReq(ctx context.Context, r *http.Request) ([]geoRow, bool, error) {
	from := rangeSeconds(r)
	country := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("country")))
	minCount := parseUintParam(r, "min_count", 0)
	rows, mmdbOK, err := s.queryGeoRows(ctx, from, 1000)
	// 迭代中断时 rows 为已扫描部分（可能非空）与 err 并存：导出侧需要部分数据
	// 写截断标记，故不完全丢弃；地图调用方见 err 即 500，不消费部分数据。
	if err != nil {
		return filterGeoRows(rows, country, minCount), mmdbOK, err
	}
	return filterGeoRows(rows, country, minCount), mmdbOK, nil
}

// hGeoAttacks 全球攻击地图数据（DEV-GEO-001 B.1）。
// GET /api/v1/attacks/geo?range=1h|24h|7d|30d&country=XX&min_count=N
// 响应：{"range":"24h","mmdb_ok":true,"rows":[{ip,country_code,country_name,count}]}
// 限流：limitHeavy（30d 视图 1000 IP 组 + 逐 IP mmdb 查询，CPU/IO 密集）。
func (s *Server) hGeoAttacks(w http.ResponseWriter, r *http.Request) {
	// 超时档对齐 hSSHTimeline/hSummary（功能审计 Minor-1）：24h/30d 视图冷启动窗口
	// GROUP BY 首查可超 5s（api.go aggTimeout 注释的生产实测），固定超时周期性 500。
	timeout := aggTimeout(r, 15*time.Second)
	if r.URL.Query().Get("range") == "30d" {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	rows, mmdbOK, err := s.geoRowsFromReq(ctx, r)
	if err != nil {
		writeDBErr(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"range": rangeEcho(r), "mmdb_ok": mmdbOK, "rows": rows})
}

// hExportAttacksCSV 全球攻击地图 CSV 导出（DEV-GEO-001 B.2）。
// GET /api/v1/export/attacks_csv?range=&country=&min_count=
// 与 /attacks/geo 同口径同筛选（geoRowsFromReq 结构强制）；输出无表头三列：IP,国家或地区,累计攻击次数。
// 与既有 /api/v1/export/csv（IP,时间,端口）并存，勿混淆。
// 限流：limitHeavy（同聚合导出成本）。
func (s *Server) hExportAttacksCSV(w http.ResponseWriter, r *http.Request) {
	// 超时档对齐 hGeoAttacks（功能审计 Minor-1）。
	timeout := aggTimeout(r, 15*time.Second)
	if r.URL.Query().Get("range") == "30d" {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	rows, _, err := s.geoRowsFromReq(ctx, r)
	// 迭代中断（err 非 nil 且已有部分数据）不再整体 500：写出已扫描部分并追加
	// 截断标记（功能审计 Minor-2，口径对齐 export_table.go/export.go 的 A4 修复），
	// 避免截断文件被当完整数据使用。
	if err != nil && len(rows) == 0 {
		writeDBErr(w, r, err)
		return
	}
	// CSV 头（查询成功后才写——查询失败须回 500 JSON）
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="sentry_attacks_geo_`+time.Now().Format("20060102_150405")+`.csv"`)
	cw := csv.NewWriter(w) // 标准库 RFC 4180 转义（国家名含逗号/引号自动加引号）；行尾 \n
	for _, row := range rows {
		if err := cw.Write([]string{row.IP, row.CountryName, strconv.FormatInt(row.Count, 10)}); err != nil {
			s.limitWarn.Report(s.sysCh, "api", "warn", "导出写入失败: "+err.Error())
			return
		}
	}
	if err != nil {
		// 标记行经 cw 写出（绕过 cw 直写 w 会与内部缓冲乱序）；单字段无逗号。
		_ = cw.Write([]string{"# EXPORT_TRUNCATED at " + time.Now().Format(time.RFC3339) + "（导出中断，以上数据不完整）"})
		s.limitWarn.Report(s.sysCh, "api", "warn", "攻击地图导出中断: "+err.Error())
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		s.limitWarn.Report(s.sysCh, "api", "warn", "导出写入失败: "+err.Error())
	}
}
