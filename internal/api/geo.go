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

// hGeoAttacks 全球攻击地图数据（DEV-GEO-001 B.1）。
// GET /api/v1/attacks/geo?range=1h|24h|7d|30d&country=XX&min_count=N
// 响应：{"range":"24h","mmdb_ok":true,"rows":[{ip,country_code,country_name,count}]}
// 限流：limitHeavy（30d 视图 1000 IP 组 + 逐 IP mmdb 查询，CPU/IO 密集）。
func (s *Server) hGeoAttacks(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	from := rangeSeconds(r)
	country := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("country")))
	minCount := parseUintParam(r, "min_count", 0)
	rows, mmdbOK, err := s.queryGeoRows(ctx, from, 1000)
	if err != nil {
		writeErr(w, 500, "查询失败: "+err.Error())
		return
	}
	rows = filterGeoRows(rows, country, minCount)
	// range 回显（R-09：非法值回显默认 24h，与 rangeSeconds 口径一致）
	rng := r.URL.Query().Get("range")
	switch rng {
	case "1h", "24h", "7d", "30d":
	default:
		rng = "24h"
	}
	writeJSON(w, 200, map[string]any{"range": rng, "mmdb_ok": mmdbOK, "rows": rows})
}

// hExportAttacksCSV 全球攻击地图 CSV 导出（DEV-GEO-001 B.2）。
// GET /api/v1/export/attacks_csv?range=&country=&min_count=
// 与 /attacks/geo 同口径同筛选；输出无表头三列：IP,国家或地区,累计攻击次数。
// 与既有 /api/v1/export/csv（IP,时间,端口）并存，勿混淆。
// 限流：limitHeavy（同聚合导出成本）。
func (s *Server) hExportAttacksCSV(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	from := rangeSeconds(r)
	country := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("country")))
	minCount := parseUintParam(r, "min_count", 0)
	rows, _, err := s.queryGeoRows(ctx, from, 1000)
	if err != nil {
		writeErr(w, 500, "查询失败: "+err.Error())
		return
	}
	rows = filterGeoRows(rows, country, minCount)
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
	cw.Flush()
	if err := cw.Error(); err != nil {
		s.limitWarn.Report(s.sysCh, "api", "warn", "导出写入失败: "+err.Error())
	}
}
