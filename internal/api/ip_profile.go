// P3-2（2026-09）：来源 IP 画像端点——跨表聚合单个 IPv4 近 7 天的行为轨迹
// （连接 / SSH 尝试 / 防火墙事件 / 封禁历史 / 蜜罐凭据），供前端点击 IP 时展示画像。
// 关键约束：
//   - 查询窗口固定 168h：firewall_events 无 src_ip 索引，全部聚合必须带 ts >= ?
//     窗口条件走 idx_fw_ts（生产 245 万行防全表扫描，同 topHits 的 PERF-FIX 注释），
//     其余各表统一同窗口口径（响应 window_hours=168 回显）；
//   - creds 段不含 password 字段——攻击者可控输入不入画像，缩小 XSS 面；
//   - 所有聚合 SQL 带 LIMIT 保护；空数据段输出零值 + 空数组（数组恒非 null，m4 口径）。
package api

import (
	"context"
	"net"
	"net/http"
	"time"

	"sentry-agent/internal/event"
)

// ipWindowHours IP 画像查询窗口（小时，7 天）。
const ipWindowHours = 168

// ipCountry 国家信息（geo 命中时输出对象；geo 未配置/未加载/未命中为 null）。
type ipCountry struct {
	Code string `json:"code"`
	Name string `json:"name"`
}

// ipPortCount 连接目标端口 TOP 行。
type ipPortCount struct {
	DstPort int   `json:"dst_port"`
	Count   int64 `json:"count"`
}

// ipProtoCount 连接协议 TOP 行（proto 为整数协议号，如 6=TCP）。
type ipProtoCount struct {
	Proto int   `json:"proto"`
	Count int64 `json:"count"`
}

// ipUserCount SSH 用户名 TOP 行。
type ipUserCount struct {
	Username string `json:"username"`
	Count    int64  `json:"count"`
}

// ipActionCount 防火墙动作 TOP 行。
type ipActionCount struct {
	Action string `json:"action"`
	Count  int64  `json:"count"`
}

// ipBanRecent 封禁近记录行。
type ipBanRecent struct {
	TS   int64  `json:"ts"`
	Type string `json:"type"`
	Jail string `json:"jail"`
}

// ipCredRecent 蜜罐凭据近记录行（刻意无 password 字段）。
type ipCredRecent struct {
	TS       int64  `json:"ts"`
	Proto    string `json:"proto"`
	Username string `json:"username"`
}

// ipConnAgg connections 表聚合段。
type ipConnAgg struct {
	Total       int64          `json:"total"`
	FirstTS     int64          `json:"first_ts"`
	LastTS      int64          `json:"last_ts"`
	TopDstPorts []ipPortCount  `json:"top_dst_ports"`
	Protos      []ipProtoCount `json:"protos"`
}

// ipSSHAgg ssh_attempts 表聚合段。
type ipSSHAgg struct {
	Total        int64         `json:"total"`
	Failed       int64         `json:"failed"`
	OK           int64         `json:"ok"`
	FirstTS      int64         `json:"first_ts"`
	LastTS       int64         `json:"last_ts"`
	TopUsernames []ipUserCount `json:"top_usernames"`
}

// ipFwAgg firewall_events 表聚合段。
type ipFwAgg struct {
	Total      int64           `json:"total"`
	FirstTS    int64           `json:"first_ts"`
	LastTS     int64           `json:"last_ts"`
	TopActions []ipActionCount `json:"top_actions"`
}

// ipBanAgg ban_events 表聚合段。
type ipBanAgg struct {
	Total  int64         `json:"total"`
	Recent []ipBanRecent `json:"recent"`
}

// ipCredAgg cred_events 表聚合段。
type ipCredAgg struct {
	Total  int64          `json:"total"`
	Recent []ipCredRecent `json:"recent"`
}

// ipProfileResp /api/v1/ip 响应契约（字段名与前端并行开发契约一致，勿改名）。
type ipProfileResp struct {
	IP          string     `json:"ip"`
	WindowHours int        `json:"window_hours"`
	Country     *ipCountry `json:"country"` // null 或 {"code","name"}
	BannedNow   bool       `json:"banned_now"`
	Connections ipConnAgg  `json:"connections"`
	SSH         ipSSHAgg   `json:"ssh"`
	Firewall    ipFwAgg    `json:"firewall"`
	Bans        ipBanAgg   `json:"bans"`
	Creds       ipCredAgg  `json:"creds"`
}

// hIPProfile 来源 IP 画像（GET /api/v1/ip?ip=<点分 IPv4>；limitAPI 档，handler 内 5s ctx）。
// 任一聚合查询错误 → writeDBErr 500；空数据段输出零值 + 空数组（非 null）。
func (s *Server) hIPProfile(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	raw := r.URL.Query().Get("ip")
	if raw == "" {
		writeErr(w, http.StatusBadRequest, "缺少 ip 参数")
		return
	}
	parsed := net.ParseIP(raw)
	if parsed == nil {
		writeErr(w, http.StatusBadRequest, "ip 参数非法（需点分 IPv4）")
		return
	}
	if parsed.To4() == nil {
		writeErr(w, http.StatusBadRequest, "IPv6 不支持（字段限制）")
		return
	}
	srcIP := event.IPv4ToUint32(parsed)
	from := time.Now().Unix() - ipWindowHours*3600

	out := ipProfileResp{
		IP:          event.Uint32ToIPv4(srcIP),
		WindowHours: ipWindowHours,
		Country:     s.ipCountry(parsed),
		BannedNow:   s.ipBannedNow(srcIP),
	}
	agg, err := s.ipConnAggQuery(ctx, srcIP, from)
	if err != nil {
		writeDBErr(w, r, err)
		return
	}
	out.Connections = agg
	ssh, err := s.ipSSHAggQuery(ctx, srcIP, from)
	if err != nil {
		writeDBErr(w, r, err)
		return
	}
	out.SSH = ssh
	fw, err := s.ipFwAggQuery(ctx, srcIP, from)
	if err != nil {
		writeDBErr(w, r, err)
		return
	}
	out.Firewall = fw
	bans, err := s.ipBanAggQuery(ctx, srcIP, from)
	if err != nil {
		writeDBErr(w, r, err)
		return
	}
	out.Bans = bans
	creds, err := s.ipCredAggQuery(ctx, srcIP, from)
	if err != nil {
		writeDBErr(w, r, err)
		return
	}
	out.Creds = creds
	writeJSON(w, 200, out)
}

// ipCountry geo 国家查询（nil / 未加载 / 未命中 → nil，JSON null）。
func (s *Server) ipCountry(ip net.IP) *ipCountry {
	if s.geo == nil || !s.geo.OK() {
		return nil
	}
	code, name, ok := s.geo.Lookup(ip)
	if !ok || code == "" {
		return nil
	}
	return &ipCountry{Code: code, Name: name}
}

// ipBannedNow 目标 IP 是否在 fail2ban 当前封禁名单（bannedFn 线性比较；nil=未启用 → false）。
func (s *Server) ipBannedNow(srcIP uint32) bool {
	if s.bannedFn == nil {
		return false
	}
	ips, _ := s.bannedFn()
	for _, v := range ips {
		if v == srcIP {
			return true
		}
	}
	return false
}

// ipConnAggQuery connections 段聚合（total / 首末时间 / 目标端口 TOP5 / 协议 TOP3）。
// 空段 TopDstPorts/Protos 为空切片（非 null）。COUNT/MIN/MAX 单行聚合无 LIMIT 面；
// TOP 类 GROUP BY 均带 LIMIT 上限。
func (s *Server) ipConnAggQuery(ctx context.Context, srcIP uint32, from int64) (ipConnAgg, error) {
	agg := ipConnAgg{TopDstPorts: []ipPortCount{}, Protos: []ipProtoCount{}}
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(MIN(ts),0), COALESCE(MAX(ts),0)
		FROM connections WHERE src_ip = ? AND ts >= ?`, srcIP, from).
		Scan(&agg.Total, &agg.FirstTS, &agg.LastTS)
	if err != nil {
		return agg, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT dst_port, COUNT(*) FROM connections
		WHERE src_ip = ? AND ts >= ? GROUP BY dst_port ORDER BY COUNT(*) DESC, dst_port LIMIT 5`, srcIP, from)
	if err != nil {
		return agg, err
	}
	defer rows.Close()
	for rows.Next() {
		var p ipPortCount
		if rows.Scan(&p.DstPort, &p.Count) == nil {
			agg.TopDstPorts = append(agg.TopDstPorts, p)
		}
	}
	rows2, err := s.db.QueryContext(ctx, `SELECT proto, COUNT(*) FROM connections
		WHERE src_ip = ? AND ts >= ? GROUP BY proto ORDER BY COUNT(*) DESC, proto LIMIT 3`, srcIP, from)
	if err != nil {
		return agg, err
	}
	defer rows2.Close()
	for rows2.Next() {
		var p ipProtoCount
		if rows2.Scan(&p.Proto, &p.Count) == nil {
			agg.Protos = append(agg.Protos, p)
		}
	}
	return agg, nil
}

// ipSSHAggQuery ssh_attempts 段聚合（total / failed(result=0) / ok(result=1) / 首末时间 / 用户名 TOP5）。
func (s *Server) ipSSHAggQuery(ctx context.Context, srcIP uint32, from int64) (ipSSHAgg, error) {
	agg := ipSSHAgg{TopUsernames: []ipUserCount{}}
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*),
		COALESCE(SUM(CASE WHEN result = 0 THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN result = 1 THEN 1 ELSE 0 END),0),
		COALESCE(MIN(ts),0), COALESCE(MAX(ts),0)
		FROM ssh_attempts WHERE src_ip = ? AND ts >= ?`, srcIP, from).
		Scan(&agg.Total, &agg.Failed, &agg.OK, &agg.FirstTS, &agg.LastTS)
	if err != nil {
		return agg, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT username, COUNT(*) FROM ssh_attempts
		WHERE src_ip = ? AND ts >= ? GROUP BY username ORDER BY COUNT(*) DESC, username LIMIT 5`, srcIP, from)
	if err != nil {
		return agg, err
	}
	defer rows.Close()
	for rows.Next() {
		var u ipUserCount
		if rows.Scan(&u.Username, &u.Count) == nil {
			agg.TopUsernames = append(agg.TopUsernames, u)
		}
	}
	return agg, nil
}

// ipFwAggQuery firewall_events 段聚合（total / 首末时间 / action TOP4）。
// INDEXED BY idx_fw_ts 强制时间过滤先行（该表无 src_ip 索引，生产大库防全表扫描）。
func (s *Server) ipFwAggQuery(ctx context.Context, srcIP uint32, from int64) (ipFwAgg, error) {
	agg := ipFwAgg{TopActions: []ipActionCount{}}
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(MIN(ts),0), COALESCE(MAX(ts),0)
		FROM firewall_events INDEXED BY idx_fw_ts WHERE ts >= ? AND src_ip = ?`, from, srcIP).
		Scan(&agg.Total, &agg.FirstTS, &agg.LastTS)
	if err != nil {
		return agg, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT action, COUNT(*) FROM firewall_events
		INDEXED BY idx_fw_ts WHERE ts >= ? AND src_ip = ?
		GROUP BY action ORDER BY COUNT(*) DESC, action LIMIT 4`, from, srcIP)
	if err != nil {
		return agg, err
	}
	defer rows.Close()
	for rows.Next() {
		var a ipActionCount
		if rows.Scan(&a.Action, &a.Count) == nil {
			agg.TopActions = append(agg.TopActions, a)
		}
	}
	return agg, nil
}

// ipBanAggQuery ban_events 段聚合（total + recent ≤10 条 ts 降序取 type/jail）。
func (s *Server) ipBanAggQuery(ctx context.Context, srcIP uint32, from int64) (ipBanAgg, error) {
	agg := ipBanAgg{Recent: []ipBanRecent{}}
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM ban_events
		WHERE ip = ? AND ts >= ?`, srcIP, from).Scan(&agg.Total)
	if err != nil {
		return agg, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT ts, type, jail FROM ban_events
		WHERE ip = ? AND ts >= ? ORDER BY ts DESC LIMIT 10`, srcIP, from)
	if err != nil {
		return agg, err
	}
	defer rows.Close()
	for rows.Next() {
		var b ipBanRecent
		if rows.Scan(&b.TS, &b.Type, &b.Jail) == nil {
			agg.Recent = append(agg.Recent, b)
		}
	}
	return agg, nil
}

// ipCredAggQuery cred_events 段聚合（total + recent ≤10 条 ts 降序取 proto/username；
// 刻意不查 password——攻击者可控输入不入画像）。
func (s *Server) ipCredAggQuery(ctx context.Context, srcIP uint32, from int64) (ipCredAgg, error) {
	agg := ipCredAgg{Recent: []ipCredRecent{}}
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM cred_events
		WHERE src_ip = ? AND ts >= ?`, srcIP, from).Scan(&agg.Total)
	if err != nil {
		return agg, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT ts, proto, username FROM cred_events
		WHERE src_ip = ? AND ts >= ? ORDER BY ts DESC LIMIT 10`, srcIP, from)
	if err != nil {
		return agg, err
	}
	defer rows.Close()
	for rows.Next() {
		var c ipCredRecent
		if rows.Scan(&c.TS, &c.Proto, &c.Username) == nil {
			agg.Recent = append(agg.Recent, c)
		}
	}
	return agg, nil
}
