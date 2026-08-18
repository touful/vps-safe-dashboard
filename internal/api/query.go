package api

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// hResources 资源指标（方案 3.7：range + step 聚合）。
func (s *Server) hResources(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	from := rangeSeconds(r)
	step := r.URL.Query().Get("step")
	stepSec := int64(60)
	if step == "5s" {
		stepSec = 5
	}
	rows, err := s.db.QueryContext(ctx, `SELECT (ts / ?) * ? AS bucket,
		AVG(cpu_percent), AVG(mem_percent), AVG(disk_percent),
		MAX(net_rx_bps), MAX(net_tx_bps)
		FROM resources WHERE ts >= ? GROUP BY bucket ORDER BY bucket`, stepSec, stepSec, from)
	if err != nil {
		writeErr(w, 500, "查询失败: "+err.Error())
		return
	}
	defer rows.Close()
	type pt struct {
		TS      int64   `json:"ts"`
		CPU     float64 `json:"cpu"`
		Mem     float64 `json:"mem"`
		Disk    float64 `json:"disk"`
		NetRx   int64   `json:"net_rx_bps"`
		NetTx   int64   `json:"net_tx_bps"`
	}
	var out []pt
	for rows.Next() {
		var p pt
		if rows.Scan(&p.TS, &p.CPU, &p.Mem, &p.Disk, &p.NetRx, &p.NetTx) == nil {
			out = append(out, p)
		}
	}
	writeJSON(w, 200, map[string]any{"points": out, "step_s": stepSec})
}

// hConnections 连接事件查询（方案 3.7：limit/proto/dst_port/src_ip/since/until）。
func (s *Server) hConnections(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	q := r.URL.Query()
	limit := parseUintParam(r, "limit", 200)
	if limit > 1000 {
		limit = 1000
	}
	conds := []string{"1=1"}
	args := []any{}
	if p := q.Get("proto"); p != "" {
		conds = append(conds, "proto = ?")
		args = append(args, p)
	}
	if p := q.Get("dst_port"); p != "" {
		conds = append(conds, "dst_port = ?")
		args = append(args, p)
	}
	if p := q.Get("src_ip"); p != "" {
		conds = append(conds, "src_ip = ?")
		args = append(args, p)
	}
	if p := q.Get("since"); p != "" {
		conds = append(conds, "ts >= ?")
		args = append(args, p)
	}
	if p := q.Get("until"); p != "" {
		conds = append(conds, "ts <= ?")
		args = append(args, p)
	}
	query := `SELECT ts, ev_type, proto, src_ip, src_port, dst_ip, dst_port, packets, bytes, mark, src_ip6, dst_ip6
		FROM connections WHERE ` + strings.Join(conds, " AND ") + ` ORDER BY ts DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		writeErr(w, 500, "查询失败: "+err.Error())
		return
	}
	defer rows.Close()
	type connRow struct {
		TS      int64  `json:"ts"`
		EvType  int    `json:"ev_type"`
		Proto   int    `json:"proto"`
		SrcIP   int64  `json:"src_ip"`
		SrcPort int    `json:"src_port"`
		DstIP   int64  `json:"dst_ip"`
		DstPort int    `json:"dst_port"`
		Packets int64  `json:"packets"`
		Bytes   int64  `json:"bytes"`
		Mark    int64  `json:"mark"`
		SrcIP6  string `json:"src_ip6"`
		DstIP6  string `json:"dst_ip6"`
	}
	var out []connRow
	for rows.Next() {
		var c connRow
		if rows.Scan(&c.TS, &c.EvType, &c.Proto, &c.SrcIP, &c.SrcPort, &c.DstIP, &c.DstPort,
			&c.Packets, &c.Bytes, &c.Mark, &c.SrcIP6, &c.DstIP6) == nil {
			out = append(out, c)
		}
	}
	writeJSON(w, 200, map[string]any{"rows": out})
}

// hSSH SSH 登录尝试查询（range/src_ip/result/username）。
func (s *Server) hSSH(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	q := r.URL.Query()
	from := rangeSeconds(r)
	limit := parseUintParam(r, "limit", 200)
	if limit > 1000 {
		limit = 1000
	}
	conds := []string{"ts >= ?"}
	args := []any{from}
	if p := q.Get("src_ip"); p != "" {
		conds = append(conds, "src_ip = ?")
		args = append(args, p)
	}
	if p := q.Get("result"); p != "" {
		conds = append(conds, "result = ?")
		args = append(args, p)
	}
	if p := q.Get("username"); p != "" {
		conds = append(conds, "username = ?")
		args = append(args, p)
	}
	query := `SELECT ts, src_ip, username, auth_method, result, fingerprint, detail
		FROM ssh_attempts WHERE ` + strings.Join(conds, " AND ") + ` ORDER BY ts DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		writeErr(w, 500, "查询失败: "+err.Error())
		return
	}
	defer rows.Close()
	type sshRow struct {
		TS          int64  `json:"ts"`
		SrcIP       int64  `json:"src_ip"`
		Username    string `json:"username"`
		AuthMethod  string `json:"auth_method"`
		Result      int    `json:"result"`
		Fingerprint string `json:"fingerprint"`
		Detail      string `json:"detail"`
	}
	var out []sshRow
	for rows.Next() {
		var r sshRow
		if rows.Scan(&r.TS, &r.SrcIP, &r.Username, &r.AuthMethod, &r.Result, &r.Fingerprint, &r.Detail) == nil {
			out = append(out, r)
		}
	}
	writeJSON(w, 200, map[string]any{"rows": out})
}

// hFirewall 防火墙事件查询（range/dst_port/action/src_ip）。
func (s *Server) hFirewall(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	q := r.URL.Query()
	from := rangeSeconds(r)
	limit := parseUintParam(r, "limit", 200)
	if limit > 1000 {
		limit = 1000
	}
	conds := []string{"ts >= ?"}
	args := []any{from}
	for _, k := range []string{"dst_port", "action", "src_ip"} {
		if p := q.Get(k); p != "" {
			conds = append(conds, k+" = ?")
			args = append(args, p)
		}
	}
	query := `SELECT ts, chain, action, proto, src_ip, src_port, dst_ip, dst_port, raw
		FROM firewall_events WHERE ` + strings.Join(conds, " AND ") + ` ORDER BY ts DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		writeErr(w, 500, "查询失败: "+err.Error())
		return
	}
	defer rows.Close()
	type fwRow struct {
		TS      int64  `json:"ts"`
		Chain   string `json:"chain"`
		Action  string `json:"action"`
		Proto   int    `json:"proto"`
		SrcIP   int64  `json:"src_ip"`
		SrcPort int    `json:"src_port"`
		DstIP   int64  `json:"dst_ip"`
		DstPort int    `json:"dst_port"`
		Raw     string `json:"raw"`
	}
	var out []fwRow
	for rows.Next() {
		var f fwRow
		if rows.Scan(&f.TS, &f.Chain, &f.Action, &f.Proto, &f.SrcIP, &f.SrcPort, &f.DstIP, &f.DstPort, &f.Raw) == nil {
			out = append(out, f)
		}
	}
	writeJSON(w, 200, map[string]any{"rows": out})
}

// hTopPorts 被探测端口 TOP（方案 4.4 DPT 口径 → DEV-045：统计所有防火墙事件，
// inbound 扫描探测 / reject 拦截 / drop 丢弃均计入"被探测端口"；DPT 警示固化）。
func (s *Server) hTopPorts(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	from := rangeSeconds(r)
	top := parseUintParam(r, "top", 10)
	if top > 50 {
		top = 50
	}
	rows, err := s.db.QueryContext(ctx, `SELECT dst_port, COUNT(*) AS hits FROM firewall_events
		WHERE ts >= ? GROUP BY dst_port ORDER BY hits DESC LIMIT ?`, from, top)
	if err != nil {
		writeErr(w, 500, "查询失败: "+err.Error())
		return
	}
	defer rows.Close()
	type hit struct {
		DstPort int   `json:"dst_port"`
		Hits    int64 `json:"hits"`
	}
	var out []hit
	for rows.Next() {
		var h hit
		if rows.Scan(&h.DstPort, &h.Hits) == nil {
			out = append(out, h)
		}
	}
	writeJSON(w, 200, map[string]any{"rows": out})
}

// hTopSources 攻击源 IP TOP（方案 4.4）。
func (s *Server) hTopSources(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	from := rangeSeconds(r)
	top := parseUintParam(r, "top", 10)
	if top > 50 {
		top = 50
	}
	rows, err := s.db.QueryContext(ctx, `SELECT src_ip, COUNT(*) AS hits FROM firewall_events
		WHERE ts >= ? GROUP BY src_ip ORDER BY hits DESC LIMIT ?`, from, top)
	if err != nil {
		writeErr(w, 500, "查询失败: "+err.Error())
		return
	}
	defer rows.Close()
	type hit struct {
		SrcIP int64 `json:"src_ip"`
		Hits  int64 `json:"hits"`
	}
	var out []hit
	for rows.Next() {
		var h hit
		if rows.Scan(&h.SrcIP, &h.Hits) == nil {
			out = append(out, h)
		}
	}
	writeJSON(w, 200, map[string]any{"rows": out})
}

// hArchive 归档文件列表（方案 3.7：file/month/size_mb/gzip）。
func (s *Server) hArchive(w http.ResponseWriter, r *http.Request) {
	entries, err := os.ReadDir(s.archiveDir)
	if err != nil {
		writeJSON(w, 200, map[string]any{"rows": []any{}})
		return
	}
	type arcFile struct {
		File    string  `json:"file"`
		Month   string  `json:"month"`
		SizeMB  float64 `json:"size_mb"`
		Gzip    bool    `json:"gzip"`
	}
	var out []arcFile
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".db.gz") {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		month := strings.TrimSuffix(strings.TrimSuffix(name, ".gz"), ".db")
		out = append(out, arcFile{
			File: name, Month: month,
			SizeMB: float64(fi.Size()) / 1024 / 1024, Gzip: true,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Month > out[j].Month })
	writeJSON(w, 200, map[string]any{"rows": out})
}

// hSnapshot 当前连接列表（ss 快照通道，方案 3.7/3.8 页面②；IP 转点分十进制——API 层负责互转）。
func (s *Server) hSnapshot(w http.ResponseWriter, r *http.Request) {
	if s.snapshotFn == nil {
		writeJSON(w, 200, map[string]any{"ts": 0, "rows": []any{}})
		return
	}
	snap := s.snapshotFn()
	if snap == nil {
		writeJSON(w, 200, map[string]any{"ts": 0, "rows": []any{}})
		return
	}
	type snapRow struct {
		Proto   int    `json:"proto"`
		SrcIP   string `json:"src_ip"`
		SrcPort int    `json:"src_port"`
		DstIP   string `json:"dst_ip"`
		DstPort int    `json:"dst_port"`
		State   string `json:"state"`
		Pid     int    `json:"pid"`
	}
	out := make([]snapRow, 0, len(snap.Conn))
	for _, c := range snap.Conn {
		out = append(out, snapRow{
			Proto: int(c.Proto),
			SrcIP: ipToDotted(c.SrcIP), SrcPort: int(c.SrcPort),
			DstIP: ipToDotted(c.DstIP), DstPort: int(c.DstPort),
			State: c.State, Pid: c.Pid,
		})
	}
	writeJSON(w, 200, map[string]any{"ts": snap.TS, "rows": out})
}

// ipToDotted uint32 → 点分十进制（API 层转换，方案 3 章说明）。
func ipToDotted(v uint32) string {
	if v == 0 {
		return "0.0.0.0"
	}
	return fmt.Sprintf("%d.%d.%d.%d", byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// hSSHTimeline SSH 失败时间线（每小时聚合，方案 4.4；前端"SSH 爆破时间线"用）。
func (s *Server) hSSHTimeline(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	from := rangeSeconds(r)
	rows, err := s.db.QueryContext(ctx, `SELECT (ts/3600)*3600 AS hour, COUNT(*) FROM ssh_attempts
		WHERE ts >= ? AND result = 0 GROUP BY hour ORDER BY hour`, from)
	if err != nil {
		writeErr(w, 500, "查询失败: "+err.Error())
		return
	}
	defer rows.Close()
	type pt struct {
		TS   int64 `json:"ts"`
		Hits int64 `json:"hits"`
	}
	var out []pt
	for rows.Next() {
		var p pt
		if rows.Scan(&p.TS, &p.Hits) == nil {
			out = append(out, p)
		}
	}
	writeJSON(w, 200, map[string]any{"rows": out})
}

// hFirewallTimeline 防火墙事件小时聚合时间线（DEV-017 双通道 → DEV-045 三通道）。
// 三通道语义：inbound=入站观察（扫描器流量，主通道）、reject=拦截（fail2ban）、
// drop=丢弃；accept 保留仅为向后兼容（实际生产无 accept 记录）。
// 与 hSSHTimeline 同模式（小时桶 + range 过滤）；按任务书要求缺数据小时补零桶，
// 保证前端各通道按时间对齐（ssh/timeline 无补零，由前端按本端点桶时间轴对齐）。
// 注意：防火墙日志为限速采样视图（默认 5 包/s），聚合值代表采样趋势而非全量计数。
func (s *Server) hFirewallTimeline(w http.ResponseWriter, r *http.Request) {
	// DEV-018 P-01（AUD-007）：30d 视图千万行级全量 SUM CASE 聚合估 2-8s，context 5s 超时会周期性 500，
	// 导致双通道图/FW spark/评分/态势条同时失效——30d 放宽超时至 30s，其余保持 5s。
	rng := r.URL.Query().Get("range")
	timeout := 5 * time.Second
	if rng == "30d" {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	from := rangeSeconds(r)
	// R-04（reviewer）：统计窗口对齐小时桶边界——首桶补零起点为 (from/3600)*3600，
	// SQL 过滤须同为桶边界，否则首桶缺失 [from_floor, from) 区间最多 3599 秒数据。
	fromBucket := (from / 3600) * 3600
	rows, err := s.db.QueryContext(ctx, `SELECT (ts/3600)*3600 AS hour,
		SUM(CASE WHEN action='drop' THEN 1 ELSE 0 END),
		SUM(CASE WHEN action='accept' THEN 1 ELSE 0 END),
		SUM(CASE WHEN action='reject' THEN 1 ELSE 0 END),
		SUM(CASE WHEN action='inbound' THEN 1 ELSE 0 END)
		FROM firewall_events WHERE ts >= ? GROUP BY hour ORDER BY hour`, fromBucket)
	if err != nil {
		writeErr(w, 500, "查询失败: "+err.Error())
		return
	}
	defer rows.Close()
	type bucket struct {
		TS      int64 `json:"ts"`
		Drop    int64 `json:"drop"`
		Accept  int64 `json:"accept"`
		Reject  int64 `json:"reject"`
		Inbound int64 `json:"inbound"`
	}
	got := make(map[int64]*bucket)
	for rows.Next() {
		var b bucket
		if rows.Scan(&b.TS, &b.Drop, &b.Accept, &b.Reject, &b.Inbound) == nil {
			got[b.TS] = &b
		}
	}
	// 补零：从 from 对齐到小时起，到当前小时止（含），缺失小时补零桶。
	// 30d 窗口上限 721 桶；加 1000 硬上限防御异常。
	now := time.Now().Unix()
	var out []bucket
	for h := fromBucket; h <= now; h += 3600 {
		if b, ok := got[h]; ok {
			out = append(out, *b)
		} else {
			out = append(out, bucket{TS: h})
		}
		if len(out) >= 1000 {
			break
		}
	}
	// range 回显（R-09：非法值回显默认 24h，与 rangeSeconds 口径一致，避免响应与实际查询不符；
	// DEV-018 P-01：rng 已在函数头读取用于超时判定，此处复用并校验）。
	switch rng {
	case "1h", "24h", "7d", "30d":
	default:
		rng = "24h"
	}
	writeJSON(w, 200, map[string]any{"range": rng, "granularity": "1h", "buckets": out})
}

// hBans fail2ban 封禁记录（ban_events 表时间线）。
func (s *Server) hBans(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	from := rangeSeconds(r)
	limit := parseUintParam(r, "limit", 100)
	if limit > 500 {
		limit = 500
	}
	rows, err := s.db.QueryContext(ctx, `SELECT ts, ip, type, jail FROM ban_events
		WHERE ts >= ? ORDER BY ts DESC LIMIT ?`, from, limit)
	if err != nil {
		writeErr(w, 500, "查询失败: "+err.Error())
		return
	}
	defer rows.Close()
	type banRow struct {
		TS   int64  `json:"ts"`
		IP   int64  `json:"ip"`
		Type string `json:"type"`
		Jail string `json:"jail"`
	}
	var out []banRow
	for rows.Next() {
		var b banRow
		if rows.Scan(&b.TS, &b.IP, &b.Type, &b.Jail) == nil {
			out = append(out, b)
		}
	}
	writeJSON(w, 200, map[string]any{"rows": out})
}
