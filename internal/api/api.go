// Package api 实现 M-07 API 与 WebSocket 模块（方案 3.7）。
// 只读查询 REST + WS 实时推送；监听地址可配置（默认 127.0.0.1:8080，D-03）。
// 关键实现约束：主库写线程独占连接（MaxOpenConns(1)），
// 本包使用独立只读连接（WAL 模式支持多读者）——绝不与写线程共享连接。
package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"os"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite" // 与主库一致

	"sentry-agent/internal/event"
	"sentry-agent/internal/web"
)

// Server M-07 HTTP 服务。
type Server struct {
	db             *sql.DB // 独立只读连接（auditor 坑点：不与写线程共享）
	dbPath         string  // 主库路径（health db_size 用，SetDBPath 注入）
	archiveDir     string
	wsOrigin       string
	allowNoOrigin  bool                       // M-02：非回环监听时拒绝无 Origin 请求
	snapshotFn     func() *event.ConnSnapshot // ss 快照最新值（active_conns/连接列表口径）
	startTime      time.Time
	overrunCounter *atomic.Uint64 // conntrack 溢出累计（M-01：conn 模块共享 atomic，main 注入）
	hub            *wsHub
	mux            *http.ServeMux
	// VS-03/VS-04（DEV-P1-001）：WS 连接数上限 + API 速率限制（令牌桶，无新依赖）。
	wsMaxConns   int
	apiLimiter   *tokenBucket             // 全局 API 限流（默认 10 rps / burst 20）
	heavyLimiter *tokenBucket             // 重聚合端点限流（默认 1 rps / burst 6）
	sysCh        chan<- event.SystemEvent // system_event 通道（限流拒绝留痕，main 注入）
	limitWarn    *event.RateLimiter       // 限流拒绝留痕限频（1/分钟）
	// connFallbackRep activeConns 回退 ss 口径留痕限频（1/小时）。
	connFallbackRep *event.RateLimiter
	// retentionDays 数据保留天数（health 返回，前端 range 提示）。
	retentionDays int
	// geo GeoIP 国家查询（DEV-GEO-001；nil = 未配置，地图降级 Unknown）。
	// 与 mmdb 文件生命周期解耦：*geoip.Reader 由 main 创建（updater 原子替换内部句柄），
	// API 仅持接口引用。
	geo GeoLookuper
}

// NewServer 创建 API 服务。
// dbPath 为主库路径——内部以独立只读连接打开（mode=ro；WAL 下只读连接可并发读）。
// allowNoOrigin：监听回环地址时允许无 Origin 的 WS 请求（本机 CLI 工具场景）；
// 非回环地址时拒绝（M-02：防止任意远程客户端绕过 Origin 白名单直连）。
func NewServer(dbPath, archiveDir, wsOrigin string, allowNoOrigin bool, snapshotFn func() *event.ConnSnapshot) (*Server, error) {
	db, err := sql.Open("sqlite", "file:"+urlPathEscape(dbPath)+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("打开只读连接失败: %w", err)
	}
	db.SetMaxOpenConns(4) // 只读并发查询（WAL 多读者）
	s := &Server{
		db:             db,
		archiveDir:     archiveDir,
		wsOrigin:       wsOrigin,
		allowNoOrigin:  allowNoOrigin,
		snapshotFn:     snapshotFn,
		startTime:      time.Now(),
		overrunCounter: new(atomic.Uint64),
		hub:            newWSHub(),
		// VS-03/VS-04 默认值（与 config.Defaults 一致；main 经 SetLimits 注入配置值，
		// 未注入时测试/直接构造场景按默认安全参数运行）。
		wsMaxConns:   100,
		apiLimiter:   newTokenBucket(10, 20),
		heavyLimiter: newTokenBucket(1, 6),
		limitWarn:    event.NewRateLimiter(time.Minute),
		// activeConns 回退 ss 口径留痕限频（1/小时，fallback 等无模块环境为预期常态）。
		connFallbackRep: event.NewRateLimiter(time.Hour),
	}
	s.routes()
	return s, nil
}

// SetLimits 注入 VS-03/VS-04 限制参数（config 加载后调用一次；运行期不热更新）。
// 注意：须在 Serve 之前调用——内部直接替换 apiLimiter/heavyLimiter 指针，
// Serve 启动后并发读与指针替换构成数据竞争（时序约束）。
func (s *Server) SetLimits(rateRPS, rateBurst, heavyRPS, wsMaxConns int) {
	if rateRPS >= 1 && rateBurst >= 1 {
		s.apiLimiter = newTokenBucket(float64(rateRPS), float64(rateBurst))
	}
	if heavyRPS >= 1 {
		// heavy burst 固定 6（DEV-P1-001 关键决策，见 routes 注释：真实浏览器实测
		// Chrome 同源 6 连接限制下，慢查询轮的部分 heavy 请求会在浏览器侧排队，
		// 与下一轮请求重叠到达（实测两轮 5-6 个 heavy <1s 内到达）——burst 3 仍会偶发
		// 误伤稳态轮询；6 覆盖双轮重叠窗口，持续 >1 rps 的攻击仍被限到 1 rps）。
		s.heavyLimiter = newTokenBucket(float64(heavyRPS), 6)
	}
	if wsMaxConns >= 1 {
		s.wsMaxConns = wsMaxConns
	}
}

// SetSystemChannel 注入 system_event 通道（限流拒绝留痕；main 注入 ch.System，
// 测试未注入时 nil 安全——ReportSys 对 nil 通道静默丢弃）。
// 注意：须在 Serve 之前调用（运行期不热更新）。
func (s *Server) SetSystemChannel(sys chan<- event.SystemEvent) {
	s.sysCh = sys
}

// routes 注册路由（全部只读，无任何写操作暴露面）。
// VS-04（DEV-P1-001）：除 health（运维探活豁免）外全部 /api/ 端点经全局令牌桶
// （默认 10 rps / burst 20）；重聚合端点（summary/ssh timeline/firewall timeline，
// 30d 视图 CPU 密集 2-8s）再叠加重桶（默认 1 rps / burst 6），防暴露场景循环调用打满单核
// （AUD-VPS-001 VS-04）。
// heavy burst=6 的取舍（关键决策，实测驱动）：
//   - 前端 5s 轮询一轮内 summary + ssh/timeline + firewall/timeline 三请求同时发出
//     （pollOverview + pollAttack 同步连续 fetch）；burst 2/3 的推演虽覆盖单轮，
//     但真实浏览器实测（Chrome 同源 6 连接限制）中，慢查询轮的部分 heavy 请求在
//     浏览器侧排队，与下一轮请求重叠到达服务器（实测：两轮 5-6 个 heavy <1s 内到达，
//     单测按页面节奏模拟零拒绝、浏览器 30s 监控却偶发 2 个 429）——burst 3 仍误伤稳态；
//   - burst 6 覆盖双轮重叠窗口（稳态消耗 0.6 rps << 1 rps 补充，永不亏空）；
//   - 攻击者持续 >1 rps 仍被限到 1 rps（每秒仅补充 1 令牌），初始突发窗口 6 个
//     30d 聚合 ≈ 12-48s CPU（mem_limit 256m 兜底），符合 VS-04 防循环调用意图。
func (s *Server) routes() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/health", s.hHealth) // 豁免限流：健康检查（运维探活/容器健康检查）
	mux.HandleFunc("/api/v1/summary", s.limitHeavy(s.hSummary))
	mux.HandleFunc("/api/v1/resources", s.limitAPI(s.hResources))
	mux.HandleFunc("/api/v1/connections", s.limitAPI(s.hConnections))
	mux.HandleFunc("/api/v1/ssh", s.limitAPI(s.hSSH))
	mux.HandleFunc("/api/v1/firewall", s.limitAPI(s.hFirewall))
	mux.HandleFunc("/api/v1/attacks/top_ports", s.limitAPI(s.hTopPorts))
	mux.HandleFunc("/api/v1/attacks/top_sources", s.limitAPI(s.hTopSources))
	mux.HandleFunc("/api/v1/ssh/timeline", s.limitHeavy(s.hSSHTimeline))
	mux.HandleFunc("/api/v1/firewall/timeline", s.limitHeavy(s.hFirewallTimeline))
	// DEV-GEO-001：全球攻击地图（SSH 失败按国家聚合；30d 视图 1000 IP 组 + 逐 IP mmdb
	// 查询 CPU/IO 密集，纳入 heavy 限流——与 export/csv 同档）。
	mux.HandleFunc("/api/v1/attacks/geo", s.limitHeavy(s.hGeoAttacks))
	mux.HandleFunc("/api/v1/export/attacks_csv", s.limitHeavy(s.hExportAttacksCSV))
	// DEV-EXPORT-001：数据导出（30d 全量可能数万行 + 流式写），纳入 heavy 限流（1 rps / burst 6）。
	mux.HandleFunc("/api/v1/export/csv", s.limitHeavy(s.hExportCSV))
	mux.HandleFunc("/api/v1/bans", s.limitAPI(s.hBans))
	mux.HandleFunc("/api/v1/archive", s.limitAPI(s.hArchive))
	mux.HandleFunc("/api/v1/snapshot", s.limitAPI(s.hSnapshot))
	// DEV-HONEY-001：蜜罐凭据捕获查询（range/proto/limit；只读，普通限流档）。
	mux.HandleFunc("/api/v1/honeypot/events", s.limitAPI(s.hHoneypotEvents))
	mux.HandleFunc("/ws", s.hWS)
	// 静态前端（embed，见 internal/web）。
	mux.Handle("/", web.Handler())
	s.mux = mux
}

// limitAPI 全局 API 限流包装（429 + JSON 错误体；前端 errCb 已有失败态机制）。
// 拒绝留痕：system_event warn（限频 1/分钟，防刷屏）——运维可观测限流误伤。
func (s *Server) limitAPI(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.apiLimiter.allow() {
			w.Header().Set("Retry-After", "1")
			writeErr(w, http.StatusTooManyRequests, "请求过于频繁（全局速率限制）")
			s.limitWarn.Report(s.sysCh, "api", "warn", "API 限流拒绝: "+r.URL.Path)
			return
		}
		h(w, r)
	}
}

// limitHeavy 重聚合端点限流（全局桶 + 重桶双层；重桶更严，1 rps / burst 6）。
func (s *Server) limitHeavy(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.apiLimiter.allow() || !s.heavyLimiter.allow() {
			w.Header().Set("Retry-After", "1")
			writeErr(w, http.StatusTooManyRequests, "请求过于频繁（聚合查询限流）")
			s.limitWarn.Report(s.sysCh, "api", "warn", "聚合限流拒绝: "+r.URL.Path)
			return
		}
		h(w, r)
	}
}

// Handler 返回 HTTP 处理器（供 main 挂载）。
func (s *Server) Handler() http.Handler { return s.mux }

// Serve 启动 HTTP 服务（阻塞直至 ctx 取消）。
// VS-02（DEV-P1-001，AUD-VPS-001）：补 ReadHeaderTimeout/IdleTimeout/MaxHeaderBytes
// 防 Slowloris 与超大 header（暴露场景连接耗尽 DoS）。
// 刻意不设 ReadTimeout/WriteTimeout：WS 长连接在 gorilla 升级时 hijack 后由
// websocket.Conn 自管（写循环已有 SetWriteDeadline 10s），http.Server 的
// Read/Write/IdleTimeout 对已 hijack 连接不再生效（gorilla/websocket 标准语义）；
// 此处仅约束升级前的 HTTP 头读取阶段，不影响 WS 长连接生命周期。
func (s *Server) Serve(ctx context.Context, addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.mux,
		ReadHeaderTimeout: 5 * time.Second,  // Slowloris：慢速头连接 5s 内未发完整头即断开
		IdleTimeout:       60 * time.Second, // 空闲 keep-alive 连接回收（WS hijack 后不适用）
		MaxHeaderBytes:    64 << 10,         // 默认 1MB → 64KB（超大 header 内存面收敛）
	}
	go func() {
		<-ctx.Done()
		shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shCtx)
	}()
	err := srv.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// Close 关闭只读连接。
func (s *Server) Close() error { return s.db.Close() }

// SetOverrunCounter 注入共享溢出计数（conn 模块直接累加，API 只读展示，
// 避免通道双消费者竞争；替换旧 AddOverrun 增量注入方式）。
// 注意：须在 Serve 之前调用（运行期不热更新）。
func (s *Server) SetOverrunCounter(c *atomic.Uint64) {
	if c != nil {
		s.overrunCounter = c
	}
}

// ---- JSON 工具 ----

type errResp struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, errResp{Error: msg})
}

// rangeSeconds 解析 range 参数（1h/24h/7d/30d，默认 24h）为起始时间戳。
func rangeSeconds(r *http.Request) int64 {
	v := r.URL.Query().Get("range")
	if v == "" {
		v = "24h"
	}
	now := time.Now().Unix()
	switch v {
	case "1h":
		return now - 3600
	case "24h":
		return now - 86400
	case "7d":
		return now - 7*86400
	case "30d":
		return now - 30*86400
	default:
		return now - 86400
	}
}

// parseUintParam 解析无符号整数参数（非法/缺失返回默认值；≥20 位数字溢出回绕
// 也返回默认值——R-01（reviewer）：防 min_count 等过滤参数经回绕绕过阈值语义）。
func parseUintParam(r *http.Request, key string, def uint64) uint64 {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	var n uint64
	for _, c := range v {
		if c < '0' || c > '9' {
			return def
		}
		if n > (math.MaxUint64-uint64(c-'0'))/10 {
			return def // 乘法前检测溢出
		}
		n = n*10 + uint64(c-'0')
	}
	return n
}

// eqConds 为指定查询参数生成 "key = ?" 等值条件与对应参数（缺失参数跳过）。
// 参数名与表列名一致时使用（hConnections/hSSH/hFirewall 共用）。
func eqConds(q url.Values, keys []string) ([]string, []any) {
	var conds []string
	var args []any
	for _, k := range keys {
		if v := q.Get(k); v != "" {
			conds = append(conds, k+" = ?")
			args = append(args, v)
		}
	}
	return conds, args
}

// urlPathEscape 路径 URL 编码（R-05：统一为 url.PathEscape，与 store/f2b 同规则；
// SQLite URI 模式对 %XX 解码，转义 '?'/'#'/'%' 等 DSN 特殊字符）。
func urlPathEscape(p string) string {
	return url.PathEscape(p)
}

// ---- handlers ----

// hHealth 健康检查（方案 3.7；R-06：ok 基于 meta 查询成败判定，DB 故障时返回 500 + ok:false）。
func (s *Server) hHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	var schemaVer string
	metaErr := s.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key='schema_version'`).Scan(&schemaVer)
	if metaErr != nil {
		writeErr(w, http.StatusInternalServerError, "数据库不可用: "+metaErr.Error())
		return
	}
	var dbSize int64
	if s.dbPath != "" {
		if fi, err := os.Stat(s.dbPath); err == nil {
			dbSize = fi.Size()
		}
	}
	var seCount int64
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_events`).Scan(&seCount)
	writeJSON(w, 200, map[string]any{
		"ok":                      true,
		"uptime_s":                int64(time.Since(s.startTime).Seconds()),
		"db_size_mb":              float64(dbSize) / 1024 / 1024,
		"system_events_total":     seCount,
		"conntrack_overrun_total": s.overrunCounter.Load(),
		"schema_version":          schemaVer,
		// 数据保留天数（前端 range 提示"数据保留 N 天"；
		// <=0 表示禁用清理=永久保留）。
		"retention_days": s.retentionDays,
	})
}

// SetDBPath 设置主库路径（health 的 db_size_mb 使用）。
// 注意：须在 Serve 之前调用（运行期不热更新）。
func (s *Server) SetDBPath(p string) { s.dbPath = p }

// SetRetentionDays 注入数据保留天数（health 返回，前端 range 提示）。
// 注意：须在 Serve 之前调用（运行期不热更新）。
func (s *Server) SetRetentionDays(days int) { s.retentionDays = days }

// SetGeo 注入 GeoIP 国家查询（DEV-GEO-001；nil 或未加载 reader 时 mmdb_ok=false，
// 地图数据 country 恒 Unknown，前端显示降级提示）。
// 注意：须在 Serve 之前调用（运行期不热更新）。
func (s *Server) SetGeo(g GeoLookuper) { s.geo = g }

// hSummary 总览聚合（方案 3.7/4.4）。
func (s *Server) hSummary(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	from := rangeSeconds(r)

	var fwCnt, sshFail, sshOK int64
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM firewall_events WHERE ts >= ?`, from).Scan(&fwCnt)
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM ssh_attempts WHERE ts >= ? AND result = 0`, from).Scan(&sshFail)
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM ssh_attempts WHERE ts >= ? AND result = 1`, from).Scan(&sshOK)

	// 攻击端口 TOP（防火墙 DPT 口径，方案 3.4 强制：只允许 DPT；与 hTopPorts
	// 同口径——统计所有防火墙事件，inbound 扫描探测/reject 拦截/drop 丢弃均计入）。
	type portHit struct {
		DstPort int   `json:"dst_port"`
		Hits    int64 `json:"hits"`
	}
	rows, err := s.db.QueryContext(ctx, `SELECT dst_port, COUNT(*) FROM firewall_events
		WHERE ts >= ? GROUP BY dst_port ORDER BY COUNT(*) DESC LIMIT 5`, from)
	if err == nil {
		defer rows.Close()
		var top []portHit
		for rows.Next() {
			var p portHit
			if rows.Scan(&p.DstPort, &p.Hits) == nil {
				top = append(top, p)
			}
		}
		writeJSON(w, 200, map[string]any{
			"active_conns": s.activeConns(),
			"fw_events":    fwCnt,
			"ssh_fail":     sshFail,
			"ssh_ok":       sshOK,
			"top_ports":    top,
			"disk_percent": s.diskPercent(),
		})
		return
	}
	writeErr(w, 500, "查询失败: "+err.Error())
}

// activeConns 活跃连接数（现场核查结论 8）：优先 conntrack count 文件值
// （Cnt>=0，sysctl 接口模块加载即可读）；读取失败（Cnt=-1，如 fallback 模式无模块）回退
// ss 快照连接数口径。
// 回退口径切换限频留痕（info，1/小时）——运维可观测口径变化；
// fallback 等无模块环境为预期常态，不告警。
func (s *Server) activeConns() int {
	if s.snapshotFn == nil {
		return 0
	}
	snap := s.snapshotFn()
	if snap == nil {
		return 0
	}
	if snap.Cnt >= 0 {
		return int(snap.Cnt)
	}
	s.connFallbackRep.Report(s.sysCh, "api", "info",
		"活跃连接数回退 ss 快照口径（conntrack count 文件不可读，Cnt=-1）")
	return len(snap.Conn)
}

// diskPercent 当前磁盘使用率（归档目录分区）。
func (s *Server) diskPercent() float64 {
	usage, err := diskUsagePercent(s.archiveDir)
	if err != nil {
		return -1
	}
	return usage
}
