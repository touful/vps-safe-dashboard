// Package store 实现 M-06 存储模块（方案 3.6）。
// 单写线程消费 out.Channels 各采集通道，批量事务写入 SQLite（WAL）。
// 关闭语义（auditor M-02 / 方案 3.6"排空后关闭"）：ctx 取消后先等待全部生产者退出，
// 再排空通道在途事件，最后提交末批——零丢失。
package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite" // 纯 Go 驱动（CGO_ENABLED=0 兼容，方案 6.4.1）

	"sentry-agent/internal/archive"
	"sentry-agent/internal/event"
	"sentry-agent/internal/out"
)

// schema 建库 DDL（方案 4.2 全量；含 PRAGMA 与索引）。
const schema = `
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA busy_timeout = 5000;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS resources (
    id           INTEGER PRIMARY KEY,
    ts           INTEGER NOT NULL,
    cpu_percent  REAL    NOT NULL,
    mem_used_mb  REAL    NOT NULL,
    mem_percent  REAL    NOT NULL,
    disk_used_mb REAL    NOT NULL,
    disk_percent REAL    NOT NULL,
    net_rx_bps   INTEGER NOT NULL DEFAULT 0,
    net_tx_bps   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_resources_ts ON resources(ts);

CREATE TABLE IF NOT EXISTS connections (
    id       INTEGER PRIMARY KEY,
    ts       INTEGER NOT NULL,
    ev_type  INTEGER NOT NULL,
    proto    INTEGER NOT NULL,
    src_ip   INTEGER NOT NULL,
    src_port INTEGER NOT NULL,
    dst_ip   INTEGER NOT NULL,
    dst_port INTEGER NOT NULL,
    packets  INTEGER NOT NULL DEFAULT 0,
    bytes    INTEGER NOT NULL DEFAULT 0,
    mark     INTEGER NOT NULL DEFAULT 0,
    src_ip6  TEXT    NOT NULL DEFAULT '',
    dst_ip6  TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_conn_ts    ON connections(ts);
CREATE INDEX IF NOT EXISTS idx_conn_dport ON connections(dst_port);
CREATE INDEX IF NOT EXISTS idx_conn_src   ON connections(src_ip);
-- R-03（reviewer）：W-01 conn_stats 双游标每秒按 (ev_type, id) 过滤计数，
-- 需该索引避免全表扫描（connections 表只增不减，长期运行必须走索引）。
CREATE INDEX IF NOT EXISTS idx_conn_evid  ON connections(ev_type, id);

CREATE TABLE IF NOT EXISTS ssh_attempts (
    id          INTEGER PRIMARY KEY,
    ts          INTEGER NOT NULL,
    src_ip      INTEGER NOT NULL,
    username    TEXT    NOT NULL DEFAULT '',
    auth_method TEXT    NOT NULL DEFAULT '',
    result      INTEGER NOT NULL,
    fingerprint TEXT    NOT NULL DEFAULT '',
    detail      TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_ssh_ts   ON ssh_attempts(ts);
CREATE INDEX IF NOT EXISTS idx_ssh_src  ON ssh_attempts(src_ip);
CREATE INDEX IF NOT EXISTS idx_ssh_user ON ssh_attempts(username);

CREATE TABLE IF NOT EXISTS firewall_events (
    id       INTEGER PRIMARY KEY,
    ts       INTEGER NOT NULL,
    chain    TEXT    NOT NULL,
    action   TEXT    NOT NULL,
    proto    INTEGER NOT NULL,
    src_ip   INTEGER NOT NULL,
    src_port INTEGER NOT NULL,
    dst_ip   INTEGER NOT NULL,
    dst_port INTEGER NOT NULL,
    raw      TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_fw_ts     ON firewall_events(ts);
CREATE INDEX IF NOT EXISTS idx_fw_dport  ON firewall_events(dst_port);
CREATE INDEX IF NOT EXISTS idx_fw_action ON firewall_events(action);

CREATE TABLE IF NOT EXISTS ban_events (
    id   INTEGER PRIMARY KEY,
    ts   INTEGER NOT NULL,
    ip   INTEGER NOT NULL,
    type TEXT    NOT NULL,
    jail TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_ban_ts ON ban_events(ts);
CREATE INDEX IF NOT EXISTS idx_ban_ip ON ban_events(ip);

CREATE TABLE IF NOT EXISTS system_events (
    id      INTEGER PRIMARY KEY,
    ts      INTEGER NOT NULL,
    source  TEXT    NOT NULL,
    level   TEXT    NOT NULL,
    message TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_se_ts ON system_events(ts);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
`

// Store M-06 存储模块。生命周期：NewStore → Run（单写线程）→ ctx 取消后自动两阶段排空。
type Store struct {
	db         *sql.DB
	dbPath     string // 主库路径（VS-01：Run 首次写后补收 WAL/SHM，见 flush）
	ch         *out.Channels
	producers  *sync.WaitGroup
	batchEvery time.Duration
	batchSize  int
	archiveDir string
	gzipLevel  int
	// archiveCriticalPct 归档跳过阈值（配置 disk.critical_percent，R-01 与 diskmon 共用）。
	archiveCriticalPct float64
	// retentionDays 事件数据保留天数（DEV-031 优化⑤；<=0 禁用清理）。
	retentionDays int
	// copyAfterDays 归档跨度（archive.copy_after_days，空洞语义 warn 检测用，B.5.1）。
	copyAfterDays int

	// archiveReq 归档请求队列（写线程内同步执行，方案 3.9）。
	archiveReq chan string
}

// NewStore 打开主库并初始化 DDL。
// VS-01（DEV-P1-001，AUD-VPS-001）：数据目录 MkdirAll 0700（原 0755）——同机其他本地
// 用户/被攻破的低权限服务账号不可读安全数据（SSH 指纹/用户名/防火墙 raw）。
// 目录权限为 Linux 语义：Windows 上 mode 参数被忽略（无权限位模型），功能不回归。
// DEV-031 优化⑤：新增 retentionDays（<=0 禁用清理）与 copyAfterDays（归档空洞 warn 检测）。
func NewStore(dbPath, archiveDir string, batchIntervalMS, batchSize, gzipLevel, retentionDays, copyAfterDays int, archiveCriticalPct float64, ch *out.Channels, producers *sync.WaitGroup) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		return nil, fmt.Errorf("创建主库目录失败: %w", err)
	}
	// 归档目录必须存在：execArchive 的磁盘水位检查（statfs）依赖目录可达，
	// 否则归档会因"目录不存在→水位检查失败→保守跳过"而永久失效（A-02 实测发现）。
	if err := os.MkdirAll(archiveDir, 0o700); err != nil {
		return nil, fmt.Errorf("创建归档目录失败: %w", err)
	}
	// 启动自愈（方案 4.6）：清理归档目录残留 .tmp（中断恢复续跑语义）。
	if err := archive.CleanStaleTmp(archiveDir); err != nil {
		return nil, fmt.Errorf("清理归档残留失败: %w", err)
	}
	db, err := openDB(dbPath)
	if err != nil {
		return nil, fmt.Errorf("打开主库 %s 失败: %w", dbPath, err)
	}
	// VS-01：库文件权限收敛 0600（创建时 mode 受 umask 影响，Open 后显式 Chmod；
	// WAL/SHM 伴随文件存在时一并收权——WAL 含未 checkpoint 数据，权限缺口同主文件）。
	// Chmod 失败仅留 system_event warn 不阻塞（Windows 上为受限 no-op，无权限语义）。
	if err := chmodDataFiles(dbPath); err != nil {
		event.ReportSys(ch.System, "store", "warn", "数据文件权限收敛失败（"+dbPath+"）: "+err.Error())
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("初始化 DDL 失败: %w", err)
	}
	if err := initMeta(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("初始化 meta 失败: %w", err)
	}
	return &Store{
		db:                 db,
		dbPath:             dbPath,
		ch:                 ch,
		producers:          producers,
		batchEvery:         time.Duration(batchIntervalMS) * time.Millisecond,
		batchSize:          batchSize,
		archiveDir:         archiveDir,
		gzipLevel:          gzipLevel,
		archiveCriticalPct: archiveCriticalPct,
		retentionDays:      retentionDays,
		copyAfterDays:      copyAfterDays,
		archiveReq:         make(chan string, 8),
	}, nil
}

// openDB 打开（不存在则创建）SQLite 主库。
// DSN 路径 URL 编码（A-11 同规则：路径含 '?'/'#' 等特殊字符须 PathEscape）。
func openDB(path string) (*sql.DB, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)", url.PathEscape(path))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // 单写线程（方案 4.5：WAL 单写者限制由唯一写协程化解）
	return db, nil
}

// chmodDataFiles 将主库文件及其 WAL/SHM 伴随文件权限收敛为 0600（VS-01）。
// 首个失败即返回（调用方留 warn 不阻塞）；伴随文件不存在时跳过（WAL 模式运行中
// 通常存在 -wal/-shm，关闭时可能已清理）。
func chmodDataFiles(dbPath string) error {
	if err := os.Chmod(dbPath, 0o600); err != nil {
		return err
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		p := dbPath + suffix
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			if err := os.Chmod(p, 0o600); err != nil {
				return err
			}
		}
	}
	return nil
}

// initMeta 写入预置 meta 项（方案 4.2）。
func initMeta(db *sql.DB) error {
	hostname, _ := os.Hostname()
	for k, v := range map[string]string{
		"schema_version": "1",
		"created_at":     fmt.Sprintf("%d", time.Now().Unix()),
		"hostname":       hostname,
	} {
		if _, err := db.Exec("INSERT OR IGNORE INTO meta(key, value) VALUES(?, ?)", k, v); err != nil {
			return err
		}
	}
	return nil
}

// Run 运行单写线程直至 ctx 取消并完成两阶段排空。
// 退出语义（auditor M-02）：①ctx 取消 → 等待 producers 全部退出（不再有新 send）；
// ②排空各通道在途事件；③提交末批 → 返回。
func (s *Store) Run(ctx context.Context) error {
	defer s.db.Close()

	var pending []eventItem // 本批待写入事件
	var nInBatch int
	walChmodDone := false // VS-01（reviewer R-11）：首次写后 WAL/SHM 伴随文件才创建，
	// NewStore 内 chmodDataFiles 早于首个写事务（伴随文件尚不存在）；首次 flush 后补收权，
	// 避免 Linux 上 wal/shm 以 umask 默认权限（如 0644）残留（Windows 无权限语义 no-op）。

	flush := func() error {
		if nInBatch == 0 {
			return nil
		}
		// 单写线程：flush 仅在 Run goroutine 内调用，无并发（reviewer R-14）。
		if err := s.writeBatch(pending[:nInBatch]); err != nil {
			return err
		}
		if !walChmodDone {
			walChmodDone = true
			if err := chmodDataFiles(s.dbPath); err != nil {
				event.ReportSys(s.ch.System, "store", "warn", "WAL/SHM 权限收敛失败（"+s.dbPath+"）: "+err.Error())
			}
		}
		pending = pending[:0]
		nInBatch = 0
		return nil
	}

	// 主循环：select 各通道 + 批量定时器 + 归档请求 + retention 定时清理。
	ticker := time.NewTicker(s.batchEvery)
	defer ticker.Stop()
	// DEV-031 优化⑤：retention 清理（写线程内串行，MaxOpenConns(1) 约束）。
	// AUDIT-005 A-01 整改：首轮清理不再于 select 前同步执行（旧实现清理期间不消费
	// 通道，通道 4096 满后 conntrack hook 阻塞 → netlink 缓冲积压 → ENOBUFS 溢出丢
	// 事件）——改为 retentionNow 独立 channel 在 select 循环内触发，批间 yield 消费
	// 一轮通道维持写吞吐；此后每日 02:30（固定，运营官 D.4 裁定 4）触发。
	// retentionDays<=0 时 retentionNow/retentionC 均为 nil（nil channel 永不就绪，select 跳过）。
	s.warnRetentionArchiveGap() // 归档空洞语义提示（B.5.1，启动留痕一条）
	var retentionC <-chan time.Time
	var retentionNow chan struct{}
	if s.retentionDays > 0 {
		retentionNow = make(chan struct{}, 1)
		retentionNow <- struct{}{} // 启动立即触发首轮（select 循环内执行，不阻塞写路径）
		rt := time.NewTimer(time.Until(nextRetentionTime(time.Now())))
		defer rt.Stop()
		retentionC = rt.C
	}

	// retention 批间让出（AUDIT-005 A-01 整改）：清理批间消费一轮通道并达批阈值即提交，
	// 维持启动期写吞吐——避免大库清理期间通道积压 → conntrack hook 阻塞 → netlink
	// 溢出丢事件。flush 失败为致命错误：记录到 yieldErr，retention 分支返回前检查并终止 Run。
	var yieldErr error
	yield := func() {
		s.drainInto(&pending, &nInBatch)
		if nInBatch >= s.batchSize {
			if err := flush(); err != nil && yieldErr == nil {
				yieldErr = err
			}
		}
	}

	for {
		select {
		case <-ctx.Done():
			// 阶段一：等待生产者退出。
			s.producers.Wait()
			// 阶段二：排空在途事件（生产者已退出，drain 到空即完成）。
			s.drainInto(&pending, &nInBatch)
			if err := flush(); err != nil {
				return err
			}
			return nil
		case <-ticker.C:
			if err := flush(); err != nil {
				return fmt.Errorf("批量提交失败: %w", err)
			}
		case <-retentionNow:
			// 首轮清理（启动立即触发；批间 yield 消费通道维持写吞吐）。
			if err := s.runRetentionOnce(ctx, yield); err != nil {
				event.ReportSys(s.ch.System, "store", "error", "retention 首轮清理失败: "+err.Error())
			}
			if yieldErr != nil {
				return fmt.Errorf("批量提交失败: %w", yieldErr)
			}
		case <-retentionC:
			// 每日 02:30 定时清理；失败仅留痕不退出（清理是容错可重试操作，
			// 写路径主职责不受影响）。
			if err := s.runRetentionOnce(ctx, yield); err != nil {
				event.ReportSys(s.ch.System, "store", "error", "retention 定时清理失败: "+err.Error())
			}
			if yieldErr != nil {
				return fmt.Errorf("批量提交失败: %w", yieldErr)
			}
			// 重置为下一个 02:30：time.After 新建 channel 替换（触发后旧 channel 已消费，
			// 无 Reset 语义需求，避免 timer.Reset 的排空前提，reviewer R-07）。
			retentionC = time.After(time.Until(nextRetentionTime(time.Now())))
		case req := <-s.archiveReq:
			// 归档在写线程内同步执行（方案 3.9）；期间事件继续进入 pending 积压，不丢失。
			// 留痕（开始/完成/失败含耗时）由 execArchive 统一完成（A-02）。
			// 注意（reviewer N-01）：归档失败仅记录不退出——归档是容错可重试操作
			// （水位跳过/幂等/自愈，方案 3.9），归档失败 ≠ 主库写失败；
			// A-01 的 os.Exit(1) 退出语义仅适用于 Run 主写路径错误（flush/writeBatch 失败）。
			_ = s.execArchive(req)
		case v := <-s.ch.Resource:
			pending = append(pending, eventItem{kind: "resource", v: v})
			nInBatch++
		case v := <-s.ch.Conn:
			pending = append(pending, eventItem{kind: "conn", v: v})
			nInBatch++
		case v := <-s.ch.Overrun:
			pending = append(pending, eventItem{kind: "overrun", v: v})
			nInBatch++
		case v := <-s.ch.SSH:
			pending = append(pending, eventItem{kind: "ssh", v: v})
			nInBatch++
		case v := <-s.ch.FW:
			pending = append(pending, eventItem{kind: "fw", v: v})
			nInBatch++
		case v := <-s.ch.F2B:
			pending = append(pending, eventItem{kind: "f2b", v: v})
			nInBatch++
		case v := <-s.ch.System:
			// 高优先：system 事件立即提交（方案 3.6"立即批"，防丢失）。
			if err := s.writeBatch([]eventItem{{kind: "system", v: v}}); err != nil {
				return fmt.Errorf("system 事件写入失败: %w", err)
			}
		}
		if nInBatch >= s.batchSize {
			if err := flush(); err != nil {
				return fmt.Errorf("批量提交失败: %w", err)
			}
		}
	}
}

// drainInto 排空全部通道在途事件到 pending（生产者已退出的前提下）。
func (s *Store) drainInto(pending *[]eventItem, n *int) {
	for {
		select {
		case v := <-s.ch.Resource:
			*pending = append(*pending, eventItem{kind: "resource", v: v})
			*n++
		case v := <-s.ch.Conn:
			*pending = append(*pending, eventItem{kind: "conn", v: v})
			*n++
		case v := <-s.ch.Overrun:
			*pending = append(*pending, eventItem{kind: "overrun", v: v})
			*n++
		case v := <-s.ch.SSH:
			*pending = append(*pending, eventItem{kind: "ssh", v: v})
			*n++
		case v := <-s.ch.FW:
			*pending = append(*pending, eventItem{kind: "fw", v: v})
			*n++
		case v := <-s.ch.F2B:
			*pending = append(*pending, eventItem{kind: "f2b", v: v})
			*n++
		case v := <-s.ch.System:
			*pending = append(*pending, eventItem{kind: "system", v: v})
			*n++
		default:
			return
		}
	}
}

// RequestArchive 投递归档请求（写线程内同步执行；非阻塞）。
func (s *Store) RequestArchive(month string) error {
	select {
	case s.archiveReq <- month:
		return nil
	default:
		return fmt.Errorf("归档请求队列已满")
	}
}

// Close 关闭主库（Run 结束后调用；幂等）。
func (s *Store) Close() error {
	if s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}
