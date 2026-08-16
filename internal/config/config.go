// Package config 实现 config.json 加载与校验。
// M2 起覆盖方案 6.6 全部配置项（采集 + db + archive）；web/disk 相关项属 M3 范围。
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Config 采集配置（M3 起含 web/disk 全量项，与方案 6.6 对应）。
type Config struct {
	Collect   CollectCfg   `json:"collect"`
	SS        SSCfg        `json:"ss"`
	Conntrack ConntrackCfg `json:"conntrack"`
	SSH       SSHCfg       `json:"ssh"`
	FW        FWCfg        `json:"fw"`
	F2B       F2BCfg       `json:"f2b"`
	DB        DBCfg        `json:"db"`
	Archive   ArchiveCfg   `json:"archive"`
	Web       WebCfg       `json:"web"`
	Disk      DiskCfg      `json:"disk"`
	Log       LogCfg       `json:"log"`
}

// CollectCfg 资源采集（M-01）。
type CollectCfg struct {
	// ResourceIntervalSeconds 资源轮询间隔（秒）。
	// 固定 5s，禁止调小（R-03：仅提供 >=5s 校验，防误改）。
	ResourceIntervalSeconds int `json:"resource_interval_seconds"`
}

// SSCfg ss 快照（M-02 展示通道）。
type SSCfg struct {
	// SnapshotIntervalS ss 快照间隔（秒），建议 10-30（R-03 约束同上）。
	SnapshotIntervalS int `json:"snapshot_interval_s"`
}

// ConntrackCfg conntrack 监听（M-02 主通道）。
type ConntrackCfg struct {
	// BufferSizeKB netlink 接收缓冲（KB），默认 2048，可扩至 8192（R-10）。
	BufferSizeKB int `json:"buffer_size_kb"`
	// EnableAcct 是否开启 nf_conntrack_acct（取每流包/字节数）。
	EnableAcct bool `json:"enable_acct"`
	// OverrunWarnIntervalS 溢出计数检查间隔（秒），默认 60。
	OverrunWarnIntervalS int `json:"overrun_warn_interval_s"`
	// FallbackIntervalS 降级模式（B5）下 ss 快照 diff 近似间隔（秒），默认 5。
	FallbackIntervalS int `json:"fallback_interval_s"`
}

// SSHCfg SSH 登录解析（M-03）。
type SSHCfg struct {
	// Source 日志源：journald（默认，journalctl 流式）| rsyslog（tail -F auth.log）。
	Source string `json:"source"`
	// VerboseFingerprint 是否要求 LogLevel VERBOSE 取公钥指纹（默认 true）。
	VerboseFingerprint bool `json:"verbose_fingerprint"`
}

// FWCfg 防火墙日志解析（M-04）。
type FWCfg struct {
	// Source 日志源：journald-kernel（默认）| kmsg（/dev/kmsg）。
	Source string `json:"source"`
	// Prefix 防火墙日志前缀，仅解析此前缀行（默认 SENTRY_FW:）。
	Prefix string `json:"prefix"`
	// RateLimitPktS 内核限速（包/秒），默认 5（采样性质，R-09；此值仅注释用，规则由部署脚本写入）。
	RateLimitPktS int `json:"rate_limit_pkt_s"`
}

// F2BCfg fail2ban 集成（M-05）。
type F2BCfg struct {
	// Enabled 是否启用（D-02 定稿保留 fail2ban，默认 true）。
	Enabled bool `json:"enabled"`
	// LogPath fail2ban 日志路径。
	LogPath string `json:"log_path"`
	// DBPath fail2ban sqlite 库路径（封禁名单查询，M2 联调）。
	DBPath string `json:"db_path"`
}

// DBCfg 存储模块（M-06，方案 3.6/6.6）。
type DBCfg struct {
	// Path 主库路径（默认 /var/lib/sentry-agent/state.db）。
	Path string `json:"path"`
	// BatchIntervalMS 批量事务周期（毫秒，默认 1000）。
	BatchIntervalMS int `json:"batch_interval_ms"`
	// BatchSize 批量事务行数（默认 500）。
	BatchSize int `json:"batch_size"`
	// ArchiveDir 压缩副本目录（默认 /var/lib/sentry-agent/archive）。
	ArchiveDir string `json:"archive_dir"`
}

// ArchiveCfg 归档模块（M-09，方案 3.9/6.6）。
type ArchiveCfg struct {
	// MonthlyHour 每月归档执行时刻（HH:MM，默认 02:00）。
	MonthlyHour string `json:"monthly_hour"`
	// GzipLevel gzip 压缩级别（1-9，默认 6）。
	GzipLevel int `json:"gzip_level"`
	// CopyAfterDays 超过此天数的数据进入按月压缩副本（默认 60）；主库永久保留（D-04）。
	CopyAfterDays int `json:"copy_after_days"`
}

// WebCfg Web 面板（M-07/M-08，方案 6.6/6.7）。
type WebCfg struct {
	// Listen 监听地址（默认 127.0.0.1:8080；D-03：可改 0.0.0.0，暴露面自担）。
	Listen string `json:"listen"`
	// WSOriginAllow WS 升级 Origin 白名单（默认 http://127.0.0.1:8080，防跨站）。
	WSOriginAllow string `json:"ws_origin_allow"`
	// WSMaxConns WS 并发连接数上限（默认 100，超限拒绝新连接返回 503，VS-03）。
	WSMaxConns int `json:"ws_max_conns"`
	// RateLimitRPS 全局 API 速率限制（令牌桶补充速率，默认 10 rps，VS-04）。
	RateLimitRPS int `json:"rate_limit_rps"`
	// RateLimitBurst 全局 API 速率限制突发容量（默认 20，VS-04）。
	RateLimitBurst int `json:"rate_limit_burst"`
	// HeavyLimitRPS 重聚合端点（30d 视图 CPU 密集）单独限流（默认 1 rps，VS-04；
	// burst 固定 6 为实测取值——浏览器同源 6 连接限制下慢查询排队与下轮重叠，见 api.go routes 注释）。
	HeavyLimitRPS int `json:"heavy_limit_rps"`
}

// DiskCfg 磁盘水位（方案 7.3 三级告警）。
type DiskCfg struct {
	// WarnPercent 磁盘告警线（默认 80）。
	WarnPercent int `json:"warn_percent"`
	// CriticalPercent 磁盘紧急线（默认 90；归档跳过阈值）。
	CriticalPercent int `json:"critical_percent"`
	// EmergencyPercent 磁盘最高级阈值（默认 95）。
	EmergencyPercent int `json:"emergency_percent"`
}

// LogCfg 日志级别。
type LogCfg struct {
	Level string `json:"level"`
}

// Defaults 返回全部配置项默认值（与方案 6.6 一致）。
func Defaults() *Config {
	return &Config{
		Collect: CollectCfg{ResourceIntervalSeconds: 5},
		SS:      SSCfg{SnapshotIntervalS: 20},
		Conntrack: ConntrackCfg{
			BufferSizeKB:         2048,
			EnableAcct:           true,
			OverrunWarnIntervalS: 60,
			FallbackIntervalS:    5,
		},
		SSH: SSHCfg{Source: "journald", VerboseFingerprint: true},
		FW:  FWCfg{Source: "journald-kernel", Prefix: "SENTRY_FW:", RateLimitPktS: 5},
		F2B: F2BCfg{Enabled: true, LogPath: "/var/log/fail2ban.log", DBPath: "/var/lib/fail2ban/fail2ban.sqlite3"},
		DB: DBCfg{
			Path:            "/var/lib/sentry-agent/state.db",
			BatchIntervalMS: 1000,
			BatchSize:       500,
			ArchiveDir:      "/var/lib/sentry-agent/archive",
		},
		Archive: ArchiveCfg{MonthlyHour: "02:00", GzipLevel: 6, CopyAfterDays: 60},
		Web:     WebCfg{Listen: "127.0.0.1:8080", WSOriginAllow: "http://127.0.0.1:8080", WSMaxConns: 100, RateLimitRPS: 10, RateLimitBurst: 20, HeavyLimitRPS: 1},
		Disk:    DiskCfg{WarnPercent: 80, CriticalPercent: 90, EmergencyPercent: 95},
		Log:     LogCfg{Level: "info"},
	}
}

// Load 从 JSON 文件加载配置：先取默认值，再以文件内容覆盖（缺失键保持默认）。
// 文件不存在时返回错误（配置缺失属部署错误，不允许静默运行）。
func Load(path string) (*Config, error) {
	cfg := Defaults()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("解析配置文件 %s 失败: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Validate 校验配置合法性（R-03：轮询间隔仅提供 >=5s 校验，禁止调小）。
func (c *Config) Validate() error {
	if c.Collect.ResourceIntervalSeconds < 5 {
		return fmt.Errorf("collect.resource_interval_seconds=%d 小于下限 5s（R-03 固定值防误改，禁止调小）", c.Collect.ResourceIntervalSeconds)
	}
	if c.SS.SnapshotIntervalS < 5 {
		return fmt.Errorf("ss.snapshot_interval_s=%d 小于下限 5s（R-03 约束）", c.SS.SnapshotIntervalS)
	}
	if c.Conntrack.BufferSizeKB < 1 || c.Conntrack.BufferSizeKB > 8192 {
		return fmt.Errorf("conntrack.buffer_size_kb=%d 超出范围 1-8192（R-10 缓冲上限 8MB）", c.Conntrack.BufferSizeKB)
	}
	if c.Conntrack.OverrunWarnIntervalS < 5 {
		return fmt.Errorf("conntrack.overrun_warn_interval_s=%d 小于下限 5s", c.Conntrack.OverrunWarnIntervalS)
	}
	if c.Conntrack.FallbackIntervalS < 5 {
		return fmt.Errorf("conntrack.fallback_interval_s=%d 小于下限 5s", c.Conntrack.FallbackIntervalS)
	}
	if c.SSH.Source != "journald" && c.SSH.Source != "rsyslog" {
		return fmt.Errorf("ssh.source=%q 非法，仅支持 journald|rsyslog", c.SSH.Source)
	}
	if c.FW.Source != "journald-kernel" && c.FW.Source != "kmsg" {
		return fmt.Errorf("fw.source=%q 非法，仅支持 journald-kernel|kmsg", c.FW.Source)
	}
	if c.FW.Prefix == "" {
		return fmt.Errorf("fw.prefix 不能为空")
	}
	if c.F2B.LogPath == "" || c.F2B.DBPath == "" {
		return fmt.Errorf("f2b.log_path / f2b.db_path 不能为空")
	}
	if c.DB.Path == "" || c.DB.ArchiveDir == "" {
		return fmt.Errorf("db.path / db.archive_dir 不能为空")
	}
	if c.DB.BatchIntervalMS < 100 || c.DB.BatchIntervalMS > 60000 {
		return fmt.Errorf("db.batch_interval_ms=%d 超出范围 100-60000", c.DB.BatchIntervalMS)
	}
	if c.DB.BatchSize < 1 || c.DB.BatchSize > 100000 {
		return fmt.Errorf("db.batch_size=%d 超出范围 1-100000", c.DB.BatchSize)
	}
	if c.Archive.GzipLevel < 1 || c.Archive.GzipLevel > 9 {
		return fmt.Errorf("archive.gzip_level=%d 超出范围 1-9", c.Archive.GzipLevel)
	}
	if c.Archive.CopyAfterDays < 1 {
		return fmt.Errorf("archive.copy_after_days=%d 小于下限 1", c.Archive.CopyAfterDays)
	}
	if _, _, err := parseHourMinute(c.Archive.MonthlyHour); err != nil {
		return fmt.Errorf("archive.monthly_hour=%q 非法: %v", c.Archive.MonthlyHour, err)
	}
	if c.Web.Listen == "" {
		return fmt.Errorf("web.listen 不能为空")
	}
	// R-07：ws_origin_allow 须为合法 http(s) URL（与前端页面 Origin 联动，留空/非法将导致 WS 全 403）。
	if c.Web.WSOriginAllow == "" {
		return fmt.Errorf("web.ws_origin_allow 不能为空（须与页面 Origin 一致，如 http://127.0.0.1:8080）")
	}
	if !strings.HasPrefix(c.Web.WSOriginAllow, "http://") && !strings.HasPrefix(c.Web.WSOriginAllow, "https://") {
		return fmt.Errorf("web.ws_origin_allow=%q 非法，须为 http(s):// 形式", c.Web.WSOriginAllow)
	}
	// VS-03/VS-04（DEV-P1-001）：WS 连接数上限与速率限制范围校验（1 以上正整数）。
	if c.Web.WSMaxConns < 1 || c.Web.WSMaxConns > 10000 {
		return fmt.Errorf("web.ws_max_conns=%d 超出范围 1-10000", c.Web.WSMaxConns)
	}
	if c.Web.RateLimitRPS < 1 || c.Web.RateLimitRPS > 1000 {
		return fmt.Errorf("web.rate_limit_rps=%d 超出范围 1-1000", c.Web.RateLimitRPS)
	}
	if c.Web.RateLimitBurst < 1 || c.Web.RateLimitBurst > 10000 {
		return fmt.Errorf("web.rate_limit_burst=%d 超出范围 1-10000", c.Web.RateLimitBurst)
	}
	if c.Web.HeavyLimitRPS < 1 || c.Web.HeavyLimitRPS > 100 {
		return fmt.Errorf("web.heavy_limit_rps=%d 超出范围 1-100", c.Web.HeavyLimitRPS)
	}
	if c.Disk.WarnPercent < 1 || c.Disk.WarnPercent > 100 ||
		c.Disk.CriticalPercent < 1 || c.Disk.CriticalPercent > 100 ||
		c.Disk.EmergencyPercent < 1 || c.Disk.EmergencyPercent > 100 {
		return fmt.Errorf("disk 阈值超出范围 1-100")
	}
	if c.Disk.WarnPercent >= c.Disk.CriticalPercent || c.Disk.CriticalPercent >= c.Disk.EmergencyPercent {
		return fmt.Errorf("disk 阈值须满足 warn < critical < emergency")
	}
	if c.Log.Level != "info" && c.Log.Level != "debug" && c.Log.Level != "warn" && c.Log.Level != "error" {
		return fmt.Errorf("log.level=%q 非法，仅支持 info|debug|warn|error", c.Log.Level)
	}
	return nil
}

// parseHourMinute 解析 "HH:MM" 时刻（归档执行时刻校验用）。
func parseHourMinute(s string) (int, int, error) {
	if len(s) != 5 || s[2] != ':' {
		return 0, 0, fmt.Errorf("格式应为 HH:MM")
	}
	var h, m int
	for _, c := range s[:2] {
		if c < '0' || c > '9' {
			return 0, 0, fmt.Errorf("格式应为 HH:MM")
		}
		h = h*10 + int(c-'0')
	}
	for _, c := range s[3:] {
		if c < '0' || c > '9' {
			return 0, 0, fmt.Errorf("格式应为 HH:MM")
		}
		m = m*10 + int(c-'0')
	}
	if h > 23 || m > 59 {
		return 0, 0, fmt.Errorf("时分超出范围")
	}
	return h, m, nil
}
