package config

import "testing"

func TestDefaults(t *testing.T) {
	cfg := Defaults()
	if cfg.Collect.ResourceIntervalSeconds != 5 {
		t.Errorf("resource_interval_seconds 默认应为 5，实际 %d", cfg.Collect.ResourceIntervalSeconds)
	}
	if cfg.Conntrack.BufferSizeKB != 2048 {
		t.Errorf("buffer_size_kb 默认应为 2048，实际 %d", cfg.Conntrack.BufferSizeKB)
	}
	if cfg.SSH.Source != "journald" || cfg.FW.Source != "journald-kernel" {
		t.Errorf("默认数据源错误: ssh=%s fw=%s", cfg.SSH.Source, cfg.FW.Source)
	}
	if !cfg.F2B.Enabled {
		t.Error("f2b.enabled 默认应为 true（D-02）")
	}
	// DEV-031 新增默认项。
	if !cfg.FW.ExcludeInternal {
		t.Error("fw.exclude_internal 默认应为 true（只显示真实威胁）")
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"resource 小于 5", func(c *Config) { c.Collect.ResourceIntervalSeconds = 3 }},
		{"ss 小于 5", func(c *Config) { c.SS.SnapshotIntervalS = 2 }},
		{"buffer 超上限", func(c *Config) { c.Conntrack.BufferSizeKB = 9000 }},
		{"buffer 非法 0", func(c *Config) { c.Conntrack.BufferSizeKB = 0 }},
		{"ssh.source 非法", func(c *Config) { c.SSH.Source = "file" }},
		{"fw.source 非法", func(c *Config) { c.FW.Source = "syslog" }},
		{"fw.prefix 空", func(c *Config) { c.FW.Prefix = "" }},
		{"f2b.log_path 空", func(c *Config) { c.F2B.LogPath = "" }},
		{"f2b.db_path 空", func(c *Config) { c.F2B.DBPath = "" }}, // TEST-001 整改（R-05）
		{"overrun_warn_interval 小于 5", func(c *Config) { c.Conntrack.OverrunWarnIntervalS = 3 }}, // TEST-001 整改（R-05）
		{"fallback_interval 小于 5", func(c *Config) { c.Conntrack.FallbackIntervalS = 1 }},        // TEST-001 整改（R-05）
		{"internal_cidrs 无掩码", func(c *Config) { c.FW.InternalCIDRs = []string{"10.0.0.0"} }},    // DEV-031
		{"internal_cidrs 非 CIDR", func(c *Config) { c.FW.InternalCIDRs = []string{"abc"} }},        // DEV-031
		{"internal_cidrs 混入非法项", func(c *Config) { c.FW.InternalCIDRs = []string{"10.0.0.0/8", "bad"} }}, // DEV-031
		{"db.path 空", func(c *Config) { c.DB.Path = "" }},
		{"db.archive_dir 空", func(c *Config) { c.DB.ArchiveDir = "" }},
		{"db.batch_interval_ms 过小", func(c *Config) { c.DB.BatchIntervalMS = 50 }},
		{"db.batch_size 非法 0", func(c *Config) { c.DB.BatchSize = 0 }},
		{"archive.gzip_level 越界", func(c *Config) { c.Archive.GzipLevel = 0 }},
		{"archive.copy_after_days 过小", func(c *Config) { c.Archive.CopyAfterDays = 0 }},
		{"archive.monthly_hour 非法", func(c *Config) { c.Archive.MonthlyHour = "25:99" }},
		{"archive.monthly_hour 格式错", func(c *Config) { c.Archive.MonthlyHour = "0200" }},
		{"web.listen 空", func(c *Config) { c.Web.Listen = "" }},
		{"ws_origin_allow 空", func(c *Config) { c.Web.WSOriginAllow = "" }},
		{"ws_origin_allow 非 http 前缀", func(c *Config) { c.Web.WSOriginAllow = "ws://127.0.0.1:8080" }},
		{"disk 阈值越界", func(c *Config) { c.Disk.WarnPercent = 101 }},
		{"disk 阈值序错", func(c *Config) { c.Disk.WarnPercent = 95 }}, // warn>=critical
		{"log.level 非法", func(c *Config) { c.Log.Level = "verbose" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := Defaults()
			c.mutate(cfg)
			if err := cfg.Validate(); err == nil {
				t.Error("应校验失败")
			}
		})
	}
}

func TestValidateOK(t *testing.T) {
	if err := Defaults().Validate(); err != nil {
		t.Errorf("默认配置应通过校验: %v", err)
	}
}

// TestValidateInternalCIDRsOK（DEV-031 优化②）：合法自定义 CIDR 列表通过校验。
func TestValidateInternalCIDRsOK(t *testing.T) {
	cfg := Defaults()
	cfg.FW.InternalCIDRs = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	if err := cfg.Validate(); err != nil {
		t.Errorf("合法 internal_cidrs 应通过校验: %v", err)
	}
}
