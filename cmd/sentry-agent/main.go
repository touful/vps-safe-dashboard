// sentry-agent 轻量化 VPS 安全态势感知工具。
// M2 里程碑：M-01~M-05 采集通道 + M-06 存储（SQLite 单写线程批量事务）+ M-09 归档；
// 采集事件经有界 channel 汇入 Store 落库；-stdout 时改走 stdout 输出器（debug 模式）。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"sentry-agent/internal/api"
	"sentry-agent/internal/archive"
	"sentry-agent/internal/collect"
	"sentry-agent/internal/config"
	"sentry-agent/internal/conn"
	"sentry-agent/internal/diskmon"
	"sentry-agent/internal/event"
	"sentry-agent/internal/f2b"
	"sentry-agent/internal/fw"
	"sentry-agent/internal/out"
	"sentry-agent/internal/ssh"
	"sentry-agent/internal/store"
)

func main() {
	configPath := flag.String("config", "config.json", "配置文件路径")
	duration := flag.Duration("duration", 0, "运行时长（0=持续运行；验证/压测时设置有限时长）")
	stdoutMode := flag.Bool("stdout", false, "stdout 输出模式（debug，替代 SQLite 落库；M2 默认落库）")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "配置加载失败: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 信号处理：SIGINT/SIGTERM 触发优雅退出。
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case <-sigCh:
			fmt.Fprintln(os.Stderr, "收到退出信号，优雅退出中...")
			cancel()
		case <-ctx.Done():
		}
	}()

	// 时长限制（验证/压测用）。
	if *duration > 0 {
		go func() {
			select {
			case <-time.After(*duration):
				cancel()
			case <-ctx.Done():
			}
		}()
	}

	// 有界 channel（方案 2.3.3：容量 4096，背压传导）。
	ch := out.NewChannels(4096)

	// 生产者 WaitGroup：采集协程（供 Store/out 两阶段排空协议使用，auditor M-02）。
	var producers sync.WaitGroup
	var all sync.WaitGroup
	startProducer := func(f func()) {
		producers.Add(1)
		all.Add(1)
		go func() {
			defer producers.Done()
			defer all.Done()
			f()
		}()
	}
	startService := func(f func()) {
		all.Add(1)
		go func() {
			defer all.Done()
			f()
		}()
	}

	// ss 快照最新值（展示通道，atomic.Value 共享）。
	var latest atomic.Value
	// M-01：conntrack 溢出累计（conn 模块直接累加；API health 只读展示；无通道竞争）。
	var overrunTotal atomic.Uint64

	// 消费端：默认 Store 落库；-stdout 时输出器（debug）。
	var st *store.Store
	if *stdoutMode {
		startService(func() {
			_ = out.Run(ctx, os.Stdout, ch, &producers, func() (int64, int) {
				if v := latest.Load(); v != nil {
					s := v.(*event.ConnSnapshot)
					return s.TS, len(s.Conn)
				}
				return 0, 0
			})
		})
	} else {
		var err error
		st, err = store.NewStore(cfg.DB.Path, cfg.DB.ArchiveDir, cfg.DB.BatchIntervalMS, cfg.DB.BatchSize, cfg.Archive.GzipLevel, cfg.DB.RetentionDays, cfg.Archive.CopyAfterDays, float64(cfg.Disk.CriticalPercent), ch, &producers)
		if err != nil {
			fmt.Fprintf(os.Stderr, "存储模块初始化失败: %v\n", err)
			os.Exit(1)
		}
		startService(func() {
			if err := st.Run(ctx); err != nil {
				// A-01：存储写失败为致命故障——stderr + 非零退出，配合 M4 systemd
				// Restart=on-failure 自动重启；Run 内部 defer 已关闭数据库连接。
				fmt.Fprintf(os.Stderr, "致命错误: 存储模块退出（数据写入失败）: %v\n", err)
				os.Exit(1)
			}
			_ = st.Close()
		})
		// M-09 archiver：每日检查（1 小时检查粒度；每月 1 日且过 monthly_hour 时触发）。
		startService(func() {
			_ = archive.RunArchiver(ctx, time.Hour, cfg.Archive.MonthlyHour, cfg.Archive.CopyAfterDays, func(month string) error {
				if err := st.RequestArchive(month); err != nil {
					event.ReportSys(ch.System, "archiver", "warn", "归档请求投递失败（"+month+"）: "+err.Error())
				}
				return nil
			})
		})

		// M-07 API + WebSocket（仅落库模式：查询依赖主库；独立只读连接，auditor 坑点）。
		startService(func() {
			// M-02：监听回环地址时允许无 Origin 的 WS 请求（本机工具）；
			// 非回环（0.0.0.0 等）时拒绝无 Origin 并告警（D-03 暴露面自担提示）。
			allowNoOrigin := isLoopbackListen(cfg.Web.Listen)
			if !allowNoOrigin {
				event.ReportSys(ch.System, "api", "warn",
					"web.listen 非回环地址（"+cfg.Web.Listen+"）：WS 将拒绝无 Origin 请求（D-03 暴露面自担）")
			}
			srv, err := api.NewServer(cfg.DB.Path, cfg.DB.ArchiveDir, cfg.Web.WSOriginAllow, allowNoOrigin, func() *event.ConnSnapshot {
				if v := latest.Load(); v != nil {
					return v.(*event.ConnSnapshot)
				}
				return nil
			})
			if err != nil {
				event.ReportSys(ch.System, "api", "error", "API 初始化失败: "+err.Error())
				return
			}
			defer srv.Close()
			srv.SetDBPath(cfg.DB.Path)
			// A-04（AUDIT-005）：注入数据保留天数（health 返回，前端 range 提示）。
			srv.SetRetentionDays(cfg.DB.RetentionDays)
			// VS-03/VS-04（DEV-P1-001）：注入 WS 连接数上限与速率限制（config 默认
			// 100 连接 / 全局 10 rps burst 20 / 重聚合 1 rps；前端 5s 轮询 9 请求/轮
			// ≈ 1.8 rps 峰值 burst 9，全局桶余量充足不误伤正常轮询）。
			srv.SetLimits(cfg.Web.RateLimitRPS, cfg.Web.RateLimitBurst, cfg.Web.HeavyLimitRPS, cfg.Web.WSMaxConns)
			// VS-04：限流拒绝留痕（system_event warn，运维可观测限流误伤）。
			srv.SetSystemChannel(ch.System)
			// M-01：共享溢出计数（conn 模块直接累加，无通道竞争；health 只读展示）。
			srv.SetOverrunCounter(&overrunTotal)
			// WS 推送循环（1s/5s/30s 帧）。
			startService(func() {
				srv.PushLoop(ctx)
			})
			if err := srv.Serve(ctx, cfg.Web.Listen); err != nil {
				event.ReportSys(ch.System, "api", "error", "API 服务退出: "+err.Error())
			}
		})

		// 磁盘水位监控（方案 7.3 三级告警，A-02 完整形态；每 5 分钟）。
		startService(func() {
			_ = diskmon.RunDiskMonitor(ctx, 5*time.Minute, cfg.DB.ArchiveDir,
				cfg.Disk.WarnPercent, cfg.Disk.CriticalPercent, cfg.Disk.EmergencyPercent, ch.System)
		})
	}

	// M-01 资源采集（5s 轮询 /proc）。
	startProducer(func() {
		if err := collect.RunResourceCollector(ctx, time.Duration(cfg.Collect.ResourceIntervalSeconds)*time.Second, ch.Resource, ch.System); err != nil {
			event.ReportSys(ch.System, "collector", "error", "资源采集通道退出: "+err.Error())
		}
	})

	// M-02 连接监听：conntrack 主通道；不可用自动切换 B5 降级（ss diff 近似）。
	// DEV-031 优化④：mode=fallback 跳过主通道直接降级；主通道连续 3 次启动失败
	// 自动放弃并降级（修复 NET_ADMIN 缺失导致无限重启、B5 永不触发的缺陷）。
	startProducer(func() {
		runConnChannel(ctx, cfg, ch, &overrunTotal)
	})

	// M-02 ss 快照（展示通道，不落库）。
	startProducer(func() {
		_ = conn.RunConnSnapshotter(ctx, time.Duration(cfg.SS.SnapshotIntervalS)*time.Second, &latest, ch.System)
	})

	// M-03 SSH 登录解析。
	startProducer(func() {
		if err := ssh.RunSSHParser(ctx, cfg.SSH.Source, ch.SSH, ch.System); err != nil {
			event.ReportSys(ch.System, "ssh", "error", "SSH 解析通道退出: "+err.Error())
		}
	})

	// M-04 防火墙日志解析（DEV-031 优化②：采集层过滤内网/自身来源，B.2）。
	startProducer(func() {
		// internal_cidrs 格式已由 config.Validate 校验；此处失败仅理论路径，
		// 保守关闭过滤（恢复全量记录）并留痕。
		cidrs, err := fw.ParseCIDRs(cfg.FW.InternalCIDRs)
		if err != nil {
			event.ReportSys(ch.System, "fw", "warn", "fw.internal_cidrs 解析失败，本次启动关闭内网过滤（全量记录）: "+err.Error())
			cidrs = nil
		}
		// DEV-039 用户需求2：exclude_ips 格式已由 config.Validate 校验；失败仅理论路径，
		// 保守不排除（保留全量）并留痕。
		excludeIPs, err := fw.ParseExcludeIPs(cfg.FW.ExcludeIPs)
		if err != nil {
			event.ReportSys(ch.System, "fw", "warn", "fw.exclude_ips 解析失败，本次启动不排除指定 IP（全量记录）: "+err.Error())
			excludeIPs = nil
		}
		filter := fw.FwFilter{
			ExcludeInternal:   cfg.FW.ExcludeInternal,
			FilterDstInternal: cfg.FW.FilterDstInternal,
			CIDRs:             cidrs,
			ExcludeIPs:        excludeIPs,
		}
		if err := fw.RunFwParser(ctx, cfg.FW.Source, cfg.FW.Prefix, filter, ch.FW, ch.System); err != nil {
			event.ReportSys(ch.System, "fw", "error", "防火墙解析通道退出: "+err.Error())
		}
	})

	// M-05 fail2ban 日志监听 + 封禁名单查询刷新（每 60s，方案 3.5）。
	if cfg.F2B.Enabled {
		startProducer(func() {
			if err := f2b.RunF2BListener(ctx, cfg.F2B.LogPath, ch.F2B, ch.System); err != nil {
				event.ReportSys(ch.System, "f2b", "error", "fail2ban 监听通道退出: "+err.Error())
			}
		})
		startProducer(func() {
			refreshBanned(ctx, cfg.F2B.DBPath, ch.System)
		})
	}

	<-ctx.Done()
	// 等待全部协程退出（Store 含两阶段排空，事件零丢失）。
	done := make(chan struct{})
	go func() {
		all.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		fmt.Fprintln(os.Stderr, "协程退出超时（60s），强制结束")
	}
	fmt.Fprintln(os.Stderr, "sentry-agent 已退出")
}

// runConnChannel 启动连接采集通道（M-02，DEV-031 优化④）。
// 决策：conntrack.mode=fallback → 跳过主通道尝试直接走 B5 降级（消除预期降级告警噪音）；
// auto → 尝试主通道，失败（含连续 3 次启动失败，见 conn.connStartTracker）切换 B5 降级。
func runConnChannel(ctx context.Context, cfg *config.Config, ch *out.Channels, counter *atomic.Uint64) {
	if cfg.Conntrack.Mode == "fallback" {
		event.ReportSys(ch.System, "conntrack", "info",
			"conntrack.mode=fallback：跳过主通道尝试，直接使用 B5 ss 快照 diff 降级模式")
		if err := conn.RunFallbackConnListenerQuiet(ctx, time.Duration(cfg.Conntrack.FallbackIntervalS)*time.Second, ch.Conn, ch.System); err != nil && ctx.Err() == nil {
			event.ReportSys(ch.System, "conntrack", "error", "降级通道退出: "+err.Error())
		}
		return
	}
	if err := conn.RunConntrackListener(ctx, cfg.Conntrack, ch.Conn, ch.Overrun, ch.System, counter); err != nil {
		event.ReportSys(ch.System, "conntrack", "warn", "conntrack 通道不可用，切换 B5 降级: "+err.Error())
		if err2 := conn.RunFallbackConnListener(ctx, time.Duration(cfg.Conntrack.FallbackIntervalS)*time.Second, ch.Conn, ch.System); err2 != nil && ctx.Err() == nil {
			event.ReportSys(ch.System, "conntrack", "error", "降级通道退出: "+err2.Error())
		}
	}
}

// refreshBanned 查询 fail2ban 当前封禁名单（M-05 联调，方案 3.5；DEV-031 优化①）。
// 启动后立即执行一次（不等 60s 周期）；结果经 system_event 记录（条数变化信息/查询失败告警，限频）。
func refreshBanned(ctx context.Context, dbPath string, sys chan<- event.SystemEvent) {
	rep := event.NewRateLimiter(5 * time.Minute)
	query := func() {
		banned, err := f2b.QueryBanned(ctx, dbPath)
		if err != nil {
			// 错误文案由 f2b 携带根因分类与修复指引（DEV-031 B.1.2）。
			// DEV-033（DEV-032 现场核查结论 5）：hot journal 待恢复场景为预期瞬时状态
			// （下轮 60s 自动重试），info 级留痕不告警；其余分类按 warn 告警。
			var qe *f2b.BannedQueryError
			if errors.As(err, &qe) && qe.Kind == "hotjournal" {
				event.ReportSys(sys, "f2b", "info", "封禁名单暂不可用（hot journal 恢复中）: "+err.Error())
				return
			}
			rep.Report(sys, "f2b", "warn", "封禁名单查询失败: "+err.Error())
			return
		}
		event.ReportSys(sys, "f2b", "info", fmt.Sprintf("当前封禁 IP 数: %d", len(banned)))
	}
	query() // 启动后立即执行一次（DEV-031：首次封禁名单不再等 60s）
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			query()
		}
	}
}

// isLoopbackListen 判断监听地址是否为回环（127.0.0.1/localhost/::1）。
// M-02：回环监听允许无 Origin 的 WS 请求；非回环（0.0.0.0/具体 IP/空 host）拒绝。
// R-01（reviewer Major）：空 host（":8080"）在 Go net 语义中等价监听全部接口（0.0.0.0），
// 必须判为非回环——否则 M-02 的无 Origin 拒绝被 ":8080" 配置绕过。
func isLoopbackListen(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		// 非 host:port 形式（如纯 "8080" 或异常输入）：保守判非回环。
		return false
	}
	if host == "" {
		return false // 空 host = 监听全部接口（R-01）
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
