// SSH 成功登录自动白名单学习（DEV-042）。
// 数据源：ssh_attempts 表（store.Store 实现 SuccessfulSSHIPSource 接口）。
// 学习窗口：近 windowDays 天成功登录（result=1）的源 IP（去重）。
// 触发时机：启动立即学习一次 + 每 interval 轮询增量更新。
// 过期策略：窗口自然过期——每次学习从 DB 重建近 windowDays 天集合，无需单独持久化。
// 安全：仅学习成功登录（可信来源），不学习失败登录。
package fw

import (
	"context"
	"fmt"
	"net"
	"time"

	"sentry-agent/internal/event"
)

// SuccessfulSSHIPSource 成功登录 IP 数据源接口（由 store.Store 实现，DEV-042）。
type SuccessfulSSHIPSource interface {
	QuerySuccessfulSSHIPs(ctx context.Context, windowDays int) ([]uint32, error)
}

// RunSSHLearner 定期从数据源学习近 windowDays 天成功登录的源 IP，更新 filter 动态白名单。
// filterReady 为 fw 采集 producer 创建 FwFilter 后投递的通道（cap 1）；学习器等待其就绪，
// 确保启动学习不早于 filter 创建。查询失败仅限频留痕不退出（下轮重试）。
func RunSSHLearner(ctx context.Context, src SuccessfulSSHIPSource, windowDays int, interval time.Duration, filterReady <-chan *FwFilter, sys chan<- event.SystemEvent) error {
	// 等待 filter 就绪（fw producer 创建 FwFilter 后投递）。
	var filter *FwFilter
	select {
	case filter = <-filterReady:
	case <-ctx.Done():
		return nil
	}
	rep := event.NewRateLimiter(5 * time.Minute)
	learn := func() {
		ips, err := src.QuerySuccessfulSSHIPs(ctx, windowDays)
		if err != nil {
			rep.Report(sys, "fw", "warn", "SSH 成功登录 IP 学习失败: "+err.Error())
			return
		}
		parsed := make([]net.IP, 0, len(ips))
		for _, v := range ips {
			parsed = append(parsed, ipv4ToNetIP(v))
		}
		filter.SetDynamicExcludeIPs(parsed)
		event.ReportSys(sys, "fw", "info",
			fmt.Sprintf("SSH 成功登录动态白名单已更新: %d 个 IP（近 %d 天）", len(parsed), windowDays))
	}
	learn() // 启动立即学习一次（验收标准 4：启动时加载近 N 天成功登录 IP）
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			learn() // 定期轮询增量更新（验收标准 5）
		}
	}
}

// ipv4ToNetIP 将 uint32 转为 4 字节 net.IP（与 ParseExcludeIPs 输出格式一致）。
func ipv4ToNetIP(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)).To4()
}
