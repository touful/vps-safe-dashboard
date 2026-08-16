// Package collect 实现 M-01 资源采集模块。
// 每 5s 轮询 /proc/stat、/proc/meminfo、/proc/net/dev、/proc/self/mountinfo + statfs，
// 仅用 os.ReadFile 读文本 + 手工解析，不引入 psutil 类依赖（方案 3.1 约束）。
package collect

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"sentry-agent/internal/event"
)

// 连续读取失败升级阈值（方案 3.1：连续 10 次失败才升级为 error 退出，由 supervisor 重启）。
const maxConsecutiveFailures = 10

// RunResourceCollector 启动资源采集协程。
// 与方案 3.1 签名一致，另增 sys 通道用于上报 system_event（M1 输出出口，M2 改为 Store.EnqueueSystemEvent）。
func RunResourceCollector(ctx context.Context, interval time.Duration, sink chan<- event.ResourceSample, sys chan<- event.SystemEvent) error {
	prevCPU, prevNet, err := readPrevCounters()
	if err != nil {
		event.ReportSys(sys, "collector", "warn", "资源采集初始化失败: "+err.Error())
	}
	failures := 0
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			sample, err := collectOnce(prevCPU, prevNet, interval)
			if err != nil {
				failures++
				event.ReportSys(sys, "collector", "warn", fmt.Sprintf("资源采样失败(第 %d 次): %v", failures, err))
				if failures >= maxConsecutiveFailures {
					return fmt.Errorf("资源采集连续 %d 次失败: %w", maxConsecutiveFailures, err)
				}
				continue
			}
			failures = 0
			prevCPU, prevNet = sample.cpu, sample.net
			select {
			case sink <- sample.res:
			case <-ctx.Done():
				return nil
			}
		}
	}
}

// counters 保存相邻两次采样的原始计数。
type counters struct {
	cpuTotal uint64 // /proc/stat cpu 总时间
	cpuIdle  uint64 // idle + iowait
	netRx    uint64 // 所有非 lo 接口接收字节合计
	netTx    uint64
}

// resourceSample 单次采样结果。
type resourceSample struct {
	res event.ResourceSample
	cpu counters
	net counters
}

func readPrevCounters() (counters, counters, error) {
	stat, err := os.ReadFile("/proc/stat")
	if err != nil {
		return counters{}, counters{}, err
	}
	cpuTotal, cpuIdle, err := ParseProcStat(string(stat))
	if err != nil {
		return counters{}, counters{}, err
	}
	dev, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return counters{}, counters{}, err
	}
	rx, tx, err := ParseProcNetDev(string(dev))
	if err != nil {
		return counters{}, counters{}, err
	}
	return counters{cpuTotal: cpuTotal, cpuIdle: cpuIdle}, counters{netRx: rx, netTx: tx}, nil
}

func collectOnce(prevCPU, prevNet counters, interval time.Duration) (resourceSample, error) {
	ts := time.Now().Unix()
	// CPU：两次采样差值/总时间差计算百分比。
	stat, err := os.ReadFile("/proc/stat")
	if err != nil {
		return resourceSample{}, err
	}
	cpuTotal, cpuIdle, err := ParseProcStat(string(stat))
	if err != nil {
		return resourceSample{}, err
	}
	// 内存：used = MemTotal - MemAvailable（含 page cache 可回收部分的口径）。
	meminfo, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return resourceSample{}, err
	}
	memTotal, memAvail, err := ParseProcMeminfo(string(meminfo))
	if err != nil {
		return resourceSample{}, err
	}
	// 磁盘：根分区使用量（mountinfo 定位挂载点 + statfs）。
	diskUsed, diskPercent, err := diskUsage()
	if err != nil {
		return resourceSample{}, err
	}
	// 网络：非 lo 接口字节计数差值按间隔折算速率。
	dev, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return resourceSample{}, err
	}
	rx, tx, err := ParseProcNetDev(string(dev))
	if err != nil {
		return resourceSample{}, err
	}

	sample := event.ResourceSample{TS: ts}
	sample.CPUPercent = cpuPercent(prevCPU.cpuTotal, prevCPU.cpuIdle, cpuTotal, cpuIdle)
	if memTotal > 0 {
		sample.MemUsedMB = float64(memTotal-memAvail) / 1024
		sample.MemPercent = float64(memTotal-memAvail) / float64(memTotal) * 100
	}
	sample.DiskUsedMB = diskUsed
	sample.DiskPercent = diskPercent
	secs := float64(interval) / float64(time.Second)
	sample.NetRxBps = rate(prevNet.netRx, rx, secs)
	sample.NetTxBps = rate(prevNet.netTx, tx, secs)
	return resourceSample{res: sample, cpu: counters{cpuTotal: cpuTotal, cpuIdle: cpuIdle}, net: counters{netRx: rx, netTx: tx}}, nil
}

// rate 计算差值速率（字节/秒）；prev > cur 视为计数器回绕，按 0 处理。
func rate(prev, cur uint64, secs float64) uint64 {
	if cur < prev || secs <= 0 {
		return 0
	}
	return uint64(float64(cur-prev) / secs)
}

// cpuPercent 由两次 /proc/stat 采样计算 CPU 使用率（0-100）。
func cpuPercent(pTotal, pIdle, cTotal, cIdle uint64) float64 {
	totalDelta := cTotal - pTotal
	if totalDelta == 0 {
		return 0
	}
	idleDelta := cIdle - pIdle
	return float64(totalDelta-idleDelta) / float64(totalDelta) * 100
}

// ParseProcStat 解析 /proc/stat 第一行（cpu 合计），返回总时间与空闲时间（idle+iowait）。
// 平台无关纯函数，可单测。
func ParseProcStat(content string) (total, idle uint64, err error) {
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		// 至少需要 user nice system idle iowait 5 个数值（索引 1..5），
		// 否则后续 vals[4]（iowait）越界（auditor m-06 防御）。
		if len(fields) < 6 {
			return 0, 0, fmt.Errorf("cpu 行字段不足: %q", line)
		}
		vals := make([]uint64, 0, len(fields)-1)
		for _, f := range fields[1:] {
			v, err := strconv.ParseUint(f, 10, 64)
			if err != nil {
				return 0, 0, fmt.Errorf("解析 cpu 数值 %q 失败: %w", f, err)
			}
			vals = append(vals, v)
		}
		for _, v := range vals {
			total += v
		}
		// 字段顺序：user nice system idle iowait irq softirq steal guest guest_nice
		idle = vals[3] + vals[4]
		return total, idle, nil
	}
	return 0, 0, fmt.Errorf("未找到 cpu 行")
}

// ParseProcMeminfo 解析 /proc/meminfo 的 MemTotal 与 MemAvailable（单位 kB）。
func ParseProcMeminfo(content string) (total, available uint64, err error) {
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "MemTotal:"):
			total, err = parseKB(line)
		case strings.HasPrefix(line, "MemAvailable:"):
			available, err = parseKB(line)
		}
		if err != nil {
			return 0, 0, err
		}
		if total > 0 && available > 0 {
			return total, available, nil
		}
	}
	if total == 0 {
		return 0, 0, fmt.Errorf("MemTotal 缺失")
	}
	if available == 0 {
		return 0, 0, fmt.Errorf("MemAvailable 缺失")
	}
	return total, available, nil
}

// parseKB 解析形如 "MemTotal:       16384000 kB" 的行。
func parseKB(line string) (uint64, error) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0, fmt.Errorf("字段不足: %q", line)
	}
	return strconv.ParseUint(fields[1], 10, 64)
}

// ParseProcNetDev 解析 /proc/net/dev，聚合所有非 lo 接口的接收/发送字节数。
func ParseProcNetDev(content string) (rx, tx uint64, err error) {
	scanner := bufio.NewScanner(strings.NewReader(content))
	first := true
	for scanner.Scan() {
		line := scanner.Text()
		if first {
			first = false
			continue // 跳过表头
		}
		idx := strings.IndexByte(line, ':')
		if idx < 0 {
			continue
		}
		iface := strings.TrimSpace(line[:idx])
		if iface == "lo" {
			continue
		}
		fields := strings.Fields(line[idx+1:])
		if len(fields) < 9 {
			return 0, 0, fmt.Errorf("接口 %s 字段不足: %q", iface, line)
		}
		r, err1 := strconv.ParseUint(fields[0], 10, 64)
		t, err2 := strconv.ParseUint(fields[8], 10, 64)
		if err1 != nil || err2 != nil {
			return 0, 0, fmt.Errorf("解析接口 %s 计数失败: %v %v", iface, err1, err2)
		}
		rx += r
		tx += t
	}
	return rx, tx, nil
}
