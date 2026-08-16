package diskmon

import (
	"context"
	"testing"
	"time"

	"sentry-agent/internal/event"
)

// TestClassify 三级阈值判定（方案 7.3：warn 80 / critical 90 / emergency 95）。
func TestClassify(t *testing.T) {
	cases := []struct {
		usage float64
		want  Level
	}{
		{50, LevelOK},
		{79.9, LevelOK},
		{80.0, LevelWarn},
		{89.9, LevelWarn},
		{90.0, LevelCritical},
		{94.9, LevelCritical},
		{95.0, LevelEmergency},
		{99.9, LevelEmergency},
		{100, LevelEmergency},
	}
	for _, c := range cases {
		if got := Classify(c.usage, 80, 90, 95); got != c.want {
			t.Errorf("Classify(%.1f) = %v, 期望 %v", c.usage, got, c.want)
		}
	}
}

// TestClassifyInvalidThresholds 阈值序错误时行为（配置校验已拦截，此处防 panic）。
func TestClassifyInvalidThresholds(t *testing.T) {
	// 不 panic 即可（结果未定义）。
	_ = Classify(85, 90, 80, 95)
	_ = Classify(85, 80, 95, 90)
}

// TestFirstCheckLevelSync（M-03）：首轮检查后 lastLevel 同步，同级别 ticker 不重复告警。
func TestFirstCheckLevelSync(t *testing.T) {
	sys := make(chan event.SystemEvent, 16)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	usage := 95.0 // 高水位（emergency）
	go func() {
		// 两个 ticker 周期，水位保持 95：首轮 1 条 + 限频后 0 条（10 分钟内不重复）。
		_ = RunDiskMonitorWithUsage(ctx, 50*time.Millisecond, func() (float64, error) {
			return usage, nil
		}, 80, 90, 95, sys)
	}()

	// 收集 250ms（约 5 个周期）内告警。
	deadline := time.After(250 * time.Millisecond)
	var alerts []event.SystemEvent
collect:
	for {
		select {
		case ev := <-sys:
			alerts = append(alerts, ev)
		case <-deadline:
			break collect
		}
	}
	// 断言：emergency 级别告警（source=disk, level=error）恰好 1 条（首轮），
	// 后续同级别周期因 lastLevel 同步被抑制（M-03 修复点）。
	errCnt := 0
	for _, ev := range alerts {
		if ev.Source == "disk" && ev.Level == "error" {
			errCnt++
		}
	}
	if errCnt != 1 {
		t.Errorf("emergency 告警条数 = %d, 期望 1（首轮同步后同级别不重复）", errCnt)
	}
}
