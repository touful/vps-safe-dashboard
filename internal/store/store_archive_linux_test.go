//go:build linux

package store

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"sentry-agent/internal/event"
	"sentry-agent/internal/out"
)

// TestExecArchiveSystemEvents（A-02 实测）：execArchive 前后 system_event 留痕。
// 场景：构造含数据月份 → 调 execArchive → 断言 system 通道收到 archiver 留痕事件。
// 依赖 DiskUsagePercent（linux），Windows 跳过（build tag）。
func TestExecArchiveSystemEvents(t *testing.T) {
	ch := out.NewChannels(64)
	st := newTestStore(t, ch, &sync.WaitGroup{})
	defer st.Close()

	// 构造上月数据（resources 5 行）。
	prev := time.Now().AddDate(0, -1, 0)
	start := time.Date(prev.Year(), prev.Month(), 1, 0, 0, 0, 0, time.Local).Unix()
	month := prev.Format("2006-01")
	for i := 0; i < 5; i++ {
		if err := st.writeBatch([]eventItem{{kind: "resource", v: event.ResourceSample{
			TS: start + int64(i), CPUPercent: 1, MemUsedMB: 1, MemPercent: 1, DiskUsedMB: 1, DiskPercent: 1,
		}}}); err != nil {
			t.Fatal(err)
		}
	}

	// 后台收集 system 事件（带 10s 超时，防挂起）。
	gotCh := make(chan event.SystemEvent, 64)
	go func() {
		for ev := range ch.System {
			gotCh <- ev
		}
	}()

	if err := st.execArchive(month); err != nil {
		t.Fatalf("execArchive 失败: %v", err)
	}

	// 收集留痕（execArchive 同步执行完毕后事件已在通道中）。
	timeout := time.After(5 * time.Second)
	var got []event.SystemEvent
collect:
	for {
		select {
		case ev := <-gotCh:
			got = append(got, ev)
			if len(got) >= 2 {
				break collect
			}
		case <-timeout:
			break collect
		}
	}

	// 断言（reviewer R-04 增强）：开始/完成两条 info、完成事件含耗时、副本文件存在。
	var startEv, doneEv *event.SystemEvent
	for i := range got {
		ev := got[i]
		if ev.Source != "archiver" {
			continue
		}
		// 注意：字符串前缀比较须用 HasPrefix（中文字符 UTF-8 多字节，[:4] 字节切片会错）。
		if ev.Level == "info" && strings.HasPrefix(ev.Message, "归档开始") {
			startEv = &ev
		}
		if ev.Level == "info" && strings.HasPrefix(ev.Message, "归档完成") {
			doneEv = &ev
		}
	}
	if startEv == nil {
		t.Errorf("未收到'归档开始'留痕，实际: %+v", got)
	}
	if doneEv == nil {
		t.Errorf("未收到'归档完成'留痕，实际: %+v", got)
	} else if !strings.Contains(doneEv.Message, "耗时") {
		t.Errorf("归档完成留痕缺耗时信息: %q", doneEv.Message)
	}
	// 副本文件必须存在（WSL 磁盘水位远低于 90%，水位跳过不应发生）。
	if _, err := os.Stat(filepath.Join(st.archiveDir, month+".db.gz")); err != nil {
		t.Errorf("副本文件未生成（水位未跳过时归档应完成）: %v", err)
	}
}
