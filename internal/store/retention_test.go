// retention 清理测试（DEV-031 优化⑤，B.5.5）。
package store

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"sentry-agent/internal/event"
)

// nowSec 当前 Unix 秒。
func nowSec() int64 { return time.Now().Unix() }

// TestCleanupTable 构造 ts 分布（现在/6 天前/8 天前/0 值）→ 清理后仅保留期内行 + 0 值行。
func TestCleanupTable(t *testing.T) {
	st := newTestStore(t, event.NewChannels(16), &sync.WaitGroup{})
	defer st.Close()
	db := st.db

	insert := func(ts int64, v string) {
		t.Helper()
		if _, err := db.Exec(`INSERT INTO ssh_attempts (ts, src_ip, username, auth_method, result, fingerprint, detail) VALUES (?,?,?,?,?,?,?)`,
			ts, 1, "u", "password", 0, "", v); err != nil {
			t.Fatal(err)
		}
	}
	insert(nowSec(), "now")            // 保留
	insert(nowSec()-6*86400, "6d")     // 保留（> cutoff? 见下）
	insert(nowSec()-8*86400, "8d")     // 清理
	insert(0, "zero")                  // 0 值行保留（ts>0 守卫）
	insert(nowSec()-100*86400, "100d") // 清理

	// cutoff = now - 7 天。
	cutoff := time.Now().AddDate(0, 0, -7).Unix()
	n, err := cleanupTable(context.Background(), db, "ssh_attempts", cutoff, 100, nil)
	if err != nil {
		t.Fatalf("cleanupTable 失败: %v", err)
	}
	if n != 2 {
		t.Errorf("清理行数 = %d, 期望 2（8d + 100d）", n)
	}
	var remaining int64
	if err := db.QueryRow(`SELECT COUNT(*) FROM ssh_attempts`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 3 {
		t.Errorf("剩余行数 = %d, 期望 3（now + 6d + zero）", remaining)
	}
	// 0 值行守卫验证。
	var zeroCnt int64
	if err := db.QueryRow(`SELECT COUNT(*) FROM ssh_attempts WHERE ts = 0`).Scan(&zeroCnt); err != nil {
		t.Fatal(err)
	}
	if zeroCnt != 1 {
		t.Errorf("0 值行应保留（ts>0 守卫），实际 %d", zeroCnt)
	}
}

// TestCleanupTableBatchBoundary 超过单批上限（10000）的行分批正确清空。
func TestCleanupTableBatchBoundary(t *testing.T) {
	st := newTestStore(t, event.NewChannels(16), &sync.WaitGroup{})
	defer st.Close()
	db := st.db

	const n = 25000 // 2.5 批（batchSize=10000）
	old := nowSec() - 30*86400
	for i := 0; i < n; i++ {
		if _, err := db.Exec(`INSERT INTO connections (ts, ev_type, proto, src_ip, src_port, dst_ip, dst_port) VALUES (?,?,?,?,?,?,?)`,
			old, 1, 6, 1, 1, 2, 22); err != nil {
			t.Fatal(err)
		}
	}
	cutoff := time.Now().AddDate(0, 0, -7).Unix()
	got, err := cleanupTable(context.Background(), db, "connections", cutoff, 10000, nil)
	if err != nil {
		t.Fatalf("cleanupTable 失败: %v", err)
	}
	if got != n {
		t.Errorf("清理行数 = %d, 期望 %d", got, n)
	}
	var remaining int64
	if err := db.QueryRow(`SELECT COUNT(*) FROM connections`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Errorf("剩余行数 = %d, 期望 0", remaining)
	}
}

// TestCleanupTableCtxCancel ctx 取消时返回已清理行数 + ctx.Err()（幂等中断语义）。
func TestCleanupTableCtxCancel(t *testing.T) {
	st := newTestStore(t, event.NewChannels(16), &sync.WaitGroup{})
	defer st.Close()
	db := st.db

	old := nowSec() - 30*86400
	for i := 0; i < 50000; i++ {
		if _, err := db.Exec(`INSERT INTO connections (ts, ev_type, proto, src_ip, src_port, dst_ip, dst_port) VALUES (?,?,?,?,?,?,?)`,
			old, 1, 6, 1, 1, 2, 22); err != nil {
			t.Fatal(err)
		}
	}
	// 预取消 ctx：首轮即中断（返回 0 行 + ctx.Err）。
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	n, err := cleanupTable(ctx, db, "connections", nowSec(), 10000, nil)
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Errorf("ctx 取消应返回 Canceled: %v", err)
	}
	if n != 0 {
		t.Errorf("中断前清理行数 = %d, 期望 0（首轮即中断）", n)
	}
}

// TestNextRetentionTime 每日 02:30 固定时刻计算（02:30 前 → 今日；02:30 后 → 明日）。
func TestNextRetentionTime(t *testing.T) {
	loc := time.Local
	cases := []struct {
		name string
		now  time.Time
		want time.Time
	}{
		{"02:30 前", time.Date(2026, 8, 17, 1, 0, 0, 0, loc), time.Date(2026, 8, 17, 2, 30, 0, 0, loc)},
		{"正好 02:30", time.Date(2026, 8, 17, 2, 30, 0, 0, loc), time.Date(2026, 8, 18, 2, 30, 0, 0, loc)},
		{"02:30 后", time.Date(2026, 8, 17, 10, 0, 0, 0, loc), time.Date(2026, 8, 18, 2, 30, 0, 0, loc)},
		{"月末跨月", time.Date(2026, 8, 31, 23, 59, 59, 0, loc), time.Date(2026, 9, 1, 2, 30, 0, 0, loc)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := nextRetentionTime(c.now); !got.Equal(c.want) {
				t.Errorf("nextRetentionTime(%v) = %v, 期望 %v", c.now, got, c.want)
			}
		})
	}
}

// TestRunRetentionOnce 集成：预插旧数据 → 启动首轮清理 + meta.last_retention_ts + system 留痕。
func TestRunRetentionOnce(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(filepath.Join(dir, "state.db"), filepath.Join(dir, "archive"),
		1000, 500, 6, 7, 60, 90, event.NewChannels(16), &sync.WaitGroup{})
	if err != nil {
		t.Fatalf("NewStore 失败: %v", err)
	}
	defer st.Close()

	// 预插：1 条保留期内 + 1 条超期。
	if _, err := st.db.Exec(`INSERT INTO ban_events (ts, ip, type, jail) VALUES (?,?,?,?)`, nowSec(), 1, "ban", "sshd"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`INSERT INTO ban_events (ts, ip, type, jail) VALUES (?,?,?,?)`, nowSec()-30*86400, 2, "ban", "sshd"); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	if err := st.runRetentionOnce(ctx, nil); err != nil {
		t.Fatalf("runRetentionOnce 失败: %v", err)
	}
	var remaining int64
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM ban_events`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 1 {
		t.Errorf("清理后 ban_events 行数 = %d, 期望 1", remaining)
	}
	// meta.last_retention_ts 已记录。
	var last string
	if err := st.db.QueryRow(`SELECT value FROM meta WHERE key = 'last_retention_ts'`).Scan(&last); err != nil {
		t.Errorf("meta.last_retention_ts 未记录: %v", err)
	} else if last == "" {
		t.Error("meta.last_retention_ts 为空")
	}
}

// TestWarnRetentionArchiveGap 归档空洞语义提示（B.5.1）：阈值 copy_after_days+30。
// 直接构造 Store 结构体（不经 NewStore，避免数据文件权限 warn 噪音）。
func TestWarnRetentionArchiveGap(t *testing.T) {
	// retention=7, copy_after=60 → 7 < 90 → warn。
	ch := event.NewChannels(16)
	st := &Store{retentionDays: 7, copyAfterDays: 60, ch: ch}
	st.warnRetentionArchiveGap()
	select {
	case ev := <-ch.System:
		if ev.Level != "warn" {
			t.Errorf("留痕等级 = %s, 期望 warn", ev.Level)
		}
		if !strings.Contains(ev.Message, "空洞") {
			t.Errorf("文案应含空洞语义，实际: %s", ev.Message)
		}
	default:
		t.Error("retention < copy_after_days+30 应产生 warn")
	}

	// retention=90 >= 60+30 → 不 warn。
	ch2 := event.NewChannels(16)
	st2 := &Store{retentionDays: 90, copyAfterDays: 60, ch: ch2}
	st2.warnRetentionArchiveGap()
	select {
	case ev := <-ch2.System:
		t.Errorf("retention >= 跨度不应 warn，实际: %s", ev.Message)
	default:
	}
	// retention<=0 → 不 warn。
	ch3 := event.NewChannels(16)
	st3 := &Store{retentionDays: 0, copyAfterDays: 60, ch: ch3}
	st3.warnRetentionArchiveGap()
	select {
	case ev := <-ch3.System:
		t.Errorf("retention<=0 不应 warn，实际: %s", ev.Message)
	default:
	}
}
