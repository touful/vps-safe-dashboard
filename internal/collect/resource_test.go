package collect

import (
	"math"
	"testing"
)

const procStatFixture = `cpu  100 0 50 200 10 5 0 0 0 0
cpu0 50 0 25 100 5 3 0 0 0 0
intr 12345
ctxt 67890
btime 1700000000
processes 123
procs_running 2
`

const procMeminfoFixture = `MemTotal:       16384000 kB
MemFree:          8000000 kB
MemAvailable:    11000000 kB
Buffers:          1000000 kB
Cached:           2000000 kB
SwapTotal:        2000000 kB
SwapFree:         2000000 kB
`

const procNetDevFixture = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 100000 1000 0 0 0 0 0 0 100000 1000 0 0 0 0 0 0
  eth0: 1000000 2000 0 0 0 0 0 0 500000 1000 0 0 0 0 0 0
  eth1: 3000000 3000 0 0 0 0 0 0 4000000 4000 0 0 0 0 0 0
`

func TestParseProcStat(t *testing.T) {
	total, idle, err := ParseProcStat(procStatFixture)
	if err != nil {
		t.Fatalf("ParseProcStat 报错: %v", err)
	}
	// cpu 行合计：100+0+50+200+10+5 = 365；idle = 200+10 = 210
	if total != 365 {
		t.Errorf("total = %d, 期望 365", total)
	}
	if idle != 210 {
		t.Errorf("idle = %d, 期望 210", idle)
	}
}

func TestParseProcStatNoCPULine(t *testing.T) {
	if _, _, err := ParseProcStat("intr 123\n"); err == nil {
		t.Error("缺少 cpu 行时应报错")
	}
}

func TestParseProcStatShortLine(t *testing.T) {
	// 恰好 5 字段的畸形行（无 iowait）不应 panic。
	for _, content := range []string{"cpu 100 0 50 200\n", "cpu 1 2 3 4\n"} {
		if _, _, err := ParseProcStat(content); err == nil {
			t.Errorf("字段不足的 cpu 行应报错: %q", content)
		}
	}
}

func TestParseProcMeminfo(t *testing.T) {
	total, avail, err := ParseProcMeminfo(procMeminfoFixture)
	if err != nil {
		t.Fatalf("ParseProcMeminfo 报错: %v", err)
	}
	if total != 16384000 || avail != 11000000 {
		t.Errorf("total=%d avail=%d, 期望 16384000/11000000", total, avail)
	}
}

func TestParseProcMeminfoMissing(t *testing.T) {
	if _, _, err := ParseProcMeminfo("MemTotal: 100 kB\n"); err == nil {
		t.Error("缺少 MemAvailable 时应报错")
	}
}

func TestParseProcNetDev(t *testing.T) {
	rx, tx, err := ParseProcNetDev(procNetDevFixture)
	if err != nil {
		t.Fatalf("ParseProcNetDev 报错: %v", err)
	}
	// eth0+eth1，排除 lo：rx=1000000+3000000=4000000；tx=500000+4000000=4500000
	if rx != 4000000 {
		t.Errorf("rx = %d, 期望 4000000", rx)
	}
	if tx != 4500000 {
		t.Errorf("tx = %d, 期望 4500000", tx)
	}
}

func TestCPUPercent(t *testing.T) {
	// 前一次：total=365 idle=210；后一次：total=465 idle=212（busy +98，idle +2）
	p := cpuPercent(365, 210, 465, 212)
	want := 98.0 // 100 * (100-2)/100
	if math.Abs(p-want) > 0.001 {
		t.Errorf("cpuPercent = %v, 期望 %v", p, want)
	}
	if cpuPercent(0, 0, 0, 0) != 0 {
		t.Error("totalDelta 为 0 时应返回 0")
	}
}

func TestRate(t *testing.T) {
	if rate(1000, 2000, 2) != 500 {
		t.Error("rate 应返回差值/秒")
	}
	if rate(2000, 1000, 2) != 0 {
		t.Error("计数器回绕时应返回 0")
	}
	if rate(1000, 2000, 0) != 0 {
		t.Error("间隔为 0 时应返回 0")
	}
}
