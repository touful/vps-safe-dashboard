package conn

import (
	"errors"
	"strings"
	"testing"
)

// mockNetlinkProc 构造 /proc/net/netlink 文本（列：sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode）。
func mockNetlinkProc(rows ...string) string {
	var b strings.Builder
	b.WriteString("sk               Eth Pid        Groups   Rmem     Wmem     Dump  Locks    Drops    Inode\n")
	for _, r := range rows {
		b.WriteString(r + "\n")
	}
	return b.String()
}

// TestParseNetlinkOwn 解析过滤：协议过滤、inode 归属过滤、表头/缺列跳过、Groups/Drops 提取。
func TestParseNetlinkOwn(t *testing.T) {
	inodes := map[uint64]bool{100: true, 200: true}
	data := mockNetlinkProc(
		"ffff000000000001 12   1          00000007 0        0        0     2        0        100", // 本进程 ctnetlink，Groups=7
		"ffff000000000002 12   1          00000005 0        0        0     2        13       200", // 本进程，Groups=5，Drops=13
		"ffff000000000003 12   0          00000000 0        0        0     2        0        300", // 非本进程 inode
		"ffff000000000004 4    0          00000000 0        0        0     2        0        400", // 其他协议（Eth=4）
		"ffff000000000005 12   1          00000007",                                               // 列数不足
	)
	infos := parseNetlinkOwn(data, inodes, netlinkNetfilterProto)
	if len(infos) != 2 {
		t.Fatalf("应解析出 2 条本进程记录，实际 %d: %+v", len(infos), infos)
	}
	if infos[0].groups != 0x7 || infos[0].drops != 0 {
		t.Errorf("记录 0 解析错误: %+v", infos[0])
	}
	if infos[1].groups != 0x5 || infos[1].drops != 13 {
		t.Errorf("记录 1 解析错误: %+v", infos[1])
	}
}

// TestParseNetlinkOwnNoRows 无本进程记录（空 inode 集合）→ 空结果不崩溃。
func TestParseNetlinkOwnNoRows(t *testing.T) {
	infos := parseNetlinkOwn(mockNetlinkProc(
		"ffff000000000001 12   1          00000007 0        0        0     2        0        100",
	), map[uint64]bool{}, netlinkNetfilterProto)
	if len(infos) != 0 {
		t.Fatalf("无归属记录时应为空，实际 %d", len(infos))
	}
}

// TestVerifyGroups 订阅组位核对（核心验证逻辑）：
// 组位齐全 → nil；缺失/无记录 → errSubscriptionInvalid。
func TestVerifyGroups(t *testing.T) {
	t.Run("组位齐全", func(t *testing.T) {
		if err := verifyGroups([]netlinkOwnInfo{{groups: 0x7}}); err != nil {
			t.Errorf("Groups=7 应验证通过: %v", err)
		}
	})
	t.Run("多套接字组位合并", func(t *testing.T) {
		// 两个 socket 组位互补（OR 后齐全）→ 通过（任一订阅有效即可收到广播）。
		if err := verifyGroups([]netlinkOwnInfo{{groups: 0x5}, {groups: 0x2}}); err != nil {
			t.Errorf("组位合并后齐全应通过: %v", err)
		}
	})
	t.Run("Groups=0 订阅未生效", func(t *testing.T) {
		// 现场故障形态：唯一套接字 Groups=00000000。
		err := verifyGroups([]netlinkOwnInfo{{groups: 0x0}})
		if !errors.Is(err, errSubscriptionInvalid) {
			t.Fatalf("Groups=0 应判定订阅无效（errSubscriptionInvalid），实际: %v", err)
		}
	})
	t.Run("部分组位缺失", func(t *testing.T) {
		// 缺 UPDATE（位 1 = 0x2）。
		err := verifyGroups([]netlinkOwnInfo{{groups: 0x5}})
		if !errors.Is(err, errSubscriptionInvalid) {
			t.Fatalf("缺组位应判定无效，实际: %v", err)
		}
	})
	t.Run("无匹配套接字", func(t *testing.T) {
		err := verifyGroups(nil)
		if !errors.Is(err, errSubscriptionInvalid) {
			t.Fatalf("无套接字应判定无效，实际: %v", err)
		}
	})
}

// TestStaleVerdict 新鲜度停滞判定：
// 事件推进 → 不停滞；停滞 + 表连接数变化 → 表活跃（warn 级）；停滞 + 表无变化 → 仅停滞（info 级）。
func TestStaleVerdict(t *testing.T) {
	cases := []struct {
		name              string
		prevEvts, curEvts uint64
		prevCnt, curCnt   int64
		wantStalled       bool
		wantTableActive   bool
	}{
		{"事件推进", 10, 11, 5, 5, false, false},
		{"停滞且表活跃", 10, 10, 5, 9, true, true},
		{"停滞且表无变化", 10, 10, 5, 5, true, false},
		{"停滞且表不可读", 10, 10, -1, -1, true, false},
		{"停滞且表从不可读到可读", 10, 10, -1, 5, true, false},
		{"首次检查停滞", 0, 0, -1, 31, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stalled, tableActive := staleVerdict(c.prevEvts, c.curEvts, c.prevCnt, c.curCnt)
			if stalled != c.wantStalled || tableActive != c.wantTableActive {
				t.Errorf("staleVerdict(%d,%d,%d,%d) = (%v,%v), 期望 (%v,%v)",
					c.prevEvts, c.curEvts, c.prevCnt, c.curCnt, stalled, tableActive, c.wantStalled, c.wantTableActive)
			}
		})
	}
}

// TestConnStartErrorSubscriptionInvalid 订阅验证失败应被分类为启动类错误（外层连续计数降级）。
func TestConnStartErrorSubscriptionInvalid(t *testing.T) {
	err := &connStartError{err: verifyGroups([]netlinkOwnInfo{{groups: 0x0}})}
	var se *connStartError
	if !errors.As(err, &se) {
		t.Fatal("订阅验证失败包装后应可被 errors.As 识别为启动类错误")
	}
	if !strings.Contains(err.Error(), "订阅未生效") {
		t.Errorf("错误文案应含订阅未生效语义: %v", err)
	}
}
