//go:build linux

package fw

import (
	"context"
	"fmt"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// kmsgReadLoop 读取 /dev/kmsg 消息并逐条回调（Linux 实现）。
//
// 防重放（tester D-07 / auditor m-03）：/dev/kmsg 每次 open 从环形缓冲头部读取；
// 本实现以 O_NONBLOCK 打开后先排空历史到 EAGAIN（当前尾部），仅回调之后的实时消息——
// 语义等价于 "dmesg -w --since 启动时刻"，保证注入 N 条仅产出 N 条。
//
// 排空窗口竞态防御（reviewer R-02）：排空阶段记录最后一条已读消息的 SEQUENCE（drainSeq），
// 实时阶段解析每条消息 SEQUENCE 并跳过 SEQUENCE <= drainSeq 的消息——
// 防御目标：多读者消费 / 内核 seq 行为差异（单读者 + 单调 seq 下该条件理论不可达，
// 属防御性冗余，防内核行为变化时静默重放）。
//
// 可取消读（tester D-08）：非阻塞读 + 100ms 轮询，ctx 取消可在 EAGAIN 等待期及时退出。
//
// 记录格式：PRIORITY,SEQUENCE,TIMESTAMP,FLAGS;MESSAGE（read 返回单条记录，以 \0 结尾）。
// 时间戳口径（reviewer R-11）：kmsg 头部的 TIMESTAMP 为内核单调时间（boot time），
// 与 Unix 时间不可直接换算；M2 采用接收时刻（time.Now）近似，事件注释已说明。
func kmsgReadLoop(ctx context.Context, onLine func(string)) error {
	fd, err := unix.Open("/dev/kmsg", unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("打开 /dev/kmsg 失败: %w", err)
	}
	defer unix.Close(fd)

	buf := make([]byte, 64*1024)
	var drainSeq uint64 // 排空阶段最后一条已读消息的 SEQUENCE
	// 阶段一：排空历史（读至 EAGAIN），记录最后 SEQUENCE。
	// A-04（auditor Note）：排空循环定期检查 ctx——环形缓冲较大时排空可能耗时，
	// 必须可被取消（避免退出时排空循环阻塞 5s 兜底超时）。
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		n, err := unix.Read(fd, buf)
		if err == unix.EAGAIN {
			break // 已到当前尾部
		}
		if err != nil {
			return fmt.Errorf("排空 /dev/kmsg 历史失败: %w", err)
		}
		if seq, ok := kmsgSeq(buf[:n]); ok {
			drainSeq = seq
		}
	}

	// 阶段二：循环读取实时消息（SEQUENCE > drainSeq 才回调）。
	for {
		n, err := unix.Read(fd, buf)
		if err == unix.EAGAIN {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(100 * time.Millisecond):
			}
			continue
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("kmsg 读取失败: %w", err)
		}
		raw := buf[:n]
		seq, ok := kmsgSeq(raw)
		if ok && seq <= drainSeq {
			continue // 排空窗口内的消息（防御性跳过）
		}
		line := string(raw)
		line = strings.TrimRight(line, "\x00\n") // read 返回的记录以 \0 结尾
		if idx := strings.IndexByte(line, ';'); idx >= 0 {
			line = line[idx+1:] // 剥离 PRIORITY,SEQ,TIMESTAMP,FLAGS 元数据
		}
		onLine(line)
	}
}

// kmsgSeq 解析 /dev/kmsg 记录的 SEQUENCE 字段（格式：PRIORITY,SEQUENCE,TIMESTAMP,FLAGS;...）。
func kmsgSeq(record []byte) (uint64, bool) {
	// 跳过 PRIORITY。
	i := 0
	for i < len(record) && record[i] != ',' {
		i++
	}
	if i >= len(record) {
		return 0, false
	}
	i++ // 跳过逗号
	var seq uint64
	digits := 0
	for i < len(record) && record[i] != ',' {
		if record[i] < '0' || record[i] > '9' {
			return 0, false
		}
		seq = seq*10 + uint64(record[i]-'0')
		digits++
		i++
	}
	if digits == 0 {
		return 0, false
	}
	return seq, true
}
