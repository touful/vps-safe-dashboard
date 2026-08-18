package store

import (
	"context"
	"database/sql"
	"sync"
	"testing"
	"time"

	"sentry-agent/internal/event"
)

// TestCredSchema 蜜罐凭据表结构与索引（DEV-HONEY-001）。
func TestCredSchema(t *testing.T) {
	ch := event.NewChannels(16)
	st := newTestStore(t, ch, &sync.WaitGroup{})
	defer st.Close()

	var name string
	if err := st.db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='cred_events'`).Scan(&name); err != nil {
		t.Fatalf("cred_events 表不存在: %v", err)
	}
	for _, idx := range []string{"idx_cred_ts", "idx_cred_src", "idx_cred_proto"} {
		var n string
		if err := st.db.QueryRow(`SELECT name FROM sqlite_master WHERE type='index' AND name=?`, idx).Scan(&n); err != nil {
			t.Errorf("索引 %s 不存在: %v", idx, err)
		}
	}
}

// TestWriteBatchCred 蜜罐凭据批量落库（字段完整性 + 明文密码仅本地存储语义）。
func TestWriteBatchCred(t *testing.T) {
	ch := event.NewChannels(16)
	st := newTestStore(t, ch, &sync.WaitGroup{})
	defer st.Close()

	items := []eventItem{
		{kind: "cred", v: event.CredEvent{TS: 200, Proto: "telnet", SrcIP: 0xCB007105, Username: "root", Password: "toor123", Extra: ""}},
		{kind: "cred", v: event.CredEvent{TS: 201, Proto: "mysql", SrcIP: 0xCB007106, Username: "admin", Password: "d41d8cd98f00b204e9800998ecf8427e", Extra: "密码 hash（mysql_native_password），不可逆"}},
		{kind: "cred", v: event.CredEvent{TS: 202, Proto: "memcached", SrcIP: 0xCB007107, Username: "", Password: "", Extra: "协议无认证机制，仅命令概览"}},
	}
	if err := st.writeBatch(items); err != nil {
		t.Fatalf("writeBatch 失败: %v", err)
	}

	var n int64
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM cred_events`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("cred_events 行数 = %d, 期望 3", n)
	}
	// 字段回读校验（含敏感字段明文存储——本地单机定位，代码注释标注）。
	var ts int64
	var proto, username, password, extra string
	var srcIP int64
	if err := st.db.QueryRow(`SELECT ts, proto, src_ip, username, password, extra FROM cred_events WHERE ts=200`).
		Scan(&ts, &proto, &srcIP, &username, &password, &extra); err != nil {
		t.Fatal(err)
	}
	if ts != 200 || proto != "telnet" || srcIP != 0xCB007105 || username != "root" || password != "toor123" {
		t.Errorf("行回读不符: ts=%d proto=%s src=%d user=%s pass=%s", ts, proto, srcIP, username, password)
	}
}

// TestCredChannelDrain 蜜罐凭据经通道排空落库（Run 排空语义：cred 通道不丢事件）。
func TestCredChannelDrain(t *testing.T) {
	ch := event.NewChannels(16)
	producers := &sync.WaitGroup{}
	dir := t.TempDir()
	st, err := NewStore(dir+"/state.db", dir+"/archive", 500, 10, 6, 7, 60, 90, ch, producers)
	if err != nil {
		t.Fatalf("NewStore 失败: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		if err := st.Run(ctx); err != nil {
			t.Errorf("Run 失败: %v", err)
		}
		_ = st.Close()
	}()

	// 模拟蜜罐 producer：发送后退出（producer 协议：Wait 后进入排空阶段）。
	producers.Add(1)
	go func() {
		defer producers.Done()
		ch.Cred <- event.CredEvent{TS: 300, Proto: "redis", SrcIP: 0xCB007108, Username: "default", Password: "secret", Extra: ""}
		ch.Cred <- event.CredEvent{TS: 301, Proto: "ftp", SrcIP: 0xCB007109, Username: "ftpuser", Password: "ftp123", Extra: ""}
		time.Sleep(150 * time.Millisecond) // 在途窗口（cancel 后仍未 Done）
	}()

	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case <-runDone:
	case <-time.After(10 * time.Second):
		t.Fatal("Store.Run 未在超时内退出（疑似死锁）")
	}

	// Run 返回后 st.db 已关闭（Run 内 defer 关闭）——独立只读打开验证落库。
	db, err := sql.Open("sqlite", "file:"+dir+"/state.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int64
	if err := db.QueryRow(`SELECT COUNT(*) FROM cred_events`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("cred_events 排空后行数 = %d, 期望 2", n)
	}
}
