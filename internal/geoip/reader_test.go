package geoip

import (
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// TestReaderLoadErrors：错误路径——文件不存在/目录路径/损坏文件均返回明确错误且 OK()=false、
// Lookup 未命中（降级不崩溃，供 API mmdb_ok=false 路径）。
func TestReaderLoadErrors(t *testing.T) {
	dir := t.TempDir()
	cases := []string{
		filepath.Join(dir, "no_such.mmdb"),          // 不存在
		dir,                                          // 目录（Open 失败）
		filepath.Join(dir, "garbage.mmdb"),           // 垃圾内容（先写后测）
	}
	if err := os.WriteFile(cases[2], []byte("not a maxmind db"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, p := range cases {
		r := NewReader(p)
		if err := r.Load(); err == nil {
			t.Errorf("%s: Load 应返回错误", p)
		}
		if r.OK() {
			t.Errorf("%s: OK() 应为 false", p)
		}
		if code, name, ok := r.Lookup(net.ParseIP("8.8.8.8")); ok || code != "" || name != "" {
			t.Errorf("%s: Lookup 应未命中（got code=%q name=%q ok=%v）", p, code, name, ok)
		}
	}
}

// TestReaderReplaceFromRollback：ReplaceFrom 在临时文件非法（无法打开）时返回错误，
// reader 保持不可用（db=nil），不残留损坏状态。
func TestReaderReplaceFromRollback(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "GeoLite2-Country.mmdb")
	r := NewReader(dbPath)
	bad := filepath.Join(dir, "bad.tmp")
	if err := os.WriteFile(bad, []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := r.ReplaceFrom(bad); err == nil {
		t.Fatal("ReplaceFrom 对非法临时文件应返回错误")
	}
	if r.OK() {
		t.Error("替换失败后 OK() 应为 false")
	}
	// 备份路径不应残留（旧库本不存在）
	if _, err := os.Stat(dbPath + ".bak"); !os.IsNotExist(err) {
		t.Error("不应产生 .bak（原库不存在）")
	}
}

// TestReaderReplaceFromNoTmp：临时文件缺失时返回错误。
func TestReaderReplaceFromNoTmp(t *testing.T) {
	r := NewReader(filepath.Join(t.TempDir(), "x.mmdb"))
	if err := r.ReplaceFrom(filepath.Join(t.TempDir(), "missing.tmp")); err == nil {
		t.Fatal("临时文件缺失应返回错误")
	}
}

// TestLookupNotLoaded：未 Load 的 Reader Lookup 未命中。
func TestLookupNotLoaded(t *testing.T) {
	r := NewReader(filepath.Join(t.TempDir(), "never.mmdb"))
	if code, name, ok := r.Lookup(net.ParseIP("1.2.3.4")); ok || code != "" || name != "" {
		t.Errorf("未加载 Lookup 应未命中（got %q %q %v）", code, name, ok)
	}
}

// TestReaderConcurrentReplace（门控 GEOIP_TEST_MMDB，本地验证用）：查询与原子替换并发——
// 验证 R-02（reviewer）修复后无 TOCTOU（Lookup 全程持读锁）。Windows 无 C 编译器无法
// 执行 -race，以结构并发替代：4 goroutine 连续 Lookup + 5 轮 ReplaceFrom，最终查询正常。
func TestReaderConcurrentReplace(t *testing.T) {
	p := os.Getenv("GEOIP_TEST_MMDB")
	if p == "" {
		t.Skip("未设置 GEOIP_TEST_MMDB，跳过并发替换验证")
	}
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "GeoLite2-Country.mmdb")
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dbPath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	r := NewReader(dbPath)
	if err := r.Load(); err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, _, _ = r.Lookup(net.ParseIP("8.8.8.8"))
			}
		}()
	}
	for i := 0; i < 5; i++ { // 5 轮原子替换（同分区 rename + 重开）
		tmp := filepath.Join(dir, "GeoLite2-Country.mmdb.tmp")
		if err := os.WriteFile(tmp, data, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := r.ReplaceFrom(tmp); err != nil {
			t.Fatalf("第 %d 轮替换失败: %v", i+1, err)
		}
	}
	close(stop)
	wg.Wait()
	code, name, ok := r.Lookup(net.ParseIP("8.8.8.8"))
	if !ok || code != "US" || name != "美国" {
		t.Errorf("并发后查询 = %q %q ok=%v, 期望 US 美国", code, name, ok)
	}
}

// TestRealMMDBSmoke：真实 GeoLite2-Country 冒烟（本地验证用）。
// 设置环境变量 GEOIP_TEST_MMDB=<mmdb 路径> 时运行（含 zh-CN 名称与 IPv4 查询）；
// CI/无库环境自动跳过。
func TestRealMMDBSmoke(t *testing.T) {
	p := os.Getenv("GEOIP_TEST_MMDB")
	if p == "" {
		t.Skip("未设置 GEOIP_TEST_MMDB，跳过真实库冒烟")
	}
	r := NewReader(p)
	if err := r.Load(); err != nil {
		t.Fatalf("Load 失败: %v", err)
	}
	if !r.OK() {
		t.Fatal("OK() = false")
	}
	cases := []struct {
		ip   string
		code string
	}{
		{"8.8.8.8", "US"},
		{"114.114.114.114", "CN"},
		{"1.1.1.1", "AU"},
	}
	for _, c := range cases {
		code, name, ok := r.Lookup(net.ParseIP(c.ip))
		if !ok || code != c.code {
			t.Errorf("%s: code=%q ok=%v, 期望 %s", c.ip, code, ok, c.code)
		}
		if name == "" {
			t.Errorf("%s: name 为空", c.ip)
		}
		t.Logf("%s → %s %s", c.ip, code, name)
	}
	// 内网地址未命中（ok=false）
	if code, name, ok := r.Lookup(net.ParseIP("192.168.1.1")); ok || code != "" || name != "" {
		t.Errorf("内网地址应未命中（got %q %q %v）", code, name, ok)
	}
}
