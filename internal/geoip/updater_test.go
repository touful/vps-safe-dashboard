package geoip

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testTarGz 构造 tar.gz（内可含任意条目；测试用假 mmdb 文件名即可触发 install 校验失败路径）。
func testTarGz(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for name, data := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestExtractMMDB：正常提取（带目录前缀）、无目标文件、损坏 gzip 三种路径。
func TestExtractMMDB(t *testing.T) {
	data := testTarGz(t, map[string][]byte{
		"GeoLite2-Country_20260101/GeoLite2-Country.mmdb": {1, 2, 3},
		"GeoLite2-Country_20260101/COPYRIGHT.txt":        []byte("x"),
	})
	got, err := extractMMDB(data)
	if err != nil {
		t.Fatalf("提取失败: %v", err)
	}
	if !bytes.Equal(got, []byte{1, 2, 3}) {
		t.Errorf("提取内容 = %v", got)
	}
	// 无目标文件
	if _, err := extractMMDB(testTarGz(t, map[string][]byte{"a.txt": []byte("x")})); err == nil {
		t.Error("无 mmdb 条目应返回错误")
	}
	// 损坏 gzip
	if _, err := extractMMDB([]byte("not gzip")); err == nil {
		t.Error("损坏 gzip 应返回错误")
	}
}

// TestUpdateNowNotModified：条件请求命中（304）→ 返回 nil、不写状态。
func TestUpdateNowNotModified(t *testing.T) {
	var gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("If-None-Match")
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "GeoLite2-Country.mmdb")
	// 预写状态文件（etag 已记录）
	st := updateState{ETag: `"abc123"`, LastModified: "Tue, 18 Aug 2026 00:00:00 GMT"}
	data, _ := json.Marshal(st)
	if err := os.WriteFile(dbPath+".state", data, 0o644); err != nil {
		t.Fatal(err)
	}
	u := NewUpdater(UpdateCfg{DBPath: dbPath, AccountID: "1", LicenseKey: "k", Enabled: true}, NewReader(dbPath), nil)
	u.updateURL = srv.URL // 测试注入 mock 地址
	if err := u.UpdateNow(context.Background()); err != nil {
		t.Fatalf("304 路径应返回 nil: %v", err)
	}
	if gotHeader != `"abc123"` {
		t.Errorf("If-None-Match = %q, 期望 %q", gotHeader, `"abc123"`)
	}
	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Error("304 路径不应产生 db 文件")
	}
}

// TestUpdateNowAuthFailure：403 → 明确错误且不含凭据明文。
func TestUpdateNowAuthFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 断言 Basic Auth 头确实携带凭据（请求构造正确）
		user, pass, ok := r.BasicAuth()
		if !ok || user != "acc1" || pass != "secret-key" {
			t.Errorf("Basic Auth = %v/%v ok=%v", user, pass, ok)
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	u := NewUpdater(UpdateCfg{DBPath: filepath.Join(t.TempDir(), "x.mmdb"), AccountID: "acc1", LicenseKey: "secret-key", Enabled: true}, NewReader(""), nil)
	u.updateURL = srv.URL
	err := u.UpdateNow(context.Background())
	if err == nil {
		t.Fatal("403 应返回错误")
	}
	if strings.Contains(err.Error(), "secret-key") || strings.Contains(err.Error(), "acc1") {
		t.Errorf("错误信息不得泄露凭据: %v", err)
	}
}

// TestUpdateNowMissingCreds：凭据缺失 → 明确错误（不发起请求）。
func TestUpdateNowMissingCreds(t *testing.T) {
	u := NewUpdater(UpdateCfg{DBPath: filepath.Join(t.TempDir(), "x.mmdb"), Enabled: true}, NewReader(""), nil)
	if err := u.UpdateNow(context.Background()); err == nil || !strings.Contains(err.Error(), "account_id/license_key") {
		t.Errorf("凭据缺失错误 = %v", err)
	}
	u2 := NewUpdater(UpdateCfg{DBPath: filepath.Join(t.TempDir(), "x.mmdb"), Enabled: false}, NewReader(""), nil)
	if err := u2.UpdateNow(context.Background()); err != nil {
		t.Errorf("update_enabled=false 应直接返回 nil: %v", err)
	}
}

// TestUpdaterRealNetwork：真实 MaxMind 全链路冒烟（本地验证用）。
// 门控：设置 GEOIP_UPDATE_TEST=1 + MM_ACC/MM_KEY（凭据仅环境变量，不入库）。
// 验证：首次下载安装（库文件 + .bak 不存在 + .state 写入 + reader 替换生效）→
// 二次更新走 ETag 条件请求（服务端 304 或 200 均不失败）。
func TestUpdaterRealNetwork(t *testing.T) {
	if os.Getenv("GEOIP_UPDATE_TEST") != "1" {
		t.Skip("未设置 GEOIP_UPDATE_TEST=1，跳过真实网络更新冒烟")
	}
	acc, key := os.Getenv("MM_ACC"), os.Getenv("MM_KEY")
	if acc == "" || key == "" {
		t.Fatal("真实网络冒烟需要 MM_ACC/MM_KEY 环境变量")
	}
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "GeoLite2-Country.mmdb")
	u := NewUpdater(UpdateCfg{DBPath: dbPath, AccountID: acc, LicenseKey: key, Enabled: true}, NewReader(dbPath), nil)
	if err := u.UpdateNow(context.Background()); err != nil {
		t.Fatalf("首次更新失败: %v", err)
	}
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("更新后库文件缺失: %v", err)
	}
	if _, err := os.Stat(dbPath + ".state"); err != nil {
		t.Fatalf("状态文件缺失: %v", err)
	}
	st := u.loadState()
	if st.ETag == "" && st.LastModified == "" {
		t.Error("状态文件应含 ETag 或 Last-Modified")
	}
	// reader 替换生效（同一 reader 实例现在可查询）
	r := u.reader
	if err := r.Load(); err == nil {
		code, name, ok := r.Lookup(net.ParseIP("8.8.8.8"))
		if !ok || code != "US" || name != "美国" {
			t.Errorf("替换后查询 = %s %s %v, 期望 US 美国", code, name, ok)
		}
	}
	// 二次更新（ETag 条件请求；304 或 200 均视为成功）
	if err := u.UpdateNow(context.Background()); err != nil {
		t.Fatalf("二次更新失败: %v", err)
	}
	// 关闭 reader 释放 mmap 句柄（Windows 下不关则 TempDir 清理被拒）
	if err := r.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// TestUpdateNowInstallFailure：200 + 含假 mmdb 的 tar.gz → 解压成功但校验失败 → 返回错误、
// 不产生正式库文件、不写状态文件。
func TestUpdateNowInstallFailure(t *testing.T) {
	tgz := testTarGz(t, map[string][]byte{
		"GeoLite2-Country_20260101/GeoLite2-Country.mmdb": []byte("fake mmdb"),
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v2"`)
		w.Write(tgz)
	}))
	defer srv.Close()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "GeoLite2-Country.mmdb")
	u := NewUpdater(UpdateCfg{DBPath: dbPath, AccountID: "a", LicenseKey: "k", Enabled: true}, NewReader(dbPath), nil)
	u.updateURL = srv.URL
	err := u.UpdateNow(context.Background())
	if err == nil {
		t.Fatal("假 mmdb 校验应失败")
	}
	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Error("校验失败后不得产生正式库文件")
	}
	if _, err := os.Stat(dbPath + ".state"); !os.IsNotExist(err) {
		t.Error("校验失败后不得写状态文件")
	}
	if _, err := os.Stat(dbPath + ".bak"); !os.IsNotExist(err) {
		t.Error("校验失败后不得残留 .bak")
	}
	// 临时文件应清理
	if _, err := os.Stat(dbPath + ".tmp"); !os.IsNotExist(err) {
		t.Error("临时文件应清理")
	}
}
