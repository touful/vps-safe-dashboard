// Package geoip 实现 GeoLite2-Country.mmdb 离线查询与每日更新（DEV-GEO-001）。
// 查询：IPv4 → country iso_code + 中文名（country.names 含 zh-CN 时优先，否则回退 en）；
// 未配置/未命中返回 ok=false（API 层降级为 Unknown）。
// 更新：MaxMind 下载（HTTP Basic Auth + ETag/Last-Modified 条件请求）→ tar.gz 解压 →
// 校验（打开新库 + 测试 IP 查询）→ 原子替换（临时文件 + rename + .bak 备份）。
// 凭据安全：account_id/license_key 仅来自配置（部署时填入 deploy/config.json），代码零硬编码；
// 更新失败的错误文案不打印凭据。
package geoip

import (
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/oschwald/maxminddb-golang"
)

// Reader 封装 mmdb 查询。文件缺失/损坏时 db 为 nil（OK()=false），调用方降级处理，不崩溃。
// 并发安全：查询持读锁；updater 原子替换持写锁（替换前须先关闭旧 reader 释放文件句柄，
// Windows 下 rename 已打开文件会失败——跨平台统一采用"先关旧、再 rename、后开新"顺序）。
type Reader struct {
	mu   sync.RWMutex
	db   *maxminddb.Reader
	path string
}

// NewReader 创建 Reader 实例（无论文件是否存在均不失败；加载结果经 Load/OK 判定）。
func NewReader(dbPath string) *Reader {
	return &Reader{path: dbPath}
}

// Load 打开 mmdb。文件不存在/损坏返回明确错误（含路径）；已加载时先关闭旧库重开。
// 失败后 db 保持 nil，后续 OK()=false、Lookup 返回未命中——调用方可继续运行。
func (r *Reader) Load() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.db != nil {
		_ = r.db.Close()
		r.db = nil
	}
	db, err := maxminddb.Open(r.path)
	if err != nil {
		return fmt.Errorf("GeoIP 库打开失败（路径 %s）: %w", r.path, err)
	}
	r.db = db
	return nil
}

// OK 返回 mmdb 是否可用（已成功加载）。
func (r *Reader) OK() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.db != nil
}

// Lookup 查询 IPv4 地址对应的国家 ISO code 与名称（zh-CN 优先，回退 en）。
// country 字段缺失时回退 registered_country（MaxMind GeoLite2-Country 语义：
// 未分配位置属性的 IP（如 anycast DNS）仅有注册国——如 1.1.1.1 → AU）。
// ok=false 表示未配置/未命中/查询失败；code/name 为空。
// 并发安全：整个查询持读锁（R-02（reviewer）：db.Lookup 须在 RLock 内执行，
// 否则与 ReplaceFrom 的 Close 存在 TOCTOU——查询仅 µs 级，替换阻塞可忽略）。
func (r *Reader) Lookup(ip net.IP) (code, name string, ok bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.db == nil {
		return "", "", false
	}
	var rec struct {
		Country struct {
			ISOCode string            `maxminddb:"iso_code"`
			Names   map[string]string `maxminddb:"names"`
		} `maxminddb:"country"`
		RegisteredCountry struct {
			ISOCode string            `maxminddb:"iso_code"`
			Names   map[string]string `maxminddb:"names"`
		} `maxminddb:"registered_country"`
	}
	if err := r.db.Lookup(ip, &rec); err != nil {
		return "", "", false
	}
	code = rec.Country.ISOCode
	names := rec.Country.Names
	if code == "" { // 回退注册国
		code = rec.RegisteredCountry.ISOCode
		names = rec.RegisteredCountry.Names
	}
	if code == "" {
		return "", "", false
	}
	name = names["zh-CN"]
	if name == "" {
		name = names["en"]
	}
	return code, name, true
}

// ReplaceFrom 用已校验通过的临时文件原子替换当前 mmdb（updater 安装流程专用）。
// 步骤：关闭旧库 → 旧文件改名 .bak → 临时文件 rename 为正式路径 → 重新打开。
// 任一步失败尽力回滚（rename 回退/从 .bak 恢复），返回错误供留痕。
func (r *Reader) ReplaceFrom(tmpPath string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.db != nil {
		_ = r.db.Close()
		r.db = nil
	}
	bak := r.path + ".bak"
	if _, err := os.Stat(r.path); err == nil {
		if err := os.Rename(r.path, bak); err != nil {
			return fmt.Errorf("备份旧库失败: %w", err)
		}
	}
	if err := os.Rename(tmpPath, r.path); err != nil {
		if _, err2 := os.Stat(bak); err2 == nil {
			_ = os.Rename(bak, r.path) // 尽力恢复旧库
		}
		return fmt.Errorf("替换新库失败: %w", err)
	}
	db, err := maxminddb.Open(r.path)
	if err != nil {
		// 新库打开失败：尝试从 .bak 恢复（校验已通过，理论路径，兜底保数据）
		if _, err2 := os.Stat(bak); err2 == nil {
			_ = os.Rename(bak, r.path)
			if db2, err3 := maxminddb.Open(r.path); err3 == nil {
				r.db = db2
			}
		}
		return fmt.Errorf("打开新库失败: %w", err)
	}
	r.db = db
	return nil
}

// Close 关闭 mmdb（释放文件句柄）。
func (r *Reader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.db == nil {
		return nil
	}
	err := r.db.Close()
	r.db = nil
	return err
}
