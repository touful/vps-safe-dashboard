package geoip

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/oschwald/maxminddb-golang"

	"sentry-agent/internal/event"
)

// defaultUpdateURL MaxMind GeoLite2-Country 下载地址（HTTP Basic Auth：account_id:license_key）。
const defaultUpdateURL = "https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz"

// probeIP 新库校验用测试 IP（Google DNS，GeoLite2-Country 必然收录）。
const probeIP = "8.8.8.8"

// UpdateCfg 更新配置（来自 config.geoip 段；凭据仅存配置，代码零硬编码）。
type UpdateCfg struct {
	DBPath     string
	AccountID  string
	LicenseKey string
	Enabled    bool
	Hour       int // 每日执行时刻（UTC 时）
	Minute     int
}

// updateState 本地更新状态（db_path + ".state"）：上次响应头的 ETag/Last-Modified 用于条件请求。
type updateState struct {
	ETag         string `json:"etag"`
	LastModified string `json:"last_modified"`
	UpdatedAt    string `json:"updated_at"`
}

// Updater 每日更新器。失败不崩溃（system_event 留痕 + 下轮重试）。
type Updater struct {
	cfg        UpdateCfg
	reader     *Reader
	sys        chan<- event.SystemEvent
	rep        *event.RateLimiter // 留痕限频（下载失败等告警 1/小时，避免网络故障刷屏）
	httpCl     *http.Client
	updateURL  string  // 下载地址（默认 MaxMind；测试注入 mock）
	lastRunDay int     // 当日已执行标记（UTC 日期），防同日内重复触发
}

// NewUpdater 创建更新器。sys 可为 nil（测试/未注入场景静默）。
func NewUpdater(cfg UpdateCfg, reader *Reader, sys chan<- event.SystemEvent) *Updater {
	return &Updater{
		cfg: cfg, reader: reader, sys: sys,
		rep:       event.NewRateLimiter(time.Hour),
		httpCl:    &http.Client{Timeout: 5 * time.Minute},
		updateURL: defaultUpdateURL,
	}
}

// Run 常驻循环：启动时若基础库缺失且凭据齐全 → 立即拉取一次；此后每日
// cfg.Hour:cfg.Minute（UTC）执行一次。失败仅留痕，不退出（下次自动重试）。
func (u *Updater) Run(ctx context.Context) {
	if u.cfg.Enabled && u.cfg.AccountID != "" && u.cfg.LicenseKey != "" {
		if _, err := os.Stat(u.cfg.DBPath); errors.Is(err, os.ErrNotExist) {
			event.ReportSys(u.sys, "geoip", "info", "GeoIP 基础库缺失，启动时立即拉取")
			if err := u.UpdateNow(ctx); err != nil {
				u.rep.Report(u.sys, "geoip", "warn", "GeoIP 启动拉取失败: "+err.Error())
			}
		}
	}
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !u.cfg.Enabled || u.cfg.AccountID == "" || u.cfg.LicenseKey == "" {
				continue
			}
			now := time.Now().UTC()
			if now.Hour() == u.cfg.Hour && now.Minute() == u.cfg.Minute && u.lastRunDay != now.YearDay() {
				u.lastRunDay = now.YearDay()
				if err := u.UpdateNow(ctx); err != nil {
					u.rep.Report(u.sys, "geoip", "warn", "GeoIP 每日更新失败: "+err.Error())
				}
			}
		}
	}
}

// UpdateNow 执行单次更新（可独立调用/测试）。
// 流程：条件 GET（ETag/Last-Modified）→ 304 跳过；200 → 解压 → 校验 → 原子替换 → 记录状态。
// 错误文案不含凭据（Basic Auth 由 http 库管理，错误信息不携带 Authorization 头）。
func (u *Updater) UpdateNow(ctx context.Context) error {
	if !u.cfg.Enabled {
		return nil
	}
	if u.cfg.AccountID == "" || u.cfg.LicenseKey == "" {
		return errors.New("未配置 MaxMind account_id/license_key，跳过更新（部署时在 deploy/config.json 填写）")
	}
	st := u.loadState()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.updateURL, nil)
	if err != nil {
		return fmt.Errorf("构造下载请求失败: %w", err)
	}
	req.SetBasicAuth(u.cfg.AccountID, u.cfg.LicenseKey)
	req.Header.Set("User-Agent", "sentry-agent-geoip/1.0")
	if st.ETag != "" {
		req.Header.Set("If-None-Match", st.ETag)
	}
	if st.LastModified != "" {
		req.Header.Set("If-Modified-Since", st.LastModified)
	}
	resp, err := u.httpCl.Do(req)
	if err != nil {
		return fmt.Errorf("下载请求失败: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil // 服务端无更新，跳过
	case http.StatusOK:
		// 继续下载
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("MaxMind 鉴权失败（HTTP %d）：请检查 geoip.account_id/license_key", resp.StatusCode)
	default:
		return fmt.Errorf("MaxMind 下载失败（HTTP %d）", resp.StatusCode)
	}
	// 200MB 上限防御（正常 tar.gz 约 6-10MB；防御异常响应撑爆内存）
	body, err := io.ReadAll(io.LimitReader(resp.Body, 200<<20))
	if err != nil {
		return fmt.Errorf("读取下载内容失败: %w", err)
	}
	mmdbData, err := extractMMDB(body)
	if err != nil {
		return fmt.Errorf("解压失败: %w", err)
	}
	if err := u.install(mmdbData); err != nil {
		return err
	}
	st.ETag = resp.Header.Get("ETag")
	st.LastModified = resp.Header.Get("Last-Modified")
	st.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	u.saveState(st)
	event.ReportSys(u.sys, "geoip", "info", "GeoIP 基础库更新完成（"+u.cfg.DBPath+"）")
	return nil
}

// install 写临时文件 → 校验（打开 + 测试 IP 查询）→ 原子替换。
func (u *Updater) install(data []byte) error {
	dir := filepath.Dir(u.cfg.DBPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("创建库目录失败: %w", err)
	}
	tmp := u.cfg.DBPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("写入临时文件失败: %w", err)
	}
	defer os.Remove(tmp) // 替换成功后 tmp 已被 rename 移走，Remove 幂等
	probe, err := maxminddb.Open(tmp)
	if err != nil {
		return fmt.Errorf("新库校验失败（无法打开）: %w", err)
	}
	var rec struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	if err := probe.Lookup(net.ParseIP(probeIP), &rec); err != nil || rec.Country.ISOCode == "" {
		_ = probe.Close()
		return errors.New("新库校验失败（测试 IP 查询未命中）")
	}
	_ = probe.Close()
	if err := u.reader.ReplaceFrom(tmp); err != nil {
		return err
	}
	return nil
}

// extractMMDB 从 tar.gz 中提取 GeoLite2-Country.mmdb 内容（文件名匹配，忽略目录前缀）。
func extractMMDB(gz []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if filepath.Base(hdr.Name) == "GeoLite2-Country.mmdb" {
			return io.ReadAll(io.LimitReader(tr, 500<<20)) // 单文件 500MB 上限防御
		}
	}
	return nil, errors.New("压缩包内未找到 GeoLite2-Country.mmdb")
}

// stateFile 状态文件路径（与库同目录：<db_path>.state）。
func (u *Updater) stateFile() string { return u.cfg.DBPath + ".state" }

func (u *Updater) loadState() updateState {
	var st updateState
	data, err := os.ReadFile(u.stateFile())
	if err != nil {
		return st
	}
	_ = json.Unmarshal(data, &st) // 状态文件损坏视为无状态（下次全量下载）
	return st
}

func (u *Updater) saveState(st updateState) {
	data, err := json.Marshal(st)
	if err != nil {
		return
	}
	_ = os.WriteFile(u.stateFile(), data, 0o644)
}
