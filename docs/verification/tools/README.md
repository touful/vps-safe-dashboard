# 归档工具（docs/verification/tools/）

已归档的手动/一次性验证工具。均不在日常部署与运行链路中使用；保留供复现历史验证结论或特殊场景备用。

## 前端视觉回归（2026-09-08）

[frontend_visual_check.py](frontend_visual_check.py) 使用原生 Python Playwright 与 Chromium 检查本地静态前端。`--serve` 临时启动仅监听 `127.0.0.1:18765` 的静态服务器及 WebSocket 握手，结束后关闭；API 由浏览器路由返回受控示例，不读取数据库、不启动采集器、不连接生产服务。预览使用与正式静态 Handler 一致的 CSP。

在项目根目录执行：

```powershell
& 'D:\software\program\miniconda\envs\py312\python.exe' docs/verification/tools/frontend_visual_check.py --serve
```

前提：Python 环境内已安装 Playwright 及 Chromium。默认输出至 Git 忽略的 `.dev-fe-test/`，包含结果 JSON 和总览、连接、攻击、导出、移动端截图；可用 `--output` 指定任务专用输出目录。`--base-url` 用于连接已启动的测试服务器，不能指向生产站点。不要在同一端口并行启动多个预览。

覆盖：四页 × 10 档宽度（320～1920px）、页签与焦点、图表呈现、折叠、密码遮蔽、IP 画像、时间范围、端口 / 国家过滤、CSV 下载、空态与 503 失败态。结果不代表生产数据准确性、真实 WS 数据帧回归、完整读屏测试或持续性能测试。

本次记录见 [FE-20260908_视觉升级验证.md](../FE-20260908_视觉升级验证.md)。

## 1. TEST-HONEY-001 蜜罐治理证据脚本（2026-09 从 scripts/ 归档）

| 脚本 | 来源 | 用途 |
| :--- | :--- | :--- |
| `honeypot_concurrency.py` | TEST-HONEY-001 reviewer R-02 整改 | 并发 200 上限真实测试：205 个独立 loopback 源 IP 各 1 连接同时活跃，验证 maxConns=200 上限（预期 accepted=200 + rejected=5） |
| `honeypot_governance2.py` | TEST-HONEY-001 连接治理实测 v2 | 限速（10 连接/分/IP）+ 30s 超时判定：限速拒绝 = accept 后立即 Close（客户端 recv 立即 EOF）；正常接受 = 服务端等待数据（recv 超时或收到协议数据） |
| `honeypot_malformed.py` | TEST-HONEY-001 reviewer R-01 整改 | 畸形输入鲁棒性测试 v2：46 用例，每用例绑定独立 loopback 源 IP 绕过每 IP 限速；已接受连接 2s 内被关闭 = 解析器快速失败（期望），超 2s 无响应 = HANG（缺陷） |

**复跑前提（重要）**：三个脚本依赖 `honeypot_test_config.json`（蜜罐专用测试配置，health 端口 18099、蜜罐端口按协议映射：mysql 13306 / redis 16379 / memcached 11212 / mssql 11433 / mongodb 17017 / postgres 15432 / rdp 13389 / smb 1445 / telnet 10023 / ftp 10021；脚本头注释为端口口径单一来源）。该配置文件**未随档**——需按脚本头注释自行重建后方可复跑；不要假定仓库中存在。

**对应验证报告**：[TEST-HONEY-001_回归报告.md](../TEST-HONEY-001_回归报告.md)（DEV-HONEY-001/002 蜜罐凭据捕获回归，基线 `dfb64f4`；原始执行证据见 `evidence/` 相关目录）。TEST-HONEY-001 的回归结论已由 [TEST-HONEY-002_回归报告.md](../TEST-HONEY-002_回归报告.md) 后续覆盖验证。

## 2. GeoLite2 手动下载脚本（2026-09 从 deploy/ 归档）

| 脚本 | 原位置 | 保留场景 |
| :--- | :--- | :--- |
| `fetch_geolite2.sh` | `deploy/fetch_geolite2.sh` | 无网络出站 VPS 的离线预置（本地下载后上传）或手动强制刷新 GeoLite2-Country 库 |

**日常不需要**：库更新由 agent 内置 geoip updater 自动完成（启动缺库即拉取 + 每日 ETag/Last-Modified 条件请求检查 + 8.8.8.8 探针校验 + 热替换，见 `internal/geoip/updater.go`——与本脚本同一下载通道：MaxMind Basic Auth + 解压 + 同分区原子替换）。归档原因：双下载通道重复维护，updater 功能为严格超集。

**对应文档**：部署手册 `docs/M4_部署手册.md` §DEV-GEO-001 升级说明②；验证记录 [TEST-GEO-001_回归报告.md](../TEST-GEO-001_回归报告.md)（其中引用的 `deploy/fetch_geolite2.sh` 为归档前路径口径，报告为历史证据保持原样）。
