# 归档工具（docs/verification/tools/）

已归档的手动/一次性验证工具。均不在日常部署与运行链路中使用；保留供复现历史验证结论或特殊场景备用。

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
