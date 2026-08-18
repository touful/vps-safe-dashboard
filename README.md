# sentry-agent：轻量化 VPS 安全态势感知面板

单进程 Go 二进制，面向 1 核 1GB 低配 VPS：全量采集连接、SSH、防火墙、fail2ban 与资源指标，SQLite 本地持久化，Web 面板（纯原生 JS + ECharts，零 CDN）实时展示攻击态势。**只记录、不过滤、不耗资源**。

## 核心特性

- **五通道采集，事件驱动优先**：资源（5s 轮询 /proc）、连接（conntrack 事件流 + ss 快照兜底）、SSH 登录尝试（journald/rsyslog 流式解析，VERBOSE 指纹）、防火墙日志（nftables/iptables LOG 解析，限速采样）、fail2ban 封禁记录（日志/数据库双源）。
- **蜜罐凭据捕获（DEV-HONEY-001）**：对 mysql/redis/memcached/mssql/mongodb/postgres/rdp/smb/telnet/ftp 十种协议标准端口提供最小认证握手模拟，捕获攻击者尝试登录的用户名/密码（明文协议完整捕获，加密/哈希协议捕获不可逆摘要并如实标注）；不执行任何命令、不返回真实系统信息；连接治理严格（超时/并发上限/每 IP 限速）；凭据仅本地存储，前端默认遮蔽展示。
- **只记录不预判**：所有数据源全量采集入库，采集路径不做业务级丢弃；过滤仅在展示层（面板查询参数）进行。
- **攻击态势聚合现有防护日志**：SSH 失败 / 防火墙 drop / fail2ban 封禁 / 磁盘水位四维风险评分 + 态势结论条，不引入重型检测引擎。
- **SQLite WAL 持久化**：单写线程 + 批量事务，synchronous=NORMAL；主库永久保留，gzip 归档对抗磁盘增长。
- **Web 面板**：四页签（总览/连接/攻击/导出）、KPI 卡、风险评分环形仪表、攻击双通道趋势、TOP 攻击源/端口、全球攻击地图（GeoIP）、协议凭据捕获表（密码遮蔽点击显示）、明细表（排序/过滤/联动）、时间范围切换（1h/24h/7d/30d）、WS 实时推送 + 轮询兜底。
- **轻量化硬约束**：采集端常驻 CPU < 1%~2%、内存 < 100MB（按 1C1G 最低配设计）。

## 架构概览

Go 单进程（`sentry-agent`）：各采集通道以协程组织，统一写入 SQLite（WAL），对外提供 17 个只读 HTTP API（含 /api/v1/export/csv 数据导出与 /api/v1/honeypot/events 蜜罐凭据查询）+ 1 个 WebSocket 实时通道；前端为内嵌静态文件（index.html + app.js + 本地 echarts.min.js，零 CDN、零外部资源）。

```
采集通道（资源/连接/SSH/防火墙/fail2ban/蜜罐）
        │ 事件驱动（conntrack/journald 流式）+ 资源 5s 轮询 + 蜜罐握手捕获
        ▼
SQLite WAL（单写线程 + 批量事务）──► 归档（gzip，可配）
        │
        ▼
HTTP API（17 只读端点）+ WS 实时推送 ──► 前端面板（原生 JS + ECharts）
```

外部组件仅限系统既有服务（journald/rsyslog、fail2ban、nftables/iptables），均位于宿主机；容器以只读挂载方式访问其数据。详细设计见 `docs/技术方案.md`。

## 目录结构

```
├── cmd/sentry-agent/      主程序入口（main.go + 测试）
├── internal/
│   ├── api/               HTTP API + WebSocket（17 只读端点 + /ws）
│   ├── archive/           归档模块（gzip 压缩、按月归档）
│   ├── event/             事件队列（有界缓冲，采集→存储解耦）
│   ├── honeypot/          蜜罐假服务（10 协议最小认证握手模拟 + 连接治理）
│   ├── web/static/        前端静态文件（index.html / app.js / echarts.min.js，go:embed 内嵌）
├── deploy/                Docker 部署资产（Dockerfile、compose、部署/防火墙/fail2ban 脚本）
├── scripts/               长期资产：测试库种子与验证脚本（dev015/dev017 系列）
├── tools/archive-trigger/ 归档触发辅助工具（独立小工具）
├── docs/                  技术方案、M4 部署手册、VPS 复验清单、验证档案（docs/verification/）
├── config.example.json    配置样例（全部字段注释见技术方案）
└── bin/                   构建产物（sentry-agent；本目录被 git 忽略）
```

## 快速开始

### 构建

```bash
# Linux amd64（生产目标）
GOOS=linux GOARCH=amd64 go build -o bin/sentry-agent ./cmd/sentry-agent

# 本地开发（Windows/macOS 可直接 go run）
go run ./cmd/sentry-agent -config config.example.json
```

依赖：Go 1.26+。构建期使用 4 个纯 Go 模块（florianl/go-conntrack、gorilla/websocket、golang.org/x/sys、modernc.org/sqlite），静态编译为单二进制，运行期无动态库/解释器依赖；前端资源（echarts.min.js 等）本地内嵌，零 CDN、零外部资源。

### 配置

复制 `config.example.json` 为实际配置并按需修改：`web.listen` 默认 `127.0.0.1:8080`（面板访问方式由用户自配，工具不内置反代/隧道）；`db.path` 主库路径（默认 `/var/lib/sentry-agent/state.db`，**主库永久保留**）；`fw.source` 默认 `journald-kernel`（防火墙模式 B：DROP 前插 LOG 记录，见 `deploy/setup_firewall.sh`）。

### Docker 部署（推荐）

VPS 部署走 `deploy/` 目录资产，逐步执行详见 **[docs/M4_部署手册.md](docs/M4_部署手册.md)**（含环境检查、一键部署、健康检查与故障排查）；VPS 侧验收清单见 **[docs/M4_VPS复验清单.md](docs/M4_VPS复验清单.md)**。

### 本地快速验证（开发）

```bash
# 用测试库种子脚本生成演示数据后启动
python scripts/dev015_seed_db.py        # 30 小时攻击数据种子库
python scripts/dev017_seed_noidle_db.py # 零攻击种子库（空态验证）
go run ./cmd/sentry-agent -config scripts/test_m1_b5_config.json
```

种子库统一写入仓库根 `.dev015-test/` 目录（被 .gitignore 忽略，不入库）；
`test_m1_b5_config.json` 的 `db.path` 指向 dev015 攻击数据种子库
（`.dev015-test/state.db`，相对仓库根解析）；各脚本支持环境变量
（`DEV015_DB` / `DEV017_NOIDLE_DB`）覆盖默认路径。

## 验证档案

全部验证/回归/审计报告归档于 **[docs/verification/README.md](docs/verification/README.md)**（索引表：V1-V4 里程碑验证、TEST-001~007 测试与回归、AUD-006 审计、evidence/ 执行证据）。

## 关键约束

- 默认监听 `127.0.0.1:8080`，仅暴露 Web 面板；访问方式（反代/TLS/隧道）由用户自配。
- 主库永久保留（归档压缩仅副本，不清理主库）；`db.archive_dir` 归档目录默认 `/var/lib/sentry-agent/archive`。
- 防火墙模式 B（D-05 用户裁定）：DROP 规则前插 LOG，防火墙日志为限速采样视图（默认 5 包/s，面板已显著标注）。
- 数据不出 VPS（单机部署），无多机集中管理。
- 蜜罐默认关闭（`honeypot.enabled=false` 保守）；启用前须确认对应标准端口无真实服务，并运行 `deploy/setup_firewall.sh` 放行蜜罐端口（配置驱动，未启用时保持原 DROP 行为）；Docker 部署低端口需 `NET_BIND_SERVICE`（compose 已配置）。
- `config.exclude_ips` 为操作方自身 IP 白名单（运维配置），**不做脱敏处理**（用户裁定，2026-08-18）。

