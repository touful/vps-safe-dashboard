# AUD-VPS-001 VPS 部署攻击面审计报告（威胁建模）

- 审计人：auditor 子 Agent（sci-touful 管辖）
- 任务书：AUD-VPS-001（sentry-agent VPS 部署攻击面审计，防御性安全分析）
- 日期：2026-08-16
- 性质：纯只读安全审计（交付物报告写入除外；Git 提交 N/A，报告归属运营官统一处理）

## 1. 审计范围与方法

### 1.1 候选基线

| 项 | 值 |
| :--- | :--- |
| 候选基线 commit | `858c769`（main 分支 HEAD，`chore: DEV-FE-006 审计遗留清理`） |
| 工作区状态 | 干净（nothing to commit, working tree clean），无基线漂移 |
| 受审代码面 | `internal/` 全部（api/query/ws/embed/store/collect/conn/ssh/fw/f2b/archive/event/config/diskmon/out）+ `cmd/sentry-agent/main.go` + `tools/archive-trigger` |
| 受审部署面 | `deploy/` 全部 8 文件 + `config.example.json` + `docs/M4_部署手册.md` + `docs/M4_VPS复验清单.md` |
| 参考档案 | `docs/技术方案.md`（§8 安全设计、§9 风险表 R-14、§6.4 容器化）、`docs/verification/AUD-006`、`AUD-FE-001/002/003` |

### 1.2 方法与证据状态

- 全部代码级结论基于逐文件通读（api/query/ws/embed/store 系/ssh/fw/f2b/conn/collect/archive/event/config/diskmon/out/main），行号以基线 858c769 为准，标"已验证"。
- 依赖 CVE 核查经 searcher 子 Agent 联网查证（2026-08-16），来源含 NVD/GHSA/OSV/Debian tracker/go.dev release notes，标"已验证（searcher 来源）"。
- 推理性结论（攻击路径可行性、DoS 量级）标"推断 + 依据"；无法在本地验证的标"未验证"并列入 §8。
- 审查清单覆盖：①逻辑健壮性 ②安全漏洞 ③性能瓶颈 ④资源生命周期 ⑤异常处理 ⑥架构可维护性 ⑦重复逻辑；科研审查维度 8-11 标 N/A（安全审计非科研代码，无实验方法论/数据可信度/统计方法/可复现性维度适用）。

## 2. 威胁模型

### 2.1 部署形态（已确认事实，基线核验）

- Docker 部署：debian:bookworm-slim + 非 root（UID 1000，nologin）+ no-new-privileges + mem_limit 256m。
- **network_mode: host + cap_add NET_ADMIN**（conntrack 事件订阅前提，技术方案 6.4.2 调研结论）。
- 监听 `127.0.0.1:8080`（deploy/config.json）；WS Origin 白名单 `http://127.0.0.1:8080`。
- 采集通道：conntrack（netlink 组播）、journald（journalctl 子进程流式）、fail2ban 日志/库（只读挂载 + ACL）、ss 快照、/proc 资源。
- 只读挂载：/var/log/journal、/etc/machine-id、/var/log/fail2ban.log、/var/lib/fail2ban/fail2ban.sqlite3、配置；rw 卷：/var/lib/sentry-agent（chown 1000:1000）。
- 前端内嵌静态，任务书口径 12 只读 API（当前实现 13 个 /api/v1/* 路由，含 snapshot，api.go:65-78）+ 1 WS；无鉴权（D-03 定稿：访问方式用户自配）。

### 2.2 资产清单

| 资产 | 敏感度 | 位置/载体 |
| :--- | :--- | :--- |
| SSH 登录记录（username/指纹/结果/detail） | 高（含公钥指纹、攻击者用户名模式） | SQLite ssh_attempts |
| 防火墙日志（raw 完整原文 + 结构化） | 中高（IP/端口/时间线） | SQLite firewall_events |
| 封禁记录 + fail2ban 当前封禁库 | 中高 | SQLite ban_events + 宿主 fail2ban.sqlite3 |
| 连接明细（五元组/包字节/pid） | 中（流量画像） | SQLite connections + ss 快照 |
| 资源/磁盘水位 | 低 | SQLite resources + health |
| 归档压缩副本 | 高（含全部历史数据） | /var/lib/sentry-agent/archive/*.db.gz |
| 宿主 journal 全文 | 高（但不属于本工具存储） | 宿主 /var/log/journal |

### 2.3 攻击者模型与信任边界

| 攻击者 | 触达能力 | 前提条件 |
| :--- | :--- | :--- |
| A. 公网扫描者/脚本小子 | 触达 22 端口（SSH 爆破）、面板若被暴露则触达全部 API/WS | 面板暴露（反代无鉴权/直连 0.0.0.0） |
| B. 恶意网页（浏览器跨站） | 通过浏览器向 127.0.0.1:8080 发请求/WS（DNS rebinding、恶意页面） | 受害者本机浏览器访问恶意页；面板在本机回环 |
| C. 本地低权限用户/被攻破服务账号（www-data 等） | 读 /var/lib/sentry-agent 下文件（若权限过宽）、连 127.0.0.1:8080 | 同机多用户/服务降权被攻破 |
| D. 恶意日志注入者（任意公网攻击者） | 通过 SSH 登录尝试/畸形流量向采集链路注入数据 | 无需任何权限（攻击者天然可达 22 端口） |
| E. 容器逃逸者 | 若实现容器内代码执行，叠加 NET_ADMIN + host 网络影响宿主 | 需先有可利用漏洞（当前无已知入口） |
| F. 内部人员/运维失误 | 直接操作宿主 | 已登录 VPS |

**信任边界**：① 网络边界：`127.0.0.1:8080` 回环 = 本机进程与用户浏览器；公网 → SSH(22) 唯一强制开放面；面板暴露面由用户自配（D-03）。② 进程边界：容器 UID 1000 无特权，但持有 NET_ADMIN 且共享宿主 netns（能力面宽于常规容器）。③ 数据边界：容器可读宿主 journal/fail2ban 库（只读）、可写 /var/lib/sentry-agent（rw）。④ 存储边界：SQLite 明文落盘。

**关键设计边界（审计重点结论）**：WS Origin 白名单仅防"浏览器跨站"（攻击者 B），**不防**任何能建立 TCP 连接至 8080 的客户端——回环监听下 `allowNoOrigin=true`（main.go:140），无 Origin 头的非浏览器客户端（curl/脚本/隧道/反代转发的直连）直接放行（ws.go:78-84）。该边界与无鉴权叠加后，面板一旦被网络可达，数据全量可读。

## 3. 攻击面枚举（A~E 五组）

### A. Web 面板/API/WS 暴露面

**A-1 无鉴权数据读取（13 API + WS，任务书口径 12）**

| 项 | 内容 |
| :--- | :--- |
| 暴露途径 | 用户自配反代/TLS/隧道将面板外露（D-03）；或改 web.listen=0.0.0.0 |
| 攻击路径 | 公网 → 反代/直连 → GET 任一 /api/v1/* → 全量数据 JSON 返回 |
| 响应字段敏感度 | ssh：username（攻击者模式画像）、fingerprint（公钥指纹，可离线撞库比对）、detail（原始日志）；firewall：raw（内核日志原文）；bans：封禁 IP 集合；connections：全量五元组 + mark + pid（snapshot）；archive：归档文件清单（月份/大小）；health：db 大小/事件总量 |
| 利用条件 | 面板网络可达即成立（无鉴权、无 IP 白名单、无速率限制） |
| 影响 | 机密性全失：攻击者获知本机被攻击面、防护策略（fail2ban 封禁名单）、活跃服务画像（connections pid） |
| 可行性 | **高**（D-03 设计使然：一旦配置失误即全暴露；无任何代码侧防线） |

**A-2 WS Origin 校验边界（已验证）**

| 项 | 内容 |
| :--- | :--- |
| 事实 | ws.go:78-88：Origin 缺失时按 `allowNoOrigin`（回环监听=true）放行；Origin 不等白名单 403。main.go:140：`allowNoOrigin := isLoopbackListen(cfg.Web.Listen)` |
| 绕过路径 | ① 非浏览器客户端不携带 Origin 头 → 回环监听下直接放行；② 反代转发的 WS 升级请求（nginx 默认透传 Origin，浏览器场景 Origin=https://域名 ≠ 白名单 → 403；脚本客户端无 Origin → 放行） |
| 利用条件 | 攻击者能触达 8080（经反代/隧道/SSRF）且不带 Origin |
| 影响 | WS 推送流（conn_stats 1s / resource 5s / system / heartbeat）可被第三方订阅，实时流量画像 |
| 可行性 | **中**（需先穿透访问通道；默认回环形态下仅本机进程可达） |

**A-3 反代暴露场景 WS 默认 403（功能降级，非安全问题）**

| 项 | 内容 |
| :--- | :--- |
| 事实 | 白名单默认 `http://127.0.0.1:8080`（config.json:10）；Nginx 反代 TLS 后页面 Origin 变为 `https://panel.example.com` → 浏览器 WS 升级被 403（ws.go:85-87）；前端降级为轮询（app.js:1366 connectWS 失败 → setInterval 轮询仍工作） |
| 影响 | 面板功能降级（实时推送失效），前端有轮询兜底（PF-01 已记录 WS+轮询并存），不致命 |
| 备注 | 部署手册 §3 仅提示"改 listen 时同步修改"（M4_部署手册.md:49），未覆盖"反代不改 listen 但需改 ws_origin_allow"场景 → 文档缺口（VS-06） |

**A-4 HTTP 层健壮性（超时/体积/连接数）**

| 项 | 事实（已验证） | 风险 |
| :--- | :--- | :--- |
| 超时 | api.go:89 `http.Server{Addr, Handler}` 无 ReadTimeout/ReadHeaderTimeout/WriteTimeout/IdleTimeout | Slowloris：慢速 HTTP 头连接长期占用；回环场景低，暴露场景真实 |
| 请求体 | 无 body 大小限制（handler 均不消费 body；POST 仅触发只读查询） | 低（无 body 处理面） |
| MaxHeaderBytes | 默认 1MB | 暴露场景超大 header 消耗内存（有 mem_limit 256m 兜底） |
| 方法匹配 | CT-04（既有 Note）：POST 也执行只读查询返回 200 | 无写副作用，仅语义不严谨 |
| 路径处理 | embed.go:20 `http.FileServer(http.FS(sub))`——Go 标准库内置路径清理，拒绝 `..` 穿越 | **已验证：无路径穿越** |
| SQL 注入 | query.go 全部参数化（`?` 占位符）；rangeSeconds 白名单（1h/24h/7d/30d 之外回落 24h）；parseUintParam 仅接受数字 | **已验证：无注入面** |

**A-5 DoS 面**

| 项 | 事实 | 评估 |
| :--- | :--- | :--- |
| 30d 聚合 | query.go:383-385 hFirewallTimeline 30d 放宽超时 30s（DEV-018 实测同类聚合 2-8s）；无 API 层速率限制 | 暴露场景：循环调用可打满 1C1G CPU（1 核被聚合查询占满时采集通道同受影响）；回环场景：本机进程自伤 |
| WS 连接数 | wsHub（ws.go:29-70）无最大连接数；每连接 2 goroutine + send chan 64 帧；PushLoop 每秒广播 conn_stats | 暴露场景：数百连接 × 1 帧/s 推送 + 读循环 goroutine 消耗内存/CPU（mem_limit 256m 触发 OOM kill 兜底，进程重启后 restart: unless-stopped 拉起） |
| WS 帧大小 | gorilla Upgrader 未设 SetReadLimit（ws.go:14-20）——客户端可发送任意大小帧 | 暴露场景：超大帧内存分配压力（256m 兜底） |
| SQLite 读并发 | api.go:47 MaxOpenConns(4) 独立只读连接；WAL 多读者 | 4 并发 30d 查询占满连接后新查询排队（busy_timeout 5000）→ 面板响应阻塞，不崩库 |
| hResources 响应放大 | query.go:14-48：step 白名单 {60s, 5s} 但无 range 联动/桶数上限；range=30d&step=5s → 约 51.8 万桶，单响应可达数十 MB JSON（5s 采样 × 30d；正常前端固定 step=60s 不受影响） | 暴露场景：并发请求放大内存/带宽/序列化 CPU（5s context 超时 + mem_limit 256m 兜底）；见 VS-18 |

**A-6 信息泄露纵深**：无鉴权下 13 API 全量可读（任务书口径 12）（A-1）；snapshot 含 pid（进程画像）；archive 列归档清单（泄露数据规模）。纵深缺失：无 CSP/X-Frame-Options/X-Content-Type-Options（embed.go，SC-02 既有 Note）——点击劫持在回环场景无实际目标，暴露场景为纵深缺口。

### B. 采集通道输入面（日志/事件 → 解析 → SQLite → API → 前端）

**B-1 SSH 日志注入面（重点，全链路复核）**

| 环节 | 事实（已验证） | 结论 |
| :--- | :--- | :--- |
| 解析 | ssh/parse.go:17-42：username 以 `\S+` 提取（不含空白/换行）；fingerprint 正则提取；detail = Truncate512(line)（event.go:165-172 rune 安全截断 512）；行级正则白名单 8 模式，不匹配行限频忽略 | 无解析器可利用缺陷（正则无回溯风险，Go RE2 线性时间） |
| 落库 | store_batch.go:23-25 INSERT 参数化 | 无 SQL 注入 |
| 输出 | query.go:139-164 JSON 序列化（Go json.Marshal 默认转义 `<`/`>`/`&` → \u003c 等） | JSON 结构不可被破坏 |
| 渲染 | app.js escapeHtml/textContent 全覆盖（AUD-FE-001 SC-01 已核验；本审计复核 raw/username/detail 渲染路径 L614-616/L634-637/L938 一致） | **XSS 链路闭合**：攻击者可控的 username/detail 无法注入 HTML/JS |
| 控制字符 | journald MESSAGE 可含控制字符（\x1b ANSI 等）→ detail 原文保留 | JSON \uXXXX 转义 + 前端 textContent 不解释控制字符 → 无终端注入/结构破坏面；展示层可能出现不可见字符（Note 级干扰） |
| 超长输入 | scanner 上限 1MB/行（ssh.go:52）；sshd 单条日志不可能超限 | 无超长行 DoS（ErrTooLong 路径理论存在但 sshd 源受限） |

**结论：SSH 日志注入的攻击者可控数据（username/指纹/超长 detail）在完整链路上无执行/注入利用点，仅能造成展示污染与存储数据污染（低影响）。**

**B-2 防火墙日志注入面**

| 项 | 事实 | 结论 |
| :--- | :--- | :--- |
| 解析 | fw/parse.go：SENTRY_FW 前缀 + `SRC/DST/PROTO/SPT/DPT=` 键值提取；无 SRC/DST 键则丢弃；ipToUint32/atou16 严格校验 | 结构字段（IP/端口）无注入面 |
| raw 字段 | event.go:118 `Raw: 原始内核日志行（完整保留）`——**无业务截断**（对比 SSH detail 512 截断不对称）；单行上限 scanner 1MB（fw.go:58） | 原始行长度攻击者半可控（包内容影响 LOG 行字段，内核格式固定）；实测行长约 200-300 字节；DB 存储放大有限。Note 级（VS-09） |
| 内容控制 | 内核日志行由 nftables LOG 生成，字段值由包头决定（源 IP 可伪造、端口可指定）；LOG 前缀为部署脚本静态写入（setup_firewall.sh:11） | 攻击者不能注入任意文本（内核格式化输出），仅控制字段值 |

**B-3 fail2ban 通道**：parse.go 正则严格（jail 名 `[A-Za-z0-9_.-]+`、IP 点分校验）；QueryBanned 参数化 + mode=ro DSN（f2b.go:66-90）；只读挂载 + ACL u:1000:r。**已验证：无注入面**。注意：①readOnlyDSN 未设 busy_timeout（f2b.go:94-95），fail2ban 写库瞬时可能 SQLITE_BUSY → 查询失败告警（限频 5min，main.go:241-253），功能降级非安全面；②若 fail2ban 库以 WAL 模式运行（Debian 默认未确认），只读挂载仅挂主库文件时容器侧 QueryBanned 可能读到滞后视图（WAL 未 checkpoint）——功能/数据一致性风险非安全面，见 §8 U-8。

**B-4 存储层**：store_batch.go 全部 INSERT 参数化；事务 BEGIN IMMEDIATE（store_batch.go:43）；DDL 固定；归档 ATTACH 路径经 sqliteQuote 转义（archive.go:360-362）。**已验证：无 SQL 注入面**。

**B-5 日志洪泛（写放大 DoS）**：ssh 通道无应用层限速，依赖宿主 journald RateLimit（5s/5000，setup_system.sh）+ fail2ban 封禁兜底；fw 通道内核限速 5/s burst 10（setup_firewall.sh:12）；conn 通道 netlink 溢出留痕（R-10）。评估：SSH 爆破高峰 journald 丢弃部分日志（数据不完整，V-02 复验项），agent 与 SQLite 不被击穿（有界通道 4096 + 背压 + 批量 500）。**推断：可接受（R-11 已调高宿主限额）**。

### C. 容器与宿主隔离面

**C-1 NET_ADMIN + host 网络组合（重点）**

| 项 | 事实（已验证） | 评估 |
| :--- | :--- | :--- |
| 能力面 | compose 仅 add NET_ADMIN（docker-compose.yml:15-16）；netlink 订阅 conntrack 组播组需 NET_ADMIN（技术方案 6.4.2 调研，NET_RAW 不足） | 能力最小集成立（R-14 披露） |
| **sysctl 写入：代码事实 vs 运行时事实** | **代码事实（已验证）**：conn.go:41/46 存在 WriteFile 调用，写 `/proc/sys/net/netfilter/nf_conntrack_acct`（=1）与 `/proc/sys/net/core/rmem_max`（→8MB）。**运行时事实（已验证，V1_验证报告.md:104 实测）**：容器形态下 /proc/sys 为只读挂载（Docker 默认），写入失败仅留 system_event warn、不阻塞——默认容器部署无宿主副作用。能力面论证不依赖 sysctl 写成功（见下行） | **能力面（推断 + 依据）**：host netns 共享 + NET_ADMIN 具备经 netlink 操纵 nftables/iptables/路由/ARP 的能力（netlink 权限模型静态成立，未实测）；若代码被攻破，可流量劫持/嗅探/封锁宿主网络。功能降级披露：默认容器部署下 nf_conntrack_acct 不生效（connections.packets/bytes 恒 0）、rmem_max 不提升（netlink 缓冲被内核 clamp 至默认上限，R-10 的 2MB/8MB 扩容不可达，V-04 overrun 压测预期受影响）——见 §8 U-8 
| RCE 前提 | 无已知可利用漏洞（解析器 Go RE2 正则、无 unsafe、无 cgo、无 shell 拼接；HTTP 面无内存破坏面） | 容器 RCE 无现实入口，能力面为"潜在放大器"而非"已利用路径" |
| 缓解现状 | no-new-privileges、全部日志挂载 :ro、容器 UID 1000、仅只读 API | 纵深防御四件套已落地（AUD-006 F-03 修复项） |
| 缓解评估 | setcap 二进制 + 去 cap-add（技术方案 R-14 备选）未实施；rootless/userns 与 host 网络组合复杂 | 建议维持现状 + 完成 D-09 能力面专项验证（复验清单缺失，见 §8 U-1） |

**C-2 非 root 有效性**

| 项 | 事实 | 评估 |
| :--- | :--- | :--- |
| journal 只读 | deploy.sh:53-62 ACL u:1000:rx + 默认 ACL（轮转新文件不失效） | 已验证设计正确（V1b-2 待 VPS 复验） |
| fail2ban 只读 | install_fail2ban.sh:71-76 ACL u:1000:r + 回读校验 | 正确 |
| 数据目录属主 | deploy.sh:39-43 chown 1000:1000，失败即退出 | 正确 |
| **目录/文件权限** | store.go:138-145 `MkdirAll(..., 0o755)`；SQLite 文件默认 0644（受 umask）；archive gzip 0644（archive.go:217）；deploy.sh **无 chmod 收权步骤** | **方案 8.1/8.3 声称"数据目录 0700、state.db 0600"未落实（文档-实现不一致）**：同机其他本地用户可读全部安全数据（VS-01，Minor） |
| no-new-privileges / mem_limit | compose:37-39 | 已落地；无 CPU limit、无自定义 seccomp/AppArmor、rootfs 可写（纵深防御 Note，VS-13） |
| 镜像含 shell | Dockerfile:18-21 debian:bookworm-slim 自带 bash/dash + systemd 包（journalctl）+ iproute2（ss/ip）；USER sentry nologin 仅限登录 shell | **8.1 披露"无 shell 镜像"不成立**（VS-08）；deploy.sh:92 健康检查依赖 `docker exec bash`（保留 bash 有功能依据） |

**C-3 容器逃逸面**：基础镜像 debian:bookworm-slim 处于 LTS 安全支持期（至 2028-06-30，searcher 验证）；无 SYS_ADMIN/无挂载能力、seccomp 默认开启（Docker 默认 profile）；host 网络下 8080 端口与宿主其他服务冲突为部署操作风险（Note）。**评估：逃逸面常规，无特殊放大器。**

**C-4 Docker 守护进程暴露面**：部署手册未包含 Docker daemon 安全建议（远程 API 暴露、镜像签名等）——手册完备性 Note（P2）。

### D. VPS 主机层面

| 项 | 事实 | 评估 |
| :--- | :--- | :--- |
| SSH 加固 | setup_system.sh 仅 sshd LogLevel VERBOSE；fail2ban jail maxretry 5/findtime 10m/bantime 1h（install_fail2ban.sh:60-66） | **未覆盖禁用密码登录/强制密钥认证**（VS-07，Minor）；bantime 1h 偏保守（P1 可调） |
| 防火墙 | setup_firewall.sh 模式 B 零策略变更：仅在既有 DROP 规则前插 LOG（5/s burst 10），不设默认策略、不开端口清单（D-05 定稿）；持久化仅提示（脚本:155） | 符合设计；**依赖用户宿主已有默认拒绝策略**——手册/复验清单未含"默认策略确认"项（VS-14，Note） |
| 敏感数据落盘 | SQLite 明文（IP/用户名/指纹/raw）；目录 0755/文件 0644（见 C-2）；journal/f2b 只读 ACL 正确；归档副本 0644 | 权限缺口见 VS-01；明文存储无加密（VPS 本地磁盘场景可接受，备份迁移需注意权限） |
| 与 fail2ban 配合 | agent 只读消费 fail2ban 日志/库；封禁由宿主 fail2ban 执行（容器无权封禁——正确隔离） | 职责边界正确 |

### E. 供应链与运维面

| 项 | 事实 | 评估 |
| :--- | :--- | :--- |
| 依赖 CVE | searcher 核查（2026-08-16）：gorilla/websocket v1.5.3 无已知 CVE（唯一 CVE-2020-27813 ≤v1.4.0 已修复）；modernc.org/sqlite v1.56.0 无 CVE（对应上游 ≥3.53.3 含全部修复）；go-conntrack v0.7.0 / x/sys v0.47.0 / modernc libc/memory 无 CVE；x/net 2022-09 旧版模块级漏洞均在未编译子包（http2/html/idna/dns），实际编译进二进制的仅 x/net/bpf（无 CVE） | **直接依赖无已知漏洞**；x/net 旧版造成扫描器误报噪声（建议升级 x/net 至 v0.55+ 消除，VS-17 Note） |
| Go 工具链 | Dockerfile:3 `golang:1.26-alpine`（浮动标签，构建时拉最新 1.26.x patch）；本机 go1.26.2 落后 1.26.3~1.26.6 共 4 个安全版本（含 CVE-2026-33814 net/http HTTP/2 transport 无限循环影响 1.26.0-1.26.2；CVE-2026-56860 net/url 二次复杂度；CVE-2026-56862 TLS KeyUpdate） | **实际利用条件在默认部署不成立**：sentry-agent 无出站 HTTP 客户端功能（无 transport 调用）、不启用 h2c、无 TLS 服务端；net/url 面在 URL 参数解析（暴露场景可触发 CPU 放大）。浮动标签构建会自动吸收修复；固定版本手动构建则滞后（VS-05，Minor） |
| 归档与 archive-trigger | 归档仅压缩副本不删除（D-04）；archive-trigger 为开发工具（tools/archive-trigger/main.go:1 明确非交付组件，警示需停 agent 后用） | 无攻击面（本地命令行） |
| 更新机制 | 无自动更新：重建镜像 `docker compose up -d --build`（部署手册:121）；数据卷不动；schema_version=1 无迁移机制 | 更新靠用户手动；镜像不固定 tag（latest）可致构建不可复现（Note，P2） |


## 4. 薄弱点清单（按 AGENTS.md §4.6 分级）

> 统计：**Blocker 0 + Major 0 + Minor 8 + Note 10**。无阻塞项；所有安全问题均可经部署纪律与 P1 建议收敛。

### 4.1 Minor（非阻塞，建议修复）

| ID | 代码位置 | 事实 | 风险推导 | 触发条件 | 影响 | 建议 | 置信度 | 是否阻塞 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| VS-01 | deploy/deploy.sh:39-43（仅 chown 无 chmod）；store/store.go:138-145（MkdirAll 0o755）；archive/archive.go:217（gzip 0644） | 方案 8.1/8.3 声称"数据目录 0700、state.db 0600"，实际：目录 0755、SQLite 0644、归档 0644 | 同机其他本地用户/被攻破的低权限服务账号可读全部安全数据（SSH 指纹/用户名/防火墙 raw） | VPS 存在多用户或任意服务账号被降权攻破 | 敏感数据横向泄露；与已声明设计矛盾 | deploy.sh 增加 chmod 700 /var/lib/sentry-agent；store 建目录 0700、OpenFile 0600（或容器 ENTRYPOINT 前置 umask 077） | 高（静态确认，权限位明确） | 否 |
| VS-02 | api/api.go:89 `http.Server{Addr, Handler}` 无任何超时配置 | 无 ReadHeaderTimeout/IdleTimeout/MaxHeaderBytes（默认 1MB） | Slowloris 慢速头连接长期占连接/内存 | 面板被暴露到公网/不可信网络 | 连接耗尽 DoS（1C1G 下数百连接即可占满） | ReadHeaderTimeout 5s、IdleTimeout 60s、MaxHeaderBytes 64KB、WriteTimeout 30s | 高（代码静态确认） | 否 |
| VS-03 | api/ws.go:14-20（upgrader 无 SetReadLimit）、ws.go:29-70（hub 无连接数上限） | WS 连接数无限制；客户端帧大小无限制；每连接 2 goroutine + 64 帧缓冲 | 暴露场景：连接洪泛 + 超大帧内存压力（mem_limit 256m 触发 OOM kill 兜底重启） | 面板暴露 + 攻击者脚本建立大量 WS 连接 | 推送通道资源耗尽、容器反复 OOM 重启 | hub 最大连接数（如 32）+ SetReadLimit(4KB) + 握手后读写 deadline | 高 | 否 |
| VS-04 | api/query.go:383-385（30d 放宽 30s 超时） | 30d 大范围聚合 CPU 密集（DEV-018 实测 2-8s）；API 层无速率限制 | 暴露场景：循环调用 30d 端点打满 1C1G CPU（聚合与采集共享单核） | 面板暴露 + 攻击者脚本循环请求 | 面板不可用、采集延迟、宿主 CPU 飙高 | API 层简单令牌桶（如每端点 ≤2 req/s，或按 IP/全局计数）；至少前端已 30d 降频（30s 轮询） | 中（CPU 占满量级推断，需压测确认） | 否 |
| VS-05 | deploy/Dockerfile:3 `golang:1.26-alpine`；go.mod `go 1.26.2` | Go 1.26.2 落后 1.26.3~1.26.6 四个安全版本（CVE-2026-33814 net/http HTTP/2 无限循环、CVE-2026-56860 net/url 二次复杂度、CVE-2026-56862 TLS KeyUpdate 等，searcher 核查） | 默认部署无出站 HTTP 客户端/h2c/TLS 服务端，实际利用条件不成立；但 net/url 面在暴露场景可做 CPU 放大；固定版本手动构建则风险真实 | 使用固定 1.26.2 手动构建（非浮动标签）；或未来新增出站 HTTP 功能 | 标准库已知漏洞暴露窗口 | 构建锁定 `golang:1.26.6-alpine`（或更高 patch）并升级 go.mod；Dockerfile 注释注明"构建时确认 Go patch ≥1.26.6" | 高（searcher 来源 + go list 确认依赖面） | 否 |
| VS-06 | docs/M4_部署手册.md:48-49 | 手册仅提示"改 listen 时同步修改 ws_origin_allow"，未覆盖"反代不改 listen 但页面 Origin 变化"场景 | 用户照手册配反代后 WS 全 403，误以为面板故障；或反向——用户把 ws_origin_allow 改为公网域名后未意识到该值同时是唯一 WS 防线 | 反代 + TLS 部署 | 功能降级 + 文档误导 | 手册补"反代场景须将 ws_origin_allow 改为反代对外域名"说明，并注明该白名单仅防浏览器跨站 | 高 | 否 |
| VS-07 | deploy/install_fail2ban.sh:60-66（jail bantime 1h）；setup_system.sh（仅 LogLevel VERBOSE） | 部署套件未覆盖 SSH 密码登录禁用/密钥强制；fail2ban 阈值保守 | 密码认证开启时暴力破解窗口长（bantime 1h），依赖 fail2ban 兜底 | 弱密码 + 公网可达 22 | 账户被爆破风险 | 手册 P1 增加"禁用密码登录（PasswordAuthentication no）、仅密钥认证"建议与检查项；bantime 按需调大（如 24h） | 高（配置面事实） | 否 |
| VS-08 | deploy/Dockerfile:18-23（debian slim + systemd/iproute2 包）；技术方案 8.1 表"无 shell 镜像" | 镜像含 bash/dash/journalctl/ss/ip；8.1 披露"无 shell"与实际不符 | 容器 RCE 后攻击者拥有完整 shell 与网络工具，横向利用成本低（no-new-privileges 限制提权，但工具可用） | 容器代码执行（当前无已知入口） | 缓解面削弱 + 文档披露失真 | 修正 8.1 披露；评估删除非必需包（健康检查 deploy.sh:92 依赖 bash——可改 docker inspect 或 agent 自带 /api/v1/health 探活替代）；不阻塞 | 高（Dockerfile 事实） | 否 |

### 4.2 Note（风格/可选/提示）

| ID | 代码位置 | 事实 | 问题 | 建议 |
| :--- | :--- | :--- | :--- | :--- |
| VS-09 | event/event.go:118（fw Raw 完整保留）vs ssh detail Truncate512 | raw 字段无业务截断（单行上限 scanner 1MB 兜底） | 存储不对称放大；DB 行大小攻击者半可控 | raw 截断 512-1024 与 detail 对齐 |
| VS-10 | ws.go:78-84 + main.go:140 | 回环监听 allowNoOrigin=true，无 Origin 客户端直连放行 | Origin 白名单仅防浏览器跨站（DNS rebinding/恶意页），不防直连客户端——文档应明示边界 | 手册/代码注释补充防护边界声明 |
| VS-11 | query.go:309-338（snapshot 含 pid）、query.go:276-306（archive 列清单）、query.go:81-112（connections 含 IPv6 字段） | 暴露场景可枚举进程 pid/归档规模/IPv6 流量。注：非 root 容器（UID 1000）内 ss -tanup 的 -p 进程信息依赖 /proc/&lt;pid&gt; 读权限，宿主 root 服务 pid 大概率不可见（推断，DEV-VPS-001 §6 #9），实际泄露面约为 agent 自身及同 UID 进程 | 信息枚举面（数据本属面板功能，暴露场景由访问控制兜底） | 保持现状；暴露场景必须前置鉴权（P0）；VPS 复验可补 ss -tanup pid 可见性实测 |
| VS-12 | embed.go:14-20（无安全头，SC-02 既有 Note 继承） | 无 CSP/X-Frame-Options/X-Content-Type-Options | 点击劫持/内容嗅探：回环场景无实际目标（无写操作、无敏感交互）；暴露场景为纵深缺口 | 暴露场景建议加 CSP（default-src 'self'）+ X-Content-Type-Options |
| VS-13 | docker-compose.yml:37-43 | 无 CPU limit、无自定义 seccomp/AppArmor、rootfs 可写 | 纵深防御缺失（mem_limit 256m 已兜底内存） | P2：cpus: 0.5、自定义 seccomp profile、rootfs ro（数据卷 rw） |
| VS-14 | setup_firewall.sh:154-156 | 模式 B 零策略变更，不设默认 DROP/不开端口清单；持久化仅提示 | 依赖用户宿主已有防火墙；空环境部署无默认拒绝策略时全端口开放 | 手册/复验清单增加"确认宿主默认拒绝策略 + 端口开放清单 + 规则持久化"检查项 |
| VS-15 | ssh.go:24-65（无应用层限速） | ssh 通道依赖宿主 journald RateLimit（5s/5000）+ fail2ban 兜底 | 爆破高峰 journald 丢日志（数据不完整，V-02 复验），agent 不被打垮 | 可接受（R-11 已调高）；记录即可 |
| VS-16 | docker-compose.yml:12-16（host 网络） | 8080 端口与宿主其他服务冲突；journal GID 需按宿主调整（deploy.sh 注释） | 部署操作面 | 手册提示端口检查（check_env 可加） |
| VS-17 | go.mod x/net v0.0.0-20220923203811 | 旧版 x/net 模块级漏洞均未编译（仅 bpf 编译进二进制），但扫描器按模块版本误报 | 供应链扫描噪声 | 升级 x/net 至 v0.55+（建议 v0.57.0）消除误报 |
| VS-18 | api/query.go:14-48（hResources） | step 白名单 {60s,5s} 无 range 联动/桶数上限：range=30d&step=5s → 约 51.8 万桶、单响应数十 MB（前端固定 step=60s 不受影响） | 暴露场景响应放大 DoS（并发请求放大内存/带宽/CPU） | step 与 range 组合校验或桶数上限（如 step=5s 时 range ≤7d）（P2，与 DEV-VPS-001 D7 对齐） |

## 5. 最可能的攻击路径排序（Top 5 利用链）

| # | 利用链 | 可行性 | 影响 | 依据 |
| :--- | :--- | :--- | :--- | :--- |
| 1 | 面板公网暴露（反代无鉴权/直连 0.0.0.0/隧道误配）→ 无鉴权 GET 12 API 全量读取（SSH 指纹/用户名/防火墙 raw/封禁库/连接明细/pid） | **高**（D-03 设计使然：配置失误即成立，无任何代码侧防线；风险不来自代码缺陷而来自部署决策） | 机密性全失：攻击者获得本机被攻击面画像、防护策略、活跃服务指纹 | A-1/A-6、VS-10/VS-11 |
| 2 | 面板暴露 → 循环调用 30d 聚合端点（30s 超时窗口）→ 打满 1C1G CPU | 中-高（端点无速率限制，1 核易饱和） | 面板不可用 + 采集延迟；agent 数据不丢失（进程内存兜底） | A-5、VS-04 |
| 3 | 面板暴露 → 无 Origin 直连 WS + 大量连接/超大帧 → 推送通道资源耗尽 | 中（需脚本客户端；allowNoOrigin 放行） | 容器 OOM 反复重启（restart 拉起）；推送中断 | A-2/A-5、VS-03/VS-10 |
| 4 | 公网 SSH 爆破 → 恶意 username/detail 注入（特殊字符/超长/伪造模式）→ 存储与展示污染 | 高（无需任何权限）但**影响低** | 仅数据污染/展示干扰；XSS 已闭合（B-1 全链路复核），无执行、无注入 | B-1 |
| 5 | 容器 RCE（先需可利用漏洞，当前无已知）→ NET_ADMIN + host 网络 → nftables/iptables 操纵、流量嗅探/劫持、ARP、sysctl 修改 | **低**（无现实入口：解析器 Go RE2 线性正则、无 cgo/unsafe/无 shell 拼接、HTTP 面无内存破坏面） | 宿主完全失陷（若发生）；能力面为潜在放大器（R-14 已登记） | C-1、§8 U-1（D-09 未验证） |

**排序结论**：现实风险集中在"面板暴露 → 无鉴权读取 + DoS"（#1-#3），全部源于 D-03 部署决策而非代码缺陷；日志注入与容器 RCE 链当前无可利用漏洞。**防线本质上是部署纪律（访问通道）+ 纵深防御（P1 建议）。**

## 6. 加固建议清单（分层）

### P0 必做（部署纪律，本次交付即可执行，无代码变更）

1. **面板访问通道红线**：仅允许 SSH 隧道或带鉴权（Basic Auth/客户端证书）的反代；**任何公网直接暴露（含 0.0.0.0）视为高风险配置**，须有独立鉴权层（对应攻击路径 #1-#3）。
2. **数据目录权限收权**：部署后执行 `chmod 700 /var/lib/sentry-agent && chmod 600 /var/lib/sentry-agent/state.db`（对应 VS-01，立即生效；代码修复走 P1）。
3. **宿主防火墙默认策略确认**：部署后核对默认拒绝策略与仅开放 22（+面板隧道源 IP）端口，并持久化规则（对应 VS-14）。
4. **SSH 加固**：禁用密码登录、仅密钥认证（对应 VS-07）；确认 fail2ban sshd jail active。

### P1 建议（代码/脚本修复，需开发任务）

1. VS-01 代码修复：store MkdirAll 0700 + SQLite/归档文件 0600（或 ENTRYPOINT 前置 umask 077）。
2. VS-02：http.Server 补 ReadHeaderTimeout/IdleTimeout/MaxHeaderBytes。
3. VS-03：WS hub 连接数上限 + SetReadLimit + 握手 deadline。
4. VS-04：API 层速率限制（令牌桶，重点覆盖 30d 聚合端点）。
5. VS-05：Dockerfile 锁定 `golang:1.26.6-alpine`，go.mod 升 1.26.6。
6. VS-06/VS-10：部署手册补反代 WS Origin 配置说明与 Origin 防护边界声明。
7. VS-09：fw raw 截断对齐 detail。
8. 手册补 P0 四条为部署前置检查项（check_env.sh 或复验清单）。

### P2 可选（纵深防御）

1. VS-12：CSP + X-Content-Type-Options 安全头（既有 SC-02 建议）。
2. VS-13：cpus limit、自定义 seccomp profile、rootfs 只读；**cap_drop: [ALL] + 仅保留 cap_add: [NET_ADMIN]**（Docker 官方安全基线，当前默认 cap 集 14 项仍生效；需 VPS 复验 V-03 确认纯 NET_ADMIN 下 conntrack 正常；与 DEV-VPS-001 C1 对齐）。
3. VS-08：镜像最小化评估（健康检查去 bash 依赖）。
4. VS-17：升级 x/net 消除扫描噪声。
5. VS-18：hResources step/range 组合校验或桶数上限（P2，DEV-VPS-001 D7）。
6. C-4：手册补 Docker daemon 安全建议（远程 API 关闭、镜像固定 digest）。
7. D-09 落地：容器能力面专项验证（nft/ip 修改能力实测 + 8.1 披露回写）。


## 7. 与既有审计结论的对照

| 既有结论 | 本审计处置 | 说明 |
| :--- | :--- | :--- |
| AUD-FE-001 SC-01（XSS 转义全覆盖） | **继承并扩展复核**：B-1 组对 SSH 日志注入面做全链路复核（解析→存储→API→渲染），结论一致——链路闭合，无注入利用点 | 新增视角：攻击者可控输入（username/detail/raw）在 JSON 序列化与 textContent 渲染下的控制字符/结构破坏面评估 |
| AUD-FE-001 SC-02（无安全头 Note） | **继承**：VS-12（Note），暴露场景建议 CSP | 无新增风险 |
| AUD-FE-001 SC-03（raw title 完整原文） | **继承**：raw 完整原文展示风险与本审计 VS-09（raw 无截断）合并 | 新增存储侧不对称发现 |
| AUD-FE-001 CT-04（POST 返回 200 Note） | **继承**：无写副作用，无新风险 | A-4 复核一致 |
| AUD-FE-002（WS Origin 零改动） | **继承并补充边界**：Origin 白名单仅防浏览器跨站；回环监听 allowNoOrigin=true 时无 Origin 客户端直连放行（VS-10） | 新增部署形态下的防护边界结论 |
| AUD-006（M4 七项修复） | **继承**：F-03 纵深防御四件套已落地（C-1 缓解现状）；M4B-01/02、F-01/05/06/07 与本审计无冲突 | — |
| 技术方案 R-14（NET_ADMIN + host 能力面 Major） | **继承风险登记**：C-1 组确认能力面真实存在（新增证据经 reviewer R-01 修正：conn.go 写宿主 sysctl 的代码事实存在，但容器运行时 /proc/sys 只读、写入失败——默认部署无宿主副作用，能力面基于基础能力推导）；无新增可利用路径；D-09 专项验证未在复验清单落地（§8 U-1） | R-14 维持 Major 登记不变 |
| 技术方案 8.1/8.3（0700/0600、无 shell 镜像） | **新增不一致发现**：VS-01（权限未落实）、VS-08（镜像含 shell）——文档-实现矛盾 | 需开发任务修正实现或修订文档 |
| DEV-VPS-001（同日同基线交叉文档，docs/VPS攻击链分析-开发视角.md） | **交叉对照（新增，reviewer R-07）**：链路级结论与本报告一致——链 1 XSS 闭合（低）、链 4 WS Origin 绕过（中低，M-02 回环假设失效）、链 5 DoS（中，条件触发）；DEV 特有补充已吸收：hResources 放大（VS-18/D7）、pid 可见性受限（VS-11 注）、fail2ban WAL（U-8）、cap_drop ALL（P2-2）；DEV 的 C6（数据目录 0700）与本报告 VS-01 双向印证 | 两份文档结论互证；建议运营官合并归档 |

## 8. 未验证假设清单（待确认，不混入问题清单）

| # | 假设描述 | 待验证方法 | 把握度 |
| :--- | :--- | :--- | :--- |
| U-1 | D-09 容器能力面专项验证（容器内 nft/ip 修改宿主网络配置的能力实测）未在 M4_VPS复验清单落地——R-14 的缓解面结论缺少实测支撑 | VPS/隔离环境实测：容器内执行 `nft add rule` / `ip link` 修改尝试，记录受限或被阻断的证据，回写技术方案 8.1 | 中（netlink 权限模型静态成立，实测值待补） |
| U-2 | 30d 大库聚合对 1C1G 的实际 CPU 占用（VS-04 的量级：是否可打满单核） | VPS 种子库压测：并发 5-10 个 30d 请求观察 CPU/响应时间 | 中（DEV-018 实测单查询 2-8s，并发放大为推断） |
| U-3 | golang:1.26-alpine 浮动标签在用户构建时实际拉取的 Go patch 版本（决定 VS-05 是否已自愈） | `docker build` 后 `docker run --rm sentry-agent go version`（或构建日志）确认 ≥1.26.6 | 中（浮动标签行为推断） |
| U-4 | Slowloris/WS 连接洪泛在 1C1G 的实际量级（VS-02/VS-03） | 暴露场景（或模拟）下压测连接数阈值 | 中（标准库行为静态成立，阈值待实测） |
| U-5 | VPS 是否为多用户/多服务账号环境（决定 VS-01 实际影响） | 用户部署前确认宿主用户与降权服务账号清单 | 中（环境依赖） |
| U-6 | fail2ban 真实库 bans 表结构与 QueryBanned 兼容（f2b.go:72 `SELECT DISTINCT ip FROM bans`） | VPS 复验清单"fail2ban 真实库 bans 表联调"项 | 中（已有复验项） |
| U-7 | 暴露场景下攻击者实际利用 30d DoS 的概率（面板多为内网/隧道形态） | 无（部署形态依赖）——由 P0 访问纪律收敛 | 低-中 |
| U-8 | ①fail2ban.sqlite3 的 journal 模式（WAL?）与只读挂载一致性（R-06，DEV-VPS-001 §6 #2 同类）；②默认容器部署下 sysctl 写入失败导致的功能降级（conntrack packets/bytes 恒 0、netlink 缓冲未扩容）在 VPS 真实 Docker 版本下的实际表现（R-01） | ①VPS 复验：PRAGMA journal_mode 检查 + 容器挂载后 QueryBanned 一致性；②VPS 复验：system_events 中 conntrack warn 实态 + connections.packets/bytes 字段值 | 中（V1 实测为 Docker Desktop 形态，VPS 版本行为待确认） |
| U-9 | 非 root 容器内 ss -tanup 的 pid 可见性边界（VS-11 注） | VPS 复验：容器内执行 ss -tanup 观察 root 进程 pid 是否可见（DEV-VPS-001 §6 #9） | 中-高（/proc 权限模型静态成立） |

## 9. 审计结论

| 项 | 结论 |
| :--- | :--- |
| 总体风险评级 | **按推荐部署（SSH 隧道/受控反代）：低-中**；**面板公网直接暴露：高**（无鉴权全量数据可读 + DoS 面）。风险主体是 D-03 部署决策（访问方式用户自配）而非代码缺陷 |
| Blocker/Major | 0 项。R-14（NET_ADMIN 能力面）为既有 Major 风险登记，本审计确认无新增可利用路径，维持登记并建议 D-09 落地 |
| Minor | 8 项（VS-01~VS-08）：权限未收权（文档-实现不一致）、HTTP 超时缺失、WS 无连接/帧限制、30d 无速率限制、Go 版本滞后、手册 WS Origin 缺口、SSH 加固缺口、镜像 shell 披露失真 |
| Note | 10 项（VS-09~VS-18） |
| 攻击面结论 | 无注入/无 XSS/无路径穿越/无 SQL 注入（全部参数化）；DoS 面集中于暴露场景；容器能力面为设计取舍（R-14）；依赖供应链无已知可利用漏洞 |
| 放行意见 | **PASS_WITH_NOTES（放行）**：本报告作为部署决策安全依据成立；前提是 P0 四条部署纪律执行 + P1 建议排期修复。若用户坚持公网暴露面板，须先落地 P0-1（独立鉴权层）与 P1-2~P1-4（超时/连接/速率限制） |

## 10. 自检结果 + reviewer 反思结论

### 10.1 auditor 自检

- 审查清单 7 项全覆盖：①逻辑健壮性（A-4/A-5/B-5）②安全漏洞（A/B/C/E 全组）③性能瓶颈（A-5 30d 聚合/WS 推送）④资源生命周期（连接/goroutine/文件权限 C-2）⑤异常处理（f2b busy、scanner 超长行、OOM 兜底）⑥架构可维护性（D-05 职责边界、fail2ban 隔离）⑦重复逻辑（raw/detail 截断不对称经合并评估）；科研审查维度 8-11 标 N/A（安全审计非科研代码，理由见 §1.2）。
- 每条问题含完整 10 字段（ID/等级/位置/事实/风险推导/触发条件/影响/建议/置信度/是否阻塞）✓
- 等级使用统一标准（Blocker/Major/Minor/Note），未用旧称 ✓；无阻塞项（Blocker/Major 0）已如实标注 ✓
- 风格偏好未列入正式缺陷（无独立风格清单——本审计未发现纯风格问题，Notes 均为有实际影响的轻量问题）✓
- 未验证假设单列 §8（U-1~U-9），未定性为缺陷 ✓
- 候选基线 `858c769` 已记录；审查全程工作区干净无漂移 ✓
- 纯只读审计 + 交付物报告写入：Git 提交项 N/A（报告归属运营官统一处理）✓
- 事实与推断严格区分：代码级证据标"已验证"，推理性结论（攻击路径可行性/DoS 量级）标"推断 + 依据"，无法本地验证的列入 §8。**整改记录（reviewer R-01）**：初稿曾将 conn.go sysctl 写入的代码事实（WriteFile 调用存在）标为"已验证的宿主副作用"，经 reviewer 指出与 V1_验证报告.md:104 容器实测（/proc/sys 只读、写入失败仅 warn）矛盾后，已修正为"代码事实 vs 运行时事实"分离标注（§3 C-1），能力面论证改为基础能力推导 ✓

### 10.2 reviewer 反思结论

**第 1 轮（2026-08-16）：REVISE**。问题：R-01（Major）C-1 组"已验证的宿主副作用"与 V1_验证报告.md:104 容器实测（/proc/sys 只读、sysctl 写入失败仅 warn）直接矛盾，违反 §4.2 证据四态且与 §8 U-1 自相矛盾，需分离代码事实/运行时事实并补功能降级披露；R-02（Minor）A-5 遗漏 hResources 响应放大向量；R-03（Minor）API 口径 12/13 未标注；R-04（Minor）B-4 BEGIN IMMEDIATE 行号引用错误（store.go:43 → store_batch.go:43）；R-05（Note）VS-11 pid 可见性受容器非 root 限制；R-06（Note）B-3 未覆盖 fail2ban.sqlite3 WAL 一致性；R-07（Note）未引用/对照同日同基线交叉文档 DEV-VPS-001（含 cap_drop ALL 等建议）。评分 7/10。

### 10.3 reviewer 报告摘要与整改情况

**第 1 轮整改情况（本轮）**：
- R-01（Major）✅：C-1 表改为"sysctl 写入：代码事实 vs 运行时事实"分离标注（引用 V1_验证报告.md:104），能力面论证改为基础能力推导（host netns + NET_ADMIN → netlink 操纵 nftables/iptables，不依赖 sysctl 写成功）；§7 R-14 行删除"已验证的宿主副作用"表述；补功能降级披露（acct 不生效 → packets/bytes 恒 0、rmem_max 不提升 → netlink 缓冲受限）并列入 §8 U-8；§10.1 自检修正。
- R-02（Minor）✅：A-5 补 hResources 响应放大行 + 新增 VS-18（Note，P2 建议与 DEV-VPS-001 D7 对齐）。
- R-03（Minor）✅：§2.1/A-1/A-6 三处口径标注"任务书口径 12 / 实现 13（含 snapshot，api.go:65-78）"。
- R-04（Minor）✅：B-4 引用修正为 store_batch.go:43。
- R-05（Note）✅：VS-11 补 pid 可见性受限注（引用 DEV-VPS-001 §6 #9，U-9 待 VPS 复验）。
- R-06（Note）✅：B-3 补 WAL 一致性风险（§8 U-8 待 VPS 复验）。
- R-07（Note）✅：§7 对照表补 DEV-VPS-001 交叉对照行；P2 补 cap_drop: [ALL] + cap_add NET_ADMIN；VS-18 与 D7 对齐。

**第 2 轮（2026-08-16）：PASS_WITH_NOTES**。reviewer 逐行核验：R-01~R-07 七条整改全部真实落地（C-1 代码事实/运行时事实分离、conn.go:41/46 与 V1_验证报告.md:104 引用准确、§7 R-14 行与 §10.1 自检同步修正；A-5 补行与 VS-18、口径 12/13 三处标注、store_batch.go:43、VS-11 注与 U-9、B-3 WAL 注与 U-8、§7 DEV-VPS-001 对照行与 cap_drop ALL）；无 Blocker/Major 遗留；评分 8/10。本轮 N-01/N-02/N-03 三项文本级瑕疵已修正：N-01 经复核为 reviewer 子串匹配误报（range 含 ange 子串），L117/L226 实际均为 range=30d&step=5s；N-02 统计数已统一为 Note 10 项（VS-09~VS-18，§4/§9 两处）；N-03 交叉引用已移至 U-8①。§10.2/§10.3 回填如实。最终判定：**PASS_WITH_NOTES（无 Blocker/Major，可交付）**。
