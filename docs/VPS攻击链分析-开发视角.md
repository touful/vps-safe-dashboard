# VPS 攻击链分析——开发视角（DEV-VPS-001）

> 交付类型：只读分析（不修改任何代码/脚本/文档）；与 auditor（AUD-VPS-001）形成交叉分析。
> 分析对象：sentry-agent 部署 VPS（1C1G）场景，防御性分析（用户自有项目）。
> 证据状态约定：全文遵循 AGENTS.md §4.2 四态——「已验证」（有可追溯证据并核验）/「已观察」（有执行记录未独立核验）/「推断」（基于已知信息推导）/「未验证」。

## 1. 分析范围与方法

### 1.1 候选基线

- 候选基线 commit：`858c769`（chore: DEV-FE-006 审计遗留清理……），分支 `main`，工作区无已跟踪文件变更；本文档为新增未提交文件（Git 提交项 N/A，报告归属运营官统一处理，4.9 候选基线一致性以运营官核验为准）。
- 交付物：本文档（`docs/VPS攻击链分析-开发视角.md`）。

### 1.2 分析输入（已核验文件清单）

| 类别 | 文件 | 核验状态 |
| :--- | :--- | :--- |
| 部署资产 | `deploy/docker-compose.yml`、`deploy/Dockerfile`、`deploy/config.json`、`deploy/deploy.sh`、`deploy/check_env.sh`、`deploy/setup_firewall.sh`、`deploy/install_fail2ban.sh`、`deploy/setup_system.sh` | 已验证（全文阅读） |
| 采集/解析 | `internal/ssh/parse.go`、`internal/ssh/ssh.go`、`internal/fw/parse.go`、`internal/fw/fw.go`、`internal/fw/fw_kmsg_linux.go`、`internal/f2b/parse.go`、`internal/f2b/f2b.go`、`internal/conn/conn.go` | 已验证（全文阅读） |
| 存储/API | `internal/store/store.go`、`internal/store/store_batch.go`、`internal/api/api.go`、`internal/api/query.go`、`internal/api/ws.go`、`internal/event/event.go`、`internal/out/out.go`、`internal/config/config.go`、`cmd/sentry-agent/main.go`、`go.mod` | 已验证（全文阅读） |
| 前端 | `internal/web/static/app.js`（escapeHtml/表格/textContent/事件流/raw 显示点）、`internal/web/embed.go` | 已验证（关键点定位） |
| 文档 | `docs/技术方案.md`（6.4/6.5/6.7/7/8/9/10 章）、`docs/M4_部署手册.md`、`docs/M4_VPS复验清单.md` | 已验证（全文阅读） |
| 归档 | `internal/archive/archive.go`（文件创建权限点） | 已验证（关键点定位） |

### 1.3 方法与分工

- 方法：五条攻击链端到端走查（攻击者可控点 → 代码/配置防护 → 可利用性分级）＋ 部署配置可实施性复核 ＋ 运维纵深建议。
- 分工边界：auditor 侧重代码级安全审计与威胁建模（A~E 组攻击面）；本文档侧重**攻击链全链路的可利用性**（攻击者视角）与**加固方案的部署可实施性**，两者结论相互引用不重复。
- 分级标准：可利用性「高/中/低」= 触发条件可达性 × 影响面；「缺口」= 现有防护未覆盖且具备现实触发路径的点。

## 2. 五条攻击链走查结果

### 2.1 链 1：恶意 SSH 登录尝试 → journald → ssh parse → SQLite → API → 前端渲染

**链路节点与攻击者可控点**

| 节点 | 攻击者可控输入 | 现有防护（已验证代码位置） |
| :--- | :--- | :--- |
| journald 条目 | 攻击者经 SSH 协议可控制：username、公钥指纹、auth 次数；日志由 sshd 程序输出（非攻击者任意文本） | journald RateLimit 5s/5000（`setup_system.sh` 写入，journald.conf.d/99-sentry.conf） |
| ssh parse | username（`(\S+)`）、fingerprint（`(\S+)`）、src_ip（`(\S+)` + `net.ParseIP` 校验） | `internal/ssh/parse.go:83-124`：8 条模式全部限定 `\S+` 取用户名/IP，IP 经 `net.ParseIP` 合法才转 uint32；auth_method 由模式硬编码（password/publickey/空），非日志提取 |
| SQLite | username/detail 原样落库（无清洗，`store_batch.go:82-87`） | 参数化插入；detail 截断 512（`event.Truncate512`，rune 安全）；无任何拼接 SQL |
| API | —（查询参数全部参数化，`query.go` hSSH 的 conds/args 拼接为 `?` 占位） | 已核对 hSSH/hConnections/hFirewall 全参数化 |
| 前端渲染 | username 出现在：SSH 表格 username 列（`app.js:899` text 写入）、事件流 `'SSH 失败 <b>'+u+'</b>'`（`app.js:671-673`，escapeHtml 后 innerHTML）、折叠摘要 plain（textContent） | SSH 表格 cell 走 `textContent` 写入（`app.js:852-854`，DOM API 自动转义）；事件流 username 经 `escapeHtml`（`app.js:66-70`）；`title` 属性全部为 DOM 属性赋值（不解析 HTML）；态势条数字经 `Number()` 转换（`app.js:524`） |

**可利用性评估：低。**

依据：
1. 逃逸出"文本"语义的路径均被阻断：username 换行/空白注入 → 日志行不匹配任何模式（`\S+` 不跨行），该行被忽略（`ssh.go:100-105` 记 system_event），无法进入 DB——攻击者只能实现"记录绕过"（让自己的恶意用户名行不被采集），不能实现注入；
2. 前端渲染链全部走 textContent 或 escapeHtml，无 XSS 面（已验证 `app.js` 六处文本写入点：SSH 表/fw 表/事件流/折叠摘要/态势条/空态占位）；
3. detail 字段为原始日志行（可能含换行——journal 条目多行场景），textContent 渲染时换行折叠为空格，无标签逃逸（textContent 不解析 HTML，属浏览器行为，把握度高）；
4. 特殊 Unicode（RTL 覆盖符 U+202E、零宽字符）可进入 username 并正常匹配（`\S+` 匹配非空白 Unicode），渲染层不解析仅展示——**视觉混淆面**：攻击者可用隐藏字符伪造/混淆用户名（如显示为 root 实为 root\u200B）。影响为显示欺诈，无代码执行。

**缺口（Minor 级）：**
- 视觉混淆：用户名含 RTL/零宽字符时 UI 展示可被误导（防社工/报告误导）。
- 记录绕过：控制符用户名（含换行/制表）导致整行不匹配而被丢弃——攻击者可借此隐藏部分尝试（不产生计数），属"记录完整性"问题而非注入。
- 超长用户名（协议上限 255 字节）落库无长度限制：主要影响 DB 膨胀（DoS 向量之一，见链 5），UI 侧由 textContent 截断视觉。

### 2.2 链 2：构造恶意包 → nftables LOG → journald-kernel → fw parse → raw 字段 → 前端

**链路节点与攻击者可控点**

| 节点 | 攻击者可控输入 | 现有防护（已验证代码位置） |
| :--- | :--- | :--- |
| nftables LOG 输出 | 攻击者数据包头部字段（SRC/DST/SPT/DPT/PROTO/MAC/LEN 等）；内核按固定格式打印 | `setup_firewall.sh` 限速 5/s 突发 10（内核 `limit` 目标，事件率上界） |
| journald-kernel | —（journalctl -f -o json -k 子进程，仅内核日志） | `fw.go:48` 仅订阅内核通道 |
| fw parse | prefix 之后整行 | `fw/parse.go`：`strings.Index` 定位前缀；`reFWKV` 提取 `(SRC\|DST\|PROTO\|SPT\|DPT)=([^\s]+)`（值不得含空白）；IP 经 `ipToUint32` 严格点分校验；PROTO 走白名单映射；无 SRC/DST 键的行整体丢弃（`parse.go:72-74`） |
| SQLite | raw 字段原样存库（完整原始行，`store_batch.go:26-28`） | 参数化插入 |
| 前端 | raw 显示：`(r.raw \|\| '').slice(0, 60)` 截断 + `title: r.raw` 完整原文（`app.js:938`） | textContent 写入（截断文本）＋ title 为 DOM 属性赋值（完整原文，不解析 HTML） |

**可利用性评估：低。**

依据：
1. 内核 LOG 行格式固定（`SENTRY_FW:input:drop IN=... SRC=... DST=...`），攻击者能控制的是**字段值**（IP/端口/MAC），不能控制字段名、结构或插入空白（内核打印逻辑，`[^\s]+` 提取值亦确认值内无空白）；畸形 IP/端口值被 `ipToUint32`/`atou16` 校验消化为 0；
2. 前缀解析健壮性：`strings.Index(line, prefix)` 在行内任意位置匹配 `SENTRY_FW:`；攻击者无法向**内核日志**写入含该前缀的伪造行（写内核日志需内核模块/驱动能力，攻击者不具备——除非已 RCE，此时防护失去意义）；解析失败（缺 SRC/DST）限频记 system_event（`fw.go:89-93`）；
3. **信息面（SC-03 相关）**：raw 全量存库并经 `/api/v1/firewall` 返回；前端显示截断 60 字符、hover title 展示完整原文。信息面 = 面板读者可见攻击者自身流量的完整内核行（含 MAC 地址——若攻击者直连发包则为其本机网卡 MAC，经网关则为其网关 MAC；含 LEN/窗口等包特征）。MAC 泄露给面板读者属低价值信息（读者本即 VPS 管理员或经授权的访问者）；若面板经反代暴露公网（链 4 场景），攻击者读到的仍是自己的流量细节，无新增敏感面。

**缺口（Note 级）：**
- raw 全量保留无长度上限（内核行 ~1KB 内，journal 条目无额外截断）：DB 膨胀贡献因子之一，受链 5 缓解项覆盖。
- 前缀匹配为子串匹配：若未来有其他程序向**内核**日志输出含 `SENTRY_FW:` 的文本（如第三方内核模块），可能产生误解析——当前无现实路径，属防御性提示。

### 2.3 链 3：fail2ban.sqlite3（只读挂载）→ f2b 解析 → API → 前端

**链路节点与攻击者可控点**

| 节点 | 攻击者可控输入 | 现有防护（已验证代码位置） |
| :--- | :--- | :--- |
| fail2ban.sqlite3 | 攻击者不能直接写（root 属主 + 只读挂载）；攻击者能影响的是库中**自己的 IP** 与触发计数 | 挂载 `:ro`（compose:31）；库由 fail2ban 进程独占写入 |
| f2b 解析（QueryBanned） | — | `f2b.go:66-90`：`mode=ro` 只读打开；查询为静态 SQL `SELECT DISTINCT ip FROM bans`（无用户输入拼接）；IPv6 跳过 |
| f2b 日志（tail -F 子进程） | 日志行由 fail2ban 程序输出；攻击者可控制的是行内**自己的源 IP** | `f2b/parse.go:20` 正则 `\[([A-Za-z0-9_.-]+)\]\s+(Ban\|Unban\|Found)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`：jail 名限字符集（管理员配置，攻击者不可控）；IP 必须合法 IPv4（攻击者 IP 即源地址，格式被正则消化） |
| API/前端 | ban 事件表 + jail 名 | `query.go` hBans 参数化；前端 `app.js:687` jail 经 escapeHtml |

**可利用性评估：低。**

依据：
1. 只读模式 + 参数化查询 + 攻击者输入被正则严格消化（jail 名/类型/IP 三段均为受限字符集），无注入路径；
2. 攻击者唯一"输入面"是自己的 IP 字符串，受 IPv4 点分格式限制，无法携带控制字符或任意文本（fail2ban 程序格式化输出，非原样回显攻击者输入——已观察 fail2ban 日志格式固定，见 `f2b/parse.go:13-17` 行示例）。

**缺口（部署风险点，P1）：**
- **fail2ban.sqlite3 的 journal 模式未验证**：若 fail2ban 以 WAL 模式运行（Debian 包默认配置未确认），只读挂载仅挂主库文件时，容器侧读取可能滞后（WAL 数据未 checkpoint）或读到不一致视图；且 `QueryBanned` 的 DSN（`f2b.go:94-95`）未设 `busy_timeout`——fail2ban 写库瞬间只读打开可能立即 `SQLITE_BUSY`（每 60s 重试 + 限频告警，可用性问题而非安全问题）。需 VPS 复验项（对应 M4_VPS复验清单 fail2ban 真实库联调项，本报告补充 WAL 检查子项）。
- 只读挂载 + ACL（`install_fail2ban.sh:72`）组合在 fail2ban 轮转/重建库文件后 ACL 是否保持——install_fail2ban.sh 已用 setfacl 一次性设置，库文件被 fail2ban 重建时 ACL 丢失将导致容器读取失败（有告警路径，无静默风险）。

### 2.4 链 4：公网访问者 → 反代/隧道 → API/WS

**链路节点与攻击者可控点**

| 节点 | 攻击者可控输入 | 现有防护（已验证代码位置） |
| :--- | :--- | :--- |
| 反代/隧道 | 攻击者经公网到达反代（TLS 为手册建议，鉴权需用户自行补充，D-03） | 手册 6 节给出 SSH 隧道（推荐）/反代+TLS/直连三种方式；默认监听 127.0.0.1 |
| 12 只读 API（任务书口径；当前实现为 13 个 `/api/v1/*` 路由，含 snapshot，见 `api.go:65-78`） | 查询参数（range/limit/filter） | 全参数化查询；无写路由（`api.go:63-82` 路由表全部 GET 语义处理器）；**POST 请求同样匹配路由并执行查询**（`api.go:64-78` 注册模式未按 method 限定，POST 按 path 匹配进入同一处理器）——无副作用，仅确认"无写操作"依赖处理器无写逻辑这一事实 |
| WS | 连接请求（Origin 头可控） | `ws.go:77-88`：Origin 白名单校验；无 Origin 时按 `allowNoOrigin`（仅依赖监听地址判定，`main.go:263-277`） |

**可利用性评估：中（信息面扩大，无写操作面）。**

依据与关键缺口：
1. **snapshot 的 pid 字段**：`/api/v1/snapshot`（`query.go:309-338`）返回每条连接的 `Pid`。泄露面评估（reviewer 修订）：容器非 root（UID 1000）下 `ss -tanup` 的 `-p` 进程信息依赖 `/proc/<pid>` 读取权限（无 ptrace 权限时仅同 UID 进程可见），宿主 root 服务（sshd/nginx）的 pid 大概率不可见——实际泄露面约为 agent 自身及同 UID 进程，提权侦察价值低（推断，把握度高，未实测，见 §6 #9）。pid 脱敏保留为低成本纵深防御项（§3.3 D4），不按 P1 缺口定级。
2. **WS Origin 校验的绕过评估（CT-04 相关）**：Origin 白名单仅拦截"浏览器跨站"（恶意网页 JS 连 WS 会带 `Origin: http://evil.com` ≠ 白名单 → 403 ✓）；**非浏览器客户端（curl/wscat/python）不发送 Origin 头 → 命中 `allowNoOrigin` 分支**。`allowNoOrigin` 只依赖 `cfg.Web.Listen` 是否回环（`main.go:140,263-277`），不依赖连接来源——当监听 127.0.0.1 且经 nginx 反代暴露公网时，远程非浏览器客户端**可绕过 Origin 白名单直连 WS**（M-02 的"回环 = 仅本机可达"假设被反代打破）。影响面：WS 为纯推送（读循环仅探测关闭，`ws.go:100-107` 不消费客户端消息），攻击者获得实时资源/连接统计/system 事件流增量，无写能力。风险等级：中低（信息面，无写）。
3. **攻击者经 API 可获得**：SSH 尝试明细（`query.go:116-165` hSSH 无 result 过滤——含全部失败与**成功登录记录**（合法用户名/时间/来源 IP），攻击者可确认自身记录、观察竞争者、公网暴露时观察管理员活动规律）、封禁列表与 jail（可确认自身封禁状态、推断 fail2ban 阈值策略）、fw 事件与 top_ports（探测规则布局）、归档文件名+大小（推断数据保留策略）、资源指标与 health（uptime/db_size/system_events 计数——探测负载与重启史）。全部为只读信息，无写操作接口，无 CSRF 价值面（响应为 JSON，跨站不可读，`api.go:120-124`）。
4. POST 行为确认（CT-04）：POST 到任一 API 路径会执行对应 GET 查询并返回数据（无方法校验）；无写副作用；对 CSRF 无意义。
5. **Note（reviewer 补充，可用性面）**：反代场景下正常浏览器客户端的 WS 请求 Origin 为 `https://panel.example.com`，不等于白名单 `http://127.0.0.1:8080`（`ws.go:85-87` 精确串比较）——浏览器 WS 全 403、前端自动降级轮询。反代/隧道访问形态变更时须同步修改 `web.ws_origin_allow`（`config.go:219-225` 有格式校验，无联动提示）。

**缺口（P1）：**
- 反代暴露场景下 WS 无 Origin 客户端可连（M-02 假设失效）；
- **反代鉴权缺失**：手册 6 节反代示例仅 TLS（`M4_部署手册.md:74-89` 无 auth_basic），鉴权（Basic Auth/OIDC）需用户自行补充——用户若仅按示例部署或直连 0.0.0.0，链 4 与链 5 全部可利用。

### 2.5 链 5：资源耗尽 → DoS

**链路节点与触发路径**

| 节点 | 攻击者可控输入 | 现有防护（已验证代码位置） |
| :--- | :--- | :--- |
| 聚合查询 CPU | 高频并发调用 `range=30d` 的 timeline/summary/top_ports/top_sources | 30d timeline 已放宽超时至 30s（`query.go:381-386`，DEV-018 P-01：千万行级 SUM CASE 聚合 2-8s）；**无 API 速率限制中间件**；只读连接池 4（`api.go:47`） |
| HTTP 连接 | 慢速连接（不发送请求头） | **`http.Server` 未设置 ReadHeaderTimeout/IdleTimeout/ReadTimeout**（`api.go:88-101`，Go 默认 0 = 无超时）——slowloris 面：每个挂起连接占用 goroutine + 缓冲，mem_limit 256m 下数千连接可触发 OOM kill → docker restart 循环 |
| WS 连接 | 批量建立 WS 连接 | 无连接数上限（`ws.go` wsHub 无 max）；慢客户端帧丢弃已有（`ws.go:59-70`），但连接本身占资源 |
| SQLite 锁/写线程 | 查询持续占用只读连接 | WAL 下读写并发（读不阻塞写）；`BEGIN IMMEDIATE` 写事务与归档串行（`store.go` 单写线程）；查询队列积压表现为延迟而非失败 |

**可利用性评估：中（条件触发——默认回环监听下不可达）。**

依据：
1. 触发前置条件 = API 被公网可达（直连 0.0.0.0 或反代无鉴权）。默认部署（127.0.0.1 + SSH 隧道）下外部攻击者无路径触达，链 5 不可利用；用户若按手册反代部署且未加 Basic Auth/速率限制，则 30d 聚合查询（2-8s/次）可被并发调用打满 1C1G CPU → 采集通道/存储写线程受影响 → netlink 溢出事件（有留痕，R-10）→ 记录完整性下降；
2. slowloris 面（HTTP 无超时）为 Go 标准库默认行为（已验证 `api.go:88` 未设置超时字段，标准库文档确认默认 0 无超时），真实可利用：攻击者建立 TCP 连接不发请求即可占资源，容器 256m 限制下可 OOM；
3. WS 无连接上限：批量连接 + 不发读（读循环会阻塞等待客户端消息——攻击者可只建立连接不读，写循环被 deadline 保护（10s），但连接与 goroutine 持续占用）。

**缺口（P1/P2，需开发改动，见 3.3 节）：**
- HTTP Server 超时配置缺失（slowloris）；
- 无 API/WS 连接速率与数量上限；
- 30d 聚合无缓存（重复调用重复全表扫描）；
- hResources 响应放大（reviewer 补充）：`range=30d&step=5s` 时桶数无上限（`query.go:14-48`，resources 5s 一条采样，30d 约 51.8 万桶，单响应可达数十 MB）——并发请求放大内存/带宽消耗（正常前端固定 step=60s 不受影响）；建议 step 与 range 组合校验或桶数上限（P2，§3.3 D7）。

## 3. 部署配置加固方案（按可实施性分级）

### 3.1 直接可落地配置建议（不改代码，改 compose/Dockerfile/部署脚本，工作量小）

| # | 建议 | 位置 | 说明/风险 |
| :--- | :--- | :--- | :--- |
| C1 | `cap_drop: [ALL]` + 保留 `cap_add: [NET_ADMIN]` | docker-compose.yml | 当前仅 cap_add NET_ADMIN，Docker 默认 cap 集（14 项，含 NET_RAW/SYS_CHROOT/MKNOD/AUDIT_WRITE 等）仍然生效；显式 drop ALL 是基线（Docker 官方安全基线建议）。风险：低；需 VPS 复验 conntrack 在纯 NET_ADMIN 下行为（V-03 已覆盖） |
| C2 | `read_only: true` + `tmpfs: /tmp:size=8m` | docker-compose.yml | 只读 rootfs 防持久性写入；tmpfs 兜底 /tmp 写入（journalctl/ss 子进程运行时若有临时需求）。风险：中低——需在 VPS 复验 journalctl 子进程只读 rootfs 行为（journalctl -f 读 + inotify，无写路径，把握度高；未实测，列入未验证清单 #3） |
| C3 | `pids_limit: 128` + `ulimits: nofile: 1024` | docker-compose.yml | 防 fork/连接耗尽放大；agent 子进程仅 journalctl×2 + tail×1 + ss（定期），128 上限充足。风险：低 |
| C4 | `init: true` | docker-compose.yml | docker-init（tini）回收 journalctl/tail 子进程僵尸（当前无 PID1 回收，子进程退出后可能僵尸化直到容器退出）。风险：低 |
| C5 | `healthcheck` 加入 compose | docker-compose.yml | 容器内无 curl/wget，用 bash /dev/tcp 探活（deploy.sh:92 已有同款逻辑可复用）；与 `restart: unless-stopped` 配合自动恢复。风险：低 |
| C6 | 数据目录收紧：`chmod 700 /var/lib/sentry-agent`（deploy.sh 第 5 步 chown 后追加） | deploy/deploy.sh | **当前缺口**：目录默认 0755 + SQLite 建库按 umask 创建（`store.go:177-184` 无显式 chmod；umask 022 → 0644 为 Docker 默认推断值，未实测——无论 umask 为何，代码无显式 chmod 的结论方向不变）；归档副本显式 0644（`archive.go:217` OpenFile 0o644，硬证据）——与方案 8.1"目录 0700/文件 0600"声称（`技术方案.md:975/988/993`）**不符**。多用户 VPS 上其他本地用户可读含 IP/用户名/指纹的库与归档。目录 0700 一步覆盖全部（含归档），建议立即落地。风险：低 |
| C7 | 镜像 tag 锁定与定期重建：`debian:bookworm-slim` 建议记录 digest 或固定日期 tag | Dockerfile | 防基础镜像漂移；升级路径见 4.3。风险：低 |
| C8 | 宿主 SSH 加固与防火墙默认策略（**只给建议不改手册**，P0） | 宿主 | ①SSH：公钥认证 + `PasswordAuthentication no`（或 PermitRootLogin prohibit-password）+ 白名单端口或 fail2ban 已覆盖 22 端口爆破；②防火墙默认 INPUT DROP 策略 + 放行 22/面板隧道端口——setup_firewall.sh 只插 LOG 不设策略，若 VPS 默认无拒绝策略，LOG 通道数据稀疏且暴露面大（check_env C-07b 已提示"无 drop 规则时通道稀疏"） |

### 3.2 需用户决策项

| # | 决策项 | 建议倾向 | 说明 |
| :--- | :--- | :--- | :--- |
| U1 | 面板公网访问形态（D-03 执行口径） | 仅 SSH 隧道或反代 + TLS + 鉴权（Basic Auth/OIDC，手册示例未含，需用户自行补充） | 若反代部署：必须补鉴权（否则链 4/链 5 全部可利用）；`0.0.0.0` 直连仅限内网可信网络；访问形态变更时同步改 `web.ws_origin_allow` |
| U2 | fail2ban 封禁策略强度 | 维持记录优先（bantime 1h）或调强 | 当前阈值保守（maxretry 5/findtime 10m/bantime 1h）；攻击频繁时可选 recidive jail（二次封禁加长） |
| U3 | 镜像安全更新策略 | 定期 rebuild（月/季度）+ 部署前 digest 复核 | 涉及基础镜像与 Go 依赖（4.3） |
| U4 | AppArmor/自定义 seccomp（可选） | Docker 默认 seccomp 已启用；AppArmor 需宿主 profile | 1C1G 运维成本权衡，非必需 |

### 3.3 需开发改动项（本次只建议不实施）

| # | 建议 | 工作量 | 风险 | 优先级 |
| :--- | :--- | :--- | :--- | :--- |
| D1 | `http.Server` 补超时：ReadHeaderTimeout（5s）/IdleTimeout（60s）/ReadTimeout（10s） | 小（`api.go:88-89` 结构体字段） | 低 | P1（slowloris 面） |
| D2 | WS 连接数上限（如 64）+ API 查询频控（如 10 req/s/IP 滑动窗口） | 中 | 低 | P1 |
| D3 | 主库/归档文件显式 `os.Chmod(0600)`（store 建库后、archive 写入后）或依赖目录 0700（C6 落地后可不做） | 小 | 低 | P2（C6 覆盖后可选） |
| D4 | snapshot 响应按监听地址脱敏 pid（非回环监听时 pid 置 -1） | 小 | 低 | P2 |
| D5 | 30d 聚合结果缓存（分钟级 TTL） | 中 | 低 | P2（DoS 缓解） |
| D6 | 依赖升级：`golang.org/x/net v0.0.0-20220923203811-8be639271d50`（2022-09，陈旧）与 `gorilla/websocket`（v1.5.x，1.5.3 发布于 2024 年，2026 视角下仍属陈旧，升级前核对上游 changelog）更新；`go mod tidy` 复核 | 小 | 低 | P1（漏洞响应路径，见 4.3） |
| D7 | hResources 桶数上限（如 step=5s 时限制 range ≤7d）或 step/range 组合校验 | 小 | 低 | P2（响应放大缓解） |

### 3.4 部署手册/M4 清单安全建议完备性缺口（P0/P1/P2 补充建议，只给建议不改手册）

- **P0**：SSH 公钥认证与禁密码登录（手册未含；fail2ban 仅缓解不根治）；防火墙默认 DROP 策略（手册未含策略设置，仅 LOG 插入）；
- **P1**：自动安全更新（unattended-upgrades/apt 每日）、备份验证（手册 8 节建议异地拷贝 archive——补充"定期恢复演练"与 state.db 备份一致性说明：主库直接拷贝需停 agent，手册 5 节已有提示）；
- **P1**：数据目录权限收紧（C6，含归档文件 0644 问题——与方案 8.1/8.2 权限声称不一致，属文档-实现偏差，建议运营官知会文档侧修订或代码侧显式 chmod）；
- **P2**：Docker daemon 配置复核（无 TCP 远程 API、rootless 可选）、内核参数（rp_filter/tcp_syncookies 默认开启即可，非必需）、auditd（方案 7.1 已声明不依赖）。

## 4. 运维与纵深防御建议

### 4.1 敏感数据保护

- **库与归档**：C6（目录 0700）落地后，state.db/归档 gz 均受目录保护；异地备份介质按敏感数据处理（含 IP/用户名/指纹/防火墙日志，属个人/攻击者数据，注意备份留存合规）；
- **备份**：archive 目录按月自然生成（gzip 副本），建议 rsync/rclone 异地（手册 8 节已有）；首次部署后做一次"备份→解压→查询"演练（P1）；
- **访问链路**：面板数据（用户名/IP/指纹）经隧道/反代 TLS 传输，避免明文 HTTP 公网（D-03 直连方式仅限内网）。

### 4.2 监控与告警（工具自身反哺 VPS 安全）

- **封禁告警**：面板封禁记录即 fail2ban 生效视图；system_event 中 f2b 查询失败告警（`main.go:249-256`）监控 fail2ban 库健康；
- **磁盘水位**：三级告警（warn/critical/emergency，`diskmon`）已内置，是"只记录"模式的核心兜底——建议配置外部通知（如 cron 定时 curl health/磁盘 df 报警脚本，1C1G 不加重型监控代理）；
- **攻击发现闭环**：面板自身即攻击态势视图——SSH 失败时间线、top_ports、封禁列表可交叉确认攻击源；注意面板信息面（链 4）——公网暴露时攻击者可见相同视图（封禁状态/规则布局），鉴权必须到位；
- **Docker 层**：`docker logs`（json-file 10m×3 已有）+ 容器 restart 事件监控（OOM 或异常退出时 `docker events` 留痕）。

### 4.3 升级与漏洞响应路径

- **依赖更新**：`go get -u` 定期 + `go mod tidy`；重点：`golang.org/x/net`（v0.0.0-20220923203811，2022-09 陈旧）、`gorilla/websocket`（v1.5.x，1.5.3 为 2024 年发布，2026 视角下仍陈旧）、`modernc.org/sqlite`、`florianl/go-conntrack`；审计 go.sum 后重建镜像（多阶段构建保证运行时无构建工具）；
- **镜像重建**：`docker compose up -d --build`（手册 8 节已有）；基础镜像 digest 锁定（C7）防漂移；schema 变更需版本化迁移（schema_version=1，手册已提示）；
- **响应预案**：①发现 agent 漏洞 → 停面板（`docker stop`）+ 保留数据卷 → 修复后重建；②宿主被入侵 → 面板数据（IP/指纹/攻击时间线）可作取证材料（只读挂载下攻击者无法篡改 journal 与 fail2ban 库——注意 state.db 卷为 rw，入侵后可能被篡改，取证优先用 journal/fail2ban 只读源 + 归档副本）。

## 5. 与审计（AUD-VPS-001）交叉的分歧/补充点

> 本报告主体完成时 auditor 报告尚未产出，以下为**待对照补充清单**（auditor 报告出后由运营官合并或本报告修订补充）：

1. **待对照**：auditor A~E 五组攻击面的代码级结论 vs 本文档链路级结论——重点对照链 1 的 XSS 结论（本文档：低，前端 textContent/escapeHtml 全覆盖）与链 4 的 WS Origin 绕过评估（本文档：非浏览器客户端无 Origin 头在反代场景可连，M-02 回环假设失效）；
2. **待对照**：auditor 对 SQLite 只读连接（api mode=ro、f2b mode=ro）与写线程并发模型的审计 vs 本文档链 3 的 WAL/只读挂载一致性风险；
3. **本文档特有补充**（auditor 可能不覆盖的部署侧点）：snapshot pid 字段公网可见性（链 4，reviewer 修订后为纵深防御项）、HTTP Server 无超时 slowloris 面（链 5）、主库/归档文件权限与方案 8.1 声称不符（C6）、fail2ban.sqlite3 WAL 挂载一致性（链 3）、POST 请求执行 GET 语义（CT-04）。

## 6. 未验证假设清单

| # | 假设 | 状态 | 验证路径 |
| :--- | :--- | :--- | :--- |
| 1 | NET_ADMIN 为 conntrack netlink 组播订阅必需、NET_RAW 不足（netlink(7) man 页 + searcher 调研） | 推断（把握度高，未实测 root 豁免） | M4_VPS复验清单 V1b-1（root 免 cap-add 行为） |
| 2 | fail2ban.sqlite3 的 journal 模式（WAL?）与只读挂载一致性 | 未验证 | VPS 复验：`sqlite3 fail2ban.sqlite3 "PRAGMA journal_mode;"` + 容器挂载后 QueryBanned 一致性 |
| 3 | journalctl 子进程在只读 rootfs（C2）+ tmpfs 下的行为 | 未验证 | VPS 复验（C2 落地前先行验证） |
| 4 | 30d 聚合 2-8s 记录（DEV-018 P-01 注释） | 已观察（内部文档记录，未独立复测） | VPS 大库场景计时 |
| 5 | 攻击者畸形包无法向内核 LOG 行注入空白/结构（内核打印格式固定） | 推断（把握度高，未畸形包实测） | VPS 可选：畸形包测试观察 raw |
| 6 | 容器内 /proc 资源口径（cgroup 视图 vs 宿主全貌） | 推断（方案 6.4.4 V1b-3 排期） | V1b-3 复验 |
| 7 | Go http.Server 默认无超时（ReadHeaderTimeout=0） | 已验证（标准库文档 + 代码 `api.go:88-89` 未设置） | — |
| 8 | 攻击者用户名含控制符（换行/制表）导致 ssh 行不匹配被丢弃 | 推断（基于 `\S+` 正则语义，未实测 sshd 输出行为） | 可选：构造畸形用户名实测 |
| 9 | 非 root 容器内 `ss -tanup` 的 pid 可见性受限（仅同 UID 进程可见） | 推断（基于 Linux /proc 权限模型，把握度高，未实测；若实测可见更多进程，链 4 pid 点恢复为真实缺口） | VPS 复验：容器内执行 `ss -tanup` 观察 root 进程 pid 是否可见 |

## 7. 自检结果与 reviewer 反思结论

### 7.1 developer 公共自检（AGENTS.md §4.8 七项）

1. **验收标准覆盖**：任务书 §四 的 7 节结构全部对应（§1 范围与方法 / §2 五链走查 / §3 加固方案 / §4 运维建议 / §5 交叉点 / §6 未验证假设 / §7 自检）；§五 执行要求全部满足（deploy/ 全部 + internal 关键文件 + 手册 + 技术方案已通读；只读分析未修改任何代码/脚本/手册；§4.2 四态标注贯穿全文；reviewer 已调用）。
2. **验证证据**：§2 每条链的可利用性结论均对应本次实际阅读核验的代码位置（约 30 处文件:行号引用）；部署脚本行为核验自文件原文；前端转义点核验自 `app.js` 实际写入方式。
3. **未验证项**：§6 九项假设清单（含 2 项"已验证"反向确认：http.Server 无超时、路由/权限代码位置）；NET_ADMIN 必要性为推断（把握度高，V1b-1 排期复验）。
4. **范围漂移**：无——仅新增交付物 `docs/VPS攻击链分析-开发视角.md`，未修改任何现有文件（Git 提交 N/A 归运营官）。
5. **风险与不确定点**：①NET_ADMIN 必要性未实测（推断，复验项 V1b-1）；②fail2ban.sqlite3 WAL/只读挂载一致性未验证（P1 部署风险）；③前端 XSS 结论依赖 textContent/escapeHtml 语义（把握度高，属浏览器标准行为）。
6. **下游上下文**：候选基线/变更文件/设计决策/行为变化/已知坑点已在本节与 §1.1/§3/§4 记录；交叉分析接口（§5）已预留。
7. **是否建议验收**：建议验收（PASS_WITH_NOTES）——五链可利用性评估与加固建议均有代码/文档级证据支撑，无 Blocker/Major；遗留为 Minor/Note 表述项与 VPS 复验排期项。

### 7.2 developer 角色专属自检

- 代码未改动（只读任务），风格/约定项 N/A；本地自测 N/A（无代码变更）；无硬编码密钥（未新增任何代码）。
- 非预期改动检查：diff = 仅新增 1 个交付物文件；无"改进"相邻文件、无删除。
- 既有失败区分：N/A（无执行测试）。

### 7.3 reviewer 反思结论（第 1 轮，2026-08-16）

- 结论：**PASS_WITH_NOTES**（无 Blocker/Major；10 项 Minor/Note）。
- 已整改（R-01~R-05，Minor）：①Basic Auth 表述修正——手册反代示例仅 TLS 无鉴权（§2.4/§3.2 U1）；②API 路由计数注明任务书口径 12/实现 13（§2.4 表）；③snapshot pid 泄露面降级为纵深防御项并补 §6 #9 假设（§2.4 第 1 点）；④§7 自检节实际填写（本节）；⑤依赖版本时间表述修正（§3.3 D6/§4.3）。
- 已采纳（R-06~R-10，Note）：⑥hResources 响应放大向量入链 5 缺口 + D7 建议；⑦反代下浏览器 WS Origin 误拒可用性提示（§2.4 第 5 点）；⑧ServeMux method 表述与 8.2 原文引用修正；⑨C6 umask 022 标注为推断默认值；⑩基线 git 状态表述补充（§1.1）。
- 未决风险（reviewer 标注）：ss -p 非 root 可见性、fail2ban 库 journal 模式均列入 §6 假设清单待 VPS 复验；基线状态待运营官 git 核验。

### 7.4 reviewer 第 2 轮复核结论（2026-08-16）

- 结论：**PASS_WITH_NOTES**——R-01~R-10 全部整改确认（逐项核验，新增引用行号全部准确），无新引入问题，无 Blocker/Major。
- 本轮新增 R-11（Note，已采纳）：§2.4 第 3 点信息面补充"成功登录记录（result=1）公网暴露时可观察管理员活动规律"（依据 `query.go:116-165` hSSH 无 result 过滤）。
- 遗留：仅 VPS 复验排期项（§6 #2 fail2ban 库 WAL、#9 ss -p 可见性）与 R-11 已采纳项，不阻塞交付。
