# AUD-FE-004 P1 安全加固 + 数据导出合并审计（发布候选终审）

## 1. 审计范围与方法

- **候选基线**：`b2590b7`（main，HEAD，工作区 clean）；上游含 DEV-P1-001R（`1f32fe8`+`60db089`）与 DEV-EXPORT-001（`13ab430`+`b2590b7`）全部改动。
- **审查范围**：`internal/api/{api,ratelimit,ws,export}.go`、`internal/store/store.go`、`internal/archive/archive.go`、`internal/config/config.go`、`internal/fw/parse.go`、`internal/web/embed.go`、`internal/event/event.go`（Truncate512）、`cmd/sentry-agent/main.go`、`internal/web/static/{index.html,app.js}`、`config.example.json`；配套测试 `api_test.go`/`export_test.go`/`ratelimit_test.go`/`ratelimit_rhythm_test.go`/`parse_test.go`。
- **基线漂移核验**：git diff `7a16523..b2590b7` 文件清单共 20 项（含 2 张证据图），与任务书预期清单完全一致；**无越权改动**（deploy/ 目录零变更，deploy/config.json 新字段为 DEV-P1-002 于 `d4b0a79` 预置，与 config.go 默认值一致）；**无新依赖**（go.mod 未变）。
- **动态验证**：`go test ./internal/api/... ./internal/fw/... ./internal/store/... ./internal/archive/... ./internal/config/... ./internal/event/...` 全通过（api 包 38.8s，含限流/WS/导出专项）。
- **依据文档**：AUD-VPS-001（VS-01~VS-12，P1 清单 §6）、AUD-FE-001/002/003 安全结论继承；TEST-FE-003 审计时点尚未产出（tester 并行执行中，未纳入证据链，见 U-1/U-3）。

## 2. 各要点核查结果（代码位置证据）

### 2.1 限流实现（VS-04）——通过

| 检查项 | 结论 | 证据 |
| :--- | :--- | :--- |
| 令牌桶并发安全 | Mutex 全方法串行化；elapsed 连续补充（`tokens = min(burst, tokens + dt*rate)`）封顶，无瞬时灌满 | ratelimit.go:17-44 |
| 429 响应 | `Retry-After: 1` + JSON 错误体；拒绝留痕 system_event warn（限频 1/分钟防刷屏） | api.go:136-159 |
| health 豁免 | `/api/v1/health` 未套限流包装（运维探活） | api.go:113 |
| heavy 端点清单 | summary、ssh/timeline、firewall/timeline、export/csv 四项，与任务书完全一致 | api.go:114/121-124 |
| heavy burst 决策 | 固定 6（实测驱动：Chrome 同源 6 连接限制下慢查询排队与下轮重叠，burst 3 偶发误伤稳态；单测 + 注释完整记录取舍链） | api.go:79-84, 102-110 |
| 绕过面 | ServeMux 路径归一化（Go 1.26，go.mod:3）：路径变体（`//`、`..`）被 301 归一到精确路径，重定向后再被限流；查询参数不影响路由匹配；无通配符路由。**未发现绕过路径** | api.go:111-132 |
| 与正常轮询余量 | 全局 10 rps/burst 20 vs 前端 5s 轮询 9 请求 ≈1.8 rps/burst 9；`TestRateLimitNormalPollNotAffected` 两轮 9 端点零 429 | api_test.go:671-698；main.go:157-160 |
| 配置注入 | `SetLimits` 仅启动时调用（运行期不热更新，注释声明）；config 校验范围（rps 1-1000/burst 1-10000/ws_max 1-10000/heavy 1-100） | api.go:74-89；config.go:235-247 |

### 2.2 WS 限制（VS-03）——通过（reviewer 三轮证伪点逐项核验）

| 检查项 | 结论 | 证据 |
| :--- | :--- | :--- |
| tryAdd 时机 | 在 `Upgrade` 之前原子占位，超限返回 503（hijack 后无法再写 503） | ws.go:108-111 |
| 升级失败回滚 | `s.hub.remove(c)` 回滚占位；`TestWSUpgradeFailRollback` 验证上限 1 时失败后仍可连 | ws.go:117-119；api_test.go:767-789 |
| remove 幂等 | `if _, ok := h.clients[c]; ok` 检查后才 delete+close，重复调用安全 | ws.go:56-63 |
| done 唯一 close | `close(done)` 唯一方为读循环（写循环只 `<-done`）；函数返回后 channel 无引用 GC 回收 | ws.go:131-143 |
| broadcast 非阻塞 | select default 丢弃满缓冲帧（方案 2.2.3 可丢弃陈旧帧） | ws.go:72-82 |
| 无 send-on-closed 竞态 | close(c.send) 仅在 remove 内且持锁；broadcast 持锁期间 remove 不可能并发 close | ws.go:56-82（同一把 mu） |
| SetReadLimit | 4KB（客户端仅探测消息，无业务上行帧） | ws.go:123 |
| 握手 deadline | 升级写响应 5s（ReadHeaderTimeout 5s 覆盖读侧，二者合为完整握手超时）；httptest 下 ErrNotSupported 忽略 | ws.go:115；api.go:175 |
| 拒绝路径 | Origin 白名单失败 403；超限 503；无 Origin 且非回环监听 403 | ws.go:96-105 |
| 占位回收测试 | `TestWSMaxConnsReject`：上限 2 时第 3 连接 503，断开后 3s 内占位释放可重连 | api_test.go:729-765 |

### 2.3 权限（VS-01）——通过

| 检查项 | 结论 | 证据 |
| :--- | :--- | :--- |
| 目录 0700 | 主库目录、归档目录均 `MkdirAll(0o700)`（NewStore + ArchiveMonthDB 双处） | store.go:143-150；archive.go:75-77 |
| chmodDataFiles 双时机 | NewStore（Open 后立即收权）+ Run 首次 flush 后（WAL/SHM 伴随文件创建后补收权，reviewer R-11） | store.go:162-164, 240-257 |
| WAL/SHM 0600 | 主库 0600 + `-wal`/`-shm` 存在即收权；缺失跳过 | store.go:202-215 |
| 归档 tmp/gzip 0600 | ATTACH 创建 `.db.tmp` 后显式 Chmod 0600（gzip 前）；gzip 文件 OpenFile 0o600 | archive.go:130-134, 226 |
| Windows 兼容 | Chmod 失败仅留 warn 不阻塞（Windows 受限 no-op，无权限语义，功能不回归） | store.go:161；store.go:254-256 |

### 2.4 HTTP 超时（VS-02）——通过

- `ReadHeaderTimeout: 5s`（Slowloris）、`IdleTimeout: 60s`（keep-alive 回收）、`MaxHeaderBytes: 64KB`（默认 1MB 收敛）——api.go:171-178。
- 无 ReadTimeout/WriteTimeout 的取舍注释合理：gorilla/websocket 升级 hijack 后由 `websocket.Conn` 自管（写循环 SetWriteDeadline 10s），http.Server 超时对 hijack 连接不再生效；仅约束升级前头读取阶段，不影响 WS 长连接生命周期——api.go:167-170, ws.go:154。

### 2.5 CSP 安全头（VS-12）——通过

- CSP 与任务书逐项一致：`default-src 'self'; script-src 'self'; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws://127.0.0.1:8080; font-src 'self'`；X-Content-Type-Options: nosniff；X-Frame-Options: DENY——embed.go:35-38。
- 前提核验成立：index.html 无内联 script（echarts.min.js/app.js 外部文件）；内联 style/style 属性依赖 `'unsafe-inline'`；data URI favicon 依赖 `img-src data:`——embed.go:29-32。
- 改端口/反代说明：显式 `ws://127.0.0.1:8080` 仅覆盖默认形态；CSP3 `'self'` 匹配同 host+port 的 ws/wss，改端口无需改头；反代域名场景须同步本头（部署手册 §WS Origin 说明联动）——embed.go:17-20。

### 2.6 导出端点（DEV-EXPORT-001）——通过（含信息泄露面评估）

| 检查项 | 结论 | 证据 |
| :--- | :--- | :--- |
| SQL 参数化 | 三源 UNION ALL 全部 `?` 绑定（from/to 6 处），无任何拼接；表名/列名静态 | export.go:71-81 |
| CSV 转义 | 标准库 encoding/csv（RFC 4180，逗号/引号/换行自动引号）；`TestExportCSVEscape` 断言转义行为 | export.go:90；export_test.go:206-218 |
| 参数校验 | range 与 from/to 二选一（同给/都缺 400）；from>to 400；跨度上限 90 天；**R-01 溢出回绕**（`span<0` 兜底 int64 回绕绕过）；非数字 400 | export.go:27-59；export_test.go:26-52 |
| 流式写 | 逐行 `cw.Write` 写 ResponseWriter，无整表内存峰值；空数据 200+空文件 | export.go:91-108 |
| 查询失败路径 | rows.Err() 检查 + limitWarn 留痕（R-04 reviewer 整改）；查询失败在写 CSV 头之前返回 500 JSON | export.go:87, 111-114 |
| 超时 | 30d/跨度>7d 放宽 30s，其余 5s（与 hFirewallTimeline 同模式） | export.go:63-66 |
| heavy 限流 | 注册处套 limitHeavy（1 rps/burst 6），`TestExportRateLimitHeavy` 第 7 个 429 + Retry-After 断言 | api.go:124；export_test.go:222-239 |
| 索引支撑 | firewall/ssh/ban 三表均有 ts 索引（idx_fw_ts/idx_ssh_ts/idx_ban_ts），30d 区间查询走索引非全表扫 | store.go:76/92/103 |

**信息泄露面评估（重点）**：export 暴露攻击者 IP/时间/端口全量。与既有 12 端点对比：

- **数据同类**：firewall/ssh/ban 事件本就是既有端点数据源；export 仅拉取三列（IP/时间/端口），而 `/api/v1/ssh` 含 username/fingerprint、`/api/v1/firewall` 含 raw 完整日志行、`/api/v1/connections` 含连接明细——**export 字段严格少于既有端点，无新增敏感维度**。
- **新增能力**：全量拉取（无 TOP 截断/无分页）vs 既有聚合视图——攻击者可枚举"本主机记录的全部攻击者 IP 时间线"。泄露价值限于攻击元数据画像，与面板既有信息同级。
- **限流**：heavy 1 rps/burst 6 已挂（与 30d 聚合端点同级）；默认监听 127.0.0.1。
- **判断**：**与既有 12 端点暴露策略一致，无需额外强制保护**；暴露面兜底责任在部署决策（AUD-VPS-001 Top1：面板暴露→无鉴权读取，P0 前置鉴权建议同样覆盖导出端点）。记录 Note（N-03）建议文档提示。
- **错误响应体**：export.go:83 查询失败路径将 SQLite 内部错误（"查询失败: " + err.Error()"）写入 500 JSON 响应体——与既有端点（api.go:332 hSummary 同模式）一致，非新增；错误细节可能含文件路径/DB 状态，建议后续统一收敛错误文案（Note，N-R2）。

### 2.7 前端（第 4 页签）——通过

| 检查项 | 结论 | 证据 |
| :--- | :--- | :--- |
| 页签结构 | nav 第 4 按钮 + panel-export（预设/自定义/按钮/msg/note），aria-label/role=status 齐全 | index.html:540, 652-674 |
| 导出逻辑 | fetch blob → createObjectURL → a.download → revokeObjectURL（下载后立即回收）；按钮 disabled 防重复点击；429/空数据/错误均有提示 | app.js:1410-1459 |
| 轮询门控 | `pollAll` 首行 `if (state.activePanel === 'export') return;`（R-03 整改）；export 页激活不触发任何拉取；WS 推送帧渲染由 vis() 门控跳过（render 函数开头 `if (!vis(...)) return`），无隐藏面板 DOM 开销 | app.js:1189-1193, 1464-1492, 83 |
| XSS 纪律 | 新增文案全部 textContent 赋值（exportMsg/错误消息）；无 innerHTML/insertAdjacentHTML；错误消息来自服务端固定文案 | app.js:1370-1374, 1448-1456 |
| 时区处理 | datetime-local 无时区后缀 → `new Date(v).getTime()/1000` 按本地时区解释转 Unix（与后端 time.Unix 本地时区格式对称）；默认值 fmt 本地时区 | app.js:1422-1432, 1394-1406 |
| 前后端校验一致 | from>to、90 天跨度、必填在前端均有预校验（后端仍兜底） | app.js:1430-1433 |

### 2.8 范围控制与契约——通过（附 Note）

- **范围控制**：diff 文件清单与任务书预期一致；无越权改动；无新依赖；deploy/ 零变更（config.json 新字段为 DEV-P1-002 预置，值 100/10/20/1 与 config.Defaults 一致）——已验证。
- **VS-09 raw 截断**：`Truncate512` rune 安全（[]rune 截断不劈裂 UTF-8）；测试断言 512 rune 与短行不截断——event.go:165-172；parse_test.go:36-48。
- **契约一致性**：config 新字段默认值与 deploy/config.json 一致；`SetLimits` 注入链 main.go:160 → api.go:74 正确。
- **文档同步缺口**：README.md（12 只读 API ×2 处）与技术方案.md API 表未含 export/csv——记录 Note（N-01，文档任务处理）。

## 3. 问题清单（§4.6 分级）

### Minor（1 项，非阻塞，建议修复）

| 字段 | 内容 |
| :--- | :--- |
| 问题 ID | M-01 |
| 等级 | Minor |
| 代码位置 | internal/api/export.go:109-115 |
| 事实 | 查询中断路径（rows.Err() 非 nil）直接 `return`，未先 `cw.Flush()`；正常路径 L115 Flush 后也未检查 `cw.Error()` |
| 风险推导 | csv.Writer 内部缓冲 4096 字节：中断时最后一批已扫描行（≤4096B，约几十行）仍滞留缓冲，不 Flush 则客户端连"已成功读取的前缀"都不完整；Flush 错误（客户端断开）被静默吞掉 |
| 触发条件 | 30d/大跨度导出查询在 30s 超时窗口内未完成（大库），或查询中途 DB IO 错误/客户端断开 |
| 影响 | 导出文件尾部缺失一小段（超时中断场景真实发生）；写错误无留痕 |
| 建议 | 中断路径先 `cw.Flush()` 再 return；两处 Flush 后检查 `cw.Error()` 并复用 limitWarn 留痕 |
| 置信度 | 高（静态推断，csv.Writer 缓冲行为明确） |
| 是否阻塞 | 否 |

### Note（5 项，可选）

| ID | 位置 | 内容 |
| :--- | :--- | :--- |
| N-01 | README.md:16/25/35、技术方案.md:363-372 | API 计数 12→13 未同步；技术方案 API 表整体滞后（export/csv、bans、snapshot、ssh/timeline、firewall/timeline 均不在表中）；文档任务处理，不阻塞 |
| N-02 | internal/api/ws.go:94-160 | /ws 握手路径无速率限制（仅连接数上限 100 兜底）——与 VS-03 设计一致；无效握手（Origin 失败/超限 503）快速失败，资源面可控；可选加握手级限流 |
| N-03 | internal/api/export.go:23-116 | 导出端点无鉴权可全量拉取攻击数据——与既有 12 端点数据同类且字段更少，heavy 已挂；建议文档提示"暴露场景需前置鉴权"（AUD-VPS-001 Top1 兜底） |
| N-04 | internal/api/api.go:141/154 | 限流拒绝留痕仅含 r.URL.Path（无查询参数/来源），可观测粒度有限；无安全问题 |
| N-05 | internal/api/api.go:130 | 静态文件服务（/ 兜底）与 /ws 不经限流——浏览器正常加载静态资源所需（同源 6 连接），不建议静态限流；暴露场景由鉴权兜底 |

## 4. 未验证假设（待确认）

| ID | 假设 | 待验证方法 | 把握度 |
| :--- | :--- | :--- | :--- |
| U-1 | 30d/90d 大库（数万行）导出耗时在 30s 超时内（索引 + 流式写理论可行） | TEST-FE-003 压测（tester 并行执行中，审计时点未产出） | 中-高（索引存在，量级未实测） |
| U-2 | 令牌桶/WS hub 并发正确性（-race 未运行：本机无 gcc，`go test -race` 无法执行） | 静态分析（全 Mutex 串行化）+ TestTokenBucketConcurrent 50 goroutine 冒烟通过 | 中-高（静态成立） |
| U-3 | 浏览器稳态下 heavy burst 6 零 429（决策注释引用 DEV-P1-001 浏览器 30s 实测：burst 3 偶发 2 个 429，burst 6 覆盖双轮重叠） | TEST-FE-003 浏览器实测回归 | 高（单测模拟 + 实测记录） |


## 5. 审计结论

**PASS_WITH_NOTES**（无 Blocker/Major，可交付，放行条件见下）。

- 审计要点 2.1~2.7 全部核查通过：限流（含绕过面）、WS 限制（reviewer 三轮证伪点逐项静态核验 + 专项测试）、权限、HTTP 超时、CSP、导出端点（含信息泄露面评估）、前端第 4 页签。
- 范围控制与契约：diff 清单与任务书一致、无越权、无新依赖、config 默认值与 deploy/config.json 一致；文档同步缺口记 Note（N-01）。
- 动态验证：相关包 go test 全通过（api 38.8s）。

**放行条件**：
1. 无 Blocker/Major 遗留（M-01 为 Minor，建议修复但可后置）；
2. **N-R1 联动声明**：M-01 的 Minor 判定隐含"超时中断少见"前提，依赖 U-1 验证结果——若 TEST-FE-003 压测证明 30d/大库导出在 30s 超时内无法完成，M-01 升级 Major 并阻塞发布（客户端无法区分静默截断：HTTP 200 + 无 Content-Length）；压测成功后维持 Minor。
3. 文档同步（N-01/N-03）由文档任务处理，不阻塞本次发布。

## 6. 自检结果（公共自检 AGENTS.md §4.8 + auditor 角色自检）

**公共自检**：
1. 验收标准覆盖：任务书 9 项审计要点均有对应核查结论（§2.1~2.8）与证据位置。
2. 验证证据：代码静态核查（逐文件 read）+ 动态验证（go test 全包通过，api 包 38.8s）；未执行项如实标注（-race 无 gcc；TEST-FE-003 未产出）。
3. 未验证项：U-1（大库导出超时余量）、U-2（-race）、U-3（浏览器稳态 burst 6 零 429）——单列 §4 待确认，未强行定性。
4. 范围漂移：无（纯只读审计，仅产出报告文件）。
5. 风险与不确定点：M-01 与 U-1 联动（N-R1 已声明）；行号引用已按 reviewer 核验校正（N-R4）。
6. 下游上下文：候选基线 b2590b7 已记录；M-01 修复建议、N-01 文档同步项、N-R3 测试注释过时项均已明确标注处理方。
7. 建议验收：PASS_WITH_NOTES——无 Blocker/Major，1 Minor + 10 Note（含 reviewer 补充 5 项），符合发布候选终审放行标准。
8. reviewer 调用：已调用（提示词声明禁止 bash），报告见 §7。

**auditor 角色自检**：
- 审查清单 7 项覆盖：逻辑健壮性（令牌桶/WS 竞态/导出参数）、安全（注入/绕过/XSS/CSP/权限）、性能（限流余量/索引/流式写）、资源生命周期（WS 占位回收/连接关闭）、异常处理（rows.Err/429/错误体）、架构可维护性（关注点分离/无新依赖）、重复逻辑（Truncate512 复用既有语义）——全部覆盖。
- 科研审查维度 4 项：N/A（非科研任务，无实验/统计/可复现性内容，理由：发布终审代码审计）。
- 每个问题含完整 10 字段（M-01 全字段；Note 以表格形式含位置/内容/影响/建议）。
- 严重等级使用统一标准（Blocker/Major/Minor/Note），无旧称。
- 风格偏好未升级为正式缺陷（Note 单列）。
- 未验证假设单列"待确认"（U-1~U-3）。
- 阻塞性问题已明确标记（无 Blocker/Major）。
- 候选基线 commit hash 已记录（b2590b7），基线漂移核验（HEAD=b2590b7，工作区 clean）。
- 纯只读审计：Git 提交项 N/A（归属运营官统一处理）。

## 7. reviewer 反思结论（第 1 轮，PASS_WITH_NOTES，评分 8/10）

reviewer 独立复核结论（2026-08-16，第 1 轮，上限 3 轮）：**PASS_WITH_NOTES，无 Blocker/Major**。事实准确性经独立抽查全部成立（9 组代码位置逐项相符），M-01 等级判定恰当，无遗漏 Blocker/Major；评分 8/10（扣分项均为 Note 级）。

reviewer 补充 5 项 Note（N-R1~N-R5）及本报告处理：

| ID | reviewer 建议 | 处理 |
| :--- | :--- | :--- |
| N-R1 | M-01 与 U-1 联动升级条件须显式声明 | ✅ 已声明（§5 放行条件 2）：U-1 压测失败 → M-01 升级 Major 阻塞 |
| N-R2 | 导出错误响应体（export.go:83）信息暴露面未纳入评估 | ✅ 已补（§2.6 错误响应体说明，与既有端点同模式，Note） |
| N-R3 | api_test.go:671-673 测试注释"满桶 3"与实际 burst 6 不符（SetLimits 忽略 burst 参数） | 记录为 Note：测试注释过时，建议 tester/developer 后续更新为"满桶 6"（不影响测试有效性，3 消耗 < 6 容量） |
| N-R4 | 报告行号引用系统性偏移（diff 行号 vs 实际文件行号） | ✅ 已校正（api_test.go 601/636/654/671/729/767；parse_test.go:36） |
| N-R5 | config 校验范围表述缺 rate_limit_burst；N-01 可扩展为 API 表整体滞后（bans/snapshot/timelines 均不在技术方案表中） | ✅ 已补（§2.1 校验范围四项完整列出）；N-01 扩展为"README 计数 12→13 + 技术方案 API 表整体滞后" |

reviewer 未提出 Blocker/Major，无需整改重交；本轮无遗留阻塞项。

## 8. 附：reviewer 未独立核验项（工具限制声明）

- git diff 20 项清单、基线 clean 状态、deploy/ 零变更、go test 动态结果：reviewer 无 bash 权限未独立核验（基于 auditor 报告自述，auditor 侧已有执行记录）。
- 任务书原文未随材料提供，验收标准符合度基于任务书披露要求对照代码复核。

## N/A 说明

- 科研审查维度：N/A（非科研任务，见 §6）。
- Git 提交：N/A（纯只读审计，报告文件由运营官统一处理提交）。
- TEST-FE-003：审计时点未产出，未纳入证据链（tester 并行执行中，U-1/U-3 待其覆盖）。
