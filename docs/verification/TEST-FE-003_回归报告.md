# TEST-FE-003 回归报告（P1 安全加固 + 数据导出功能合并回归）

## 一、测试概述

| 项 | 内容 |
| :--- | :--- |
| 任务 | TEST-FE-003：P1 安全加固（DEV-P1-001R）+ 数据导出（DEV-EXPORT-001）合并回归 |
| 候选基线 | **b2590b7**（main，工作区 clean；`git log --oneline -1` 确认） |
| 受测变更 | 1f32fe8（P1 加固）、60db089（reviewer 整改）、13ab430（导出）、b2590b7（导出 reviewer 整改） |
| 测试环境 | Windows 本机；Chrome DevTools MCP 浏览器实测 + Python/curl API 实测；种子库 `scripts/dev015_seed_db.py`；`go build -o bin/sentry-agent.exe ./cmd/sentry-agent` 重建二进制；8090 隔离端口（启动前确认无旧实例），配置 `.dev015-test/test_config.json` |
| 测试时间 | 2026-08-16 18:00 ~ 18:40 |
| 测试人员 | tester（独立验证，非 developer 自测） |
| 结论 | **PASS_WITH_NOTES**（无 Blocker/Major/Minor；2 项 Note 记录） |

## 二、测试环境就绪确认

1. 基线确认：`git log --oneline -1` = `b2590b7 fix: DEV-EXPORT-001 reviewer 整改（R-01 溢出回绕校验/R-02 默认预设一致/R-03 export 页轮询门控/R-04~R-06 测试与留痕补强）`，分支 main，工作区 clean。
2. 8090 端口启动前无监听进程；服务以 `sentry-agent.exe -config .dev015-test/test_config.json` 启动（PID 记录），`GET /api/v1/health` 200（`{"ok":true,"schema_version":"1"}`）。
3. 既有 Go 测试全绿（`go test -count=1` 强制重跑，api 41.8s，归档 gotest_output.txt）。
4. 服务运行期间进行了断线重连测试（人为杀进程/重启），完成后服务恢复正常。

## 三、需求/验收追踪矩阵

| 验收标准（任务书） | 测试用例 ID | 验证方法 | 结果 |
| :--- | :--- | :--- | :--- |
| 全局限流 >burst 20 → 429 + Retry-After | SEC-1 | Python 快速连发 /api/v1/resources（首次 429 后 break），抓 429 响应头 | PASS |
| heavy 四端点限流（6 次 OK 第 7 次 429） | SEC-2 | 逐端点 7 次快速请求（summary/firewall/timeline/ssh/timeline/export/csv） | PASS |
| /api/v1/health 不受限 | SEC-3 | 连续 25+30 次 health 全 200 | PASS |
| 正常轮询不误伤（60s 无 429） | SEC-4 | 总览页 5s 轮询观察 60s + system_events 限流留痕检查（90s 窗口 0 条） | PASS |
| WS 正常连接徽章 ok + WS 帧正常推送 | SEC-5 | 浏览器 WS 实测：7.5s 内收到 11 帧（conn_stats 1s/resource 5s/system），帧 JSON 结构核验 | PASS |
| WS 断线重连恢复正常 | SEC-6 | 杀进程 → 徽章"WS 断开，轮询兜底"+ 失败横幅 → 重启 → 3s 恢复"WS 实时"，数据恢复 | PASS |
| WS 连接数上限 100（超限 503 + 占位释放） | SEC-7 | Python 并发 105 连接（浏览器占 1）：99 成功满 100，第 100 个起 503；断开后重连成功 | PASS |
| CSP 响应头三件套 | SEC-8 | curl 首页/app.js 响应头 | PASS |
| 控制台零 CSP 违规零 JS 错误 | SEC-9 | 干净重载后控制台零消息；echarts/内联 SVG/WS 均未被阻断 | PASS |
| 超时配置（静态核验） | SEC-10 | api.go Serve：ReadHeaderTimeout 5s / IdleTimeout 60s / MaxHeaderBytes 64KB | PASS |
| 权限 0700/0600（静态核验） | SEC-11 | store.go MkdirAll 0700 + Chmod 0600（含 WAL 首写后收权）；archive.go 0700/0600 | PASS |
| fw raw 截断 512 | SEC-12 | fw/parse.go Truncate512 静态核验 + 前端 raw 列显示截断正常 | PASS |
| 导出 range 四档（200 + CSV 内容） | EXP-1/EXP-3 | API 四档导出 + CSV 逐项校验（无表头/三列/升序/格式） | PASS |
| from/to 自定义（有效/400 边界/空文件） | EXP-2 | API 有效区间 200、from>to 400、跨度>90d 400、未来区间 200 空文件、both/neither/非数字 400 | PASS |
| 三源合并（fw drop + ssh 失败 + f2b 封禁） | EXP-3 | CSV 行级与 DB 交叉校验：423 行 = fw_drop 224 + ssh_fail 173 + ban 26，0 缺失 0 多余 | PASS |
| SSH 失败端口=22、f2b 封禁端口为空 | EXP-3 | 行级匹配断言 + 空端口行 26 = ban 26 且 IP 全在 ban_events | PASS |
| 时间升序、格式 YYYY-MM-DD HH:MM:SS | EXP-3 | 全行解析校验严格升序 + 格式 | PASS |
| 前端第 4 页签"数据导出" | EXP-4 | 页签出现/切换/样式正常 | PASS |
| 预设 4 档按钮 + 自定义 datetime-local | EXP-5/EXP-6 | 1h 预设导出下载成功；自定义有效区间导出 20052 字节 541 行 | PASS |
| 点导出 → 下载 sentry_export_*.csv | EXP-7 | 下载落盘（Downloads 目录），内容无表头 | PASS |
| 空数据提示 | EXP-8 | 自定义无数据区间 → "该时间段无攻击记录" | PASS |
| 快速连点 429 提示 | EXP-9 | 浏览器内 fetch 6 次耗尽 heavy 桶后点导出 → "导出请求过于频繁，请稍候重试" | PASS |
| from>to 前端拦截提示 | EXP-10 | 设置 from>to 点导出 → "开始时间不能晚于结束时间"；跨度>90 天同验 | PASS |
| export 页无轮询（15s 零请求） | EXP-11 | Network 面板停留 15s：请求数 537→537 零新增 | PASS |
| 切回总览轮询恢复 | EXP-12 | 切回后请求数 537→578，全部 200 无 429 | PASS |
| 零回归：3 页签功能 | REG-1 | KPI/评分/趋势/TOP/5 表排序/过滤/行点击过滤/时间范围切换/WS 徽章/折叠区/态势条折叠/30d 降频提示 | PASS |
| 窄屏无溢出 | REG-2 | 375px 宽总览/攻击页零横向溢出零越界元素 | PASS |
| 控制台零错误 | REG-3 | 干净重载零控制台消息 | PASS |
| 既有 Go 测试全绿 | REG-4 | `go test -count=1 ./internal/api/... ./internal/fw/... ./internal/store/... ./internal/archive/... ./internal/config/... ./internal/event/...` | PASS |


## 四、逐用例执行详情与证据

### 4.1 P1 安全功能（SEC）

**SEC-1 全局限流（全局 10 rps / burst 20）—— PASS**
- 操作与结果（两次独立运行，避免混淆）：
  1. 统计运行（PowerShell 循环 25 次 `GET /api/v1/resources`）：200×21 + 429×4，**首次 429 出现在第 21 次**（first429At=20，0 起始），符合 burst 20 语义（前 20 次耗尽令牌，21 次起拒绝；循环耗时约 1.2s 期间令牌桶按 10rps 补充了少量令牌，故 25 次中 429 为 4 次而非 5 次）。
  2. 抓头运行（Python 快速 23 次，首次 429 后 break）：前 22 次 200、第 23 次 429；429 响应头含 `Retry-After: 1`；错误体 JSON `{"error":"请求过于频繁（全局速率限制）"}`。
- 证据：`evidence/testfe003/ratelimit_results.txt`（运行 1 统计）、`evidence/testfe003/retry_after_429.json`（运行 2：codes 22×200+429、retry_after=1、body）。

**SEC-2 heavy 端点限流（1 rps / burst 6）—— PASS**
- 操作：四端点（/api/v1/summary、/api/v1/firewall/timeline、/api/v1/ssh/timeline、/api/v1/export/csv）各快速 7 次请求（端点间间隔 ≥8s 等 heavy 桶恢复）。
- 结果：四端点均 **6×200 + 1×429@第7次**，精确符合 burst 6 语义。
- 补充：heavy 429 响应语义黑盒抓取（打爆 export 桶后抓 429 头+体）——共 7 次请求 codes 6×200+429，429 响应头 `Retry-After: 1` + JSON 错误体 `{"error":"请求过于频繁（聚合查询限流）"}`（`evidence/testfe003/heavy429.json`）。
- 证据：`evidence/testfe003/ratelimit_results.txt`（summary 端点统计）、`evidence/testfe003/testfe003_results.txt`（fw/ssh timeline、export/csv 三端点统计 + export 边界全部输出）。

**SEC-3 health 豁免 —— PASS**
- 操作：连续 25 次（PowerShell）+ 30 次（Python）`GET /api/v1/health`。
- 结果：全部 200，零 429。

**SEC-4 正常轮询不误伤 —— PASS**
- 操作：浏览器总览页（24h）正常 5s 轮询观察 60s（观察窗口约 18:22:40~18:23:40，每轮 9 个 API 请求）；结合 DB `system_events` 限流拒绝留痕核对。
- 结果与留痕归因（按归档事实）：
  - 全量限流留痕共 5 条，**全部可归因于人为限流测试时刻**（ratelog_output.txt ts 换算）：18:10:18 / 18:11:22（全局桶测试）、18:13:46（heavy 端点测试）、18:23:01（EXP-9 前端 429 提示测试）、18:49:22（heavy429 头/体补验）；
  - 观察窗口 18:22:40~18:23:40 内，唯一时间上相邻的留痕为 18:23:01 的 EXP-9 人为打爆桶测试（归档中 age=2380s 条目），**非轮询误伤**；
  - 无人工干扰时段复核：归档 `ratelog_output.txt`（19:02:41 运行）显示"最近 90s 内限流留痕条数: **0**"。
- 时序说明（R-10 整改）：首次 ratelog（18:24，窗口 18:22:30~18:24:00）覆盖观察窗口结尾且 0 条；归档版本（19:02:41，窗口 19:01:11~19:02:41）不覆盖观察窗口，但观察窗口内留痕可通过其 age（距 19:02 约 2300~2400s）在留痕列表中定位核对——观察窗口内不存在任何轮询请求触发的留痕条目。
- 证据：`evidence/testfe003/ratelog_output.txt`（19:02:41 运行：最近 90s 内 0 条 + 全量 5 条留痕列表）。

**SEC-5 WS 连接与帧推送 —— PASS**
- 操作：页面内 `new WebSocket('ws://127.0.0.1:8090/ws')` 独立连接，7.5s 收帧。
- 结果：opened=true 无错误；11 帧：conn_stats×7（1s 周期）、resource×2（5s 周期）、system×2；帧 JSON 结构正确。页面徽章"WS 实时"（onopen 触发，CSP 未阻断——CSP3 `connect-src 'self'` 覆盖同源 ws://127.0.0.1:8090，与 embed.go 注释的设计一致）。

**SEC-6 WS 断线重连 —— PASS（沿用 TEST-006 WS-3 口径）**
- 操作：`Stop-Process` 杀服务 → 观察 5s → 重启服务 → 观察 7s。
- 结果：断线后徽章变"WS 断开，轮询兜底"（error 态），页面显示"数据加载异常，请检查 agent 运行状态"横幅、图表失败态；重启后约 3s 内徽章恢复"WS 实时"，KPI/图表数据全部恢复。

**SEC-7 WS 连接数上限（ws_max_conns=100）—— PASS**
- 操作：Python websocket-client 并发建立 105 个连接（浏览器页面占用 1 个）。
- 结果：99 个成功（99 + 浏览器 1 = 100 满），第 100 个尝试起返回 **HTTP 503**（JSON 错误体），共拒绝 6 个；存活连接正常收帧（conn_stats）；**全部断开后重连成功**（60db089 占位及时释放修复验证通过）。
- 证据：`evidence/testfe003/ws_limit_100.json`。

**SEC-8 CSP 响应头 —— PASS**
- 操作：curl 首页与 /app.js 响应头。
- 结果：`Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws://127.0.0.1:8080; font-src 'self'`、`X-Content-Type-Options: nosniff`、`X-Frame-Options: DENY` 齐全。

**SEC-9 控制台零 CSP 违规零 JS 错误 —— PASS**
- 操作：干净重载页面后检查控制台。
- 结果：**零消息**（无 CSP 违规、无 JS 错误、无警告）。测试过程积累的 429/ERR_CONNECTION_REFUSED 日志均为人为故障注入（限流测试/断线测试）的预期产物，非缺陷。
- 证据：`evidence/testfe003/overview_page.png`（页面渲染正常截图）。

**SEC-10 超时配置（静态核验）—— PASS**
- `internal/api/api.go:175-177`：`ReadHeaderTimeout: 5 * time.Second`、`IdleTimeout: 60 * time.Second`、`MaxHeaderBytes: 64 << 10`。注释说明 WS hijack 后由 websocket.Conn 自管 deadline（写循环 SetWriteDeadline 10s），符合 gorilla 语义。

**SEC-11 权限（静态核验，Linux 语义）—— PASS**
- `internal/store/store.go:143,148`：数据目录与归档目录 `MkdirAll(..., 0o700)`；`:203,209` 库文件与 WAL/SHM 伴随文件 `Chmod(0o600)`；`:252` 首次写后收权 WAL（reviewer R-11 整改）。
- `internal/archive/archive.go:75`（0700）、`:132`（gzip 中间文件 0600）、`:225`（归档文件 0600）。
- 注：Windows 上 Chmod 为受限 no-op（代码注释已声明），Linux 语义由代码保证。

**SEC-12 raw 截断 —— PASS**
- 静态核验：`internal/fw/parse.go:39` `Raw: event.Truncate512(line)`（512 rune 安全截断，与 ssh detail 对齐）。
- 浏览器验证：攻击页防火墙明细 raw 列显示截断正常（"IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=185.220.101.4 DST=203"）。


### 4.2 数据导出（EXP）

**EXP-1 后端 range 四档 —— PASS**
- 操作：curl 依次 `GET /api/v1/export/csv?range=1h/24h/7d/30d`（端点间 ≥8s 防 heavy 桶干扰）。
- 结果：均 200；`Content-Type: text/csv; charset=utf-8`；`Content-Disposition: attachment; filename="sentry_export_*.csv"`；行数 12 / 423 / 541 / 541（种子数据仅近 30h，7d 与 30d 行数一致合理）。
- 证据：`evidence/testfe003/export_1h.csv`、`export_24h.csv`。

**EXP-2 from/to 边界 —— PASS**
| 场景 | 结果 |
| :--- | :--- |
| 有效区间（25h 前 ~ 1h 前） | 200，427 行（补验归档 exp2_valid.json：200/0.1s/427 行；原测试输出 428 行为窗口滑动数秒的边界差 1 行，同口径） |
| from > to | 400 `{"error":"参数错误：from 不能晚于 to"}` |
| 跨度 > 90 天 | 400 `{"error":"参数错误：自定义时间跨度不能超过 90 天"}` |
| 未来区间（now+1000 ~ now+2000） | 200 + 空文件（0 字节） |
| 同时给 range + from/to | 400 `{"error":"参数错误：range 与 from/to 须二选一"}` |
| 都不给 | 400（同上） |
| from 非数字 | 400 `{"error":"参数错误：from 须为 Unix 秒"}` |
- 证据：边界输出见 `evidence/testfe003/testfe003_results.txt`（原始输出，400 族错误体含 GBK 控制台乱码，HTTPCODE 硬证据成立）+ `evidence/testfe003/testfe003_400s.txt`（UTF-8 重跑归档版：5 个 400 场景 + 未来区间 200 空文件）+ `evidence/testfe003/exp2_valid.json`（valid 区间完整结果）。

**EXP-3 CSV 内容完整性（三源合并交叉校验）—— PASS**
- 以 24h 导出为例，Python 逐行解析 + 对照 `state.db` 原始表：
  - 无表头：首行即数据（IP 点分十进制）；
  - 三列：`IP,时间,端口`；
  - 时间格式 `YYYY-MM-DD HH:MM:SS` 全行有效；
  - 时间严格升序；
  - 行数 423 = DB 三源合计（fw_drop 224 + ssh_fail 173 + ban 26）**完全一致**；
  - 行级比对：缺失 0、多余 0（CSV 与 DB 三源逐行精确匹配）；
  - SSH 失败行端口固定 22、f2b 封禁行端口为空（空端口行 26 = ban 26，且 IP 全部命中 ban_events 表）。
- 结论：三源合并、无表头、流式写、端口语义全部正确。
- **窗口口径说明（R-02a 整改）**：首次校验（24h 导出文件生成于 18:11:46，校验约 18:19 执行）输出 MATCH 423/缺失 0/多余 0；归档阶段重跑校验脚本因距导出约 35 分钟、24h 窗口滑动产生假 MISMATCH（旧归档 csv_check_output.txt：合计 414/多余 9，extra 行全部落在 15 日 18:19~18:45 导出窗口内而重跑窗口外）。已按**窗口对齐口径**重新校验（从 CSV 首末行时间戳反推窗口 [2026-08-15 18:19:21, 2026-08-16 17:46:09] 查询 DB）：`csv_check_v2.json` 输出 **fw_drop=224 + ssh_fail=173 + ban=26 = 423 MATCH、缺失 0、多余 0、空端口 26/26 命中 ban_events**。旧 csv_check_output.txt 保留作为错位记录，不作为正确性证据。
- 证据：`evidence/testfe003/export_24h.csv`（423 行样例）+ `evidence/testfe003/csv_check_v2.json`（窗口对齐版校验结果，正确口径）+ `evidence/testfe003/csv_check_output.txt`（首次重跑错位记录，已披露）。

**EXP-4 前端第 4 页签 —— PASS**
- "数据导出"页签出现于导航（总览/连接/攻击/数据导出），切换正常，样式与既有页签一致；标题"数据导出（CSV）"、说明文案完整。
- 证据：`evidence/testfe003/export_page.png`。

**EXP-5/EXP-6 预设与自定义 —— PASS**
- 预设 1h 按钮点击 → 导出成功提示"sentry_export_20260816_182125.csv（371 字节）"，文件落盘 Downloads 目录，内容 10 行（1h 窗口内三源数据），无表头、升序、格式正确。
- 自定义 datetime-local 输入（2026-08-15T00:00 ~ 2026-08-16T18:00）→ 导出成功"sentry_export_20260816_182751.csv（20052 字节）"，541 行、升序、空端口行 30（ban 全量）。

**EXP-8 空数据提示 —— PASS**
- 自定义区间 2026-07-01 ~ 2026-07-02（无种子数据）→ 提示"该时间段无攻击记录"（warn 样式）。

**EXP-9 429 提示 —— PASS**
- 浏览器内先 fetch 6 次 export（耗尽 heavy 桶 burst 6）→ 立即点"导出 CSV"按钮 → 提示"导出请求过于频繁，请稍候重试"（err 样式）。此前一次尝试因 API 层 7 次请求与点击间隔 >1s（桶已补 1 令牌）导出成功，属 1rps 恢复的正常行为，非缺陷。

**EXP-10 前端拦截 —— PASS**
- from>to：提示"开始时间不能晚于结束时间"（err 样式）；
- 跨度>90 天：提示"自定义时间跨度不能超过 90 天"（err 样式）。

**EXP-11 export 页无轮询 + WS 帧推送 —— PASS**
- 停留在导出页期间记录 Network 面板最新 reqid=2283，15s 后复查：请求总数 537 → 537 **零新增**（R-03 门控生效：HTTP 轮询全停）。
- WS 推送状态补充验证（R-07）：在导出页停留期间页面徽章保持"WS 实时"，且独立建立 WS 连接实测 6.5s 内收到 11 帧（conn_stats×7、system×2、resource×1、heartbeat×1）——WS 推送与 activePanel 无关（ws.go PushLoop 无面板判断），轮询门控未误伤 WS，行为符合前端 vis() 渲染门控设计。

**EXP-12 切回总览轮询恢复 —— PASS**
- 切回总览页 8s 后：请求数 537 → 578，最新请求全部 200（summary/resources/top_ports/top_sources/ssh/timeline/firewall/timeline/bans/ssh/firewall），无 429。

### 4.3 零回归（REG）

**REG-1 三页签功能 —— PASS**
- 总览：KPI（drop/SSH 失败/封禁/评分 58/100 7d 视图）、趋势图（7d 标签"近 7 天"正确）、TOP 攻击源/端口、时间范围 1h/24h/7d/30d 切换数据全部联动更新、态势条折叠/展开、系统资源与最近事件折叠区（details 展开/折叠双向正常）、30d 视图降频提示（"30 天视图聚合较重，攻击数据刷新频率自动降至 30 秒"）；
- 连接：最近连接事件表渲染、按"包/字节"排序升序/降序切换正常（3/288643 → 17/300291 升序，489/172918 首行降序）；
- 攻击：TOP 端口/源图表、SSH 时间线、f2b 封禁表、SSH 明细"仅失败"过滤（60 行全失败）、防火墙明细"仅 drop"过滤（60 行全 drop）、攻击源 TOP 柱条点击过滤（filter-chip"过滤：源 IP 10.0.0.8 ✕（来自攻击页）"、明细联动、chip 点击清除恢复）、总览端口 TOP5 点击跳转（自动切攻击页 + chip"过滤：端口 :22 ✕（来自总览）"）；
- WS 徽章：全程"WS 实时"（断线测试期间正确降级/恢复）。

**REG-2 窄屏 —— PASS**
- 视口 401×720（MCP resize 请求 375px，实际生效视口 401px——DevTools MCP 视口取整限制，为最接近 375px 可用宽度）：总览页与攻击页 `scrollWidth <= clientWidth` 零横向溢出，无越界元素。375~401px 区间无精确覆盖（MCP 限制），溢出风险由 401px 实测与既有 CSS 栅格设计兜底。

**REG-3 控制台 —— PASS**
- 干净重载零控制台消息；全程无 JS 异常（人为故障注入期间的错误日志已甄别为预期产物）。

**REG-4 既有 Go 测试 —— PASS**
- `go test -count=1 ./internal/api/... ./internal/fw/... ./internal/store/... ./internal/archive/... ./internal/config/... ./internal/event/...` 全部 ok（归档运行 api 41.8s，见 gotest_output.txt；首次运行 48.1s，结论一致）。
- 证据：`evidence/testfe003/gotest_output.txt`。

### 4.4 U-1 大库导出压测（reviewer 第 1 轮 R-01 整改补验）—— PASS

- 背景：AUD-FE-004 放行条件 2 依赖"30d/大库导出在 30s 超时内可完成"（M-01 联动）。种子库仅 541 行，需构造数万行大库实测。
- 操作：以种子库为基底构造大库 `big_state.db`（firewall_events 35350 + ssh_attempts 25250 + ban_events 3030，时间戳分布至 30 天窗口）；8091 端口启动第二实例（`big_config.json`）指向大库；Python 实测 30d 导出。
- 结果：
  - `range=30d`：HTTP 200，**耗时 0.41s**，54641 行，2025252 字节；
  - `from/to` 30 天跨度：HTTP 200，**耗时 0.89s**，54641 行；
  - 首 200 行时间严格升序。
  - 行数对账（R-03 整改，DB 实测）：构造总量 63630（fw 35350 + ssh 25250 + ban 3030）；导出 54641 行。差异由两类构成：①**导出查询的业务过滤**——fw 仅取 `action='drop'`（30d 窗口内 accept 约 6155 行被滤）、ssh 仅取 `result=0`（30d 窗口内成功约 2829 行被滤），两项合计约 8984 行；②时间戳落在查询时刻 30d 窗口起点前约 67 行（构造脚本时间戳下界为构造时刻-30d，导出查询窗口起点为导出时刻-30d，构造到导出间隔数分钟造成边界行滤除）。DB 实测（19:24 查询）：30d 内 fw_drop 29159 + ssh_fail 22393 + ban 3027 = 54579（导出时刻窗口较现在前移 37 分钟多 62 行，与导出的 54641 完全对账）。窗口内导出有效行 54641 仍远超"数万行"压测目标。
- 断言：两档耗时均 **远小于 30s 超时上限**（0.41s/0.89s），AUD-FE-004 放行条件 2 满足，M-01 Minor 判定不受威胁，无需升级。
- 证据：`evidence/testfe003/u1_pressure.json`。


## 五、缺陷清单

| 缺陷 ID | 等级 | 描述 | 复现步骤 | 预期 | 实际 | 关联用例 | 本次回归 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| （无 Blocker/Major/Minor 缺陷） | - | - | - | - | - | - | - |

**Note 记录（不阻塞交付）：**

| Note ID | 说明 |
| :--- | :--- |
| NOTE-1 | CSP `connect-src` 显式写死 `ws://127.0.0.1:8080`（`internal/web/embed.go:36`），当前测试在 8090 端口依赖 CSP3 `'self'` 语义覆盖同源 WS（Chrome 实测通过、零违规）。**旧浏览器**（不支持 CSP3 'self' 匹配 ws）存在 WS 被 CSP 阻断的兼容性风险；embed.go 注释已声明该取舍与部署手册关联，属设计决策非缺陷。建议部署文档明示浏览器版本要求。 |
| NOTE-2 | TOP 攻击源"复制 IP"功能本次未能独立交互验证（MCP evaluate 无用户手势，clipboard API 被浏览器权限策略拒绝；click 工具交互超时）。已静态核验实现（`app.js:642-651`：writeText 成功显示"已复制"、失败显示"失败"），该功能在 **TEST-006 FE-9（"TOP 点击复制（clipboard API）"）** 轮次已通过实测。记录为"已观察，未独立核验"，不影响结论。 |

## 六、科研测试维度

N/A——本任务为黑盒功能/安全回归验收（Web 服务 + 前端），不涉及统计建模、实验脚本或数据分析，五维度（统计显著性/可复现性/消融/鲁棒性/数据完整性）不适用。数据完整性校验已在 EXP-3 以"CSV 行级 vs DB 三源交叉比对"方式覆盖（0 缺失 0 多余）。

## 七、未验证项

1. Linux 权限语义（0700/0600）实际效果：Windows 无 POSIX 权限语义，仅静态核验代码（SEC-11）。
2. TOP 攻击源复制 IP：交互验证受限（见 NOTE-2），静态核验 + 既有轮次覆盖。
3. WS 握手 5s deadline 与 4KB 帧上限：静态核验（ws.go:115/123）；超限场景未做故障注入（客户端侧需构造慢握手/大帧，收益有限，且 developer 既有单测覆盖）。
4. ReadHeaderTimeout/IdleTimeout 的实际断连行为：静态核验（SEC-10），未做 Slowloris 实测。

## 八、覆盖范围声明

| 维度 | 覆盖情况 |
| :--- | :--- |
| 正常路径 | 全量（四页签功能、导出全流程、WS 全流程） |
| 边界条件 | 导出 from/to 七种边界、限流 burst 临界、WS 100 上限临界、空数据、窄屏 |
| 异常路径 | 429（API + 前端提示）、服务中断（WS 断线/轮询兜底）、400 参数错误族 |
| 回归测试 | 既有功能全量 + 既有 Go 测试（-count=1） |
| 集成测试 | 前端↔API↔DB 三源合并链路、WS 推送链路、CSP↔WS 兼容 |
| 状态/资源生命周期 | WS 占位申请/拒绝/释放（SEC-7 断开后重连验证） |
| 并发/性能 | 限流并发语义（令牌桶）、WS 并发连接上限、**U-1 大库导出压测（54641 行 30d 导出 0.41s/0.89s < 30s）** |
| 安全 | CSP/权限/超时/限流/WS 限制/raw 截断全项 |

**覆盖率说明**：本任务为黑盒验收回归（无新增被测代码），单元测试覆盖率门槛 N/A；以"需求/验收追踪矩阵全项 PASS + 既有 Go 测试全绿"作为验收依据，关键风险（限流误伤、WS 上限、导出数据完整性）均已独立实测覆盖。

## 九、测试结论

**PASS_WITH_NOTES** —— 全部 **28 项**验收标准通过（SEC-1~12 共 12 项 + EXP-1~12 共 12 项 + REG-1~4 共 4 项；另含 4.4 节 U-1 大库压测补验），无 Blocker/Major/Minor 缺陷；2 项 Note（CSP 旧浏览器兼容性提示、复制功能交互验证环境限制）记录在案，不阻塞交付。P1 安全加固（限流/WS 限制/CSP/超时/权限/raw 截断）与数据导出（API 三源合并 + 前端页签）在候选基线 b2590b7 上合并回归通过，前端既有功能零回归；U-1 大库（54641 行）30d 导出实测 0.41s/0.89s，AUD-FE-004 放行条件 2 满足。

## 十、证据状态说明与测试证据归档

**证据四态说明（AGENTS.md §4.2 口径）**：
- **已验证**：有归档文件可追溯且已核验——限流统计（ratelimit_results.txt）、429 头/体（retry_after_429.json、heavy429.json）、WS 上限（ws_limit_100.json）、CSV 样例与交叉校验（export_*.csv、csv_check_v2.json 窗口对齐版）、U-1 压测（u1_pressure.json）、Go 测试（gotest_output.txt）、限流留痕（ratelog_output.txt）、heavy 边界输出（testfe003_results.txt + exp2_valid.json）、页面截图（overview_page.png、export_page.png）；
- **已观察，未独立核验**：浏览器交互类结果（页签切换/提示文案/无轮询观察/断线重连/图表点击过滤等，均有操作记录与快照/控制台佐证，但未逐帧录像归档）；TOP 复制功能（NOTE-2）；
- **推断**：EXP-1 中"7d 与 30d 行数一致"由种子数据仅近 30h 推断（已标注）；U-1 构造行数 63630 与导出 54641 差异由构造时间戳窗口逻辑推断（已披露，见 4.4）；
- **未验证**：Linux 权限语义、Slowloris 实测等（见"七、未验证项"）；
- **错位记录**：csv_check_output.txt 为归档阶段重跑因 24h 窗口滑动产生的假 MISMATCH 记录，已披露成因，不作为正确性证据（正确口径以 csv_check_v2.json 为准）。

`docs/verification/evidence/testfe003/`（16 个文件）：
- `export_1h.csv` / `export_24h.csv`：API 导出样例（无表头/三列/升序）
- `retry_after_429.json`：全局限流 429 + Retry-After 证据（22×200+429 抓头运行）
- `ratelimit_results.txt`：全局桶/heavy 桶/health 豁免统计（25 次统计运行）
- `heavy429.json`：heavy 429 头+体（7 次请求 6×200+429，Retry-After:1 + JSON 错误体）
- `testfe003_results.txt`：heavy 三端点（fw/ssh timeline、export/csv）7 次统计 + export 边界原始输出
- `testfe003_400s.txt`：400 族边界用例 UTF-8 重跑归档（5×400 + 未来区间 200 空文件）
- `exp2_valid.json`：EXP-2 有效区间补验归档（200/0.1s/427 行 + 窗口）
- `ratelog_output.txt`：限流拒绝留痕检查输出（19:02:41 运行：最近 90s 内 0 条 + 全量 5 条留痕）
- `csv_check_v2.json`：CSV 三源交叉校验（窗口对齐版，正确口径：423=224+173+26、0 缺失 0 多余、升序、空端口 26）
- `csv_check_output.txt`：首次重跑错位记录（24h 窗口滑动假 MISMATCH，已披露，不作为正确性证据）
- `gotest_output.txt`：既有 Go 测试 -count=1 全绿输出（api 41.8s）
- `u1_pressure.json`：U-1 大库压测（range30d 0.41s / fromto30d 0.89s，54641 行）
- `ws_limit_100.json`：WS 上限 503 拒绝 + 占位释放证据（99 ok / 6 拒绝 / first_reject_at=100）
- `overview_page.png` / `export_page.png`：页面渲染截图
- 测试脚本（工作区外临时目录，未污染仓库）：`.dev015-test/` 下 testfe003_*.ps1/py/json（gitignored）
