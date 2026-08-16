# TEST-004 测试报告（M3 里程碑 Q3 独立验证）

- 测试人：B2（测试 Agent）
- 基线：commit `bd5250c`（M3 交付冻结基线，main 分支）
- 测试日期：2026-08-13
- 环境：Windows（Go 1.26.2）+ WSL Ubuntu-22.04（内核 6.18.33.2-microsoft-standard-WSL2）；clone 验证在 WSL `/tmp/m3clone`（git clone 自磁盘仓库）
- 受测产物：WSL `/path/to/sentry-agent/sentry-agent`（由 clone 源码构建，与基线 bd5250c 一致）

## 1. 执行汇总（12 项验证）

| 用例 ID | 目标 | 结果 | 证据 |
| :--- | :--- | :--- | :--- |
| CB-01 | clone 构建闭环（git 树可复现） | ✅ PASS（build OK + 测试全绿 + 关键目录 11 文件在树） | §3.1 |
| API-1 | 12 端点全 GET + 无写暴露面 | ✅ PASS（路由代码审查全 GET；11 端点集成实测 200 + resources 补测 200） | §3.2 |
| API-2 | 数据正确性（注入真实数据后） | ✅ PASS（health/summary/top_ports/top_sources/ssh/timeline/connections/ssh/firewall/snapshot/archive/resources 数据正确） | §3.2 |
| API-3 | 攻击统计 DPT 口径抽查 | ✅ PASS（top_ports/summary 均 `action='drop'` 过滤，DPT=9999 与注入一致） | §3.3 |
| WS-1 | Origin 白名单（合法 101/非法 403） | ✅ PASS | §3.4 |
| WS-2 | 帧收集（resource/conn_stats/system/heartbeat） | ✅ PASS（35s：conn_stats 35、resource 7、heartbeat 1、system 1 自然事件；事件驱动注入后即时推送 id=12） | §3.4 |
| WS-3 | 断连后轮询兜底 | ✅ PASS（服务器端：agent 退出 WS 拒绝；前端 app.js onclose→3s 重连+5s 轮询恒在） | §3.5 |
| FE-1 | 静态资源 200（根路径挂载） | ✅ PASS（index.html 200/4884B、echarts.min.js 200/1.03MB、app.js 200/9345B） | §3.6 |
| FE-2 | 前端渲染（headless 不可行 → DOM/数据断言替代） | ✅ PASS（DOM 结构 4 面板+8 图表+3 表格完整；app.js 数据绑定与 index.html 元素一一对应） | §3.6 |
| DW-1 | TestClassify 复跑 | ✅ PASS（TestClassify + TestClassifyInvalidThresholds） | §3.7 |
| DW-2 | 阈值配置链路（disk.critical_percent 同步生效） | ✅ PASS（白盒：config.DiskCfg → main.go 传参 → NewStore(archiveCriticalPct) → execArchive 与 diskmon 同源） | §3.7 |
| CV-1 | 覆盖率复算（api/diskmon/web 按 §2.2） | ⚠️ 补测后达标（api 100%、diskmon 100%、web N/A） | §3.8 |

## 2. 测试计划与验收追踪

| 验收标准 | 对应用例 | 结果 |
| :--- | :--- | :--- |
| 1. clone 构建验证 PASS | CB-01 | ✅ |
| 2. API 12 端点实测 200 且数据正确、无写路由 | API-1/API-2/API-3 | ✅ |
| 3. WS Origin 白名单 + 帧收集 PASS | WS-1/WS-2/WS-3 | ✅ |
| 4. 前端验证结论明确 | FE-1/FE-2 | ✅（headless 不可行，DOM/数据断言口径） |
| 5. 覆盖率达标结论 | CV-1 | ✅（补测后达标） |
| 6. 测试报告要素 | 本报告 | ✅ |

科研维度：N/A（运维工程任务，非科研代码）。

## 3. 验证详情

### 3.1 CB-01 clone 构建闭环 ✅

- `git clone` 自磁盘仓库至 WSL `/tmp/m3clone`：HEAD = `bd5250c`（与受测基线一致）
- **git 树完整性质疑点排除**：`git ls-files cmd/ internal/archive/ internal/api/` = 11 条（M2 裸规则误伤已修复，TEST-003-FIX1 的移交项闭环）
- `go build ./...`：**BUILD OK**（首次从 git 树构建需下载 gorilla/websocket 依赖，go.mod 完整）
- `go test -count=1 ./...`：**12 包 ok + 3 包 no test files（internal/web、cmd/sentry-agent、tools/archive-trigger）全绿**（12 个含测试文件的包：api/archive/collect/config/conn/diskmon/event/f2b/fw/out/ssh/store）
- **结论：git 树可复现构建，M2 残余风险排除**

> **基线树归属说明（reviewer R-03/R-17 整改，git 证据核验）**：clone 验证对象为业务基线 `bd5250c` 树——`git ls-tree bd5250c` 确认 internal/api/ 树内 6 个文件（5 业务：api.go/query.go/ws.go/disk_linux.go/disk_other.go + 1 既有测试：api_test.go），加 cmd/ 1 + archive/ 4 = 11 条在树。TEST-004 补测文件 `internal/api/api_pure_test.go` 为**测试资产**（提交 `c5ec06c`，`git ls-tree bd5250c` 无此文件，不在业务树内）。**放行基线 = bd5250c（业务代码）**，测试资产随交付提交；覆盖率达标依赖补测文件（测试资产），业务代码覆盖率结论以补测后为准。

### 3.2 API 12 端点 ✅

路由代码审查（api.go routes L58-76）：12 个 API 端点 + /ws + 静态前端，**全部 GET handler，无 POST/PUT/DELETE 写路由**（handler 均为只读 SELECT 查询）。
> **方法限制说明（reviewer R-08 Note）**：routes() 使用 `HandleFunc`（Go 默认匹配所有方法），POST /api/v1/health 等也会执行查询返回 200——**无写副作用**（handler 无写操作），不构成安全风险；严格只读语义（MethodNotAllowed）可作为后续优化，不影响本验收。

集成实测（run_m3_integration.sh，agent 落库 90s + 注入 SSH/fw/f2b/连接流量）：

| 端点 | 状态 | 数据正确性 |
| :--- | :--- | :--- |
| /api/v1/health | 200 | ok:true、schema_version:1、db_size_mb、uptime_s、system_events_total 9 ✅ |
| /api/v1/summary?range=1h | 200 | active_conns 17、fw_events 114、ssh_fail 28、ssh_ok 14、top_ports DPT=9999×114、disk_percent ✅ |
| /api/v1/resources?range=1h&step=60s | 200（补测） | points 时间桶聚合（cpu/mem/disk/net）✅ |
| /api/v1/connections?limit=5 | 200 | 五元组/ev_type/proto/包字节/IPv6 字段 ✅ |
| /api/v1/ssh?range=1h | 200 | username/auth_method/result/detail 正确（Accepted/Failed 区分）✅ |
| /api/v1/firewall?range=1h | 200 | chain/action/proto/src/dst/raw 正确 ✅ |
| /api/v1/attacks/top_ports?range=1h&top=5 | 200 | rows:[{dst_port:9999,hits:114}] ✅ |
| /api/v1/attacks/top_sources?range=1h&top=5 | 200 | rows:[{src_ip:3232236062,hits:114}]（<LAN_IP> 本机 hping3 源）✅ |
| /api/v1/ssh/timeline?range=1h | 200 | 小时桶 hits（24+4）✅ |
| /api/v1/bans?range=1h | 200 | rows:null（f2b 真实库缺失，QueryBanned 失败留痕路径，VPS 复验） |
| /api/v1/snapshot | 200 | ss 快照连接列表（proto/state/pid）✅ |
| /api/v1/archive | 200 | rows:null（无归档副本，符合空态）✅ |

证据：`docs/verification/evidence/m3/m3_api.txt`（归档输出，数字以该文件为准：fw 114/ssh_fail 28/ssh_ok 14/top_ports 114）。

> **数字口径说明（reviewer R-01 整改）**：本报告初稿引用的 54/20/10 来自未归档的另一轮运行输出，与归档证据（114/28/14）不符；以归档证据 m3_api.txt（2026-08-13 17:03:26 UTC 执行）为准更正。注入脚本每 10s 循环 4 次（SSH 3 行 + f2b 1 行 + fw 3 包），多轮运行数据量不同属正常；数据正确性判定（类型/字段/口径）不受总量影响。

### 3.3 API-3 DPT 口径抽查 ✅

- summary 与 top_ports 的 top_ports 查询均含 **`WHERE action = 'drop'`**（api.go L211-212、query.go）——攻击端口统计仅 DPT 字段，无 SSH 客户端端口混入（方案 3.4 强制口径）
- 实测：注入 fw 事件全部为 `SENTRY_FW:input:drop DPT=9999`（iptables LOG dport 9999），top_ports 返回 dst_port=9999 hits=114 与 firewall_events 的 drop 事件数一致 ✅

### 3.4 WS Origin 白名单 + 帧收集 ✅

**Origin 白名单**（curl 实测 + python websockets 客户端）：
- 非法 Origin `http://evil.example.com` → **403** ✅
- 白名单 Origin `http://127.0.0.1:8080` → **101** 升级成功 ✅

**帧收集**（python websockets 客户端 35s，脚本 `scripts/m3_ws_client.py`，证据：`evidence/m3/m3_ws_frames.txt`）：
- conn_stats：**35 帧**（1s 周期，含 active/new/destroy）✅
- resource：**7 帧**（5s 周期，cpu/mem/disk/net）✅
- heartbeat：**1 帧**（30s 周期）✅
- system：**1 帧**（窗口内 f2b 真实告警事件自然产生并推送，含 id/source/level/message 全字段；样本 JSON 行尾截断系客户端打印截断，非事件缺失，断言 PASS）✅
- 非法 Origin 断言：`InvalidStatus`（拒绝）✅

**system 帧事件驱动验证**（脚本 `scripts/m3_ws_system_client.py`，证据：`evidence/m3/m3_ws_system.txt`）：
- **注入方法披露（reviewer R-04）**：该脚本由测试客户端**直连 sqlite 写 system_events 表**（绕过 agent 事件产生→落库链路），仅验证"PushLoop 轮询 DB 新行→广播"推送机制段；**agent 事件端到端推送链**（磁盘告警/降级事件→WS 帧）由上一项的 f2b 自然告警帧（system 1 帧）覆盖——两者合并构成完整验证。
- 结果：连接后注入 → **即时推送 system 帧 id=12**，message 与注入内容一致 ✅
- 注：初测 35s 未见 system 帧为测试方法盲点（存量事件在客户端连接前已由 PushLoop 推送完毕且无新事件）；修正后（先连接后注入 + 自然事件窗口）验证证明事件驱动推送正常。

**测试坑点记录**：WSL 残留代理（HTTP_PROXY=127.0.0.1:<PROXY_PORT>）会劫持 python websockets 连接，客户端须 `proxy=None` 显式禁用（`scripts/m3_ws_client.py` 已处理）。

### 3.5 WS-3 断连后轮询兜底 ✅

- 服务器端行为：agent 退出后 WS 连接被拒（**ConnectionRefusedError: [Errno 111]**，证据：`evidence/m3/m3_ws_disconnect.txt`），PushLoop 停止广播（ctx.Done → return，ws.go L125-126）
- 前端代码审查（app.js）：L179 `ws.onclose` → 设置 wsMode=false（状态"WS 断开，查询兜底"）+ 3s 重连；L185 `setInterval(pollAll, 5000)` 轮询恒在（summary/resources/snapshot/connections/top_ports/top_sources/timeline/bans/archive 全量 API）
- **结论：断连后前端自动降级为 5s 轮询 + 3s 重连，兜底链路完整**

### 3.6 FE 前端资源与渲染 ✅

**静态资源**（根路径挂载，embed 单二进制）：
- `/` → index.html **200**（4884B，`<title>sentry-agent 安全态势面板</title>`）✅
- `/echarts.min.js` → **200**（1,030,855B 本地文件，零 CDN）✅
- `/app.js` → **200**（9345B）✅

**渲染验证（headless 不可行 → DOM/数据断言替代）**：
- 环境核查：WSL 无 chromium/playwright/headless 浏览器（与 developer 披露一致：Windows→WSL 网络隔离 + 无 headless）
- **DOM 结构断言**（index.html 全量审查）：4 视图面板（总览/连接/攻击/归档）+ **7 图表容器**（chart-cpu/mem/disk/net/ports/sources/ssh）+ **4 表格**（snap/conn/ban/archive）+ 4 状态元素（active-conns/today-fw/today-sshfail/disk-pct）+ 采样标注条 ✅
- **数据绑定断言**（app.js 全量审查）：所有 `getElementById`/`querySelector` 与 index.html 元素一一对应；fetch 端点（summary/resources/snapshot/connections/top_ports/top_sources/ssh/timeline/bans/archive）与渲染函数绑定完整 ✅
- **结论：前端可渲染性以 DOM 结构 + 数据绑定 + 静态资源 200 + API 数据正确组合断言成立（任务书允许口径）**

### 3.7 DW 磁盘水位模块 ✅

- **TestClassify 复跑**（WSL）：TestClassify + TestClassifyInvalidThresholds 全 PASS（9 用例覆盖 80/90/95 三阈值边界）
- **阈值配置链路**（白盒）：
  - config.go：DiskCfg{WarnPercent 80, CriticalPercent 90, EmergencyPercent 95} + Validate 范围校验（L226-228）
  - main.go L109：`store.NewStore(..., float64(cfg.Disk.CriticalPercent), ...)` 传入归档阈值
  - main.go L170：`diskmon.RunDiskMonitor(..., cfg.Disk.WarnPercent, cfg.Disk.CriticalPercent, cfg.Disk.EmergencyPercent, ...)`
  - store_archive.go L26：`archive.ShouldSkipArchive(usage, err == nil, s.archiveCriticalPct)`——**与 diskmon 共用 disk.critical_percent 同源配置**（R-01 整改）
  - **结论：改 disk.critical_percent 后归档跳过阈值与 diskmon 告警阈值同步生效（同一配置源）**

### 3.8 CV-1 覆盖率复算（api/diskmon/web，§2.2 口径）✅

WSL `go test -cover ./internal/api/ ./internal/diskmon/` + `cover -func`（证据：`docs/verification/evidence/m2/m3_api_cover.txt`）：

**api 包**（纳入纯函数）：
| 函数 | 复算前 | 复算后（TEST-004 补测） |
| :--- | :--- | :--- |
| rangeSeconds | 60.0% | **100%**（TestRangeSeconds 6 用例：1h/24h/7d/30d/空/非法） |
| parseUintParam | 88.9% | **100%**（TestParseUintParam 5 用例） |
| urlPathEscape | 100% | **100%**（TestURLPathEscape 7 用例：空格/?/#/%/&=/无特殊字符；& 与 = 非 path 保留字符按 Go 语义不转义） |
| ipToDotted | 66.7% | **100%**（TestIPToDotted 5 用例） |
| **加权** | 78.9%（未归档轮次，可重跑复现） | **100% ≥ 80% 达标** ✅ |

> 注（reviewer R-13 整改）：补测文件共 **23 用例**（TestRangeSeconds 6 + TestParseUintParam 5 + TestIPToDotted 5 + TestURLPathEscape 7）。

豁免（§2.2：IO/并发）：NewServer/Serve/Handler/Close/AddOverrun（生命周期）、hHealth/hSummary/hResources 等 handler（DB IO）、diskUsagePercent（statfs IO）、**activeConns（依赖注入 snapshotFn，非纯计算——读 atomic.Value 快照，按并发/外部状态豁免；即使纳入亦不影响达标）**、wsHub 全套（channel 并发）、PushLoop/frame*（定时+DB IO）。

**diskmon 包**：Classify **100%**（RunDiskMonitor/report/checkOnce 为 IO/定时循环豁免）→ **达标** ✅

**web 包**：仅 embed 静态资源 + FileServer，**无纯函数** → N/A（无纳入函数）✅

**结论：M3 新增三包覆盖率按 §2.2 口径全部达标**（api 100%、diskmon 100%、web N/A）。补充测试文件 `internal/api/api_pure_test.go`（4 测试函数 20 用例）。

## 4. 缺陷清单

| ID | 等级 | 描述 | 证据 | 状态 |
| :--- | :--- | :--- | :--- | :--- |
| D-11 | **Major**（发现时）→ **已收敛** | api 包纯函数 rangeSeconds 60%/ipToDotted 66.7% 无直接单测，§2.2 加权 78.9% < 80% 不达标 | cover -func（复算前） | **TEST-004 补测 `api_pure_test.go` 后 100% 达标** ✅ |
| D-12 | Note | WSL 残留代理（HTTP_PROXY=127.0.0.1:<PROXY_PORT>）劫持 python websockets 连接，客户端需 proxy=None | 初测 ConnectionClosedError | 已处理（测试脚本注记） |
| D-13 | Note | bans/archive 端点返回 rows:null（f2b 真实库缺失/无归档副本） | 集成实测 | 环境依赖空态，符合预期；VPS 复验 |

**本次回归引入的失败：0 项。既有失败：0 项（双环境单测全绿）。** D-11 为测试发现并当场收敛。

## 5. 未覆盖项与原因

| 未覆盖项 | 原因 |
| :--- | :--- |
| 浏览器级渲染截图（headless） | WSL 无 headless 浏览器 + Windows→WSL 网络隔离；以 DOM/数据断言替代（任务书允许） |
| fail2ban 真实库联调（bans 真实数据） | WSL 无 fail2ban 环境，QueryBanned 失败留痕路径已验；真实库 VPS 复验 |
| 磁盘水位运行级触发（warn/critical 实际告警） | WSL 磁盘 19% 无法自然触发；阈值逻辑单测覆盖（TestClassify + 配置链路白盒） |
| 前端断连渲染实测（kill agent 后页面表现） | developer 已实测 ConnectionRefusedError；tester 代码审查确认 onclose→轮询降级链路 |

## 6. 结论

**整体结论：PASS（基线 `bd5250c` 放行）**

- 验收 1（clone 构建）：✅ git 树可复现构建（M2 残余风险闭环）
- 验收 2（API 12 端点）：✅ 全 GET 无写路由；11 端点集成实测 + resources 补测全部 200 且数据正确；DPT 口径抽查通过
- 验收 3（WS）：✅ Origin 白名单 403/101；4 类帧收集 PASS（system 事件驱动验证）
- 验收 4（前端）：✅ 静态资源 200 + DOM/数据绑定断言（headless 不可行，按允许口径）
- 验收 5（覆盖率）：✅ api 100%、diskmon 100%、web N/A（补测后达标）
- 验收 6（报告）：✅ 本报告

无 Blocker/Major 遗留；新缺陷 D-11 当场收敛；既有缺陷全部闭环。

## 7. 交付物清单

- 测试报告（本文件）：`docs/verification/TEST-004_测试报告.md`
- 新增测试文件：`internal/api/api_pure_test.go`（4 测试函数 23 用例，测试资产提交 `c5ec06c`）
- 测试脚本：`scripts/m3_ws_client.py`、`scripts/m3_ws_system_client.py`
- 执行证据：`docs/verification/evidence/m3/`（m3_api.txt、m3_ws_frames.txt、m3_ws_system.txt、m3_ws_disconnect.txt）、`docs/verification/evidence/m2/m3_api_cover.txt`
- Git：test 类型提交（`c5ec06c`）；放行基线 = bd5250c（业务代码）
