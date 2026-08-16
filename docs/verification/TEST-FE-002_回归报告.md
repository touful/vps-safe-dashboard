# TEST-FE-002 回归报告（DEV-FE-005 面板五项调整）

- 测试人：tester（测试 Agent）
- 任务书：TEST-FE-002（轻量回归，独立测试验收）
- 候选基线：commit `082bbbd`（main，测试前工作区 clean；测试期间无基线漂移）
- 受测对象：DEV-FE-005（`38f9135` + `082bbbd`）面板五项调整
- 前序基线：TEST-FE-001（35 用例，34 过；归档相关用例 NF-8/4 页签断言已按新行为更新）
- 测试日期：2026-08-16
- 测试环境：Windows 本机；Chrome DevTools MCP 浏览器实测；agent 由 tester 自基线 `082bbbd` 重建二进制并运行于 **8090** 隔离端口（8080 无实例）
- 测试库：`scripts/dev015_seed_db.py`（tester 重建；fw_events 268 / ssh_fail 171）
- 关键纪律：前端 go:embed 进二进制，已重建 `go build -o bin/sentry-agent.exe ./cmd/sentry-agent` 并确认 `GET /api/v1/summary?range=24h` HTTP 200

## 1. 测试计划摘要

### 1.1 测试范围与用例清单

| 用例 ID | 验证点 | 任务书引用 |
| :--- | :--- | :--- |
| TC-01 | 总览 KPI 无"攻击/系统"分组标签；2×2 布局（2×2，卡间对齐无异常） | §3.1-1 |
| TC-02 | 标题：浏览器 tab 与页面 h1 均为"VPS安全态势" | §3.1-2 |
| TC-03 | 攻击页三列并列（TOP 两图 + SSH 时间线）；SSH 时间线渲染；中间宽度 2+1；窄屏单列 | §3.1-3 |
| TC-04 | 归档：导航仅 3 页签；无归档入口；Network 无 /api/v1/archive 请求；后端端点存活；控制台零错误 | §3.1-4 |
| TC-05 | 折线平滑：攻击双通道 + 资源图（CPU/内存/磁盘/网络）series smooth=true | §3.1-5 |
| TC-06 | 3 页签切换（总览/连接/攻击）+ 切页后数据渲染 | §3.2-1 |
| TC-07 | 5 张明细表（ban/ssh/fw/snap/conn）渲染 + 排序 + 过滤联动（SSH 排序/结果过滤、FW 排序/动作过滤、行点击过滤链路） | §3.2-2 |
| TC-08 | 时间范围切换 1h/24h/7d/30d；30d 降频提示 | §3.2-3 |
| TC-09 | WS 状态徽章 + 数据新鲜度指示（正常/断开/恢复） | §3.2-4 |
| TC-10 | 攻击页 TOP 柱条点击联动过滤（chip 全局显示） | §3.2-5 |
| TC-11 | 折叠区（资源/事件）展开折叠 + sessionStorage 记忆 | §3.2-6 |
| TC-12 | 窄屏无横向溢出 | §3.2-7 |

### 1.2 覆盖范围适用性

| 维度 | 适用性 | 说明 |
| :--- | :--- | :--- |
| 正常路径 | ✅ | TC-01~TC-12 全部覆盖 |
| 边界条件 | ✅ | 窄屏 481px / 中间 801px / 桌面 1312px 三档响应式；30d 降频；排序升降切换 |
| 异常路径 | ✅ | WS 断开降级（kill agent）；连接拒绝期间轮询兜底 |
| 回归测试 | ✅ | 3.2 关键回归点 7 项全部覆盖（TEST-FE-001 对应功能重验） |
| 集成测试 | ✅ | 前端→API 数据一致性（KPI/TOP/明细/时间范围参数化请求全部 200） |
| 状态/资源生命周期 | ✅ | WS 断连→轮询兜底→自动重连恢复；折叠状态 sessionStorage 记忆 |
| 并发/性能 | N/A | 轻量回归任务书未要求性能量化验收；DOM 峰值/长任务非本次范围 |
| 安全 | N/A | 无新增安全面（本次为前端展示层调整，无接口/权限变更） |
| 科研维度 | N/A | 非科研代码任务 |

### 1.3 需求/验收追踪矩阵

| 验收标准（任务书） | 对应用例 | 验证方法 | 结果 |
| :--- | :--- | :--- | :--- |
| ① KPI 分组标签删除 | TC-01 | DOM 查询 `.kpi-group-label` + getBoundingClientRect 几何 | ✅ PASS |
| ② 标题"VPS安全态势" | TC-02 | document.title + h1 + a11y 树 | ✅ PASS |
| ③ 三列并列 + 响应式 | TC-03 | 三卡几何（同排/等高/等宽）+ canvas 渲染 + 三档宽度实测 | ✅ PASS |
| ④ 归档前端隐藏 | TC-04 | nav/panel/DOM 清理 + Network 79 请求无 archive + 后端 API 直连 200 + 控制台 | ✅ PASS |
| ⑤ 折线平滑 | TC-05 | ECharts 实例 getOption 读 series.smooth | ✅ PASS |
| 3.2 回归点 1~7 | TC-06~TC-12 | 浏览器交互实测 | ✅ PASS |

## 2. 逐用例结果

| 用例 | 结果 | 证据摘要 |
| :--- | :--- | :--- |
| TC-01 | **PASS** | `.kpi-group-label` 元素数 0；`.kpi-row` 2 行，每行 2 卡等高（h=132）等宽（w=650）x 对齐（24/686），行距 141px，无对齐异常；截图 01/03 |
| TC-02 | **PASS** | `document.title`="VPS安全态势"；h1="VPS安全态势"；a11y RootWebArea/heading 一致 |
| TC-03 | **PASS** | 桌面 1312px：三卡 y=126 同排、h=307 等高、w=429 等宽，chart-ssh canvas 渲染；820px/801px/721px：2+1（卡 0/1 同行，卡 2 第二行）；481px：单列（x=12，y=212/531/851）——响应式降级为预期行为（任务书明确记录即可）；断点覆盖：800-1024 区间内 820px 实测（reviewer N-01 整改补测） |
| TC-04 | **PASS** | nav=3 页签、panel=3 个、archive-table/disk-water/panel-archive 均不存在；Network 全程 79 请求无 `/api/v1/archive`；API 直连 `/api/v1/archive` HTTP 200 且响应体 `{"rows":null}`（reviewer R-06：rows 字段存在，响应体结构完整；rows=null 为环境态解释——种子库新建未产生归档月份，**非**后端静默归档持续工作的功能证据，该完整证据链归属后端测试范围）；**代码层不可达**（reviewer R-02 整改）：静态核对 app.js——`renderArchive`/`pollArchive`/`renderDiskWater` 函数与调用零残留，`switchPanel` 仅 overview/conn/attack 三分支无 archive 分支，无 `location.hash`/`hashchange` 路由（URL hash 直达不可达）；控制台零 JS 错误（监控范围见 §3 说明） |
| TC-05 | **PASS** | ECharts 实例级验证：chart-attack-trend 双通道 smooth=true（25 点）；chart-cpu/mem/disk/net（Rx/Tx）smooth=true（11 点）；柱状图为 bar 类型 smooth 不适用（预期） |
| TC-06 | **PASS** | 3 页签 active 类正确转移；连接页 snapshot+conn 表渲染（snapshot 空态为环境限制，见 OBS-1）；攻击页三图+明细表渲染 |
| TC-07 | **PASS** | 5 表渲染（ban 26/ssh 60/fw 60/conn 多行/snap 空态）；SSH 时间列排序 ascending→descending（aria-sort+sorted 类，升序首行 08-15 12:53:40 最早）；SSH 结果过滤"仅失败"→10/10 行为失败；FW 时间排序 ascending；FW 动作过滤"仅 drop"→10/10 行为 drop；SSH 行点击→chip"过滤：源 IP 91.240.118.77 ✕（来自攻击页）"+SSH 表收窄全部该 IP |
| TC-08 | **PASS** | 1h/24h/7d/30d 依次切换 active 正确，Network 请求 range 参数对应且全部 200；30d rate-hint 显示"30 天视图聚合较重…30 秒"（display=block），图表 dataZoom 生效（ssh 31 点）；其他范围 hint none |
| TC-09 | **PASS** | 正常："WS 实时"（ok）+ "更新于 HH:MM:SS"；kill agent："WS 断开，轮询兜底"（error）+ "降级轮询 · 更新于 HH:MM:SS"（warn）；重启 8s 内自动恢复"WS 实时"+"更新于 12:56:39" |
| TC-10 | **PASS** | 两层验证：① 处理器级——调用 ECharts 实例已注册 click 处理器（dataIndex=0 → 端口 :22，56 次）：chip"过滤：端口 :22 ✕（来自攻击页）"display=block；FW 明细抽查 8 行目的列全为 203.0.113.10:22；② 事件级（reviewer R-01 整改）——通过 zrender 事件分发层派发真实事件序列（mousemove→mousedown→mouseup→click，坐标取自柱条 shape 几何中心）：柱条 1（:22）命中 rect 并触发 chip；清除后柱条 2（:443）命中并触发 chip"过滤：端口 :443 ✕（来自攻击页）"——dataIndex 0/1 多点映射正确、重复点击/清除链路完整；chip 点击清除（display=none） |
| TC-11 | **PASS** | 折叠 fold-resources → reload → 保持折叠（open=false）；fold-events 保持展开（open=true）——sessionStorage 记忆生效 |
| TC-12 | **PASS** | 481px：docW=475≤winW=481；721px：docW=715≤721；820px（N-01 补测，同 TC-03 编号）：docW=814≤820；801px：docW=795≤801；桌面 docW=1083≤1089——无横向溢出 |

**合计：12/12 PASS，0 FAIL。**

## 3. 覆盖率

- 代码覆盖率：`N/A`——前端为 go:embed 静态资源 + 原生 JS，项目无前端单元测试框架；本任务按浏览器全量实测（12 用例覆盖任务书全部 12 个验收/回归点），不以行覆盖率衡量。
- 关键路径覆盖：五项调整全部 DOM/实例级验证（非视觉目测）；7 个回归点全部交互实测；响应式四档宽度实测（481/721/820/1312px）。关键风险（归档残留请求、标题不一致、布局错乱）均有针对性断言。
- **控制台监控范围说明**（reviewer R-03 整改）：console 消息列表为页面加载以来全程累积监控（多次 list_console_messages 覆盖 TC-01~TC-12 全时段，含各页签切换/时间范围切换/过滤操作），非仅 TC-04 期间；唯一错误为 TC-09 kill agent 测试窗口的 `ERR_CONNECTION_REFUSED`（WS 断连 + 轮询请求失败，属测试操作预期产物，与 TEST-FE-001 同口径）。Network"全程 79 请求"含 kill 窗口（该窗口仅轮询请求失败无新 URL 种类），archive 请求零出现的结论不受窗口影响。

## 3.5 旧用例裁剪与既有缺陷处置（reviewer R-04/R-05 整改）

- **TEST-FE-001 → TEST-FE-002 用例映射**：TEST-FE-001 的 35 用例中，本任务书明确聚焦 3.1 五项调整（TC-01~TC-05）+ 3.2 七个回归点（TC-06~TC-12）。未纳入本报告的旧用例及其理由：FR-1（四页签切换，归档断言按新行为迁移至 TC-04/TC-06）、FR-2/FR-3/FR-4/FR-6/FR-7/FR-8/FR-9/FR-10/FR-11（基础功能回归，由 TC-06~TC-12 采样覆盖关键断言）、NF-1~NF-16（新增功能，五项调整影响域内者已迁移：NF-1 KPI 分组标签→TC-01、NF-8 刷新分级→TC-04、NF-10 30d 降频→TC-08、NF-9 新鲜度→TC-09、NF-2 折叠记忆→TC-11；其余如 NF-3~NF-7 行点击/事件流跳转等非本次调整影响域，其功能路径未改动，按轻量回归采样原则未全量重测）、PF-1~PF-3/RC-1/AX-1~AX-4（性能/竞态/a11y 专项，非本任务书范围，标记 N/A）。
- **既有 Major 缺陷 DEF-FE-001-02 处置声明**：DEF-FE-001-02（PF-2 性能长任务，TEST-FE-001 遗留，待运营官/developer 复核窗口口径）为前序未修复 Major。本任务书为轻量回归（性能验收 N/A，任务书未含 PF-2 复测项），故**未复测**；本次调整 ⑤（smooth:true）作用于渲染路径，其渲染开销影响未做量化对比——该缺陷维持 TEST-FE-001 结论不变，处置权归属运营官/developer 复核流程，不在本报告结论范围内。本报告"无缺陷"表述口径为：**本轮调整范围内无新缺陷**。

## 4. 缺陷清单

**无缺陷。** 本次五项调整未发现 Blocker/Major/Minor 缺陷；控制台错误（kill agent 窗口的 ERR_CONNECTION_REFUSED）为测试操作预期产物，非产品缺陷。

## 5. 观察项（非缺陷）

| ID | 观察项 | 详情 | 状态 |
| :--- | :--- | :--- | :--- |
| OBS-1 | snapshot 空态（环境限制） | 连接页"暂无连接快照"：本机无 ss 命令（conntrack 降级"执行 ss -tanup 失败"），与 TEST-FE-001 记录一致；非前端缺陷 | 已验证（环境） |
| OBS-2 | disk_percent=-1 环境态 | summary.disk_percent 实测 -1（本机无法采集），KPI"磁盘使用率"61.1% 由 WS resource 帧覆盖；与 TEST-FE-001 OBS-2 一致 | 已验证（环境） |
| OBS-3 | 响应式降级记录 | 801px/721px 2+1 布局、481px 单列为预期降级（任务书明确"记录即可，不算缺陷"） | 已验证 |
| OBS-4 | 归档相关用例失效处理 | TEST-FE-001 NF-8（归档激活拉取）与 4 页签断言已失效；本报告按新行为断言（3 页签 + 无 archive 请求 + 端点存活 + 代码层不可达），TC-04 覆盖 | 已验证 |
| OBS-5 | disk24 变量保留核实 | 静态核对：disk24/disk24Ts 仍被磁盘卡 spark/trend 使用（app.js:590-592、1112-1113），非死代码；renderDiskWater 已删（其外推逻辑不再使用 disk24） | 已验证（代码核对） |

## 6. 整体结论

**PASS**：DEV-FE-005 面板五项调整全部满足验收标准（需求/验收追踪矩阵 7/7 达成），关键回归点 7/7 无回归。12 用例：12 通过 / 0 失败；本轮调整范围内无新缺陷（既有 Major DEF-FE-001-02 维持 TEST-FE-001 结论，处置归属运营官/developer 复核，见 §3.5）；5 项观察项（环境态 2 + 预期行为 1 + 用例迁移 1 + 代码核实 1）。候选基线 `082bbbd` 无漂移，结果基于该基线独立验证（非 developer 自测）。

## 7. 证据索引

| 证据 | 位置 |
| :--- | :--- |
| 浏览器实测记录（几何/实例/DOM/Network 全量） | `docs/verification/evidence/testfe002/browser_test_log.txt` |
| DOM 计数（5 表/8 图/3 页签/无 archive DOM） | `docs/verification/evidence/testfe002/dom_counts.txt` |
| 总览 KPI 布局截图（无标签 2×2） | `docs/verification/evidence/testfe002/01_overview_kpi.png` |
| 攻击页三列并列截图 | `docs/verification/evidence/testfe002/02_attack_page.png` |
| 总览最终截图 | `docs/verification/evidence/testfe002/03_overview_final.png` |
| API 预检（summary 200 / archive 200） | 本报告 §测试环境（命令输出见会话记录） |
