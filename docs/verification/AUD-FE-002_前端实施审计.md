# AUD-FE-002 前端实施审计报告（sentry-agent Web 面板 P0+P1 发布候选终审）

- 审计者：auditor 子 Agent，隶属于 sci-touful 管辖
- 任务书：AUD-FE-002（sentry-agent 前端优化 P0+P1 实施终审）
- 日期：2026-08-15
- 性质：纯只读审计（审计报告写入除外）；Git 提交项 N/A（归属运营官统一处理）
- 审查对象：`docs/前端优化方案.md`（§9/§10）、`docs/verification/AUD-FE-001_前端交叉审计.md`、DEV-FE-002/003 实施提交、`internal/web/static/index.html`（644 行）、`internal/web/static/app.js`（1581 行）

## 1. 审计范围与方法

### 1.1 候选基线

| 项 | 值 |
| :--- | :--- |
| 候选基线 commit | `b95e914`（main 分支 HEAD，`fix: DEV-FE-003 reviewer R2-01~R2-04 整改`） |
| 工作区状态 | 干净（nothing to commit, working tree clean），无基线漂移 |
| 对照基线（P0） | `325a8df`（`feat: DEV-FE-002 P0 前端优化实施`） |
| P1 提交链 | `daca4c5`（feat）→ `fa44093`（reviewer R-01~R-12 整改）→ `b95e914`（R2-01~R2-04 整改） |
| 审查文件 | `internal/web/static/index.html`、`internal/web/static/app.js` |
| 契约对照 | `internal/api/api.go`、`internal/api/query.go`、`internal/api/ws.go`、`internal/web/embed.go` |
| 参考文档 | 方案 §1 诊断/§7.4/§8/§9/§10、AUD-FE-001（§2-§5）、TEST-007 回归口径（经 AUD-FE-001 C-7 承接） |

### 1.2 方法与执行

1. 通读方案 §9.1 硬约束五条表、§9.2 技术风险表、§10.2 auditor 验收路径、§10.3 行为变化清单（8 项）。
2. 通读 AUD-FE-001 全报告：约束清单 C-1~C-9、N-1~N-5 建议、RB-01/RB-02 竞态与失败路径、R-03/R-16 失败态纪律。
3. `git diff 325a8df b95e914 -- internal/web/static/` 核对 P0→P1 改动范围（仅 index.html +95/-、app.js +965/-630 净变化）；`git diff --stat` 确认后端（internal/api、internal/web/embed.go、internal/event、internal/store）零改动。
4. 逐行通读 HEAD 版 index.html 与 app.js 全文；抽查 P0 版 app.js 的 setRange/zero-badge/reqSeq（判定问题时间归属）。
5. 验证执行：`node --check app.js`（语法，exit=0）、`go build`（cmd/sentry-agent，临时目录输出，exit=0，embed 链路完好）、`grep` 契约参数（connections since 参数与 query.go L73 一致）。
6. TEST-FE-001 测试报告在审计时尚未产出（docs/verification/ 无该文件）——运行时行为核验标注"待测试报告补充核验"（见 §7）。
7. 诊断行号引用按方案 §10.2 第 2 条"模块/函数名 + 语义"复核（实施重构导致行号漂移，死扣行号无意义）。

### 1.3 审计执行摘要

- **硬约束五条**：全部 PASS（证据见 §2）。
- **前序建议 N-1~N-5**：全部落地（证据见 §3）。
- **安全**：XSS/WS Origin/无写操作/R-03/R-16 全部通过（证据见 §4）。
- **性能与健壮性**：行级 diff/可见性门控/竞态缓解/资源生命周期/水位外推全部符合方案与审计要求；发现 1 项 P0 遗留 Minor（setRange 未同步清空 UI）+ 1 项同根因 Minor + 10 项 Note（见 §8，其中 A-09~A-12 为 reviewer 补记）。
- **审计结论**：**PASS_WITH_NOTES**（2 Minor + 10 Note，无 Blocker/Major）。

## 2. 硬约束五条核查结果（方案 §9.1 表逐条对证源码）

### 2.1 零 CDN / 零外部资源 —— PASS

| 核查点 | 证据 |
| :--- | :--- |
| 外链 | index.html 无任何 `http(s)://` 引用；脚本仅 `<script src="echarts.min.js">`（L9）与 `<script src="app.js">`（L642），均为 go:embed 本地文件（embed.go `//go:embed static` 目录级打包，前端改动无需改 embed 清单） |
| 字体 | `--font-ui` 系统栈（index.html L46-47），未新增字体加载 |
| 图标 | 全部内联 SVG（logo/nav 图标）；新增 favicon 为内联 data URI（index.html L8，方案 8.3 SC-04 顺手项，P1 落地） |
| 新增资源 | P0/P1 零新增外部文件；echarts.min.js 未替换 |

### 2.2 轻量化 —— PASS

| 核查点 | 证据 |
| :--- | :--- |
| 无新框架 | 纯原生 JS（IIFE 单文件），无 Vue/React 等运行时引入（app.js 首行 IIFE，无 import/require） |
| 无循环动画 | 全部动画为一次性/交互型：fade-up 入场 420ms（index.html L77-85）、kpi-shimmer **animation: 1 次**（L231，P0 预留样式曾为 infinite 但 P0 未启用；P1 启用时同步改为一次性——1C1G 红线正确处置）、ev-fade 600ms（L305-311）、panel-fade 150ms（L408-411）、countUp 300ms rAF 一次（app.js L446-462）、ECharts animationDuration 420ms 数据过渡（非循环） |
| reduced-motion | 全覆盖：fade-up（no-preference 门控）、kpi-shimmer（reduce 时 animation:none，L235-237）、ev-fade/panel-fade（no-preference 门控）、countUp（reduce 直接落值，L450） |
| 请求数不增 | 总览页 5s 轮询构成 = summary + resources1h + disk24（仅首轮）+ pollAttack 7 = **9 请求/5s**，低于 AUD-FE-001 PF-01 记录的 12 请求/5s 上限基线（archive/snapshot/connections 已移出常驻轮询，改为页签激活拉取，app.js L1183-1185）；30d 攻击轮询降频 30s（L1271）。**请求数只降不升（C-2）** |

### 2.3 功能保留 —— PASS

四页签（overview/conn/attack/archive，index.html L513-516）、KPI 4 卡（2×2 语义分组，L546-564）、风险评分环形仪表（L526-537）、攻击双通道趋势（L538-543）、TOP 攻击源/被攻击端口迷你榜（L566-569）、6 张明细表（snap/conn/ban/ssh/fw/archive，L593-636）、时间范围切换 1h/24h/7d/30d（L504-509）、WS 实时 + 轮询兜底（app.js connectWS L1408 + pollAll L1269）全部保留。既有 DOM id 全部未变（C-7：chart-*、*-table、top-*-mini、conn-status、filter-chip、zero-attack-badge 等，P0→P1 diff 核对无删除/改名）。

### 2.4 中文界面 —— PASS

新增文案全部中文：`更新于 --:--:--`（#freshness，index.html L502）、`数据加载异常，请检查 agent 运行状态`（L511）、`30 天视图聚合较重，攻击数据刷新频率自动降至 30 秒`（L600）、`归档副本（gzip）+ 磁盘水位`（L631）、`当前水位 62.3% · 剩余约 N 天`（renderDiskWater app.js L830）、`最近：xxx`（L696）、`展开全部（N 条）`/`收起`（L791）、`水位数据加载失败`（L811）、`态势数据加载失败，请稍后重试`（L514）、`暂无事件`（L699）、`点击过滤该源 IP`（L932）等。无英文残留文案。

### 2.5 现状兼容（12 API + /ws 契约）—— PASS

- 后端零改动：`git diff 325a8df b95e914 -- internal/api/ internal/web/ internal/event/ internal/store/` 为空；ws.go Origin 白名单（hWS：origin=="" 时按 allowNoOrigin 拒绝、origin != wsOrigin 时 403）未削弱。
- 前端调用端点仍为 12 个：summary、resources（1h/24h）、connections、archive、snapshot、attacks/top_ports、attacks/top_sources、ssh/timeline、firewall/timeline、bans、ssh、firewall + /ws。
- **P1 fetchConns 收敛（MA-01）**：app.js L1121-1129 单函数构造 `connections?limit=100&since=` + `dst_port`/`src_ip` 参数，与 AUD-FE-001 CT-01 契约记录一致；since 参数与 query.go L73 `hConnections` 实现一致（静态核验 + grep 确认）。
- 行级 diff 未改任何 API 参数构造：ssh（limit=200+range+src_ip+result）、fw（limit=200+range+dst_port/src_ip+action）、bans（limit=500+range）、timeline（range）——与 P0 完全一致。


## 3. 前序审计建议落地核对（AUD-FE-001 N-1~N-5）

| 建议 | 落地证据（HEAD 版 app.js） | 结论 |
| :--- | :--- | :--- |
| **N-1**：竞态缓解覆盖 filter 变更（reqSeq 在 setRange 与 applyFilter 均自增） | `state.reqSeq` 定义 L48；setRange 自增 L1318；applyFilter 自增 L1292；**下拉过滤（SSH 结果/防火墙动作）同样自增** L1560/L1570（reviewer R-01 补强，N-1 范围外扩展正确）；fetchJSON 回调前统一校验（成功 L1113、失败 L1116，过期即丢弃）；fwTimeline range 回显叠加校验 L1227（`d.range !== state.range` 丢弃）。**P0 已落地（325a8df 版同构），P1 未破坏** | ✅ 落地 |
| **N-2**：封禁表行点击不设 filter（仅跳转+高亮） | renderBans 行 click → `gotoBanIp(row.ip)`（L1004）；gotoBanIp（L1351-1364）仅设置 `banHighlightIp` + 按需扩充分页（上限 MAX_TABLE_PAGE=200）+ switchPanel('attack') + 60ms 后滚动定位高亮行，**不调用 applyFilter**；高亮由 renderBans cls 重算维持（L999-1002）；事件流封禁条目同样走 gotoBanIp（L747）；行 title 明示"封禁表不受过滤影响"（L1003）；无目标 IP 匹配或超出分页上限时 scrollIntoView 判空跳过（容错） | ✅ 落地 |
| **N-3**：P0 工作量排期（提示性） | P0（325a8df）于 2026-08-15 22:24 提交，P1 链 3 提交均当日完成；排期风险已随实施完成消解，无残留 | ✅ 已过 |
| **N-4**：RB-02 summary errCb（summaryFailed 标志 + 失败态） | summary fetchJSON 补 errCb（L1149-1155）：失败置 `summaryFailed=true` + noteFailure（错误横幅计数）+ renderSituation（"态势数据加载失败"）+ renderKPI（KPI -- 失败分支 L545-559）+ renderDiskWater（水位失败态 L808-812）；成功回调清除标志 + noteSuccess 清零横幅（L1135-1139）；setRange 重置标志（L1341） | ✅ 落地 |
| **N-5**：TI.chart 前 4 色顺序保持 | `TI.chart = ['#58a6ff', '#e09a4b', '#5fb877', '#d66a86']`（L169）——前 4 色顺序（蓝→橙→绿→粉）与方案 4.1 表一致，仅降饱和改值；索引引用保持：chart[1] 橙 = net Tx/disk（L263/272/591/554）、chart[2] 绿 = mem（L260），注释明示索引语义 | ✅ 落地 |

## 4. 安全审计结论

### 4.1 XSS 渲染路径全查 —— PASS

逐字段核查全部外部数据渲染路径（含 P1 新增路径）：

| 渲染路径 | 写入方式 | 安全性 |
| :--- | :--- | :--- |
| 6 表行级 diff（username/auth_method/fingerprint/detail/raw/chain/proto/action/type/jail/month/file/state/pid 等全部字符串字段） | textContent（renderTableDiff L891） | ✅ 自动转义 |
| 事件流条目（username/jail） | escapeHtml 拼接后 innerHTML（L673/L689→L770） | ✅ 已转义；IP/dst_port 为 ip() 数字串与 int64 数字 |
| 事件流折叠头摘要 | textContent（L696） | ✅ |
| 态势头 | innerHTML 仅拼接 Number() 强转数字（L526-527），正常态 textContent（L530） | ✅ 无注入面 |
| 图表 aria-label（含数据值） | setAttribute（setAria L108-111） | ✅ 无 HTML 解析 |
| 水位条文案 | textContent（L811/L830） | ✅ |
| WS system 帧浮条 | textContent（L1372） | ✅ |
| mini-top/TOP 源（dst_port/hits/src_ip 数字） | innerHTML 拼接数字（L618-621/L641-644，R-12 注释声明） | ✅ 无注入面 |
| 表格三态占位 | 代码常量（L93） | ✅ |
| 过滤 chip | textContent（L1298） | ✅ |

无任何 innerHTML 直插未转义外部数据；P1 行级 diff 将表格渲染从 innerHTML 重建改为 textContent 写入（安全性不降反升）。**R-08 纪律保持**。

### 4.2 WS Origin 白名单 / 无写操作 / R-03/R-16 —— PASS

- WS Origin：ws.go 白名单校验存在且后端零改动（见 §2.5）；前端 WS_URL 基于 location.host 同源（L20），无新增跨源请求。
- 无写操作：全部 fetch 为 GET（fetchJSON 仅传 path），无 POST/PUT/DELETE/导出外发。
- **R-03/R-16 失败态纪律**：
  - zero-line 触发条件（L376）：`fwSum === 0 && sshSum === 0 && !state.attackDataFailed && state.sshTimelineOk` ——数据源失败时**不**显示"✓ 所选范围无攻击记录" ✅（P0 与 HEAD 语义一致，P1 未弱化）；
  - 态势头失败态（L513）：`attackDataFailed || !sshTimelineOk || summaryFailed` → "态势数据加载失败"；
  - 风险评分失败态（L292-314）：gauge 显示 -- + aria 失败；
  - KPI 失败分支（L545-559）：主值 -- + danger 色（不保留旧值）；
  - 水位失败态（L808-812）；各表 errCb → error-row。**全部失败路径不落入"正常/零值"误导态**。

## 5. 性能与健壮性审计结论

### 5.1 行级 diff（renderTableDiff，PF-3）

- **key 复用**：`tb.__diff.map` 缓存 tr，存在即复用（L853-856），行/单元格属性与文本按快照比较仅变化时写入（L877-897，`__text`/`__html` 快照互斥 R-11）。
- **孤儿清理**：渲染前清理无 `__key` 或不在 map 中的行（L849-852）——覆盖三态占位行残留（setTableState 清 `__diff` 后占位行无 key）；渲染后按 seen 删除消失行（L903-909）。
- **三态占位**：setTableState 写入 innerHTML 并清 diff 缓存（L88-94），与数据行互斥。
- **排序/过滤正确性**：排序/过滤逻辑独立于重建机制（方案 9.2 铁律）；行 key = 内容组合 + 同键序号（L922-927 等），排序变化导致序号重排时少量行重建（R-06 已注明，纯性能无功能影响）；tr 复用后 `tr.__row` 每轮更新（L875），click handler 读最新数据（避免闭包过期）。
- **事件流 diff**（L663-796）：同框架，新增条目高亮 stream-new + animationend 自净（R2-04）；展开/收起抑制高亮（suppressStreamNew R-03）；孤儿清理覆盖"暂无事件"占位。
- 与 tester 结果交叉：**TEST-FE-001 尚未产出**（见 §7），运行时行为（真实浏览器滚动加载、排序切换重建量）待测试报告补充核验。

### 5.2 可见性门控（PF-2）

- 全部 render* 入口统一 `vis(panel)` 门控（L85：`!document.hidden && state.activePanel === panel`）：renderResource/renderRisk/renderAttackTrend/renderAttacks/renderKPI/renderMiniTop/renderTopSourcesMini/renderEventStream/6 表渲染全覆盖。
- 激活补渲染：switchPanel（L1455-1487）先切 active class（L1456-1460）**再** resize（L1462）**再**按页签补 render（L1463-1484）——顺序正确（resize 在容器显示后执行，隐藏面板 0 尺寸无影响、切回时恢复），无白屏路径（方案 9.2"可见性门控遗漏"风险已闭合）。
- 隐藏面板轮询挂载：conn/archive 仅激活页拉取（L1183-1185 + L1474/L1483），总览缓存补渲染（resourceData/topPorts 等）。

### 5.3 竞态缓解（RB-01/N-1）

- 校验点完整：fetchJSON 统一 seq 校验（成功+失败双路径）+ fwTimeline range 回显叠加；setRange/applyFilter/两处下拉均 reqSeq++。
- setRange 状态重置完整（L1325-1343：明细缓存、攻击三源、fwTimeline/summary/banCount/topPorts/resourceData 全置空 + 失败标志重置 + 横幅计数清零 + 攻击三图 clear），新数据到达前**无混合口径**（部分数据到齐前态势条走"计算中"分支 L516-518）。

### 5.4 资源生命周期

- 图表 click 绑定 `__clickBound` 防重（L418/L427）；滚动加载 `__scrollBound` 防重（L119）；行/单元格 click 仅建行时绑定一次（L863-872）。
- WS：onclose → 3s 重连（L1432）；onerror → close 收敛（L1434）；system 浮条计时器重置（L1374-1375）。
- 滚动加载：TABLE_PAGE=60/MAX_TABLE_PAGE=200 上限（L26-27），resetTablePages 在 setRange/applyFilter/下拉时重置；无 DOM 无限增长路径。
- 遗留：WS 固定 3s 重连无退避（AUD-FE-001 RB-04 既有 Note，P0/P1 未承诺修复，本报告 §8 引用记录）。

### 5.5 水位外推算法（reviewer R-01 修复复核）—— 通过

- resources?range=24h&step=60s 每 bucket 60 秒（query.go hResources stepSec=60 语义，代码注释 L800-802 明示）。
- 外推按**首尾点实际时间跨度**折算：`spanH = (ts[n-1] - ts[0]) / 3600; daily = delta / spanH * 24`（L820-823）——修复了"60 倍低估"（每点 1h 误算）；满 24h 窗口 daily = 24h 增量本身，正确。
- 边界处理：spanH≤0 跳过、daily≤0.005 不估（防噪声）、days<1 → "剩余不足 1 天"、days≥1000 → "剩余充足"（L824-829）；失败分支不保留旧值（L808-812）。


## 6. 范围控制核验

| 核查项 | 结果 | 证据 |
| :--- | :--- | :--- |
| P0/P1 提交 diff 范围 | ✅ 仅 `index.html` + `app.js` 两文件（+965/-630） | `git diff 325a8df b95e914 --stat`；后端/embed.go/事件/存储零改动 |
| P2 未混入 | ✅ 无时段下钻（无 timeline 桶参数）、无服务端分页、无框架迁移 | app.js 无相关端点/参数；方案 8.3 建议项均为"需用户拍板"，实施未采纳 |
| P1 顺手项 | ✅ favicon data URI（方案 8.3 明确"P1 顺手做"）；DOM 行数上限 TABLE_PAGE/MAX_TABLE_PAGE（方案 7.4 PF-04 承诺项） | index.html L8、app.js L26-27 |
| 方案 §10.3 行为变化清单（8 项） | 全部一致：① archive 仅归档页激活拉取（L1185/L1483）；② snapshot/connections 仅连接页激活 5s 拉（L1184/L1474）；③ 事件流默认 3 条 + 展开（L707）；④ 资源四图折叠区（details open + sessionStorage 记忆，L1524-1535）；⑤ 过滤 chip 全局 header（index.html L503）；⑥ 表格行可点击过滤（6 表）；⑦ 态势头提权 D2/D3 + 折叠按钮分离（L518-521）；⑧ system 帧独立浮条（L1369-1376） | HEAD 版代码逐项对照 |
| 已知限制（10.3 CT-02/CT-03） | ✅ IPv6 显示 `-:port` 保持、attack 帧文档滞后不依赖——前端未新增相关逻辑 | 行为与既有一致 |

## 7. 验收证据链核验

| 核查项 | 结果 | 证据 |
| :--- | :--- | :--- |
| 候选基线一致性 | ✅ 代码基线 b95e914 = 当前 HEAD = 任务书指定候选基线（main，工作区 clean，无漂移） | `git log/status` |
| 后端契约冻结 | ✅ 12 API + /ws 参数构造与 AUD-FE-001 CT-01 记录一致；后端零改动 | §2.5 |
| 构建可验证性 | ✅ `node --check app.js` exit=0；`go build`（cmd/sentry-agent）exit=0（临时目录输出，未污染工作区）——embed 链路可重建 | 执行记录 |
| 诊断→修复语义复核（方案 §10.2 第 2 条，抽查 8 项） | 全部真实落地（模块/函数名 + 语义）：IA-1 首屏重组（评分+趋势同排，index.html L525-544）✅；IA-3 事件流收敛（概览→明细入口化 + 默认 3 条，L582-589/L707）✅；VI-1 态势头提权（D2/D3 + sit-toggle 分离，L239-263/L518-521）✅；IN-1 行点击过滤（6 表行/单元格 click + 事件流跳转，L928-1100/L745-749）✅；PF-1 刷新分级（三档 + 页签激活，L1183-1185/L1269-1277）✅；PF-2 可见性门控（§5.2）✅；PF-3 行级 diff（§5.1）✅；MA-1 模块化（模块 1-9 分区 + fetchConns 收敛，L19 起模块 1-9 分区/L1121-1129）✅ | 逐项静态核验 |
| TEST-FE-001 交叉核验 | ⏳ **待测试报告补充核验**：审计时 `docs/verification/TEST-FE-001_测试报告.md` 尚未产出（tester 并行执行中）。基线一致性、13 项回归点（四页签/范围/TOP 联动/排序/过滤/三态/WS 断线重连/窄屏/控制台零错误）、Slow 3G 竞态专项、DOM 节点实测（PF-04）均须以该报告产出后交叉核验；本报告结论基于静态审计 + 构建验证，运行时行为项（行级 diff 实际重建量、滚动加载、30d 响应延迟）置信度受此限制 | — |

## 8. 问题清单

> 等级按 AGENTS.md §4.6 统一标准（Blocker/Major/Minor/Note）。统计：**0 Blocker + 0 Major + 2 Minor + 10 Note**。

### 8.1 Minor

**A-01（Minor）setRange 重置 state 后未同步清空/置位已渲染 UI，旧范围结论短暂残留**

| 字段 | 内容 |
| :--- | :--- |
| 代码位置 | `app.js:1308-1347`（setRange）；佐证：L1328-1330 仅清攻击三图、L1331-1337 重置 state 但无任何 render* 调用 |
| 事实 | setRange 重置 state（summary/fwTimeline/banCount/topPorts 置 null）并 clear 攻击三图，但**未调用** renderSituation/renderKPI/renderRisk/renderEventStream/renderMiniTop；DOM 上态势条文本（"共 N 次…"）、KPI 值、评分 gauge、事件流条目、TOP 榜继续显示旧 range 数值，直到新 range 首个响应回调触发重渲染（bans/summary 回调，L1241/L1147 等） |
| 风险推导 | state 层已杜绝混合口径（AUD-FE-001 RB-01 修复目标达成），但**渲染层残留旧范围完整结论**：切换范围后至新 range 首个攻击数据回调到达前（常态 1-3s，最坏约 5s——受 summary 后端 5s 超时约束（api.go L208）：summary/bans/top_sources 任一成功或失败回调（L1147/L1152/L1215/L1241/L1244 等）都会触发 renderSituation 离开旧值，故残留窗口不随 fwTimeline 30s 超时放大）态势条/KPI/评分显示旧范围结论且无"计算中"指示——与开发者对攻击三图的处理（L1328 注释"旧 range 图不得残留误导"）标准不一致，属疏漏；P0 已存在（325a8df 版 setRange 同构），P1 新增的 KPI 骨架分支（renderKPI L561）亦未接驳 setRange（骨架逻辑触发条件 `!s` 存在但无人调用） |
| 触发条件 | 用户切换时间范围（1h/24h/7d/30d）；残留窗口受 5s 轮询/后端超时约束，各 range 同量级 |
| 影响 | 安全面板结论短暂过期展示（旧范围口径被误读为新范围），自愈无数据损坏；影响面为态势条/KPI/风险评分/事件流/TOP 榜五个模块 |
| 建议 | setRange 在 state 重置后补调用：renderSituation()（进入"态势计算中…"）、renderKPI()（骨架态）、renderRisk()（-- 态）、renderEventStream()（空态或清除）、renderMiniTop([])（空态）——与攻击三图 clear 行为对齐；applyFilter 同源问题见 A-02 |
| 置信度 | 高（静态确认：setRange 全函数无 render* 调用；P0 版同构，非 P1 引入但 P1 未修复） |
| 是否阻塞 | 否（Minor） |

**A-02（Minor）applyFilter 未重置明细/事件流旧 filter 数据，渐进刷新窗口内显示旧 filter 行**

| 字段 | 内容 |
| :--- | :--- |
| 代码位置 | `app.js:1291-1305`（applyFilter）；佐证：L1292-1304 无 `state.sshRows/fwRows/banRows/connRows = null` 与对应 render 调用 |
| 事实 | applyFilter 仅自增 reqSeq、设 filter、resetTablePages、pollAttack、fetchConns；旧 filter 的 sshRows/fwRows/banRows/connRows 保留，表格与事件流继续显示旧 filter 数据直至新响应回调（≤5s，30d 场景 applyFilter 直发 pollAttack 不受节流，通常 1-3s） |
| 风险推导 | 与 A-01 同根因（state 变更后未同步 UI 渲染）；filter 场景窗口短于 range 场景（attack 不降频），但用户发起过滤后 1-5s 内表格显示旧过滤结果，无"过滤中"指示；30d 时 fw 明细聚合慢时窗口可放大 |
| 触发条件 | TOP 图/迷你榜/表格行/事件流条目点击发起过滤 |
| 影响 | 过滤反馈延迟 1-5s（旧 filter 行残留），可感知但不产生错误数据；自愈 |
| 建议 | applyFilter 内对受影响表置 null + 调用对应 render（或复用 setTableState 显示"加载中…"），与 setRange 清空行为对齐 |
| 置信度 | 高（静态确认） |
| 是否阻塞 | 否（Minor） |

### 8.2 Note

| ID | 等级 | 代码位置 | 事实与建议 |
| :--- | :--- | :--- | :--- |
| A-03 | Note | `app.js:817-826` vs 方案 §3.4 | 水位外推口径：方案文案"近 30 天增量速率"与数据源指定"resources 24h 序列"不一致，实现取 24h 首尾点线性外推。24h 短窗口对慢速磁盘增长噪声敏感（单次大写入会高估日增量 → 剩余天数低估），但**低估为安全侧**（更早告警），且有 daily≤0.005 与 spanH≤0 兜底。建议：实现注释补充口径说明（"24h 窗口近似，非 30 天"），不阻塞 |
| A-04 | Note | `app.js:1416-1418`（WS resource 帧） | WS resource 帧写 disk-pct 仅更新 textContent，不更新语义色 class（ok/warn/danger）——summary 轮询（5s 内）会修正；80% 边界处 1-5s 内颜色可能滞后。建议 WS 帧写入时同步 class 判定（与 renderKPI L574 同口径），纯视觉一致性 |
| A-05 | Note | `app.js:292-314`（renderRisk 失败分支） | 失败分支重置 gauge 与 v 文本为 --，但**不重置四通道分解条宽度**（risk-*-bar 保留旧百分比）。建议失败分支同时清零 bar 宽度，与 KPI 失败分支（L545-559 清 spark/trend）口径统一 |
| A-06 | Note | `app.js:844-910`（renderTableDiff） | 行级 diff 对列结构变化不重建（td 缺失时 L886 return 跳过）——当前 6 表列结构静态无实际风险，但未来加列须整表重建或扩展框架。建议在框架注释中记录该约束 |
| A-07 | Note | `index.html:525/583` | P1 新增 2 处内联样式（grid margin-bottom:12px、details margin-top:12px），延续 AUD-FE-001 MA-03 既有记录（CSS 内联分散）。建议后续并入 CSS 类，不阻塞 |
| A-08 | Note | `app.js:1428-1433`（connectWS onclose） | WS 断线重连固定 3s 无退避/上限（AUD-FE-001 RB-04 既有 Note，P0/P1 未承诺修复，本报告延续记录）；P1 重写 connectWS 时未顺手改进。建议后续任务可选项（指数退避 3s→30s 封顶），不阻塞 |
| A-09 | Note | `app.js:698-705`（renderEventStream 空态分支）、`app.js:1308-1347`（setRange） | 事件流高亮状态生命周期未闭合（reviewer R-02）：空态分支提前 return 跳过 L785 的 suppressStreamNew 复位；setRange 不重置 streamKeys/suppressStreamNew。后果：空态（"暂无事件"）→ 数据恢复后首轮 streamKeys={} 致全部行判"新"（L750 条件全真）→ 事件流首轮全量 stream-new 高亮闪烁；切 range 后同样首轮全量高亮——R-03"不得误报事件突增"语义边界泄漏（600ms 淡入，自愈，纯视觉）。建议：空态分支补 suppressStreamNew=false 复位；setRange 内补 streamKeys={}; suppressStreamNew=false（可与 A-01 整改合并） |
| A-10 | Note | `app.js:1414-1422`（WS onmessage） | WS 帧处理无 null 防御（reviewer R-03）：L1417/L1421 直接解引用 disk-pct/active-conns，无存在性检查——与 AUD-FE-001 RB-03 同模式（renderKPI 已修复但此处遗留新点）。当前 DOM 元素静态存在无实际风险；若未来 DOM 重构移除元素则 onmessage 抛 TypeError 中断后续帧处理（system 浮条失效）。建议两处补 var el = document.getElementById(...); if (el) {...} |
| A-11 | Note | `app.js:1351-1364`（gotoBanIp）vs `app.js:989-991`（renderBans 排序） | 封禁跳转在排序状态下高亮可能失效（reviewer R-04）：gotoBanIp 按 `state.banRows` 原始数组查 idx 并推算分页（L1353-1358），但 renderBans 渲染 sortRows().slice(0, tablePage)（L989-991）——用户按 ts 排序后目标 IP 排序位置可能超出截断范围 → DOM 无 .row-highlight → scrollIntoView 判空跳过，跳转无高亮（N-2 容错未覆盖排序偏移场景）。边缘交互（先排序再跳转），无错误数据。建议：idx 查找改用排序后序列，或跳转前清 ban-table 排序并重置分页；至少记录为已知限制 |
| A-12 | Note | `app.js:1107-1119`（fetchJSON） | fetch 无超时控制（reviewer R-05）：fetch 挂起不 reject（后端 handler 卡死/SQLite 锁等待）时既无 errCb 也无超时降级，失败态纪律（R-03/R-16、错误横幅）失效且与 A-01 残留叠加。127.0.0.1 本机场景触发概率低（连接拒绝立即 reject），属既有架构限制（方案选方案 A 请求序号而非方案 B AbortController），P0/P1 未承诺。建议列入未决风险跟踪（本表 §9 已补记），不阻塞 |


## 9. 未验证假设清单（待确认，不混入问题清单）

| # | 假设描述 | 待验证方法 | 把握度 |
| :--- | :--- | :--- | :--- |
| U-1 | 30d 场景下各攻击数据源（summary/bans/top_sources/fwTimeline）首个回调的实际到达时间（决定 A-01 残留窗口长度与"计算中"出现时机；2-8s 量级为 DEV-018 实测经验，AUD-FE-001 RB-01 引述） | 运行时 DevTools Network 实测 30d 视图切换后各请求响应时间 | 中（静态推断，依据既有实测记录） |
| U-2 | 行级 diff 在真实浏览器中的 DOM 写入量降幅（PF-3 收益未实测量化，方案 9.2 D-4 明确"实测前置"） | TEST-FE-001 性能对比（Performance/DOM 节点峰值） | 中 |
| U-3 | DOM 节点数是否低于 M3 验收线 <2000（PF-04，TABLE_PAGE=60 上限设计针对此线） | TEST-FE-001 DOM 实测 `document.getElementsByTagName('*').length` | 中 |
| U-4 | 事件流 items 每 5s 从 900 行（ssh200+fw200+ban500）派生的遍历开销在 1C1G 上的实际影响 | 浏览器实测（预计毫秒级，静态评估可接受） | 高（静态评估） |
| U-5 | 封禁表 >200 行时目标 IP 不在分页上限内的跳转降级（gotoBanIp 无高亮）是否符合用户预期 | 产品口径确认（MAX_TABLE_PAGE=200 为 1C1G 约束，跳转仅覆盖前 200 行属设计取舍） | 中 |

## 10. 审计结论

**结论：PASS_WITH_NOTES**（放行发布候选；2 Minor + 10 Note，无 Blocker/Major）

- 硬约束五条全部 PASS（§2）；N-1~N-5 全部落地（§3）；安全审计全过（§4）；范围控制严格（§6）。
- A-01/A-02（Minor）为 P0 遗留的"state 重置后未同步 UI"疏漏，不阻塞发布（自愈、无数据损坏、无混合口径），但**建议在测试验收后按 Minor 排期修复**——二者同根因（setRange/applyFilter 补 render 调用即可，改动面小、风险低）。
- 10 项 Note 均为可选优化/口径说明/既有记录延续（A-03~A-08 本报告发现；A-09~A-12 为 reviewer R-02~R-05 补记），不阻塞。

**放行条件（发布候选验收）**：
1. TEST-FE-001 测试报告产出后交叉核验：报告声明基线须为 b95e914（一致候选基线）；13 项回归点全过；竞态专项（Slow 3G 快速切换）与 DOM 实测结果与本报告静态结论一致（U-2/U-3）。
2. A-01/A-02 记录在案并列入后续修复（Minor 级，不阻塞当前发布）。
3. 若测试发现行级 diff/滚动加载/可见性门控的运行时缺陷，按 AGENTS.md §4.9 对相关结论失效重验（当前基线 b95e914 未漂移）。

## 11. 自检结果（公共 §4.8 + auditor 角色专属）

**公共自检（AGENTS.md §4.8）**：
1. 验收标准覆盖：任务书 §4.1-4.6 六组审计要点全部对应产出（§2-§7）；交付物结构 10 节齐备（§1-§11）✅
2. 验证证据：所有"已核验"项附代码位置与执行记录（node --check/go build/git diff 均有输出）✅
3. 未验证项：TEST-FE-001 未产出（§7 明示"待测试报告补充核验"）；30d 响应延迟等运行时项列 U-1~U-5 ✅
4. 范围漂移：未修改任何代码；仅写入审计报告文件 ✅
5. 风险与不确定点：A-01/A-02 窗口长度依赖运行时（U-1）；行级 diff 收益未实测（U-2）✅
6. 下游上下文：候选基线 b95e914 一致；tester 待测基线声明记录 ✅
7. 验收建议：PASS_WITH_NOTES，一句话理由见 §10 ✅
8. reviewer 分发：已调用 reviewer 独立反思（提示词声明禁止 bash），结论见 §12 ✅

**auditor 角色专属自检**：
- 审查清单 7 项覆盖：逻辑健壮性（§5.3/5.4）、安全漏洞（§4）、性能瓶颈（§5.1/5.2）、资源生命周期（§5.4）、异常处理（§4.1/RB-02 路径）、架构可维护性（MA-1 模块化核验）、重复逻辑（fetchConns 收敛核验）✅
- 科研审查维度 4 项：N/A（前端非科研代码，无实验/统计/数据溯源维度）✅
- 每个问题含完整 10 字段（A-01/A-02 完整表格式，A-03~A-12 Note 级为表格精简格式）✅
- 严重等级使用统一标准（Blocker/Major/Minor/Note，未用旧称）✅
- 风格偏好单独列出（A-03~A-12 中视觉/结构类为 Note，未升级）✅
- 未验证假设单列（§9），未强行定性 ✅
- 阻塞性问题（Blocker/Major）无，已明确标记"无"✅
- 候选基线 commit hash 记录（b95e914/对照 325a8df）；无基线漂移 ✅
- 纯只读审计：Git 提交项 N/A（归属运营官统一处理）✅

## 12. reviewer 反思结论


**第 1 轮（2026-08-16，auditor 首次提交）**：reviewer 独立反思结论 **PASS_WITH_NOTES（评分 8/10）**，无 Blocker/Major。

**reviewer 本轮意见与整改情况**：
- R-01（Note，论证修正）：A-01 风险推导"30d 残留最长 30s"不成立——残留窗口由最先到达的响应/失败回调决定：summary 后端 5s 超时（api.go L208）保证最迟 5s 触发成功或失败回调使态势条离开旧值，bans/top_sources 各回调（app.js L1215/L1241 等）均调 renderSituation；fwTimeline 30s 超时只影响自身。**已整改**：A-01 风险推导/触发条件与 U-1 表述修正为"最坏约 5s、常态 1-3s"。
- R-02（Note）：事件流 streamKeys/suppressStreamNew 生命周期未闭合（空态分支提前 return 跳过复位；setRange 不重置）→ 切 range/空态恢复后首轮全量高亮闪烁。**已整改**：补记 A-09。
- R-03（Note）：WS 帧处理无 null 防御（L1417/L1421，与 RB-03 同模式）。**已整改**：补记 A-10。
- R-04（Note）：gotoBanIp 在排序状态下高亮失效（原始数组查 idx vs 排序后渲染）。**已整改**：补记 A-11。
- R-05（Note）：fetchJSON 无超时（挂起路径失败态纪律失效）。**已整改**：补记 A-12 并列入未决风险。
- R-06（Note）：§7 MA-1 行号引用"L16-16"笔误。**已整改**：修正为"L19 起模块 1-9 分区"。

**reviewer 复核结论**：PASS_WITH_NOTES。A-01/A-02 维持 Minor 定级（三支柱对照：无混合口径、窗口 ≤5s 与面板固有轮询延迟同量级、用户主动触发知晓上下文），升级 Major 依据不足；6 项意见全部 Note 级，整改后无 Blocker/Major 遗留，第 2 轮无需再复核（reviewer 原话："补记后本报告即完成第 1 轮复核，无需第 2 轮"）。评分 8/10。
