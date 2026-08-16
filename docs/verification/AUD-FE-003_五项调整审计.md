# AUD-FE-003 五项面板调整审计报告

- 受审任务：DEV-FE-005 面板五项调整（① KPI 分组标签删除；② 标题改"VPS安全态势"；③ 攻击页三图并列；④ 归档页签前端隐藏；⑤ 折线平滑 smooth: false→true）
- 审计日期：2026-08-16
- 审计角色：auditor（sci-touful 管辖），纯只读审计
- 候选基线：`082bbbd`（main，工作区 clean）
- 前序基线：`b95e914`（AUD-FE-002 审计基线）

## 一、审计范围与方法

### 1.1 改动提交

| 提交 | 内容 | 文件（numstat 精确行数） |
| :--- | :--- | :--- |
| `38f9135` | feat: DEV-FE-005 面板五项调整 | `internal/web/static/app.js`（92 行变更：5+/87-）、`internal/web/static/index.html`（32 行变更：6+/26-） |
| `082bbbd` | chore: reviewer R-04 模块标题注释同步 | `internal/web/static/app.js`（1+/1-） |

`git diff b95e914 082bbbd --stat` 确认：代码文件仅 `app.js` + `index.html` 两处，累计 app.js 6+/88-（94 行变更）、index.html 6+/26-（32 行变更）；`internal/web/embed.go` 零改动（`git diff b95e914 082bbbd -- internal/web/embed.go` 无输出）；docs/verification 下的 README/AUD-FE-002/TEST-FE-001 等为前序任务登记提交（`be92586`/`fa8221e`），非本次实施内容。

### 1.2 审计方法

- `git show` / `git diff` / `git diff --numstat` 核对两份提交的逐行变更与精确增删行数
- grep/Select-String 全量核验归档相关标识符残留（12 个复合标识符 + 补查裸词 `archive`/中文"归档"）
- 对照基线 `b95e914` 的 fetchJSON 调用集合，核对端点契约变化
- 阅读 renderKPI 磁盘消费链、switchPanel、renderAttacks、lineSeries/barSeries、trendArrow 当前代码

### 1.3 审查维度适用性

- 通用审查清单 7 项：全部适用并覆盖（见 §7.2 逐项结论）
- 科研审查维度 4 项：N/A —— 本次为前端 UI 布局与渲染属性调整，非科研代码（实验/数据分析/统计建模/可视化科研流程）

## 二、各要点核查结果

### 2.1 改动范围（要点 1）—— 通过

- 实施提交 `38f9135`：app.js 5+/87-、index.html 6+/26-，以删除为主（净删 82 行 app.js、净删 20 行 index.html）
- 注释同步提交 `082bbbd`：app.js 1+/1-（第 43-44 行 `disk24`/`disk24Ts` 注释去除"归档水位外推"字样）
- 累计 `b95e914 → 082bbbd`：app.js 6+/88-、index.html 6+/26-；embed.go 零改动
- 后端零改动，无嵌入资源变更

### 2.2 archive 清理彻底性（要点 2）—— 通过（附残留记录）

**app.js 删除项**（`git diff b95e914 38f9135` 逐项核对）：

| 删除内容 | 证据 |
| :--- | :--- |
| `renderDiskWater()` 函数整体（含失败态/外推逻辑，约 40 行） | diff 中函数体整体移除 |
| `renderArchive()` 函数整体（含 sortRows/slice 分页/seen 去重） | diff 中函数体整体移除 |
| `pollArchive()` 函数整体（含 `/api/v1/archive` 请求） | diff 中函数体整体移除 |
| `state.arcRows` / `state.archiveRows` 字段 | 与 renderArchive 同段删除 |
| `pollAll()` 中 `if (state.activePanel === 'archive') { pollArchive(); }` 低频档分支 | diff 中删除 |
| `pollSummary` 成功/失败回调中 2 处 `if (state.activePanel === 'archive') { renderDiskWater(); }` | diff 中删除 |
| `pollResources` 24h 回调中 `if (state.activePanel === 'archive') { renderDiskWater(); }` | diff 中删除 |
| `switchPanel` 中 `archive` 分支（renderArchive + renderDiskWater + pollArchive） | diff 中删除 |
| `bindScrollLoad('archive-table', renderArchive)` 绑定 | diff 中删除 |
| `bindSort('archive-table', ...)` 绑定 | diff 中删除 |

**index.html 删除项**：`<title>` 与 `<h1>` 标题文案、2 处 `.kpi-group-label` span 与对应 CSS 规则、攻击页 SSH 卡 `style="grid-column: 1 / -1"`、nav 中归档按钮、`#panel-archive` 整块（含 `#disk-water`/`#dw-fill`/`#dw-text`/`#archive-table`）、`.disk-water` 系列 CSS 规则（注释同步说明"随 DEV-FE-005 前端静默归档删除"）。

**功能层残留核验（通过）**：grep 全量扫描 `internal/web/static/`，12 个复合标识符 `pollArchive|renderArchive|renderDiskWater|arcRows|archiveRows|archive-table|panel-archive|disk-water|dw-fill|dw-text|kpi-group-label` 零匹配 —— 无死代码引用、无未定义函数调用、无孤立 DOM id/CSS 类、无 archive 分支/绑定残留。switchPanel（app.js:1379-1407）仅 overview/conn/attack 三分支；nav 按钮（index.html:505-507）仅三页签，不存在触发 `switchPanel('archive')` 的用户路径。

**文案/注释层残留记录（reviewer 复核发现，非功能缺陷）**：
- index.html:551：磁盘 KPI 卡 note 文案仍为"归档分区水位"——归档页已删，该概念无界面载体，用户可见语义残留（详见 §3.1 A-01）
- app.js:4：头部历史注释"archive/connections 按页签激活拉取"——archive 已不按页签拉取（详见 §3.2 N-02）
- app.js:14：模块 5 头部注释"归档页磁盘水位"——所指逻辑已删
- app.js:1107：注释"水位外推需全量序列 + ts 时间跨度（R-01）"——R-01 对应实现 renderDiskWater 已删，注释悬空

**disk24/disk24Ts 消费链（回归检查）**：
- `disk24` 消费链完整：定义 app.js:43 → 写入 app.js:1112（pollResources 24h 回调）→ 消费 app.js:590-595（renderKPI 中 `if (state.disk24)` → `sparkSVG(spark-disk)` + `trendArrow(disk24)` → `trend-disk`）
- `disk24Ts` 已成孤儿字段：仅定义 app.js:44 + 写入 app.js:1113，全文件无任何读取点（原唯一消费方 renderDiskWater 已随归档删除；trendArrow 仅消费 disk24 序列，不读 ts）。不影响功能（多写一个无人读的数组，无副作用），但属死数据路径（详见 §3.2 N-01）
- 删除归档水位渲染后，磁盘卡 spark/trend 数据链未受影响；删除的仅是归档页专属的水位外推消费逻辑，无遗留引用

### 2.3 平滑改动影响面（要点 3）—— 通过

- `lineSeries` 定义 app.js:183-185：`smooth: false` → `smooth: true`，仅此一处属性变更（name/type/data/symbol/lineStyle/itemStyle/areaStyle 均未变）
- lineSeries 调用方共 7 处：资源四图 CPU（:257）/ 内存（:260）/ 磁盘（:263）/ Rx（:271）/ Tx（:272），总览攻击趋势图 防火墙 drop（:367）/ SSH 失败（:368）
- barSeries 为 `renderAttacks` 内局部函数（app.js:387-392，`type: 'bar'`），无 smooth 属性 —— 攻击页端口 TOP/来源 TOP/SSH 时间线三张柱状图不受影响
- ECharts `smooth` 为静态曲线形状插值（贝塞尔平滑），非动画属性；`animationDuration: 420`（app.js:220）等动画配置未变
- 动画/交互纪律：`prefers-reduced-motion` 媒体查询（index.html:81/235/305/408 区块规则）全部保留；app.js:450 countUp 的 `matchMedia('(prefers-reduced-motion: reduce)')` 抑制逻辑未变 —— reduced-motion 纪律未弱化

### 2.4 布局改动（要点 4）—— 通过

- 攻击页三图并列：index.html:591-593 三张卡（`chart-ports`/`chart-sources`/`chart-ssh`）均为 `.grid` 直接子卡，无任何残留 grid-column 强制属性；SSH 卡删除 `grid-column: 1 / -1` 后按流式布局排入网格；fail2ban 卡（:594）保留 `grid-column: 1 / -1` 整行展示，符合"三图并列 + 表格整行"设计意图
- `.grid` 布局 CSS（index.html:418）：`grid-template-columns: repeat(auto-fit, minmax(320px, 1fr))` —— 宽屏三列并列，窄屏自动换行（`.grid > .card { min-width: 0; }` 兜底，:420；720px 以下单列媒体查询 :483 保留）
- KPI 标签删除：index.html:538-549 两行 `.kpi-row` 各 2 张 `.kpi` 卡，`kpi-group-label` span 与 CSS 规则已删除；`kpi-row`/`kpi` 类保留；app.js:540 `document.querySelectorAll('.kpi-row .kpi')`（骨架屏切换）选择器仍有效，无 JS 引用断裂

### 2.5 安全纪律（要点 5）—— 通过

- 无新增 innerHTML 直插：diff 中无任何 innerHTML 新增行（现有 innerHTML 使用点均为基线既有代码，且集中于 escapeHtml 已处理的表格/列表渲染）
- 无新外部资源：index.html diff 无新增 `<script src>` / `<link href>`；favicon 仍为内联 data URI（基线已有）
- 无写操作边界变化：无新增 POST/PUT/DELETE 请求、无 localStorage/cookie 写入变更；后端零改动

### 2.6 契约一致性（要点 6）—— 通过

**前端端点调用集合对比**（fetchJSON 调用点）：

| 端点 | 基线 b95e914 | 当前 082bbbd |
| :--- | :--- | :--- |
| /api/v1/connections | ✓ | ✓ |
| /api/v1/summary | ✓ | ✓ |
| /api/v1/resources?range=1h | ✓ | ✓ |
| /api/v1/resources?range=24h | ✓ | ✓ |
| /api/v1/snapshot | ✓ | ✓ |
| /api/v1/archive | ✓ | ✗ 已移除 |
| /api/v1/attacks/top_ports | ✓ | ✓ |
| /api/v1/attacks/top_sources | ✓ | ✓ |
| /api/v1/ssh/timeline | ✓ | ✓ |
| /api/v1/firewall/timeline | ✓ | ✓ |
| /api/v1/bans | ✓ | ✓ |
| /api/v1/ssh（sshQS） | ✓ | ✓ |
| /api/v1/firewall（fwQS） | ✓ | ✓ |

- 归档端点是唯一移除项；其余 12 个调用点（11 个唯一资源路径，resources 1h/24h 同路径）全部保留，与任务书"其余 11 端点不变"口径一致
- WS 消费不变：`new WebSocket(WS_URL)` + `onmessage`（app.js:1333-1335）未在 diff 中变动；archive 本为 REST 拉取，非 WS 通道，无帧消费

## 三、问题清单（§4.6 分级）

### 3.1 正式缺陷

| ID | 等级 | 代码位置 | 事实 | 风险推导 | 触发条件 | 影响 | 建议 | 置信度 | 是否阻塞 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| A-01 | Minor | index.html:551 | 磁盘 KPI 卡 note 文案仍为"归档分区水位"；归档页签与 panel-archive 已删除 | 归档概念已无任何界面载体，文案语义悬空，与"前端静默归档删除"任务目标不一致；用户会看到一个不存在的功能提示 | 总览页磁盘卡常态可见 | 用户可见语义残留，非功能缺陷；无数据/安全影响 | 将文案改为"当前磁盘水位"或删除该 note | 高（已静态验证） | 否 |

**无 Blocker / Major 级缺陷。** 本次为删除型改动（累计 app.js 6+/88-、index.html 6+/26-），经逐项核对：无逻辑断裂、无死代码引用、无资源泄漏、无安全面变化、无契约破坏、无关键证据缺失。

### 3.2 Note（非阻塞提示）

| ID | 等级 | 代码位置 | 事实 | 风险推导 | 触发条件 | 影响 | 建议 | 置信度 | 是否阻塞 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| N-01 | Note | app.js:44, :1113 | `disk24Ts` 仅定义与写入，全文件无读取点（原消费方 renderDiskWater 已删） | 每次 24h 轮询回调写入无人读取的数组，属死数据路径；若未来维护者误以为其被消费而扩展，易产生误导 | 24h 轮询每轮写入 | 无功能影响，仅冗余写入与误导风险 | 删除 disk24Ts 字段与写入，或补注释说明保留理由 | 高（grep 全文件仅 2 处命中，已静态验证） | 否 |
| N-02 | Note | app.js:4, :14, :1107 | 三处注释仍指向已删除的归档逻辑（"archive/connections 按页签激活拉取"、"归档页磁盘水位"、"水位外推需全量序列 + ts 时间跨度（R-01）"） | 注释与代码现状不符，悬空引用降低可维护性；R-01 编号无对应实现 | 阅读代码时 | 仅文档性残留，无功能影响 | 删除或改写悬空注释 | 高（已静态验证） | 否 |
| N-03 | Note | app.js:185 | `smooth: true` 使折线做贝塞尔插值 | 数据稀疏或单点突变时段，贝塞尔曲线可能出现轻微过冲/尾部回弯的视觉观感变化，属渲染外观差异而非数据错误 | 7d/30d 范围下攻击趋势/资源图数据点稀疏时 | 纯视觉观感，无功能/性能影响 | 保持现状即可；如后续目验不满意，可改为 `smooth: 0.3`（有限平滑度）或按图细分 | 高（静态推断 + ECharts 行为已知） | 否 |
| N-04 | Note | internal/web（后端） | `/api/v1/archive` 后端端点仍注册，仅前端不再调用 | 前端静默隐藏后，归档数据仍可通过 REST 直连获取；符合"前端隐藏"任务边界，但若为安全约束场景需另行收敛 | 直接访问 /api/v1/archive 时 | 无（该端点本为只读展示用途） | 本次保持后端零改动符合任务书；后续如需彻底移除可另行立项 | 高（已验证前端调用已删；端点注册于后端） | 否 |

## 四、未验证假设清单（待确认）

| ID | 假设描述 | 待验证方法 | 把握度 |
| :--- | :--- | :--- | :--- |
| U-01 | `smooth: true` 在 7d/30d 大数据量 + dataZoom 联动下的实际渲染观感符合预期（无过冲/尾弯） | 浏览器目验或 Playwright 截图对比基线 | 中（ECharts 行为已知，视觉主观性高） |
| U-02 | 攻击页三图在 <1024px 宽度下的 auto-fit 换行表现（2 列/1 列降级）无布局异常 | 浏览器响应式目验 | 中（CSS 静态推断无溢出风险，实际换行点由容器宽度决定） |

以上均为视觉/布局类静态推断，不涉及功能、安全、数据正确性；不影响本审计结论。

## 五、风格偏好清单

| ID | 偏好描述 | 建议方向 |
| :--- | :--- | :--- |
| S-01 | index.html:470 磁盘水位 CSS 删除后留空行，以注释占位说明删除原因 | 无需处理，属合理做法 |

## 六、结论

**PASS_WITH_NOTES**

- 五项调整全部按任务书实施：KPI 标签删除（HTML+CSS 同步）、标题双处（title/h1）改"VPS安全态势"、攻击页三图并列（grid-column 移除）、归档页签前端隐藏（app.js 函数/分支/绑定 + index.html 区块/CSS 全量清理）、折线平滑（lineSeries 统一 smooth:true）
- archive 功能层清理彻底：12 个复合标识符全量 grep 零匹配，无死代码引用；disk24 消费链完整无回归（disk24Ts 孤儿化属冗余写入，见 N-01）
- 契约一致：仅 /api/v1/archive 调用移除，其余端点与 WS 消费不变；后端零改动
- 安全纪律：无新增 innerHTML、无新外部资源、无写操作边界变化
- 1 项 Minor（A-01 磁盘卡"归档分区水位"文案残留）+ 4 项 Note（N-01~N-04）均不阻塞交付；A-01 与 N-01/N-02 建议 developer 在后续维护中顺手清理

## 七、自检结果

### 7.1 公共自检（AGENTS.md §4.8）

| 项 | 结果 |
| :--- | :--- |
| 验收标准覆盖 | 任务书六项审计要点（改动范围/archive 清理/平滑影响面/布局/安全纪律/契约一致性）均有对应核查结论与代码位置证据 |
| 验证证据 | 全部结论基于 git diff/numstat、grep 扫描、代码阅读的可追溯证据（§2 各条标注位置）；reviewer 复核后补充的残留项均经 auditor 独立复验 |
| 未验证项 | §4 待确认清单 2 项（视觉/布局目验），已说明原因与验证方法 |
| 范围漂移 | 无；仅产出任务书指定的 AUD-FE-003 报告 |
| 风险与不确定点 | U-01/U-02 为最不确定项，均为非阻塞视觉类 |
| 下游上下文 | 交接要点：基线 082bbbd、后端 archive 端点保留属设计边界、smooth 视觉待目验、A-01 文案残留建议顺带清理 |
| 是否建议验收 | 建议验收（PASS_WITH_NOTES）：无 Blocker/Major，1 项 Minor + 4 项 Note 不阻塞 |

### 7.2 auditor 角色自检（角色专属）

| 项 | 结果 |
| :--- | :--- |
| 审查清单 7 项覆盖 | 全部覆盖（§2 结论）——逻辑健壮性（死代码/消费链/分支完整性）、安全（注入/外部资源/写边界）、性能（无新增请求/循环；archive 低频轮询移除属性能正向）、资源生命周期（WS 连接未变）、异常处理（删除型改动无新增异常路径；原失败态分支随功能删除）、架构可维护性（CSS/注释同步清理）、重复逻辑（无新增） |
| 科研审查 4 项 | N/A（非科研任务，已附理由） |
| 10 字段完整 | Blocker/Major 0 项；Minor 1 项、Note 4 项均按 10 字段完整填写 |
| 严重等级标准 | 使用 Blocker/Major/Minor/Note 统一标准，未用旧称 |
| 风格偏好单列 | §5 单独列出（S-01），未升级为正式缺陷 |
| 未验证假设单列 | §4 单独列出，未定性为缺陷 |
| 候选基线记录 | 082bbbd（main，工作区 clean）已记录；无基线漂移（审计基于任务书指定基线） |
| 纯只读审计 | 无代码文件变更，仅写入交付报告 docs/verification/AUD-FE-003_五项调整审计.md；Git 提交项 N/A（归属运营官统一处理） |

## 八、reviewer 反思结论

- reviewer 结论：**PASS_WITH_NOTES**（第 1 轮，无 Blocker/Major）
- reviewer 发现并核实的问题（auditor 已全部复验属实并整改进本报告）：
  - R-01（Minor）：index.html:551 磁盘卡"归档分区水位"用户可见文案残留 → 已补记为 A-01
  - R-02（Minor）：disk24Ts 仅写不读、断言"消费链完整"不实 → 已修正 §2.2 表述并补记 N-01；S-01 原"补充用途说明"建议（基于误解）已删除
  - R-03（Note）：app.js:1107 悬空注释 → 已补记 N-02
  - R-04（Note）：残留核验关键词清单未含裸词 archive/归档，漏检 3 处注释残留 → 已补记 N-02 并说明关键词边界
  - R-05（Note）：行数统计矛盾（92/102、32/31 不一致）→ 已用 numstat 精确行数统一（§1.1/§2.1）
- reviewer 对审计核心结论的独立复核：五项调整实施、无功能回归、无安全面变化、契约一致 —— 全部成立
- 本轮整改情况：报告已按 reviewer 建议修订定稿；无未收敛的 Blocker/Major
