# TEST-FE-001 测试报告（sentry-agent 前端优化 P0+P1 全量回归）

- 测试人：tester（测试 Agent）
- 任务书：TEST-FE-001
- 候选基线：commit `b95e914`（main，测试前工作区仅含未提交的测试计划；测试期间无基线漂移）
- 受测对象：DEV-FE-002（P0，`325a8df`）+ DEV-FE-003（P1，`b95e914`）前端优化实施
- 测试日期：2026-08-16
- 测试环境：Windows（Chrome DevTools MCP 浏览器实测；agent 重建自基线 b95e914 并运行于 8090 隔离端口——8080 存在旧实例 PID 32792）
- 测试库：`scripts/dev015_seed_db.py`（30h 攻击数据；fw_events 276 / ssh_fail 176）
- 关键纪律（TEST-007 教训）：前端 go:embed 进二进制，必须重建后实测——已 `go build -o bin/sentry-agent.exe ./cmd/sentry-agent` 并确认 `GET /api/v1/summary?range=24h` HTTP 200

## 1. 执行摘要

| 维度 | 用例数 | 通过 | 失败 | 说明 |
| :--- | :---: | :---: | :---: | :--- |
| 功能回归 FR-1~FR-11 | 11 | 11 | 0 | 全部通过 |
| 新增功能 NF-1~NF-16 | 16 | 16 | 0 | 全部通过（NF-7 ban 条目跳转为代码确认，见 §5 OBS-5） |
| 性能 PF-1~PF-3 | 3 | 2 | 1 | **PF-2 FAIL（保守口径）**：受测 8090 长任务 3 次（8080 旧实例 1 次已排除），未达 P1 自测"0 次"预期；窗口界定待运营官/developer 复核（缺陷 DEF-FE-001-02，Major） |
| 竞态 RC-1 | 1 | 1 | 0 | 通过 |
| a11y AX-1~AX-4 | 4 | 4 | 0 | AX-1 键盘实测受限转代码静态确认；伴 1 项 Minor 缺陷 |
| **合计** | **35** | **34** | **1** | 结论：**REVISE**（存在 1 项 Major，整改后重测） |

- 覆盖率：`N/A`——前端为 go:embed 静态资源 + 原生 JS，项目无前端单元测试框架；本任务按方案 §10.1 验收路径做浏览器全量实测回归（35 用例覆盖全部验收点），不以行覆盖率衡量。
- 既有失败：无（基线 b95e914 前端回归未发现既有失败；TEST-007 口径 13 项全部通过）。
- 本次回归引入失败：1 项（DEF-FE-001-02，PF-2 长任务验收未达标），见 §4。

## 2. 需求/验收追踪矩阵

| 任务书验收点 | 对应用例 | 结果 | 证据 |
| :--- | :--- | :--- | :--- |
| ① 既有功能零回归 | FR-1~FR-11 | ✅ | 浏览器实测（§3） |
| ② 新增功能正确工作 | NF-1~NF-16 | ✅ | 浏览器实测 + 代码核对（§3） |
| ③ 性能达到预期 | PF-1~PF-3 | ⚠️ 部分未达（PF-2 FAIL） | DevTools Network/Performance/DOM 计数（§3、§4） |
| ④ 状态完备（加载/空/错误三态） | NF-11/NF-12/NF-16 + FR-3 | ✅ | kill/重启 agent 实测（§3） |
| ⑤ 竞态缓解生效 | RC-1 | ✅ | Slow 3G 快速切换实测（§3） |
| ⑥ 可访问性基线达标 | AX-1~AX-4 | ✅（带 1 Minor） | 键盘 + DOM 属性 + 代码静态确认（§3、§4） |

## 3. 逐用例结果

### 3.1 功能回归（FR-1~FR-11）—— 11/11 PASS

| 用例 | 结果 | 证据摘要 |
| :--- | :--- | :--- |
| FR-1 四页签切换 | PASS | 总览/连接/攻击/归档逐页激活，panel 内容渲染，nav active 类正确 |
| FR-2 KPI 卡数值 | PASS | today-fw=165~174、today-sshfail=89~94、active-conns=0 与 /api/v1/summary 一致；**disk-pct=61.1% 注**：summary.disk_percent 实测为 -1（本机无法采集），KPI"磁盘使用率"61.1% 来自 WS resource 帧实时覆盖（app.js:1416-1417），风险评分"磁盘水位"按 -1 显示失败态"-"（app.js:330）——两处口径不同但均为正确展示（详见 OBS-2）；标签随范围联动 |
| FR-3 风险评分环形仪表 | PASS | 仪表渲染非空；SSH 失败率/防火墙 drop/封禁数/磁盘水位 4 项与 API 口径一致（磁盘水位 -1 → "-"）；失败态 `--` 路径代码确认（app.js:545） |
| FR-4 攻击双通道趋势 | PASS | 防火墙 drop（143 次）VS SSH 失败（89~94 次）双通道渲染，与 firewall/timeline、ssh/timeline 对齐 |
| FR-5 TOP 攻击源/端口 + 柱条联动 | PASS | chart-ports/chart-sources 渲染；点击柱条 → 全局 chip 出现 + 明细联动收窄 |
| FR-6 6 张明细表 + 排序 + 过滤联动 | PASS | ssh/fw/ban/snap/conn/archive 6 表渲染；排序列点击排序（sorted 类 + 升降切换 + aria-sort 同步，app.js:1397）；SSH 结果/防火墙动作下拉过滤生效；连接页同步收窄 |
| FR-7 时间范围切换 1h/24h/7d/30d | PASS | 态势条/评分/KPI/TOP/明细口径随范围更新；KPI 标签联动（近 1 小时/24 小时/7 天/30 天） |
| FR-8 WS 实时 + 断线轮询兜底 + 重连 | PASS | 正常"WS 实时"；停 agent 后"WS 断开，轮询兜底"（error 色）+ 降级徽章；重启自动恢复（domAlive 哨兵探针确认恢复为 WS 重连而非页面刷新；探针读数口径沿用 TEST-007 记录） |
| FR-9 窄屏无横向溢出 | PASS | viewport 720px/480px 下 docW ≤ winW，无横向滚动条 |
| FR-10 控制台零错误 | PASS | 全程 console/network 零 JS 错误、零资源 404（favicon 已 data URI 化） |
| FR-11 既有 DOM id 保留 | PASS | chart-*/table/top-*-mini/conn-status 等全部存在（浏览器抽查 + 代码核对） |

### 3.2 新增功能（NF-1~NF-16）—— 16/16 PASS

| 用例 | 结果 | 证据摘要 |
| :--- | :--- | :--- |
| NF-1 信息架构重组 | PASS | 首屏=态势头+风险评分与攻击趋势同排；KPI 2×2 分组（攻击组：防火墙事件/SSH 失败；系统组：活跃连接/磁盘使用率，组标签存在）；资源折叠区（details×2）；事件流默认 3 条 |
| NF-2 事件流展开/收起 + 折叠记忆 | PASS | 默认 3 条 → 展开全部（20 条）；展开状态刷新后恢复（sessionStorage）；折叠资源区刷新后保持折叠 |
| NF-3 SSH 行点击过滤 | PASS | chip 文案带"（来自攻击页）"；SSH 明细收窄为该源 IP；连接页同步收窄 |
| NF-4 FW 行点击过滤（src/dst→src/port） | PASS | 行点击→src 过滤；src cell→src；dst cell→dst_port（app.js:864 单元格级事件） |
| NF-5 conn 行点击过滤 | PASS | chip 出现（来自连接页）；连接明细收窄 |
| NF-6 ban 行点击 | PASS | 仅跳攻击页 + row-highlight 高亮该 IP；不设 filter（chip 不出现） |
| NF-7 事件流条目跳转 | PASS | SSH/fw 条目：跳攻击页 + 预置 src 过滤 + chip；ban 条目：跳攻击页 + 高亮（**ban 跳转为代码确认**，UI 实测受限，见 §5 OBS-5） |
| NF-8 刷新分级 | PASS | 总览激活：无 snapshot/connections/archive 请求；连接激活：snapshot+connections 5s 轮询；归档激活：archive 拉取；攻击激活：攻击类轮询（Network 面板核对） |
| NF-9 数据新鲜度 | PASS | "更新于 HH:MM:SS"随轮询/WS 帧刷新；WS 断开时"降级轮询 · 更新于 HH:MM:SS"（warn 色） |
| NF-10 30d 降频提示 | PASS | 切 30d 攻击页顶部 rate-hint"30 天视图聚合较重…30 秒"；切回其他范围隐藏 |
| NF-11 状态完备（kill agent） | PASS | 全局错误横幅"数据加载异常，请检查 agent 运行状态"；态势头失败态"态势数据加载失败，请稍后重试"；KPI `--` + 失败色 |
| NF-12 状态完备（重启恢复） | PASS | 横幅自动消失；态势头/KPI 恢复正常 |
| NF-13 system 帧独立浮条 | PASS | 连接徽章文字不被覆盖；右下角 sys-toast 浮条显示 system 消息 5s 内消失（连续帧行为见 OBS-3） |
| NF-14 归档页磁盘水位条 | PASS | disk-water"当前水位 X.X% · 剩余约 N 天/剩余充足/估算中"；颜色分级（本机 disk_percent=-1 环境态见 OBS-2） |
| NF-15 favicon 无 404 | PASS | 无 /favicon.ico 404；data URI favicon |
| NF-16 KPI 骨架 | PASS | summary 到达前 kpi-skeleton 块；到达后移除（app.js:1449 首载骨架 + 回调移除） |

### 3.3 性能对比（PF-1~PF-3）—— 2/3 PASS（PF-2 FAIL）

| 用例 | 结果 | 证据摘要 |
| :--- | :--- | :--- |
| PF-1 30s 窗口请求数与字节 | PASS | 稳态实测（WS 实时、页面加载完成后计时 32s，Resource Timing 统计）：**60 请求 / 361,620 B**（gzip 压缩后 transferSize）；构成 = summary 9 + resources 9 + 攻击类 7×6，折算约 **9 请求/5s**（轻轮询 summary+resources1h=2 + 攻击类 7），与 AUD-FE-002 记录"9 请求/5s"一致，较 AUD-FE-001 记录的 P0 基线 **12 请求/5s 降 25%**（"12→9、轻轮询 5→2"预期达成）；30d 降频 30s 生效（NF-10）；**口径注**：P0 基线"53 请求/69.5KB"未注明字节口径（压缩前/后、含/不含首载），字节数无法严格对比，仅作记录（`evidence/testfe001/browser_dom_counts.txt`） |
| PF-2 攻击页 30s 长任务 | **FAIL** | trace 独立分析（trace_attack30s.json，窗口 53.5s，v3 口径按进程归属分组）：受测实例 **8090 长任务 3 次**——101.1ms@+41.9s（动画帧+绘制）、50.9ms@+41.8s（Layout×3+UpdateLayoutTree×4，DOM 插入布局）、69.8ms@+43.7s（V8 GC 增量标记为主），全部集中在 +41.8~43.7s（1.9s 内），构成与滚动加载分页操作（PF-3 记录的 2540 峰值同操作）特征一致；**8080 旧实例 1 次（61ms@+25ms）已排除**（非受测）；**窗口界定限制**：trace 内无 SPA 导航事件（FCP +20ms、8090 首载 +1.7s 为锚点），30s 观察窗口起止无法从 trace 独立界定——若窗口仅覆盖录制前段（0~30s）则 8090 稳态长任务为 0 次（PASS 可能成立）；按保守口径（全程窗口）判 FAIL → 缺陷 DEF-FE-001-02（Major），建议运营官/developer 复核窗口口径与滚动加载场景归属 |
| PF-3 DOM 峰值 | PASS | 总览初始 401（<500）；攻击页全量 **1440**（<2000，本轮独立复核）；滚动加载扩展峰值 **2540**（上轮实测记录，见 OBS-1）；当前页实测：details=2、table=6、button=20、tabindex=4（均 -1，IN-6 编程聚焦） |

### 3.4 setRange 竞态专项（RC-1）—— 1/1 PASS

| 用例 | 结果 | 证据摘要 |
| :--- | :--- | :--- |
| RC-1 Slow 3G 快速切换 | PASS | Slow 3G + 连续快速切换 1h/24h/30d + 过滤变更，观察 30s：请求序号机制生效（state.reqSeq + fwTimeline range 回显校验），态势条/风险评分/双通道图口径与最终 range 一致，无旧 range 在途响应污染；30d 降频生效 |

### 3.5 a11y 抽查（AX-1~AX-4）—— 4/4 PASS（AX-1 静态确认 + 1 Minor）

| 用例 | 结果 | 证据摘要 |
| :--- | :--- | :--- |
| AX-1 Tab 键盘导航 | PASS* | *键盘实测受限（press_key Tab 注入失效，焦点停留 BODY），转代码静态确认：sit-toggle 原生 button（index.html:520）+ focus-visible（260）；折叠区原生 details/summary（index.html:571/583，Enter/Space 原生切换）+ focus-visible（360）；页签原生 button（app.js:1489）。**证据强度注**：键盘可达为原生语义推断（未实际 Tab 遍历）、焦点可见为 CSS :focus-visible 规则静态确认（未渲染实测）。完整记录见 `evidence/testfe001/ax1_keyboard_static.txt`。伴 Minor 缺陷 DEF-FE-001-01（表格行/表头点击无键盘等价） |
| AX-2 图表 aria | PASS | chart 容器 role="img" + aria-label 存在且数据渲染后更新（如"风险评分图：当前 28/100"、"攻击趋势图：防火墙 drop 143 次，SSH 失败 89 次"） |
| AX-3 表格 caption + aria-sort | PASS | 6 表 caption（sr-only）存在；排序后 th aria-sort 更新 ascending/descending（app.js:1397 setAttribute） |
| AX-4 态势条键盘激活 | PASS | sit-toggle 为原生 button（index.html:520），Enter/Space 原生激活折叠/展开；aria-label 存在 |

## 4. 缺陷清单（按 AGENTS.md §4.6 分级）

| 缺陷 ID | 等级 | 描述 | 复现/证据 | 预期 vs 实际 | 关联用例 | 本次回归 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| DEF-FE-001-02 | Major | 受测实例 8090 在录制窗口内存在 3 次 ≥50ms 主线程长任务（含 1 次 101.1ms），未达 P1 自测"0 次/0ms"预期 | trace_attack30s.json（窗口 53.5s，v3 进程归属分组）：101.1ms@+41.9s（FireAnimationFrame×3+绘制）、50.9ms@+41.8s（Layout×3+UpdateLayoutTree×4）、69.8ms@+43.7s（V8 GC 增量标记为主，Paint×22）；8080 旧实例 61ms@+25ms 已排除；3 次集中在 +41.8~43.7s（1.9s 内），构成与滚动加载分页操作特征一致 | 预期：长任务 0 次（P1 自测，窗口口径未记录）；实际（保守口径全程窗口）：3 次；若 30s 验收窗口仅覆盖录制前段则稳态长任务为 0 次（PASS 可能成立）——窗口界定证据缺失，需运营官/developer 复核 | PF-2 | 是 |
| DEF-FE-001-01 | Minor | 表格行点击过滤/单元格点击/表头排序无键盘等价路径 | app.js:871（tr click）、864（td click）、1386（th click）均无 tabindex/role/keydown；AX-1 静态确认 | 预期：键盘可触发行过滤与排序；实际：仅鼠标路径可用，键盘用户无法使用 NF-3~NF-7 行交互与 FR-6 排序 | AX-1 | 是（a11y 增强验收点内） |

说明：无 Blocker 缺陷；1 项 Major（DEF-FE-001-02，性能量化验收未达成——受测 8090 全程窗口 3 次长任务集中在 +41.8~43.7s（1.9s 内），构成与滚动加载分页/GC 一致，30s 验收窗口起止无法从 trace 独立界定（SPA 无导航事件），需运营官/developer 复核窗口口径与滚动加载场景归属后裁定是否整改）+ 1 项 Minor（DEF-FE-001-01，可访问性增强缺口，不影响功能正确性——鼠标路径全部正常，建议后续补齐 tr/th 的 tabindex+Enter 处理；**合规注**：若项目对标 WCAG 2.1 成功标准 2.1.1（键盘）A 级，NF-3~NF-7 核心行交互与 FR-6 排序无键盘路径将构成 A 级合规失败，届时需重新评级）。

## 5. 观察项（非缺陷，记录备查）

| ID | 观察项 | 详情 | 状态 |
| :--- | :--- | :--- | :--- |
| OBS-1 | DOM 滚动扩展峰值 2540 | PF-3 攻击页滚动加载后 DOM 峰值 2540，高于静态全量 1440（本轮实测）与 <2000 静态预期；属滚动分页扩展的正常放大，PF-3 设计即要求记录扩展峰值；页面操作流畅无卡顿 | 已观察，未独立核验（上轮实测） |
| OBS-2 | 水位条 disk_percent=-1 环境态 | 本机 summary.disk_percent 实测为 -1（Int64，无法采集）；风险评分"磁盘水位"按失败态显示"-"（app.js:330）、KPI"磁盘使用率"61.1% 由 WS resource 帧实时覆盖（app.js:1416-1417）——两处口径不同但均为正确展示；属环境数据缺失而非前端缺陷 | 已验证（API 实测 + 代码确认） |
| OBS-3 | system 浮条连续帧 | system 帧连续到达时 sys-toast 浮条 5s 内消失逻辑正常，但连续帧场景下 toast 会重新计时/覆盖；符合设计（5s 超时，sysToastTimer），无功能问题 | 已观察 |
| OBS-4 | ForcedReflow 35ms | 上轮 Performance 面板观察到 35ms 强制回流标记；本轮 trace 独立分析（v3，Layout 事件口径）未复现 ≥30ms 布局事件（Layout 最大 19.7ms，33 次合计 140.8ms）；面板显示口径与 trace 事件口径不一致，以 trace 为准；与 DEF-FE-001-02 同源核验，无额外风险 | 已观察，trace 复核未复现 |
| OBS-5 | 事件流 ban 跳转未 UI 实测 | NF-7 ban 条目跳转场景未做 UI 实测（上轮会话步骤限制），代码确认：跳攻击页 + 高亮（复用 NF-6 已验证的 ban 高亮逻辑 app.js:1361/1002）；SSH/fw 条目跳转已 UI 实测 | 代码确认（未 UI 实测） |

## 6. 整体结论

**REVISE**：验收点 ①②④⑤⑥ 全部满足；验收点 ③（性能）部分未达——PF-2 长任务量化验收按保守口径未达成（缺陷 DEF-FE-001-02，Major，含窗口界定证据缺失待复核），需运营官/developer 复核后裁定整改或放行。35 用例：34 通过 / 1 失败；另有 1 项 Minor（DEF-FE-001-01）与 5 项观察项（OBS-1~OBS-5）。候选基线 b95e914 无漂移，结果基于该基线独立验证（非 developer 自测）。

## 7. 证据索引

| 证据 | 位置 |
| :--- | :--- |
| 测试计划 | `docs/verification/TEST-FE-001_测试计划.md` |
| 性能 trace（攻击页 30s 窗口原始记录，63MB） | `docs/verification/evidence/testfe001/trace_attack30s.json` |
| trace 分析脚本与结果（窗口修正 v3/进程归属分组，长任务 RunTask 口径/Layout） | `docs/verification/evidence/testfe001/analyze_trace.py`、`perf_trace_analysis.txt` |
| AX-1 键盘可达性静态确认记录 | `docs/verification/evidence/testfe001/ax1_keyboard_static.txt` |
| DOM 计数/PF-1 量化/PF-2 长任务明细 | `docs/verification/evidence/testfe001/browser_dom_counts.txt` |
