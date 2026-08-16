# TEST-FE-001 测试计划（sentry-agent 前端优化 P0+P1 全量回归）

- 测试人：tester（测试 Agent）
- 任务书：TEST-FE-001
- 候选基线：commit `b95e914`（main，工作区 clean）
- 受测对象：DEV-FE-002（P0，`325a8df`）+ DEV-FE-003（P1，`b95e914`）前端优化实施
- 依据：`docs/前端优化方案.md` §10.1（验收路径）/§10.3（行为变化清单）、`docs/verification/AUD-FE-001_前端交叉审计.md`、TEST-007（13 项回归口径）、TEST-006（WS-3 断线重连口径）
- 测试日期：2026-08-16
- 环境：Windows（Go 1.26.2 + Chrome DevTools 浏览器实测；agent 重建自基线 b95e914，端口 8090 隔离——8080 存在旧实例 PID 32792）
- 测试库：`scripts/dev015_seed_db.py`（30h 攻击数据；本轮实测 seed：fw_events 276 / ssh_fail 176 / ban 记录按库内实际）

> 关键纪律（TEST-007 教训）：前端 go:embed 进二进制，必须**重建二进制**后实测；本轮已执行 `go build -o bin/sentry-agent.exe ./cmd/sentry-agent` 并确认 `GET /api/v1/summary?range=24h` HTTP 200。

## 1. 用例清单（4.1~4.5 展开为可执行用例）

### 1.1 功能回归（既有功能零回归，TEST-007 13 项清单口径）

| 用例 ID | 目标 | 步骤 | 预期结果 |
| :--- | :--- | :--- | :--- |
| FR-1 | 四页签切换正常渲染 | 依次点击 总览/连接/攻击/归档 | 各 panel 激活且内容渲染；nav 按钮 active 类正确 |
| FR-2 | KPI 卡数值正确 | 总览页读取 today-fw/today-sshfail/active-conns/disk-pct | 数值与 API summary 一致；标签随范围变化（近 24 小时防火墙事件等） |
| FR-3 | 风险评分环形仪表渲染 | 总览页 chart-risk 及 risk-*-v 明细 | 环形仪表渲染非空；SSH 失败率/防火墙 drop/封禁数/磁盘水位 4 项值与 API 口径一致；失败态显示 `--` |
| FR-4 | 攻击双通道趋势渲染 | 总览页 chart-attack-trend | 双通道（防火墙 drop vs SSH 失败）图渲染；与 firewall/timeline + ssh/timeline 数据对齐 |
| FR-5 | TOP 攻击源/端口渲染 + 柱条点击联动 | 攻击页 chart-ports/chart-sources 柱条点击 | 图渲染；点击柱条 → 全局 chip 出现（header 可见）+ 明细联动收窄 |
| FR-6 | 6 张明细表渲染 + 排序 + 过滤联动全链路 | ssh/fw/ban/snap/conn/archive 6 表 | 各表渲染数据；可排序列点击排序（sorted 类 + 升/降切换）；SSH 结果/防火墙动作下拉过滤生效；过滤后连接页同步收窄 |
| FR-7 | 时间范围切换 1h/24h/7d/30d | 依次点击 range 按钮 | 态势条/评分/KPI/TOP/明细口径随范围更新；KPI 标签联动（近 1 小时/近 24 小时/近 7 天/近 30 天） |
| FR-8 | WS 实时推送 + 断线轮询兜底 + 重连 | 观察 conn-status；受控停 agent → 重启 | 正常："WS 实时"（ok）；断线："WS 断开，轮询兜底"（error）+ 降级轮询徽章；重启：自动恢复（domAlive 探针确认非刷新） |
| FR-9 | 窄屏（≤720px）无横向溢出 | viewport 720px / 480px 检查 | 页面无横向滚动条（docW ≤ winW） |
| FR-10 | 控制台零错误 | 全程收集 console/network 错误 | 无 JS 错误；无资源 404（favicon 404 已修复） |
| FR-11 | 既有 DOM id 保留 | 抽查 chart-*/table/top-*-mini/conn-status 等 | 全部存在（代码已确认，浏览器抽查） |

### 1.2 新增功能验证（按方案 §10.3"新行为"断言）

| 用例 ID | 目标 | 步骤 | 预期结果（新行为） |
| :--- | :--- | :--- | :--- |
| NF-1 | 信息架构重组 | 总览页首屏布局检查 | 首屏 = 态势头 + 风险评分与攻击趋势同排；KPI 2×2 分组（攻击组：防火墙事件/SSH 失败；系统组：活跃连接/磁盘使用率，组标签存在）；资源折叠区（details）；事件流默认 3 条 |
| NF-2 | 事件流展开/收起 + 折叠记忆 | 点击"展开全部"；刷新页面；折叠资源区后刷新 | 默认 3 条 → 展开显示全部（最多 20 条）；展开状态刷新后恢复（sessionStorage）；折叠状态刷新后保持折叠 |
| NF-3 | SSH 行点击过滤 | 攻击页 SSH 表点击一行 | 全局 chip 出现且文案带来源"（来自攻击页）"；SSH 明细收窄为该源 IP；连接页同步收窄 |
| NF-4 | FW 行点击过滤（src/dst→src/port） | 点击 FW 行 / 源 IP 单元格 / 目的端口单元格 | 行点击 → src 过滤；src cell 点击 → src 过滤；dst cell 点击 → dst_port 过滤 |
| NF-5 | conn 行点击过滤 | 连接页 conn 表点击一行 | chip 出现（来自连接页）；连接明细收窄 |
| NF-6 | ban 行点击 | 攻击页 ban 表点击一行 | 仅跳转攻击页 + 高亮该 IP 行（row-highlight），**不设 filter**（chip 不出现） |
| NF-7 | 事件流条目跳转 | 总览页点击事件流条目 | SSH/fw 条目：跳攻击页 + 预置 src IP 过滤 + chip 出现；ban 条目：跳攻击页 + 高亮 |
| NF-8 | 刷新分级（页签激活才拉取） | Network 面板分别激活各页签 | 总览页激活：无 snapshot/connections/archive 请求；连接页激活：snapshot + connections 5s 轮询；归档页激活：archive 拉取；攻击页激活：攻击类轮询 |
| NF-9 | 数据新鲜度 | 观察 freshness 元素 | 显示"更新于 HH:MM:SS"且随轮询/WS 帧刷新；WS 断开时"降级轮询 · 更新于 HH:MM:SS"（warn 色） |
| NF-10 | 30d 降频提示 | 切 30d | 攻击页顶部 rate-hint 显示"30 天视图聚合较重…30 秒"；切回其他范围隐藏 |
| NF-11 | 状态完备（kill agent） | 停止 agent 进程 ≥2 轮轮询 | 全局错误横幅出现（"数据加载异常，请检查 agent 运行状态"）；态势头失败态"态势数据加载失败，请稍后重试"；KPI 显示 `--` + 失败色 |
| NF-12 | 状态完备（重启恢复） | 重启 agent | 横幅自动消失；态势头/KPI 恢复正常 |
| NF-13 | system 帧独立浮条 | 等待 system 帧（或检查 WS 消息） | 连接徽章文字不被覆盖；右下角 sys-toast 浮条显示 system 消息且 5s 内消失 |
| NF-14 | 归档页磁盘水位条 | 归档页激活 | disk-water 显示"当前水位 X.X% · 剩余约 N 天/剩余充足/估算中"；水位条颜色分级 |
| NF-15 | favicon 无 404 | Network 面板检查 | 无 /favicon.ico 404 请求；页面提供 data URI favicon |
| NF-16 | KPI 骨架 | 刷新页面首帧抓取 | summary 到达前 KPI 显示骨架块（kpi-skeleton class）；到达后移除 |

### 1.3 性能对比（方案 §10.1 第 3 条）

| 用例 ID | 目标 | 步骤 | 预期结果 |
| :--- | :--- | :--- | :--- |
| PF-1 | 30s 窗口请求数与总字节 | Network 面板记录总览页激活 30s 窗口 | 请求数/字节明显低于 DEV-FE-002 记录的 53 请求/69.5KB（预期 12→9/轮询 5→2）；30d 时攻击类降频 30s |
| PF-2 | 攻击页激活 30s 长任务 | Performance 面板记录攻击页 30s | JS 主线程长任务次数 ≤ P0 记录（P1 自测 0 次/0ms，复核） |
| PF-3 | DOM 峰值 | `document.getElementsByTagName('*').length` 实测 | 总览初始 <500；攻击页全量 <2000；滚动加载扩展峰值记录 |

### 1.4 setRange 竞态专项（方案 §10.1 第 5 条）

| 用例 ID | 目标 | 步骤 | 预期结果 |
| :--- | :--- | :--- | :--- |
| RC-1 | Slow 3G 快速切换无混合口径 | DevTools Slow 3G + 快速连续切换 1h/24h/30d + 过滤变更；观察 30s | 请求序号机制生效：态势条/风险评分/双通道图口径与最终 range 一致，无旧 range 在途响应污染；30d 降频生效 |

### 1.5 a11y 抽查（方案 §10.1 第 6 条）

| 用例 ID | 目标 | 步骤 | 预期结果 |
| :--- | :--- | :--- | :--- |
| AX-1 | Tab 键盘导航 | 键盘 Tab 遍历 | 可达态势条折叠按钮/折叠区/表格/页签；焦点可见 |
| AX-2 | 图表 aria | 抽查 2-3 张图 | chart 容器 role="img" + aria-label 存在且数据渲染后更新 |
| AX-3 | 表格 caption + aria-sort | 检查 6 表 | caption（sr-only）存在；排序后 th aria-sort 更新（ascending/descending） |
| AX-4 | 态势条键盘激活 | 聚焦 sit-toggle 回车/空格 | 态势条可折叠/展开（button 原生可达） |

## 2. 需求/验收追踪矩阵

| 任务书验收点 | 对应用例 | 验证方法 |
| :--- | :--- | :--- |
| ① 既有功能零回归 | FR-1~FR-11 | 浏览器实测 + Network/Console 面板 |
| ② 新增功能正确工作 | NF-1~NF-16 | 浏览器实测 + 代码核对 |
| ③ 性能达到预期 | PF-1~PF-3 | DevTools Network/Performance/DOM 计数 |
| ④ 状态完备（加载/空/错误三态） | NF-11/NF-12/NF-16 + FR-3 | 浏览器实测（kill/重启 agent） |
| ⑤ 竞态缓解生效 | RC-1 | Slow 3G + 快速切换实测 |
| ⑥ 可访问性基线达标 | AX-1~AX-4 | 键盘 + DOM 属性检查 |

## 3. 覆盖范围

- 正常路径：FR-1~FR-8、NF-1~NF-10、NF-13~NF-16 ✅
- 边界条件：空态（零攻击场景由代码核对 + 事件流空态）、KPI 失败 `--`、水位条估算边界（代码核对）✅
- 异常路径：agent 停止（NF-11）、WS 断线（FR-8）、接口失败（横幅/error-row）✅
- 回归测试：FR-1~FR-11 全量（TEST-007 口径）✅
- 集成测试：过滤联动全链路（FR-6/NF-3~NF-7）✅
- 状态/资源生命周期：折叠记忆（NF-2）、WS 重连（FR-8）、骨架→数据（NF-16）✅
- 并发/性能：PF-1~PF-3、RC-1 ✅
- 安全：N/A（本任务无新增安全面；XSS 防护由 escapeHtml/textContent 代码核对，非本次验收点）
- 科研维度：N/A（前端工程回归，非科研代码）

## 4. 执行环境与工具

- 浏览器：Chrome（DevTools MCP 控制：Network/Performance/Console/evaluate_script）
- 网络节流：DevTools Slow 3G（RC-1）
- 证据归档：`docs/verification/evidence/testfe001/`
