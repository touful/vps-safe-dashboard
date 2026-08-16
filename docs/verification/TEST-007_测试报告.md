# TEST-007 测试报告（DEV-019 前端全量美化回归）
- 测试人：B2（测试 Agent）
- 基线：commit `54e718c`（main；DEV-019 在 0b7957e 之上，仅改 internal/web/static/index.html + app.js）
- 测试日期：2026-08-15
- 环境：Windows（Go 1.26.2 + Chrome DevTools 浏览器实测，8099 攻击库 + 8098 noidle 零攻击库）
- 测试库：`scripts/dev015_seed_db.py`（30h 攻击数据）、`scripts/dev017_seed_noidle_db.py`（零攻击）

## 1. 执行汇总（13 项验证：9 组任务书回归点 + TKN-1/UT-1/CON-1 补充）

| 用例 ID | 目标 | 结果 | 证据状态 |
| :--- | :--- | :--- | :--- |
| TKN-1 | 设计 token 生效（CSS computed） | ✅ body #0A0E14、卡片 #11161D、圆角 6px | 已验证（CSS 变量 L20-41）+ 已观察（computed 实测） |
| NAV-1 | 四页签可达性与内容正确 | ✅ overview/conn/attack/archive 面板全渲染 | 已验证（DOM L409-499）+ 已观察（切换实测） |
| RNG-1 | 时间范围切换 1h/24h/7d/30d | ✅ 30d KPI 标签"近 30 天"、端口图数据更新 | 已验证（代码）+ 已观察（30d 实测） |
| RNG-2 | 30d 轮询降频节流 | ✅ minGap=30s（L839 代码确认） | 已验证 |
| LNK-1 | TOP 柱条点击联动 chip | ✅ zrender 点击 → chip "过滤：端口 :22 ✕" 出现/清除 | 已验证（代码链 L567-585）+ 已观察（chip 实测） |
| SRT-1 | 表格排序（6 表） | ✅ 8 可排序列头；时间列点击降↔升切换（sorted class） | 已验证（bindSort）+ 已观察（排序实测） |
| FLT-1 | 过滤下拉（SSH 结果/防火墙动作） | ✅ "仅失败"→176 行全失败；还原→195 行含 19 成功 | 已验证（change 绑定）+ 已观察（过滤实测） |
| STT-1 | 态势条三态 | ✅ 攻击态/零攻击态/失败态 | 已验证（renderSituation）+ 已观察（三态实测） |
| STT-2 | R-01 空→错占位切换 | ✅ errCb setChartEmpty(false) + clear() | 已验证（errCb L777-791）+ 已观察（失败态实测） |
| WS-1 | WS 状态徽章与断线重连 | ✅ "WS 实时"ok 态；断线→轮询→自动重连 | 已验证（代码链 L899-923）+ 已观察（重连恢复） |
| RSP-1 | 窄屏 480px 无横向溢出 | ✅ docW 474 < 480；表格滚动限 .scroll 容器内 | 已验证（CSS L369-370）+ 已观察（480px 实测） |
| CON-1 | 控制台零错误 | ⚠️ 仅 favicon.ico 404（Note） | 已验证（无 favicon link）+ 已观察（网络请求） |
| UT-1 | go test 全绿复核 | ✅ 13 包全绿 + vet（后端零改动确认） | 已观察（执行记录，未附输出） |

> **证据状态说明（reviewer R-02 整改）**：浏览器交互实测（CSS computed/联动/排序/过滤/窄屏/WS 恢复/控制台）为**已观察**级（会话内执行记录，未附原始截图）；代码确认项为**已验证**级（行号可独立核验）。全部用例均在**重建后的 54e718c 二进制**上执行（§3.1 起）。

## 2. 验收标准追踪

| 验收标准 | 对应用例 | 结果 |
| :--- | :--- | :--- |
| 1. 9 项回归点全部有结果证据 | NAV/RNG/LNK/SRT/FLT/STT/WS/RSP/CON（9 组回归点，含 RNG-2/STT-2 子项） | ✅（13 项实测 = 9 组回归点 + TKN-1/UT-1/CON-1 补充） |
| 2. 缺陷清单（分级） | §4 | ✅（1 Note：favicon） |
| 3. 报告按交付规范 | 本报告 | ✅ |

科研维度：N/A（前端回归，非科研代码）。

## 3. 验证详情

### 3.1 TKN-1 设计 token ✅（CSS computed style 断言）

新基线二进制实测（**关键：前端 embed 进二进制，须重建后验证**——初测用旧二进制误判 #0D1117，重建 54e718c 后正确）：
- `body` computed：**rgb(10,14,20) = #0A0E14**（`:root --bg-page`，任务书预期值一致）✅
- `.card` computed：**#11161D**（--bg-card）、**border-radius 6px**（--radius）✅
- body 字体 Segoe UI/Microsoft YaHei、文字 #E8EEF5（--text）✅
- **冷石墨·冰蓝设计系统落地确认**

### 3.2 NAV-1 四页签 ✅

- index.html 四面板 DOM：`panel-overview`（active）/`panel-conn`/`panel-attack`/`panel-archive` 全部存在（L409/460/468/499）
- 浏览器实测：总览页（态势条/KPI/风险评分/趋势/事件流全渲染）、攻击页（端口 TOP/源 TOP/SSH 时间线/封禁表/SSH 明细表+过滤下拉）、连接页/归档页面板切换正常
- 态势条文案升级："共 233 次防火墙 drop、176 次 SSH 失败，TOP 被攻击端口 :22，已封禁 17 个 IP"（drop 口径，D-23 修复延续）

### 3.3 RNG-1/RNG-2 时间范围切换 + 30d 降频 ✅

- 四个 range 按钮（1h/24h/7d/30d）存在且可点击
- **30d 实测**：KPI 标签变"近 30 天防火墙事件"、端口 TOP 图数据更新（8 柱）✅
- **30d 降频节流（DEV-018 P-01）代码确认**：pollAll 中 `minGap = (state.range==='30d') ? 30000 : 5000`（L839）——30d 攻击轮询 30s/次，其他 5s；setRange/applyFilter 直接触发 pollAttack 不受节流影响 ✅

### 3.4 LNK-1 TOP 柱条点击联动 ✅

- handler 绑定（app.js L567-585）：chart-ports click → `applyFilter({type:'port', value:dst_port})`；chart-sources → src_ip；含 setRange 后 cur null 防御（R-04）
- **浏览器实测**（reviewer R-03 派发方式披露）：zrender storage 取柱条 rect 元素 → 计算其几何中心坐标 → `zr.handler.dispatch` 依次派发 **mousedown → mouseup → click** 三事件序列（与原生点击序列一致）→ chip 显示 **"过滤：端口 :22 ✕"** ✅
- **清除**：点击 chip → `applyFilter(null)` → display:none ✅
- applyFilter 联动链：设置 state.filter → chip 显隐 → pollAttack() + connections 按 dst_port/src_ip 过滤 ✅

### 3.5 SRT-1/FLT-1 表格排序与过滤 ✅

- **6 表 32 列头**，8 个可排序列（snap 3：src_port/dst_port/pid；conn 1：packets；ban 1：ts；ssh 1：ts；fw 1：ts；archive 1：size_mb）——bindSort 绑定确认
- **排序实测**：SSH 表时间列点击 → 降序（19:15 最新）↔ 升序（08-14 最早）切换，`sorted` class 生效 ✅
- **过滤实测**（reviewer R-04 披露：两方向均程序化 set value + 手动 dispatchEvent('change')，与用户操作等效）：SSH 结果下拉选"仅失败" → 176 行全"失败"、0 成功；选"全部结果" → 195 行含 19 成功还原 ✅；防火墙动作下拉（全部/仅 drop/仅 accept）存在 ✅

### 3.6 STT-1/STT-2 三态与 R-01 占位 ✅

- **态势条三态**：攻击态（"共 233 次..."）/零攻击态（8098："✓ 当前态势正常"）/失败态（停后端："态势数据加载失败，请稍后重试"）浏览器实测 ✅
- **R-01 空→错占位切换**（代码确认 + 实测）：
  - 空态：`setChartEmpty(id, true)` → chart-empty class 显示"暂无数据"占位（8098 零攻击库实测 8 个 empty 元素——构成：3 图 chart-empty（ports/sources/ssh）+ 5 表空态（snap/conn/ban/ssh/fw 表，archive 表有数据未空；代码 6 表空态 L594/615/636/653/671/691 中 archive 未触发））
  - **错误态：errCb 执行 `setChartEmpty(id, false)`（移除占位）+ `charts[id].clear()`（清空画布）**——占位正确消失，不残留"暂无数据"（app.js L777-791（三处 errCb：ports L777/sources L784/ssh L791））✅
  - 实测：停 8098 后端后三图无 empty 残留 + 态势条失败提示 ✅

### 3.7 WS-1 状态徽章与断线重连 ✅（受控断线实测，reviewer R-01 补强）

- 徽章：`#conn-status` "WS 实时"（ok 绿态）；断线 "WS 断开，轮询兜底"（error 红态）
- 重连链路（app.js L899-923）：connectWS → onopen 设 wsMode=true + "WS 实时" → onclose 设 wsMode=false + 3s setTimeout 重连
- **受控断线实测（完整三态观察，DOM 未刷新）**：
  1. 正常态：徽章"WS 实时"（ok）
  2. 停后端 → **徽章"WS 断开，轮询兜底"（error）**，`domAlive=true`（DOM 存活，未刷新）
  3. 重启后端 → **徽章自动恢复"WS 实时"（ok）**，`domAlive` 仍 true——**排除页面刷新替代解释，确认 3s 自动重连生效** ✅
  - **domAlive 探针机制披露（reviewer N-01）**：DevTools evaluate_script 注入 `window` 哨兵标记（`window.__domAlive = 1`），页面刷新会重置该标记；实测中断线与恢复两时点标记均保持（domAlive=true），证明 DOM 未被重建。

### 3.8 RSP-1 窄屏 480px ✅

- 480x900 viewport 实测：docW 474 < winW 480，**无页面级横向溢出** ✅
- 表格横向滚动**限于 .scroll 容器内**（scrollW 560 > clientW 415，容器内滚动条）——正确设计，非页面溢出 ✅

### 3.9 CON-1 控制台 ✅（1 Note）

- 网络请求：全部 API/静态资源 200；**唯一 404 = /favicon.ico**（浏览器自动请求，页面未提供 favicon）
- 无 JS 错误、无 API 失败、无其他资源 404——控制台零错误（favicon 除外，Note）

### 3.10 UT-1 后端零改动 + 全包 ✅

- `git diff 0b7957e 54e718c --stat`：**仅 internal/web/static/app.js + index.html 2 文件**（235+/141-），后端零改动声明属实
- `go test ./...`：13 包全绿 + `go vet` 通过 ✅

## 4. 缺陷清单

| ID | 等级 | 描述 | 证据 | 建议 | 状态 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| D-25 | Note | /favicon.ico 404（页面未提供 favicon，浏览器自动请求）——控制台唯一错误，无功能影响 | CON-1 网络请求 reqid=243 | 可选：添加内联 favicon（data URI）或忽略 | 记录 |
| D-26 | Note | 测试环境 conntrack 降级提示（Windows 无 ss 二进制）——环境依赖非代码缺陷 | 浏览器 banner | VPS/目标环境无此问题 | 记录（环境） |

**本次回归引入的失败：0 项。既有失败：0 项（后端零改动）。** 无 Blocker/Major；2 项 Note（favicon/环境）。

## 5. 未覆盖项与原因

| 未覆盖项 | 原因 |
| :--- | :--- |
| 动画/微动效视觉精度 | 模型无法查看截图（a11y 文本断言替代）；渲染无 JS 错误即功能正确 |
| 长时间 WS 推送压测 | DEV-017/018 已覆盖 WS 链路；本次断线重连实测通过 |
| 30d 大窗口真实数据量（千行级聚合） | 种子库 30h 数据；30d 降频节流代码确认 + 30d 切换实测（桶 721）通过 |

## 6. 结论

**整体结论：PASS_WITH_NOTES（基线 `54e718c` 通过）**

- 验收 1（9 组回归点）：✅ 13 项实测全部通过（设计 token/四页签/范围切换/30d 降频/联动 chip/排序/过滤/三态/R-01 占位/WS 重连/窄屏/控制台）
- 验收 2（缺陷清单）：✅ 无 Blocker/Major；2 Note（favicon/环境）
- 验收 3（报告规范）：✅ 本报告

无 Blocker/Major 遗留；后端零改动确认；既有功能零回归。

## 7. 交付物清单

- 测试报告（本文件）：`docs/verification/TEST-007_测试报告.md`
- 执行证据：浏览器实测记录（CSS computed、四页签、联动 chip、排序/过滤、三态、窄屏、WS 重连——本次会话内执行记录）
- Git：test 类型提交

