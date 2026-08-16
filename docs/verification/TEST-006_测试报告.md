# TEST-006 测试报告（DEV-017 后端新端点 + 前端回归）

- 测试人：B2（测试 Agent）
- 基线：commit `8e4273d`（main；DEV-017 在 912ca4b 之上：新增 firewall/timeline 端点 + 前端大升级）
- 测试日期：2026-08-15
- 环境：Windows（Go 1.26.2 + Chrome DevTools 浏览器实测 + 8099/8098 测试实例）
- 测试库：`scripts/dev015_seed_db.py`（30h 攻击数据）、`scripts/dev017_seed_noidle_db.py`（零攻击数据）；配置生成 `scripts/dev017_test_cfg.py`（本测试新增）

## 1. 执行汇总（18 项验证）

| 用例 ID | 目标 | 结果 | 证据 |
| :--- | :--- | :--- | :--- |
| UT-1 | 全包 go test 复核 | ✅ 13 包全绿 + vet 通过 | §3.1 |
| UT-2 | api_test.go 新用例（TestFirewallTimeline）质量 | ✅ 覆盖聚合/补零/range/30d 桶数 | §3.1 |
| API-1 | 小时桶聚合正确性 | ✅ SQL 聚合 229/51 == 明细 COUNT 229/51（归档 api_firewall_timeline.txt L21-22） | §3.2 |
| API-2 | 补零连续性 | ✅ 25 桶连续（差 3600）；无攻击库 25 桶全零 | §3.2 |
| API-3 | range 合法值 | ✅ 1h→2、24h→25、7d→169、30d→721 桶 | §3.2 |
| API-4 | range 非法值/缺失 | ✅ 2d→回显 24h；缺失→默认 24h | §3.2 |
| API-5 | 1000 桶上限 | ✅ 30d 721 < 1000（硬上限防御） | §3.2 |
| API-6 | 与 ssh/timeline 模式一致性 | ✅ 聚合口径一致（(ts/3600)*3600）；JSON 结构按设计扩展（buckets/granularity/range） | §3.2 |
| API-7 | 只读特性 | ✅ mode=ro 连接 + QueryContext 只读 | §3.2 |
| FE-1 | 态势条攻击态 | ✅ 浏览器实测"来自 10 个攻击源共 229 次攻击事件…"（归档 browser_assertions.txt L5） | §3.3 |
| FE-2 | 态势条零攻击态 | ✅ "✓ 当前态势正常"（8098 noidle） | §3.3 |
| FE-3 | 态势条数据失败态 | ✅ 后端停止→"态势数据加载失败，请稍后重试" | §3.3 |
| FE-4 | KPI 环比箭头 | ✅ FW ↑25%、SSH ↓4%、磁盘 ↓1%；7d 前段 0 后段非 0 → "↑ 新增"（归档 browser_assertions.txt L6/L24） | §3.3 |
| FE-5 | 风险评分边界 | ✅ 攻击库（SSH 176/fw 229/ban 17）；零攻击库全 0 | §3.3 |
| FE-6 | 双通道图数据对齐 | ✅ fw 桶时间轴 + sshMap 补 0（代码审查 + 渲染） | §3.3 |
| FE-7 | 事件流分组/上限 | ✅ 10 分钟分组 + 最新 20 条 + 首轮不判新 | §3.3 |
| FE-8 | 零攻击徽章显隐 | ✅ 零攻击态"✓ 无攻击记录"显示；失败态隐藏（R-03 保护） | §3.3 |
| FE-9 | 既有功能零回归 | ✅ 范围切换（7d 联动全部数据）、TOP 点击复制、端口 TOP5 | §3.3 |

## 2. 测试计划与验收追踪

| 验收标准 | 对应用例 | 结果 |
| :--- | :--- | :--- |
| 1. 新端点 8 项功能点全部有用例与结果证据 | API-1~API-7 + UT-2 | ✅（证据归档 evidence/test006/） |
| 2. 前端回归清单全过或缺陷已分级记录 | FE-1~FE-9 | ✅（无 Blocker/Major；R-02/R-03 记录为前端口径缺陷，见 §4 D-23/D-24） |
| 3. 缺陷清单（分级） | §4 | ✅（3 项 Note + 2 项 Minor 前端口径） |
| 4. 测试报告按交付规范 | 本报告 | ✅ |

科研维度：N/A（工程回归任务，非科研代码）。

## 3. 验证详情

### 3.1 单元测试与用例质量 ✅

- `go test ./...`：13 包全绿（api 2.6s 含新用例）+ `go vet` 通过 ✅
- **TestFirewallTimeline 用例质量评估**（api_test.go 新增）：
  - 清空自带数据 + 精确插入 7 条跨 3 小时数据（当前 2drop+1accept / 上小时 1drop / 前 2 小时 3accept）→ 断言桶计数 {2,1}/{1,0}/{0,3} ✅
  - 补零连续性断言（相邻桶差 3600）✅
  - range 回显（24h/默认/非法 2d）✅
  - 30d 桶数 = 30*24+1 = 721 ✅
  - **边界覆盖充分**（跨小时、多桶、非法参数、桶数上限）；缺失：1000 桶硬上限的极端构造（需 >41 天数据，防御性代码未直接单测——记录 Note）

### 3.2 新端点功能测试 ✅（8099 实例 + 种子库实测，证据 evidence/test006/api_firewall_timeline.txt）

| 功能点 | 实测结果 |
| :--- | :--- |
| 小时桶聚合 | 24h → 25 桶；SQL 对照（dev017_verify_sql.py）：桶聚合 drop/accept 合计 == 明细 COUNT **PASS** |
| 补零连续性 | 25 桶相邻差均 3600；首桶 = (from/3600)*3600 对齐；**无攻击库**（8098 noidle）25 桶全为补零桶 **PASS** |
| range 合法 | 1h→2 桶、24h→25、7d→169、30d→721（均含当前小时）**PASS** |
| range 非法 | `range=2d` → 回显 `"range":"24h"` **PASS** |
| range 缺失 | 默认 24h **PASS** |
| 1000 桶上限 | 30d=721 < 1000；硬上限为防御代码 **PASS** |
| 模式一致性 | 聚合口径一致（(ts/3600)*3600 分组）；**边界差异披露（reviewer R-07）**：fw 用 fromBucket 对齐（首桶含窗口外至多 3599 秒），ssh 用原始 from（首桶缺该区间）——双通道图首桶可能 fw 有值/ssh 为 0，属设计权衡（注释 R-04 已说明），前端以 fw 时间轴对齐；JSON 结构按设计扩展（buckets/granularity/range） |
| 只读特性 | api.go L43 `mode=ro` 独立只读连接 + QueryContext 仅 SELECT **PASS** |

### 3.3 前端回归 ✅（Chrome 浏览器实测 + 代码审查，证据 evidence/test006/browser_assertions.txt）

| 项目 | 实测/审查结果 |
| :--- | :--- |
| 态势条三态 | 攻击态（8099）："来自 10 个攻击源共 229 次攻击事件，TOP 被攻击端口 :22，已封禁 17 个 IP"；零攻击态（8098）："✓ 当前态势正常（所选范围无攻击事件）"；**数据失败态**（后端停止）："态势数据加载失败，请稍后重试"——三态全部浏览器实测 **PASS**（注：攻击源数未按 drop 过滤，见 D-23） |
| KPI 环比箭头 | trendArrow 前/后半段对比：FW ↑25%、SSH ↓4%、磁盘 ↓1%（与归档 browser_assertions.txt L6 一致）；7d 切换后前段 0 后段非 0 → "↑ 新增"（R-07 防 ↑1000% 夸张）；全 0 → "—" **PASS** |
| 风险评分 | 公式 min(ssh/200,1)*30 + min(fw/1000,1)*30 + min(ban/20,1)*20 + clamp((disk-50)/40,0,1)*20；攻击库渲染 SSH 176/fw 229/ban 17（与归档 L7 一致）；零攻击库全 0（0 攻击边界）；gauge 颜色分级（≥60 danger/≥30 warn/ok）**PASS** |
| 双通道图对齐 | renderAttackTrend：fwB.forEach 主循环 + sshMap[b.ts] || 0 补 0，按 fw 桶时间轴对齐；≥7d 标签带日期 **PASS** |
| 事件流 | 三类混排（ssh 失败/fw drop/ban）→ 按 ts 倒序 → slice(0,20) → 10 分钟分组（ts-ts%600）；首轮不判新（R-08）；实测 20 条 10 分组渲染正确 **PASS** |
| 零攻击徽章 | 显隐条件 `sum===0 && !attackDataFailed && sshTimelineOk`：零攻击态显示"✓ 无攻击记录"；数据失败态隐藏（R-03 安全误报保护）**PASS** |
| 既有功能零回归 | 范围切换（1h/24h/7d/30d 按钮联动态势/KPI/TOP/风险全量更新，7d 实测）；TOP 源点击复制（clipboard API）；端口 TOP5 跳转；WS 重连状态提示"WS 断开，轮询兜底" **PASS** |

## 4. 缺陷清单

| ID | 等级 | 描述 | 证据 | 建议 | 状态 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| D-23 | Minor | **态势条"攻击源数"未按 drop 口径过滤（reviewer R-02）**：renderSituation L285 用 `srcs.length`（top_sources 端点 query.go L254-255 无 action 过滤，统计全部 firewall 事件含 accept），而事件计数 fwDrop 按 drop 口径——实测"来自 10 个攻击源"中 10.0.0.8 为 accept 合法源（**推断**：种子结构定义其为仅 accept 源，归档无 action 分布直接证据）；且 top_sources LIMIT 10 使真实攻击源 >10 时计数封顶失真 | FE-1 实测 + 代码审查 + browser_assertions.txt L8（TOP 源含 10.0.0.8(50)） | top_sources 查询加 `AND action='drop'` 或态势条改用 drop 过滤源计数；LIMIT 10 语义披露 | **上报运营官**（Minor 前端展示口径缺陷） |
| D-24 | Minor | **单数据源失败时错误态被掩盖（reviewer R-03）**：attackDataFailed 为单一共享标志，fwTimeline 成功回调无条件复位——若 top_sources 单独失败，态势条在"失败/计算中"间抖动并最终停留"态势计算中…"，违反 R-10/R-16"任一源失败→错误态"设计 | 代码审查（pollAttack L738/L749 + renderSituation L273-278） | 各攻击数据源设独立失败标志，任一失败保持错误态 | **上报运营官**（Minor 前端可用性缺陷） |
| D-20 | Note | 数据失败态下 KPI/风险评分/事件流保留旧值（态势条已提示失败）——轮询兜底期展示最后已知数据的缓存设计 | FE-3 浏览器实测 | 无需修复（设计说明）；如需可在失败态置灰 | 记录 |
| D-21 | Note | TestFirewallTimeline 未直接构造 >41 天数据验证 1000 桶硬上限分支 | UT-2 用例审查 | 可选补充 | 记录 |
| D-22 | Note | conntrack 降级提示（WSL 无 ss 二进制）：测试环境 banner 显示"降级模式执行 ss -tanup 失败"——环境依赖，非代码缺陷 | 浏览器快照 banner | VPS/目标环境无此问题 | 记录（环境） |

**本次回归引入的失败：0 项。既有失败：0 项。** 无 Blocker/Major；2 项 Minor（D-23/D-24 前端口径，上报运营官）+ 3 项环境/设计 Note。

> **取证说明（reviewer R-04 整改）**：API 实测与浏览器取证基于同一库（dev015_seed_db.py 重新播种）但**不同取证时刻**；报告首轮 API 数字（242/54）与 FE 数字（225）差异源于种子脚本未固定随机种子（dev015_seed_db.py L119-136 随机生成每次不同）——归档证据（evidence/test006/api_firewall_timeline.txt 与 browser_assertions.txt）为同库同轮取证，数字互相印证（API 24h 聚合 drop 合计 229 == 态势条 fwDrop 229，两文件同源一致）。

## 5. 未覆盖项与原因

| 未覆盖项 | 原因 |
| :--- | :--- |
| 1000 桶硬上限极端分支实测 | 需 >41 天数据（正常 range 最大 721 桶）；代码防御性检查（len>=1000 break）审查确认 |
| count-up/淡入微动效视觉效果 | 浏览器实测渲染正常（无控制台错误）；动画帧率/视觉精度属主观，截图无法人工复核（模型限制） |
| 攻击页排序/过滤下拉交互全量 | 本次聚焦总览页新功能；攻击页既有功能代码未变（DEV-017 仅改 app.js 新增段），DEV-015/016 已验 |
| WS 实时推送与 count-up 冲突 | R-02 设计已规避（磁盘直接赋值不 count-up）；未做长时间 WS 推送压测 |

## 6. 结论

**整体结论：PASS_WITH_NOTES（基线 `8e4273d` 通过；2 项 Minor 前端口径上报运营官）**

- 验收 1（新端点 8 项功能点）：✅ 全部有用例与实测证据（聚合/补零/range/上限/模式/只读；证据归档 evidence/test006/）
- 验收 2（前端回归）：✅ 态势三态/KPI 环比/风险评分/双通道/事件流/零攻击徽章全部浏览器实测 + 既有功能零回归；**D-23（攻击源计数 drop 口径）/D-24（单源失败错误态）2 项 Minor 记录上报**
- 验收 3（缺陷清单）：✅ 无 Blocker/Major；2 Minor + 3 Note
- 验收 4（报告规范）：✅ 本报告（证据归档 + 取证说明 + 边界披露）

无 Blocker/Major 遗留；无新增失败；既有功能零回归。

## 7. 交付物清单

- 测试报告（本文件）：`docs/verification/TEST-006_测试报告.md`
- 新增测试脚本：`scripts/dev017_test_cfg.py`（配置生成）、`scripts/dev017_verify_sql.py`（SQL 聚合对照）
- 执行证据归档：`docs/verification/evidence/test006/`——`api_firewall_timeline.txt`（range 参数/桶数/首末桶 + SQL 对照）、`browser_assertions.txt`（态势三态/KPI/风险/事件流/7d 切换文本断言）
- Git：test 类型提交
