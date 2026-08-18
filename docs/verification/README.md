# 验证档案索引（docs/verification/）

sentry-agent 全生命周期验证/测试/审计档案。命名约定：`Vn_验证报告` 为里程碑自验证（M1-M3），`TEST-nnn_测试报告/回归报告` 为测试 Agent 独立验收（里程碑功能验证与修复回归），`AUD-nnn` 为审计报告。原始执行证据见 [evidence/](#evidence-目录说明)。

## 里程碑验证报告（开发侧自验证）

| 报告 | 里程碑/主题 | 结论摘要 |
| :--- | :--- | :--- |
| [V1_验证报告.md](V1_验证报告.md) | M1：DROP 包 conntrack NEW 事件与防火墙日志链路 | 验证 DROP 包是否产生 conntrack NEW 事件、防火墙日志解析链路；附 VPS 复验清单判定项 |
| [V2_压测报告.md](V2_压测报告.md) | M1：SYN flood 压测 | 压测验证源预过滤（R-10）行为，详见原文 |
| [V3_验证报告_M2.md](V3_验证报告_M2.md) | M2：V3 性能验证 + 归档演练 + A 组整改证据 | M2 性能验证、归档演练与 A 组整改证据汇总，详见原文 |
| [V4_验证报告_M3.md](V4_验证报告_M3.md) | M3：Web 面板（API/WS/前端/磁盘水位/Note 尾项） | Web 面板全链路自验证，详见原文 |

## 测试与回归报告（测试 Agent 独立验收）

| 报告 | 主题 | 结论摘要 |
| :--- | :--- | :--- |
| [TEST-001_测试计划.md](TEST-001_测试计划.md) + [TEST-001_测试报告.md](TEST-001_测试报告.md) | M1 里程碑 Q3 功能验证（计划+报告） | **PASS_WITH_NOTES**：验收标准全部满足，2 项运营官裁定处理 |
| [TEST-002_测试计划.md](TEST-002_测试计划.md) + [TEST-002_测试报告.md](TEST-002_测试报告.md) | M2 里程碑 Q3 功能验证（计划+报告） | **PASS_WITH_NOTES**（含 1 项运营官裁定项） |
| [TEST-003_回归报告.md](TEST-003_回归报告.md) | M2 修复回归（DEV-004） | **PASS**，基线 `1f4f4ef` 放行 |
| [TEST-004_测试报告.md](TEST-004_测试报告.md) | M3 里程碑 Q3 功能验证 | **PASS**，基线 `bd5250c` 放行 |
| [TEST-005_回归报告.md](TEST-005_回归报告.md) | M3 修复回归（DEV-007） | **PASS**，基线 `a7b56f0` 放行 |
| [TEST-006_测试报告.md](TEST-006_测试报告.md) | DEV-017 态势结论条 + 前端回归 | **PASS_WITH_NOTES**，基线 `8e4273d` 通过，2 项 Minor 前端口径上报运营官 |
| [TEST-007_回归报告.md](TEST-007_回归报告.md) | M4 放行条件修复最终回归（DEV-009） | **PASS**，基线 `34fab2c` 放行，M4 本地部分闭环（D-14 已收敛；D-18/D-19 环境观察 Note） |
| [TEST-007_测试报告.md](TEST-007_测试报告.md) | DEV-019 前端全量美化回归 | **PASS**：13 项验证（9 组回归点 + 补充），基线 `54e718c`；1 项 Note（favicon 404） |
| [TEST-FE-001_测试计划.md](TEST-FE-001_测试计划.md) + [TEST-FE-001_测试报告.md](TEST-FE-001_测试报告.md) | DEV-FE-002/003 前端优化 P0+P1 全量回归 | **PASS_WITH_NOTES（运营官裁定）**：35 用例 34 过 1 裁定（DEF-FE-001-02 性能窗口口径，裁定不阻塞），基线 `b95e914`；1 Minor + 5 观察项记录 |
| [TEST-FE-002_回归报告.md](TEST-FE-002_回归报告.md) | DEV-FE-005 面板五项调整回归 | **PASS**：12/12 用例通过，基线 `082bbbd`；归档页签前端隐藏、三列并列、折线平滑等全验证 |
| [TEST-FE-003_回归报告.md](TEST-FE-003_回归报告.md) | P1 安全加固 + 数据导出合并回归 | **PASS_WITH_NOTES**：28 项全 PASS、0 产品缺陷，基线 `b2590b7`；限流/WS/CSP/导出/大库压测全验证 |
| [TEST-FE-004_轻量复核.md](TEST-FE-004_轻量复核.md) | M-01 修复 + 仓库整理轻量复核（DEV-CLEAN-001） | **PASS_WITH_NOTES**：基线 `ba41233`；9/9 export 用例 + 全量测试全绿、导出冒烟 413 行与 DB 精确匹配、仓库瘦身生效；1 Minor（bin/ 残留 Linux ELF 产物） |

> **TEST-007 双份说明**：编号撞车（不同里程碑各自编号）。`TEST-007_回归报告.md`（2026-08-14）属 M4/DEV-009 回归；`TEST-007_测试报告.md`（2026-08-15）属 DEV-019 前端美化回归。两份内容互补、任务不同，均保留。

## 审计报告

| 报告 | 主题 | 结论摘要 |
| :--- | :--- | :--- |
| [AUD-006_M4审计报告.md](AUD-006_M4审计报告.md) | M4 前后端审计（DEV-008/DEV-009） | M4 放行条件的代码审计结论详见原文 |
| [AUD-FE-001_前端交叉审计.md](AUD-FE-001_前端交叉审计.md) | 前端优化方案交叉审计（现状四维诊断 + 方案审查） | 方案放行 **PASS_WITH_NOTES**；现状 1 Major（RB-01 竞态，已纳入 P0） |
| [AUD-FE-002_前端实施审计.md](AUD-FE-002_前端实施审计.md) | 前端优化 P0+P1 实施终审 | **PASS_WITH_NOTES**：硬约束五条全过、N-1~N-5 落地、安全纪律无弱化；2 Minor（A-01/A-02 UI 残留）遗留后续迭代 |
| [AUD-FE-003_五项调整审计.md](AUD-FE-003_五项调整审计.md) | DEV-FE-005 面板五项调整审计 | **PASS_WITH_NOTES**：五项调整实施正确、archive 清理彻底、契约一致；1 Minor（A-01 文案残留）+ 4 Note |
| [AUD-VPS-001_VPS攻击面审计.md](AUD-VPS-001_VPS攻击面审计.md) | VPS 部署攻击面审计（威胁建模） | **PASS_WITH_NOTES**：推荐部署低-中风险/公网直曝高风险；0 Blocker/Major，8 Minor + 10 Note；Top5 攻击路径 + P0/P1/P2 加固建议 |
| [AUD-FE-004_P1加固与导出审计.md](AUD-FE-004_P1加固与导出审计.md) | P1 安全加固 + 数据导出终审 | **PASS_WITH_NOTES**：9 项要点全过；1 Minor（M-01 导出中断路径，联动条件未触发）+ 10 Note；无新依赖无越权 |
| [AUD-PUSH-001_发布安全审计.md](AUD-PUSH-001_发布安全审计.md) | 发布推送安全审计（公开仓库推送前敏感信息核查） | 审计结论 + 整改清单（DEV-RELEASE-001）；相关方案见 docs/发布推送方案.md |

## evidence/ 目录说明

各里程碑/测试的执行原始证据（命令输出、探针记录、压测数据、文本断言记录等），按阶段归档：

| 目录 | 内容 |
| :--- | :--- |
| `evidence/` 根目录 | TEST-001（M1）执行证据：agent.out/agent2.out（双实例）、agent_kmsg.out/.err（kmsg 通道）、agent_rsyslog.out（rsyslog 通道）、ct_events.log（conntrack 事件）、f2b_test.log（fail2ban 测试） |
| `evidence/m2/` | M2 阶段验证证据 |
| `evidence/m3/` | M3 阶段验证证据（WS/API/前端） |
| `evidence/m4/` | M4 阶段验证证据（部署冒烟、探活、批延迟复跑等） |
| `evidence/test006/` | TEST-006 测试证据（浏览器断言与 API 输出记录） |
| `evidence/testfe001/` | TEST-FE-001 前端优化回归证据（trace 分析与 DOM/性能实测记录） |
| `evidence/testfe002/` | TEST-FE-002 五项调整回归证据（浏览器日志/DOM 计数/截图） |
| `evidence/testfe003/` | TEST-FE-003 P1+导出回归证据（CSV 样例/429/限流统计/WS 上限/压测） |

> 一次性验证脚本已从 `scripts/` 清理（git 历史可恢复）；本目录保留的是不可再生的执行证据（原始输出与文本断言记录），请勿删除。

> **大文件处理政策（DEV-CLEAN-001）**：超过 10MB 的执行证据以 gzip 压缩形式归档（如 `evidence/testfe001/trace_attack30s.json.gz`），原始文件不保留在仓库（63.5MB 压缩为 4.1MB，可解压还原）。历史报告/脚本中引用的原始 `.json` 路径已失效，复现分析时先解压 `.gz` 还原文件名（Linux/WSL：`gzip -dk trace_attack30s.json.gz`；Windows：`tar -xzf trace_attack30s.json.gz` 或 7-Zip 解压）。
>
> **trace gz 不入库说明（DEV-RELEASE-001 / AUD-PUSH-001 S-01）**：`evidence/testfe001/trace_attack30s.json.gz` 含机器指纹（浏览器/系统特征），**有意不入库**（.gitignore 精确规则），仅存于本地工作区；公开仓库不推送该文件。其余 evidence 文件为不可再生执行证据，入库保护。

