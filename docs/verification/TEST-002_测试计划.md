# TEST-002 测试计划（M2 里程碑 Q3 独立验证）

- 测试人：B2（测试 Agent）
- 任务 ID：TEST-002
- 基线：commit `122dc91`（M2 交付冻结基线，main 分支；工作区仅 AGENTS.md 未跟踪，不影响受测代码）
- 质量等级：Q3（独立验证关卡）
- 环境：Windows（Go 1.26.2 单测与交叉编译）+ WSL Ubuntu-22.04（内核 6.18.33.2-microsoft-standard-WSL2，WSL 内 Go 1.26.2）
- 日期：2026-08-13

## 1. 任务理解与实际范围

接收目标：对 M2 交付（commit 122dc91）执行 Q3 独立验证，覆盖 A 组整改回归（V-06 kmsg 防重放、两阶段排空、B5 ss 方向、f2b 时间戳、ParseProcStat 防御）、V3 30 分钟五通道落库复测、批延迟、归档复测、覆盖率复算（TEST-001 §2.2 口径）、D-04 合规核查。

实际执行范围：
1. A 组回归：V-06 kmsg 防重放正式回归（m2_kmsg_fix_verify.sh）、两阶段排空（m2_drain_verify.sh）、B5 ss 方向（单测 TestParseSSOutputDirection + 源码核查）、f2b 时间戳（TestParseF2BTime + 源码核查）、ParseProcStat（TestParseProcStatShortLine + 源码核查）
2. V3 复测：run_m2_v3.sh（修正路径副本 run_m2_v3_t2.sh，30 分钟落库）+ 批延迟 TestBatchLatency 复跑
3. 归档复测：run_m2_archdrill.sh + archive 包单测 + 自愈集成实测（.tmp 残留清理）
4. 覆盖率复算：Windows `go test -cover` + WSL Linux `go test -cover ./internal/fw/`（kmsgSeq 归属核实）
5. D-04 合规：grep 核查 DELETE 语句 + os.Remove 白盒确认
6. DDL 核对：store.go schema vs 技术方案 4.2

非目标：V-01/V-02/V-03/V-04/V-05（VPS 复验项，环境限制延后）；fail2ban 真实库联调（QueryBanned 在 WSL 无 fail2ban 环境以失败留痕验证，真实库列入 VPS 复验）。

## 2. 测试用例清单与验收追踪矩阵

**任务书验收标准定义**（TEST-002 任务书原文，本节"验收 1~5"引用此定义）：
- 验收 1：A 组回归全部通过（V-06 为正式回归记录）
- 验收 2：V3 复测通过且与 developer 报告数字可比（偏差需说明）
- 验收 3：归档复测通过
- 验收 4：覆盖率按 §2.2 规则达标（不达标则列出缺口与整改建议，报运营官裁决）
- 验收 5：D-04 合规结论明确

| 用例 ID | 目标 | 验证方法 | 对应验收标准 |
| :--- | :--- | :--- | :--- |
| UT-01 | 全包单测通过率（Windows + WSL Linux） | `go test -count=1 ./...`（双环境） | A1/A2/A3 基础 |
| UT-02 | 覆盖率复算（§2.2 口径每包加权 ≥80%） | `go test -cover` + `cover -func` 逐函数核算 | 验收 4 |
| UT-03 | 批延迟 TestBatchLatency（1000 行 <50ms） | `go test -run TestBatchLatency -v` | 验收 3（V3 性能） |
| FT-01 | V-06 kmsg 防重放正式回归 | m2_kmsg_fix_verify.sh（历史 2 + 实时 3 → 恰 3） | 验收 1 |
| FT-02 | 两阶段排空（在途批全数落库） | m2_drain_verify.sh（f2b 40 + ssh 10 → SIGTERM 对账） | 验收 1 |
| FT-03 | V3 30 分钟五通道落库 | run_m2_v3_t2.sh + sqlite 统计 + RSS/CPU 采样 | 验收 2 |
| FT-04 | 归档复测（副本/行数/gzip/幂等/主库保留） | run_m2_archdrill.sh | 验收 3 |
| FT-05 | 归档 .tmp 中断自愈（集成实测） | 预置 .tmp 残留 → archive-trigger → 校验 | 验收 3 |
| ST-01 | DDL 核对（方案 4.2 vs store.go） | 逐表字段/索引比对 | 验收 2 |
| ST-02 | D-04 合规（主库无 DELETE） | grep DELETE + os.Remove 白盒核查 | 验收 5 |
| ST-03 | B5 ss 方向（攻击者=Src 被攻击端口=Dst） | TestParseSSOutputDirection + snapshot.go 源码核查 | 验收 1 |

科研维度：N/A（运维采集代理工程任务，非科研代码）。

## 3. 覆盖范围

- 正常路径：五通道事件解析、批量落库、归档全链路、kmsg 防重放 ✅
- 边界条件：kmsg 历史/实时边界、ParseProcStat 短行、ParseF2BTime 非法格式、ParseMonth 非法月份 ✅
- 异常路径：conntrack 溢出（R-10 留痕与自动重启）、f2b 库缺失留痕、归档残留自愈 ✅
- 回归测试：M1 全部单测 + A 组整改单测（双环境） ✅
- 集成测试：落库端到端（TestStoreRunDrainNoLoss）、排空端到端（m2_drain_verify.sh 运行级） ✅
- 状态/资源生命周期：Store.Run 两阶段关闭、归档 .tmp 生命周期 ✅
- 并发/性能：TestBatchLatency、V3 30 分钟压力 ✅
- 安全：N/A（内网采集工具，无认证/加密需求，超范围）

## 4. 风险与不确定点

1. V3 的 fw 通道计数受测试过程重复 iptables 规则影响（首次误启动残留），按双规则折算与 developer 可比——披露后判定
2. connections 通道 22401 vs developer 30404：flood 段速率受 CPU/内核约束非固定 + 溢出期内核侧丢弃（R-10 已知行为），差异属环境波动，零丢失语义由 FT-02 独立验证；高速率注入/落库精确对账列入 VPS 复验（未闭环项）
3. kmsgSeq 无单测（代码库不存在该单测文件）——fw 包 §2.2 加权 64.5% < 80% 不达标，需上报运营官裁决
4. 覆盖率豁免敏感性：store/archive 包豁免函数即使全部纳入仍 ≥80% 达标（见报告 §3.1 敏感性说明），不影响结论
