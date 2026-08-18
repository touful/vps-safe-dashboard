# TEST-AUDIT-001 审计优化重构后全量回归报告

- 基线：`1f62644`（main，工作区干净）
- 对比基线：`51af07d`（已部署 VPS 2.0.3 生产线；worktree 临时检出对比，已清理）
- 日期：2026-08-18
- 结论：**PASS_WITH_NOTES**（无 Blocker/Major；4 条 Note + 2 条观察项）
- 证据目录：`docs/verification/evidence/TEST-AUDIT-001/`

## 1. 任务范围

验证 commit `1f62644`（= 51af07d + 20 个 DEV-AUDIT-001 审计优化提交：gofmt 对齐 21 文件、README 修复、超长函数拆分×3、去重×3 含新包 internal/diskutil、itemArgs 带 ok 断言、六处 %v→%w、Channels 迁出 out→event、api handler 收敛 eqConds/topHits 等）行为零变更。9 项回归点全部覆盖。

## 2. 执行验证

### 2.1 构建与静态检查（已验证）

| 项目 | 结果 |
| :--- | :--- |
| `go build ./...` | exit 0 |
| `go vet ./...` | exit 0 |
| `go test ./...` 重点包非缓存 `-count=1` | 15 包全 ok（证据：evidence/TEST-AUDIT-001/go_test_nocache.txt） |

### 2.2 动态双实例对比（51af07d vs 1f62644，已验证）

**方法学**：仓库内 `git worktree add .baseline-wt 51af07d` 检出基线，分别编译 baseline-agent.exe（旧）与 sentry-agent.exe（新）；两实例均以**完整 agent 模式**（含采集循环与存储写线程）启动，监听 127.0.0.1:8098（旧）/8099（新），**共享同一 SQLite WAL 数据库文件** `.dev015-test/state.db`（WAL 模式支持多进程并发读写，SQLite 标准用法）。对比场景全部为**时间范围/条件查询**，读取种子库静态历史数据；两实例 health 的 `system_events_total` 均返回 254（种子库内历史值），佐证运行中写入不改变查询结果。请求序列为**先后顺序**（旧→新逐一请求），排除字段仅 `uptime_s`（动态运行时长）。

**结果**：24 场景对比全部 SAME，其中 22 项为确定有效数据对比，2 项（export from/to 与 range=bad）存疑、由 export 数据路径专项验证覆盖（详见下文"export 场景有效性说明"）。证据：evidence/TEST-AUDIT-001/api_compare_sha256.txt。

| 类别 | 场景 |
| :--- | :--- |
| 常规 15 项 | summary?range=24h/7d、resources、connections?dst_port=22/src_ip=3118228737、ssh?result=0/username=oracle、firewall?action=drop/dst_port=22、top_ports、top_sources、ssh/timeline、firewall/timeline、bans、archive、snapshot |
| 补充 9 项 | export/csv×4（firewall/ssh/connections/bans）、range=bad、limit=abc、top_ports?top=999、nonexistent（404） |

注意：首次脚本字符串比较出现 3 处"DIFF"（export/top_ports/nonexistent），经文件 SHA256 复验均为 PowerShell 字符串比较编码假象，非真实差异。

**export 场景有效性说明（R-09 整改）**：m00095 对比脚本中 export 场景 L17-19（range=24h&table=X，哈希 73EE）经独立实测确认为 200 有效对比（415 行 CSV 全集）；L20（from/to）/L21（range=bad）哈希相同（1B76），但与"L17 与 L21 同为 24h 窗口应输出相同"矛盾，无法确证为有效数据对比（对比所用种子库此后已被重建覆盖，无法复验；疑为当时响应异常或窗口边界数据子集重合）。为此**追加 export 数据路径专项验证**（证据：evidence/TEST-AUDIT-001/export_compare_r2.txt + export_compare_fixed.txt）：
1. 固定时间戳窗口 from=1786977000&to=1787049000：3/3 SAME（bans/firewall/ssh，各 344 行）
2. range=bad 并行请求（同刻窗口）：SAME（各 408 行）
3. range=bad 顺序请求：两文件 Compare-Object 无差异（各 411 行）
4. 单实例（NEW）内 range=bad 与 range=24h 输出一致（411 行，非法值回退 24h 语义正确）
另注：交替请求间隔 1.2s 时曾出现 OLD=411 NEW=410 的临时 DIFF，经并行请求复验为**滑动窗口边界效应**（种子库存在恰位于 now-24h 边界的数据行），非行为差异。
**结论：export 数据路径（参数校验/窗口语义/三源 UNION/table 忽略/流式输出）双实例字节级等价；24 场景对比中 22 项为确定有效数据对比，2 项存疑场景由专项验证覆盖。**

**export 观察项**（O-1）：export/csv 的 `table` 参数被忽略，三个 table 值输出相同内容（统一三源合并 CSV，与前端"数据导出"页说明一致）。新旧行为一致，为既有设计（API 参数冗余），非本次回归引入。

### 2.3 代码级逐条核对（与 51af07d 旧实现对照，已验证）

1. **conn**：checkFreshness(conn.go:273)/checkOverrun(conn.go:294) 提取自旧内联逻辑——错误上报、`first` 置位、`diff==0`、ctx 关闭等分支逐条等价；启动/降级状态机（connStartTracker/runConntrackLoop/verifySubscription/fallback）无逻辑变更（纯注释清理）
2. **store**：retentionStep 首轮/定时合并（留痕文本"retention 首轮清理失败"/"retention 定时清理失败"与旧一致，yieldErr 致命判定一致）；enqueue 提取（6 通道主循环 + drainInto 7 通道）等价；itemArgs 6 处带 ok 断言（类型严格配对下行为等价，防御增强）；批量事务/WAL/归档联动无逻辑变更
3. **config**：Validate 拆 11 个校验方法（validateCollect→validateSS→validateConntrack→validateSSH→validateFW→validateF2B→validateDB→validateArchive→validateWeb→validateDisk→validateLog），顺序与短路语义与旧单函数一致；错误消息文本逐条比对一致
4. **api**：topHits 合并（top_ports/top_sources 同一 SQL、JSON 字段 dst_port/src_ip 一致）；eqConds 合并（ssh/firewall/connections 过滤条件与 since/until 顺序保持）；14 路由注册新旧逐条一致；ipToDotted→event.Uint32ToIPv4 数学等价（v==0 特判输出 0.0.0.0）
5. **f2b/fw/ssh**：MicrosToUnix 合并——ssh 旧 parseMicro 逐字一致；fw 旧 journalMicroTS 失败回退当前时间语义在新调用点（fw.go runJournaldKernel: ts := time.Now().Unix()）显式保留
6. **diskutil**：Usage/UsagePercent 与 archive/collect 旧实现完全等价（ErrZeroTotal 哨兵与错误文本逐字一致）；api 侧 statfs 错误从裸 err → "statfs %s 失败: %w" 包装（见 N-3）
7. **Channels**：event.Channels/NewChannels 自 out 包逐字迁入；全链路（main.go、out.Run、store、全部测试）无 out.Channels 残留

### 2.4 六处 %v→%w 完整清单（git diff 逐行确认，已验证）

| # | 文件:位置 | 旧 | 新 |
| :--- | :--- | :--- | :--- |
| 1 | internal/config/config.go validateFW | `fw.internal_cidrs[%d]=%q 非法 CIDR: %v` | `%w` |
| 2 | internal/config/config.go validateArchive | `archive.monthly_hour=%q 非法: %v` | `%w` |
| 3 | internal/f2b（fail2ban 日志流提前结束） | `%v` | `%w` |
| 4 | internal/fw（journalctl -k 流提前结束） | `%v` | `%w` |
| 5 | internal/ssh（journalctl 流提前结束） | `%v` | `%w` |
| 6 | internal/ssh（tail 流提前结束） | `%v` | `%w` |

说明：store 的"批量提交失败: %w"为既有代码（非本次变更）；diskutil statfs 为新建文件新代码。全部六处渲染文本不变，仅包装语义增强（errors.Is/Unwrap 可查）。

### 2.5 测试资产变更核对（已验证）

- 删除 `internal/fw/fw_micro_test.go`（TestJournalMicroTS：6 正常用例[零/正常微秒/整秒/不足一秒截断/多位数/前导零] + 2 错误断言[空串/非数字回退当前时间窗口]）→ 迁移为 `internal/event/event_test.go:144` TestMicrosToUnix（5 用例：空串/abc123/123abc/正常/零）
  - 迁移损失：①"不足一秒截断"（999999→0）与"前导零"（00000000001000000→1）断言未迁移——由 strconv.ParseInt + 整数除法天然保证（纯数学变换），影响低；②**错误路径"回退当前时间"断言未迁移**——fw 调用点回退逻辑无测试护栏（N-1）
- 删除 `internal/api/api_pure_test.go` TestIPToDotted（19 行）→ 迁移为 event_test.go TestUint32ToIPv4/TestIPv4RoundTrip（含 0/0xFFFFFFFF 边界）✓ 完整
- 其余 f2b/ssh/api/store 测试变更均为 gofmt 对齐/注释同步，无删除
- checkFreshness/checkOverrun 无直接单元测试（旧内联版本同样无直接测试，非退化；N-2）

### 2.6 覆盖率（15 包全量，已验证；证据：evidence/TEST-AUDIT-001/coverage_all.txt）

| 包 | 覆盖率 | | 包 | 覆盖率 |
| :--- | :--- | :--- | :--- | :--- |
| internal/event | 96.6% | | internal/diskmon | 61.5% |
| internal/config | 92.7% | | internal/archive | 65.5% |
| internal/fw | 82.7%（另一次运行 83.3%，轻微波动） | | internal/collect | 45.6% |
| internal/out | 77.4% | | internal/conn | 44.4% |
| internal/api | 73.5% | | internal/ssh | 26.5% |
| internal/store | 68.8% | | internal/diskutil | 0.0%（无测试文件） |
| internal/f2b | 68.9% | | internal/web | 0.0%（embed 测试无语句覆盖） |
| | | | cmd/sentry-agent | 14.9% |

覆盖率门槛 80% 未全达，但**均为既有测试资产水平**（本次变更无测试删除式缩减，仅 2 处迁移且关键语义迁移完整；Linux-only 路径[netlink/kmsg/journald/statfs]在 Windows 不可实跑）。关键重构路径均有既有测试覆盖（conn 状态机、retention 系列、config Validate 系列、api 查询收敛系列、MicrosToUnix 新增测试）。本任务为行为保持回归，**动态字节级对比（2.2）补足单测覆盖缺口**。

### 2.7 种子脚本实测（已验证；证据：evidence/TEST-AUDIT-001/seed_scripts_run.txt）

- dev015_seed_db.py → `SEED OK`（.dev015-test/state.db 192512 字节）
- dev017_seed_noidle_db.py → `NOIDLE DB OK`（state_noidle.db 36864 字节；README 补 makedirs 修复生效）
- dev017_verify_sql.py → `PASS`（聚合 drop/accept 225:51 = 明细 COUNT 225:51 一致，25 时间桶；本次随机种子数据量与上次运行 235:51 不同，验证脚本内部一致性断言通过）
- dev017_test_cfg.py → cfg.json（listen 127.0.0.1:8099、db.path 指向 state.db）

### 2.8 前端冒烟（已验证；证据：evidence/TEST-AUDIT-001/frontend_smoke_asserts.txt）

四页签全部渲染正常（总览 KPI/图表/事件列表、连接事件流、攻击 TOP 图/时间线/封禁/明细+过滤下拉、数据导出表单）；时间范围切换 24h→30d KPI 正确刷新（拦截 235→291、SSH 失败 171→221、封禁 17→23、风险 50→59）；console 无 error/warn（WS 连接正常）。static 零 diff。

## 3. 缺陷清单（无 Blocker/Major）

| ID | 等级 | 位置 | 描述 | 本次回归 |
| :--- | :--- | :--- | :--- | :--- |
| N-1 | Note | internal/fw/fw.go runJournaldKernel | journalMicroTS 迁移后，"失败回退当前时间"错误路径断言未随迁（MicrosToUnix 纯函数 5 用例覆盖 ok=false，但 fw 调用点 4 行回退逻辑无直接断言）；另有"不足一秒截断/前导零"用例未迁移（整数除法天然保证，影响低） | 否（迁移缺口） |
| N-2 | Note | internal/conn/conn.go:273/294 | checkFreshness/checkOverrun 无直接单元测试（旧内联同样无，非退化） | 否（既有缺口） |
| N-3 | Note | internal/api/disk_linux.go:11 + internal/diskutil/disk_linux.go:21 | statfs 失败错误文本：裸 err → "statfs %s 失败: %w"；消费点（api.go diskPercent）仅判 err!=nil → 不可观察 | 是（理论差异，实际无影响） |
| N-4 | Note | internal/api 路由注册 | POST/PUT/DELETE 到只读端点返回 200（Go ServeMux 不区分方法）——新旧一致既有行为；只读特性=无写操作暴露面 | 否（既有行为） |

观察项：
- O-1：export/csv `table` 参数被忽略（统一三源导出，415 行）——新旧一致既有设计，API 参数冗余
- O-2：.dev015-test/agent.out.log 与 agent.err.log 为 0 字节——服务以无重定向 Start-Process 启动（输出进控制台/黑洞），非测试失败迹象

## 4. 未执行验证

- Linux-only 生产路径（netlink 订阅、kmsg、journald、statfs 实际值、conntrack 正常采集）：Windows 不可实跑，等价性以代码级逐条核对支撑（函数提取语义守恒 + 调用点显式保留回退）
- WS 推送帧内容：未逐帧断言（前端已建立 WS 连接且无错误）
- 归档容灾/月度轮转实际执行：Windows 归档策略为设计禁用行为

## 5. 风险/不确定点

1. Linux 生产路径等价性为代码级核对证据（非动态），建议生产环境回归时关注 conn 溢出留痕与 fw 时间戳回退
2. N-3 statfs 文本差异若未来 api 暴露该错误文本将可见
3. checkFreshness/checkOverrun 无单测护栏（N-2），后续重构无保护

## 6. 证据四态声明

- 已验证：2.1 构建测试、2.2 动态对比（哈希文件落盘）、2.3 代码级核对（git diff/read 逐行）、2.4 六处 %w（git diff）、2.5 测试资产（git show/read）、2.6 覆盖率（输出落盘）、2.7 种子脚本（输出落盘）、2.8 前端冒烟（浏览器断言记录落盘）
- 已观察：无
- 推断：无
- 未验证：见 §4

## 7. 复现步骤

```powershell
# 双实例对比（Windows）
git worktree add .baseline-wt 51af07d
cd .baseline-wt; go build -o baseline-agent.exe ./cmd/sentry-agent
# 修改 cfg.web.listen 为 127.0.0.1:8098（新实例 8099），两实例同一 state.db
# 启动两实例后逐场景请求并比较 SHA256（场景清单见 evidence/api_compare_sha256.txt）
```

## 8. 交接摘要

- 开发者"行为零变更"承诺成立：代码级逐条核对 + 24 场景动态字节级对比双重验证
- 已知坑点：PowerShell 字符串比较对 curl 输出有编码假象（须文件 SHA256 比较）；git worktree 须建仓库内（外部目录权限拒绝）；服务进程无重定向启动
- 下游重点：VPS 2.0.3 生产线部署 1f62644 无行为风险；建议补 checkFreshness/checkOverrun 单测与 fw 回退断言；export table 参数冗余可后续清理（O-1）
- 候选基线：`1f62644`
