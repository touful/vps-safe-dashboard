# TEST-003 回归报告（M2 修复回归，DEV-004）

- 测试人：B2（测试 Agent）
- 基线：commit `1f4f4ef`（DEV-004 修复后冻结基线，main 分支）。**基线声明修正（TEST-003-FIX1，依据 AUD-003 reviewer R-02）**：受测源码依赖磁盘工作区（WSL `/path/to/src` 由磁盘工作区复制部署）；git 树存在缺口——`git ls-files cmd/` 与 `git ls-files internal/archive/` 均为 0 条（主程序与归档包从未被跟踪，系 .gitignore 裸规则 `sentry-agent`/`archive/` 误伤，`git status --ignored` 显示 `!! cmd/`、`!! internal/archive/`）。**git 树补录完成前，基于 git 的复现构建不可行**；该问题已发现并移交 developer 修复，修复后基线以补录提交的新 hash 为准。本报告测试在磁盘工作区上执行，测试结论不受 git 树缺口影响（受测代码实体为磁盘源码）。
- 回归日期：2026-08-13
- 环境：Windows（Go 1.26.2 单测与 vet）+ WSL Ubuntu-22.04（内核 6.18.33.2-microsoft-standard-WSL2，WSL 内 Go 1.26.2）；源码部署 WSL `/path/to/src`（与基线 1f4f4ef 一致），二进制 `/tmp/a01-agent` 由 WSL 内 Go 从 `/path/to/src` 构建
- 回归范围：A-01 故障双路径、D-09 覆盖率复算 + 台账更新、A-02/A-03 单测、双环境全包健康、语义边界抽查

## 1. 执行汇总（10 项验证）

| 用例 ID | 目标 | 结果 | 证据 |
| :--- | :--- | :--- | :--- |
| A01-1 | 初始化故障：db.path=/dev/null | ✅ PASS（退出码 1 + stderr 原文） | §3.1 |
| A01-2 | 初始化故障：/proc/state.db | ✅ PASS（退出码 1 + stderr 原文） | §3.1 |
| A01-3 | 运行中写失败：2M tmpfs + SYN flood → SQLITE_FULL | ✅ PASS（退出码 1 + "致命错误: 存储模块退出"） | §3.2 |
| D09-1 | fw 包覆盖率复算（§2.2 口径） | ✅ 达标（kmsgSeq 100%、journalMicroTS 100%，完整 5 函数加权 91.6%） | §3.3 |
| D09-2 | D-09 台账更新（TEST-002 报告） | ✅ 已更新为"已收敛" | §4 |
| A02-1 | TestShouldSkipArchive（5 用例） | ✅ PASS | §3.4 |
| A03-1 | TestSqliteQuote（5 用例） | ✅ PASS | §3.4 |
| A03-2 | TestArchiveWithQuotePath（含引号路径端到端） | ✅ PASS | §3.4 |
| A02-2 | TestExecArchiveSystemEvents（归档留痕，WSL Linux 构建） | ✅ PASS | §3.4 |
| HB-1 | 双环境全包测试 + go vet | ✅ 全绿（Windows 10 包 + WSL Linux 10 包 + vet 双环境） | §3.5 |
| SB-1 | 语义边界抽查（archiveReq 容错 vs 主写路径退出） | ✅ 无回归（白盒确认） | §3.6 |

## 2. 回归范围与实际执行

任务书 5 项回归范围全部执行；A-01 脚本依赖项（/path/to/src 源码、/tmp/a01-agent 预构建、hping3、tmpfs）全部就绪，无环境受限跳过项。新增验证：TestKmsgSeq 用例质量核查（边界覆盖）、main.go 退出路径白盒。

## 3. 回归结果

### 3.1 A-01 初始化故障双路径 ✅

执行 `m2_a01_fault_test.sh`（脚本在 WSL 内构建 `/tmp/a01-agent` 后运行两场景）：

**场景 1：db.path=/dev/null（SQLite 打开失败）**
- 退出码：**1**
- stderr 原文：`存储模块初始化失败: 初始化 DDL 失败: disk I/O error (1034)`

**场景 2：不可写文件系统（/proc/state.db，root 亦不可写）**
- 退出码：**1**
- stderr 原文：`存储模块初始化失败: 初始化 DDL 失败: unable to open database file (14)`

脚本判定：PASS（两种存储故障路径均非零退出 + stderr 有错误输出）。

### 3.2 A-01 运行中写失败 ✅

执行 `m2_a01_runfault_test.sh`：2M tmpfs 挂载 → agent 正常启动（NewStore 成功）→ hping3 SYN flood + ssh 大文本并行注入填满 → SQLITE_FULL。

- 退出码：**1**
- stderr 原文：`致命错误: 存储模块退出（数据写入失败）: 批量提交失败: 提交事务失败: database or disk is full (13)`
- 脚本判定：PASS（运行中写失败 → 退出码 1 + stderr 含"致命错误: 存储模块退出"）

### 3.3 D-09 覆盖率复算 ✅（达标，完整纳入函数集合）

WSL Linux 构建 `go test -cover ./internal/fw/` + `cover -func`（证据：`evidence/m2/fw_cover_linux_test003.txt`）：

| 函数 | 覆盖率 | 备注 |
| :--- | :--- | :--- |
| kmsgSeq（fw_kmsg_linux.go L85） | **100.0%** | D-09 修复对象 |
| journalMicroTS（fw.go L102） | **100.0%** | **TEST-003 reviewer R-01 补测**（原 0%，时间戳解析属 §2.2 纳入类） |
| ParseFWLine | 92.9% | |
| ipToUint32 | 90.0% | |
| atou16 | 75.0% | |

**按 TEST-001 §2.2 口径（每包加权 ≥80%，完整 5 函数集合）**：fw 包加权 = (92.9+90+75+100+100)/5 = **91.6% ≥ 80% 达标**。

**R-01 整改说明**：TEST-003 首轮复算仅纳入 4 函数（漏 journalMicroTS 0%），算术平均 89.5%；reviewer 指出后补 `internal/fw/fw_micro_test.go`（TestJournalMicroTS：正常微秒/整秒/不足一秒截断/多位数/前导零/空串回退/非数字回退，7 用例）使 journalMicroTS 达 100%，完整集合加权 91.6%——**达标结论在完整集合下成立，D-09 收敛确认稳健**。

TestKmsgSeq 用例质量核查：11 个用例（标准格式/大序号/多位数/回绕后新序号/无逗号/仅优先级无序号/非数字序号/空记录/无分号消息/序号溢出回绕/序号后无逗号），含非法输入与 uint64 溢出边界，覆盖充分 ✅。

### 3.4 A-02/A-03 单测回归 ✅

| 测试 | 结果 | 说明 |
| :--- | :--- | :--- |
| TestShouldSkipArchive（archive） | ✅ PASS | 磁盘水位跳过逻辑（A-02） |
| TestSqliteQuote（archive） | ✅ PASS | SQLite 字面量转义（A-03） |
| TestArchiveWithQuotePath（archive） | ✅ PASS（0.25s） | 含引号路径端到端归档 |
| TestExecArchiveSystemEvents（store，Linux 构建） | ✅ PASS | 归档前后 system_event 留痕（A-02） |

### 3.5 双环境全包健康 ✅

| 环境 | go test ./... | go vet ./... |
| :--- | :--- | :--- |
| Windows（Go 1.26.2 windows/amd64） | 10 包 ok，0 失败 | ✅ 无输出（通过） |
| WSL Linux（Go 1.26.2 linux/amd64，含 //go:build linux 文件） | 10 包 ok，0 失败 | ✅ 无输出（通过） |

注：模块内 12 个包（10 个 internal/* + cmd/sentry-agent + tools/archive-trigger），其中 cmd/sentry-agent 与 tools/archive-trigger 无测试文件（go test 输出 "no test files"）；"10 包"指含测试文件的包数（与 TEST-002 口径一致）。

### 3.6 语义边界抽查（SB-1）✅ 无回归

白盒确认 store.go 与 main.go 的失败语义边界：

| 路径 | 行为 | 语义 |
| :--- | :--- | :--- |
| Run 主写路径 flush 失败（store.go L231-232/L266-267） | `return fmt.Errorf("批量提交失败: %w", err)` → main.go L122 stderr "致命错误: 存储模块退出（数据写入失败）" + `os.Exit(1)` | **致命退出**（A-01，实测验证） |
| archiveReq 分支（store.go L240） | `_ = s.execArchive(req)`——归档失败忽略返回值不退出；execArchive 内部 system_event 留痕（开始/完成/失败含耗时，store_archive.go L36-43） | **容错不退出**（方案 3.9；归档失败不影响主数据写入） |
| 初始化失败（main.go L108-110） | stderr "存储模块初始化失败" + `os.Exit(1)` | **致命退出**（A-01，实测验证） |
| 归档请求投递失败（main.go L131-133） | RequestArchive 队列满 → system_event warn，不退出 | 容错（可重试） |

边界一致性结论：**主写/初始化失败 = 致命退出（os.Exit(1) + stderr），归档失败 = 留痕容错（不退出）**——语义区分明确，与 A-01 实测行为一致，无回归。

## 4. D-09 台账更新

TEST-002 报告三处 D-09 台账已同步更新为"已收敛"：
- 缺陷清单表（§5）：状态改为 `~~Major~~ → ✅ 已收敛`，注明 TEST-003 回归确认（kmsgSeq 100%、journalMicroTS 100%，完整集合加权 91.6%）
- 未覆盖项表（§6）：kmsgSeq 单测项标记"已解决"
- 结论（§7）：覆盖率 ⚠️ 项注明"TEST-003 已收敛"

（TEST-001 报告无 D-09 台账——D-09 为 TEST-002 新增缺陷，无需更新。）

## 5. 缺陷清单

**本次回归引入的新缺陷：0 项。既有失败：0 项（双环境单测全绿）。** D-09（Major）已由 DEV-004 修复并回归确认收敛（含 TEST-003 补测 journalMicroTS 后完整集合达标）；A-01 相关（auditor Major）双路径实测通过。

**回归期间测试资产整改（reviewer 意见）**：
- 新增 `internal/fw/fw_micro_test.go`（TestJournalMicroTS 7 用例）——补齐 journalMicroTS 0% 缺口（R-01）
- 加固 `scripts/m2_a01_fault_test.sh` 判定：stderr 内容级校验"存储模块初始化失败"（原仅非空校验，弱判定假 PASS 空间，R-02）

## 6. 未覆盖项与原因

| 未覆盖项 | 原因 |
| :--- | :--- |
| A-01 场景三（自定义替代路径） | 任务书未要求；双路径 + 运行中失败已覆盖初始化/运行两阶段 |
| fail2ban 真实库联调等 VPS 复验项 | 环境限制延后（同 TEST-001/002，非本次范围） |
| A-01 故障恢复后的数据空洞量化 | 语义设计为致命退出（systemd Restart=on-failure 重启），非恢复模式，无需量化 |

## 7. 结论

**整体结论：PASS（基线 `1f4f4ef` 放行）**

- 验收 1（A-01 双路径回归）：✅ 通过——初始化故障（/dev/null、/proc）退出码 1 + stderr 原文正确；运行中写失败（SQLITE_FULL）退出码 1 + "致命错误: 存储模块退出"
- 验收 2（D-09 复算达标 + 台账更新）：✅ 通过——kmsgSeq 100%、journalMicroTS 100%，fw 包完整集合加权 91.6% ≥ 80%；TEST-002 台账三处更新
- 验收 3（A-02/A-03 单测）：✅ 通过——TestShouldSkipArchive/TestSqliteQuote/TestArchiveWithQuotePath/TestExecArchiveSystemEvents 全 PASS
- 验收 4（双环境全包测试）：✅ 通过——Windows + WSL Linux 各 10 包全绿，vet 双环境通过
- 验收 5（回归报告结论明确）：✅ 本报告——**M2 整体闭环，放行 M3**

无 Blocker/Major 遗留；无新缺陷；既有缺陷 D-07/D-08/D-09 全部收敛。

## 8. 交付物清单

- 回归报告（本文件）：`docs/verification/TEST-003_回归报告.md`
- D-09 台账更新：`docs/verification/TEST-002_测试报告.md`（§5/§6/§7）
- 覆盖率证据：`docs/verification/evidence/m2/fw_cover_linux_test003.txt`（WSL cover -func 原始输出，journalMicroTS 100%）
- 新增测试文件：`internal/fw/fw_micro_test.go`（TestJournalMicroTS）
- 脚本加固：`scripts/m2_a01_fault_test.sh`（判定内容级校验）
- 执行证据（WSL 本地）：`/tmp/a01_err1.txt`、`/tmp/a01_err2.txt`、`/tmp/a01_run_err.txt`（A-01 三场景 stderr 原文）
- Git：测试资产按 test 类型提交

## 9. 坑点与交接（TEST-003-FIX1 补充）

**检查手段教训（AUD-003 reviewer R-02）**：后续任何基线声明不得仅凭 `git status` 默认输出断言工作区状态——`git status` 默认不显示被忽略文件，裸 .gitignore 规则（本项目 `sentry-agent`/`archive/` 裸规则误伤 `cmd/sentry-agent/` 与 `internal/archive/`）可导致受测目录从未被跟踪而不被察觉。**基线声明须 `git status --ignored` 或 `git ls-files` 双查**（核对关键路径文件是否在树内），确认后填写"工作区状态"。

**已移交 developer 的事项**：.gitignore 裸规则误伤修复（补录 cmd/、internal/archive/ 等被忽略的受测目录）；修复后基线以补录提交的新 hash 为准，届时按 AGENTS.md §4.9 重新对齐候选基线。
