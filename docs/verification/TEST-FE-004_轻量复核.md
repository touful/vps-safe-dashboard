# TEST-FE-004 轻量复核记录（M-01 修复 + 仓库整理）

## 一、复核概览

| 项 | 内容 |
| :--- | :--- |
| 任务 | TEST-FE-004：M-01 修复轻量复核（Q2 关卡） |
| 候选基线 | **ba41233**（ba412333a710d31b57ad5dbbe43ca1ef484d918b），分支 main，工作区 clean |
| 复核范围 | DEV-CLEAN-001 交付：M-01 导出中断路径修复 + 文档同步 + 仓库瘦身 |
| 复核时间 | 2026-08-16 20:30 ~ 20:50 |
| 复核人员 | tester（独立执行，未采信 developer 自测） |
| 结论 | **PASS_WITH_NOTES**（0 Blocker / 0 Major / 1 Minor / 2 Note） |

## 二、需求/验收追踪矩阵

| 验收标准（任务书） | 复核结果 | 验证方法 |
| :--- | :--- | :--- |
| export 测试全绿（含 2 个新用例） | PASS | `go test -count=1 ./internal/api/ -run "TestExport" -v`：9/9 通过 |
| 全量测试全绿 | PASS | `go test -count=1 ./...`：13 包 ok，2 包无测试文件 |
| 导出冒烟：8090 + dev015 种子库，range=24h → 200 + CSV 内容正确 | PASS | 重建二进制、种子库、实起服务；HTTP 200 / text/csv / attachment；413 行与 DB 三源精确匹配 |
| trace_attack30s.json 不再被跟踪、.gz 已跟踪 | PASS | `git ls-files` 核验 |
| .gitignore 规则精确，不误伤其他 evidence 文件 | PASS | 抽查 evidence/testfe003/ 6 个小 json 全部仍被跟踪 |
| bin/ 无 p0 产物 | **FAIL（Minor）** | bin/ 下残留 8/15 19:55 的 Linux ELF 产物 bin/sentry-agent |
| git count-objects -vH 正常 | PASS | count=29 / size-pack=6.79 MiB / garbage=0 |
| README "13 只读 API" 表述存在 | PASS | README.md:16/25/35 多处命中 |
| 技术方案 API 表含 export/csv 行 | PASS | 技术方案.md:372 |

## 三、逐项复核记录

### 3.1 export 单元测试（复核项 1）

`go test -count=1 ./internal/api/ -run "TestExport" -v` 输出（9/9 PASS）：

- TestExportCSVParams / TestExportCSVBoundary / TestExportCSVFormat / TestExportCSVRange / TestExportCSVEmpty / TestExportCSVEscape / TestExportRateLimitHeavy（既有 7 个）
- **TestExportCSVFlushError**（新增）：failWriter 模拟客户端断开（缓冲 <4096B，错误延迟到 Flush 暴露），注入 sysCh 断言 warn/api/含"导出写入失败"留痕——覆盖 export.go:130-133 正常路径 Flush 后 cw.Error() 检查
- **TestExportCSVWriteErrorBreak**（新增）：预插 200 行 fw drop（≈7KB 输出 > csv.Writer 4096B 内部缓冲，Write 阶段即报错），断言留痕——覆盖 export.go:105-112 写错误提前 return

> Note-1：任务书称新增用例名为 `TestExportFlushError / TestExportWriteErrorBreak`，实际全名为 `TestExportCSVFlushError / TestExportCSVWriteErrorBreak`，功能与覆盖点一致，仅为命名简写差异。

`go test -count=1 ./...` 全量：cmd/sentry-agent、internal/api（43.1s）、archive、collect、config、conn、diskmon、event、f2b、fw、out、ssh、store 全部 `ok`；internal/web、tools/archive-trigger 无测试文件。

### 3.2 导出冒烟（复核项 2）

步骤（独立执行，与 TEST-FE-003 同法）：

1. `go build -o bin/sentry-agent.exe ./cmd/sentry-agent` 重建二进制（18,075,648 字节）
2. `scripts/dev015_seed_db.py`（hack 环境 Python）重新生成 dev015 种子库
3. 临时配置 `.dev015-test/test_config.json`（监听 127.0.0.1:8090、db.path 指向 dev015），启动服务
4. `GET /api/v1/health` → 200，`{"ok":true,"schema_version":"1"}`，db_size_mb=0.18（种子库已加载）

导出验证（`GET /api/v1/export/csv?range=24h`）：

- HTTP **200**；Content-Type `text/csv; charset=utf-8`；Content-Disposition `attachment; filename="sentry_export_*.csv"`
- CSV **413 行**，与 DB 三源统计精确匹配：fw_drop=225 + ssh_fail=172 + ban=16 = 413（0 缺失 0 多余）
- **无表头**（首行即数据行 `45.155.205.3,2026-08-15 20:36:54,22`）
- **三列**（IP 点分十进制 / `YYYY-MM-DD HH:MM:SS` 时间 / 端口数字或空）
- **升序**：全行时间字段严格非降序校验通过
- 前端静态资源 `/`、`/app.js`、`/index.html` 均 200（42,863 / 81,968 / 42,863 字节）

> 浏览器导出页签交互抽查：**未执行**（任务书条件项"若浏览器可用"）。Chrome DevTools MCP 浏览器实例被其他会话占用（`--isolated` 提示），无法打开新实例；以静态资源加载验证替代，页签交互不在本次轻量复核必测范围。

### 3.3 仓库整理抽查（复核项 3）

- `git ls-files` 含 `docs/verification/evidence/testfe001/trace_attack30s.json.gz`（已跟踪），**不含**裸 `trace_attack30s.json`（已移除跟踪）✓
- .gitignore 规则：`docs/verification/evidence/testfe001/trace_attack30s.json` 精确忽略（第 26 行规则本体，第 24-25 行为 DEV-CLEAN-001 注释；reviewer R-02 勘误，原记录 20 行有误）；抽查 `evidence/testfe003/` 下 csv_check_v2.json、exp2_valid.json、heavy429.json、retry_after_429.json、u1_pressure.json、ws_limit_100.json **全部仍被跟踪**，无误伤 ✓
- `git count-objects -vH`：count=29 loose、in-pack=1137、size-pack=**6.79 MiB**、garbage=0、prune-packable=0 —— 仓库瘦身生效，无垃圾对象 ✓
- **Minor-1**：`bin/` 下残留 `bin/sentry-agent`（Linux ELF，7F 45 4C 46 文件头，17,661,268 字节，创建于 2026-08-15 19:55:18），早于 DEV-CLEAN-001（8/16 20:18 提交）——"bin 清理"声明未完全执行。该文件被 `bin/` gitignore 规则忽略，**不影响版本库**（git status clean、未被跟踪），但为 p0 遗留产物，建议 safe-delete 清理。

### 3.4 文档抽查（复核项 4）

- README.md:16 "提供 **13 只读 HTTP API**（含 /api/v1/export/csv 数据导出）+ 1 个 WebSocket 实时通信" ✓
- README.md:25 "HTTP API：**13 只读端点**）+ WS 实时通信" ✓
- README.md:35 "internal/api/ HTTP API + WebSocket：**13 只读端点** + /ws" ✓
- 技术方案.md:372 `GET /api/v1/export/csv —— CSV 导出攻击记录（range=1h|24h|7d|30d 或 from/to 二选一；IP,时间,端口 三列，无表头）` ✓

> Note-2：docs/verification/README.md 索引未登记 TEST-FE-004（本复核记录）与 evidence 说明未更新 bin/ 相关说明——本记录交付后由索引登记一并补齐（见交付信封 Git 提交）。

> Note-3（reviewer R-01）：M-01 修复共 3 条路径——①Write 错误提前 return 留痕（export.go:105-112）②中断路径 rows.Err() → cw.Flush() + Error 合并单条留痕（export.go:120-128）③正常路径 Flush 后查 cw.Error()（export.go:129-133）。新增 2 个测试动态覆盖 ①③（failWriter 仅模拟写失败，无法触达 rows.Err() 路径）；**路径②为静态核验**（代码逻辑审查通过：先 Flush 再查 Error、两条信息合并单条留痕防限频丢弃），无动态回归保护。建议 developer 后续补充 context 取消测试（已取消 ctx 直调 hExportCSV，断言 sysCh 收到含"导出中断"的 warn 留痕），不阻塞本次交付。

## 四、缺陷清单

| 缺陷ID | 等级 | 复现步骤 | 预期 | 实际 | 关联用例 | 是否本次回归 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| DEF-FE-004-01 | Minor | `Get-ChildItem bin/` | bin/ 无 p0 产物 | 残留 bin/sentry-agent（Linux ELF，8/15 19:55 遗留，17.6MB） | 复核项 3 | 否（既有遗留，DEV-CLEAN-001 清理不彻底） |

## 五、未执行验证

| 项 | 原因 |
| :--- | :--- |
| 浏览器导出页签交互（预设按钮/自定义时间段/下载） | 浏览器实例被占用，任务书为条件项；TEST-FE-003 已全量验证页签，本次仅复核 M-01 修复，静态资源加载验证替代 |
| 科研测试维度（统计/可复现性/消融/鲁棒性/数据完整性） | N/A：本任务为 Go 服务功能复核，非科研代码任务 |

## 六、结论

**PASS_WITH_NOTES**：4 项复核内容中 3 项全过，1 项（bin/ 无 p0 产物）存在 Minor 遗留（不影响版本库与功能，不阻塞交付）。M-01 修复代码与新增测试覆盖点真实有效，未发现弱化断言或删测试换通过的情况。

## 七、复核证据

- 本记录 + 临时产物（.dev015-test/，gitignore 目录，不入库）
- `git log --oneline -1` 基线确认：ba41233（main，clean）

## 八、reviewer 反思结论

reviewer 第 1 轮结论：**PASS_WITH_NOTES**（0 Blocker / 0 Major），2 项 Note——R-01（M-01 路径②无动态测试覆盖，已补注 Note-3，建议转 developer 补 context 取消测试）、R-02（.gitignore 行号勘误，已整改）。无 Blocker/Major，无需第 2 轮复核。
