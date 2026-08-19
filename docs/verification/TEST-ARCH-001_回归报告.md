# TEST-ARCH-001 DEV-ARCH-002 架构优化回归报告

- 基线：`0b5e36f`（main，工作区干净；0c38527 之上 6 提交：86a04b1 标准库替换 / 9aac689 死代码+HH:MM / b76de8a hSummary+stdout / 19670ee DSN+条件拼接+log.level / cb5bf62 x/time / 0b5e36f reviewer 整改）
- 日期：2026-08-19
- 结论：**PASS**（无 Blocker/Major/Minor；1 Note 观察项）
- 证据目录：`docs/verification/evidence/TEST-ARCH-001/`

## 1. 任务范围

回归 DEV-ARCH-002 架构优化（A 标准库替换 / B 死代码 / C 行为变更×2 / D 收敛 / E x/time / F 死配置）：8 项回归点全部覆盖。

## 2. 执行验证

### 2.1 行为变更（回归点 1，重点）

**hSummary 吞错→500**：
- 正常路径：主库实例 summary 返回 **fw_events=110 / ssh_fail=56 / ssh_ok=5**（COUNT 正确非零）✓
- DB 故障注入：`TestSummaryDBDown` 单测 PASS（srv.db.Close() → 500，0.11s）——DB 故障不再静默返回零值 ✓

**stdout 模式蜜罐禁用**：
- `-stdout` + honeypot.enabled=true → **蜜罐 10 端口全部不监听**（13306/16379/10023/10021/11433/17017/15432/13389/1445/11212 全 False）✓
- 非 stdout 对照：蜜罐端口监听（13306/16379 True）+ 集成 ALL_MATCH ✓
- shouldStartHoneypot 纯函数（main.go:397-398 `!stdoutMode && enabled`）代码确认
- 注：stdout 模式 web 不启动为既有设计（main.go:153"仅落库模式"），非本次变更

### 2.2 x/time 迁移等价性（回归点 2）

- 页面节奏 7 轮轮询 **0 拒绝**（heavy=100 配置下）✓
- heavy_limit_rps=1 独立实例：attacks/geo 8 连 → **200×6 + 429×2 + Retry-After:1**——与 TEST-GEO-001 基线（同配置 200×6+429×3）模式一致 ✓
- honeypot 限流等价性单测全 PASS：TestRateLimiter / TestRateLimiterSweep / TestRateLimiterOverflowRebuild / TestServerRateLimitReject / TestServerConcurrentLimit ✓
- go.mod 新增**仅** `golang.org/x/time v0.15.0`（cb5bf62 引入）✓

### 2.3 蜜罐零回归（回归点 3）

- 集成脚本 10 协议 **ALL_MATCH**（telnet/ftp/redis/postgres/mysql/mongodb/mssql/smb/rdp/memcached 全 [OK]）✓
- 畸形复测（scripts/honeypot_malformed.py 全量 35s）：**CLOSED=15 + CLOSED_30S=31 + HANG=0 + CONN_FAIL=0**，agent health=200——与 TEST-HONEY-001 基线完全一致 ✓
- **utf16 代理对（H-09 修复）**：smb 用户名 `😀中admin`（U+1F600 代理对 D83D DE00）→ API 捕获 `WORKGROUP\😀中admin`（len=17 正确）→ **EMOJI PROXY PAIR DECODE: PASS** ✓

### 2.4 dbdsn 收敛（回归点 4）

- api.go:59 / f2b.go:108 / store.go:212 三处统一 `dbdsn.ReadOnly`/`ReadWrite` ✓
- ReadOnly = `file:<PathEscape>?mode=ro&_pragma=busy_timeout(5000)`；ReadWrite = WAL + synchronous=NORMAL + busy_timeout + foreign_keys ✓
- 契约测试 dbdsn_test.go + api_pure_test.go（URL 编码：空格/问号/#/%/& 用例）全 PASS ✓
- store 打开/归档正常（store 16.4s 测试全绿 + 实例运行正常）✓

### 2.5 HH:MM 收敛（回归点 5）

- config.ParseHourMinute 导出（config.go:509）：严格 HH:MM（len==5 + ':' + 数字 + h≤23/m≤59）；archive.go:335 复用 ✓
- 旧 Sscanf 宽松解析差异由 config.Validate 拦截前提消除（config.go:410 校验非法值）✓
- TestParseHourMinute 边界测试（合法/非法）PASS ✓

### 2.6 死代码/死配置（回归点 6）

- **log.level 全仓库 grep count=0**（含测试/脚本/文档，排除 docs/verification 历史报告）✓
- DefaultCriticalUsagePct / MonthOf 代码零残留（仅 docs/verification 历史报告提及）✓
- 删除后编译测试全绿 ✓

### 2.7 全量回归（回归点 7）

| 项目 | 结果 |
| :--- | :--- |
| `go build ./...` / `go vet ./...` | exit 0 |
| `go test ./...` | **19 包全绿**（含新包 dbdsn） |
| 重点包 -count=1 非缓存 | api 40.7s / store 16.4s / honeypot 3.7s / config / archive / f2b / fw / ssh / dbdsn 全绿 |
| Linux amd64 交叉编译 | exit 0 |

### 2.8 前端/API 冒烟（回归点 8）

- 关键 API 全 200：health / summary / attacks/geo / honeypot/events / export/csv?range=24h ✓
- 页面渲染：标题"VPS安全态势"、四页签（总览/连接/攻击/数据导出）可切换、18 卡片、5 表格、攻击页蜜罐卡 + 地图 canvas + hp-table 60 行 ✓
- summary COUNT 非零正确（fw=110/ssh_fail=56/ssh_ok=5）✓

## 3. 缺陷清单

**无 Blocker/Major/Minor。**

| ID | 等级 | 描述 |
| :--- | :--- | :--- |
| Note-1 | Note | stdout 模式 web 不启动为既有设计（main.go:153"仅落库模式"），非本次变更引入；验证时需注意 stdout 模式仅输出采集日志 |

## 4. 未执行验证

- hSummary DB 故障动态注入（采用单测 TestSummaryDBDown 作为 DB 故障权威验证——srv.db.Close() 后查询返回 500；动态侧验证正常路径 COUNT）
- 真实客户端兼容性（沿用 TEST-HONEY-001 结论，非本次变更范围）
- setup_firewall.sh 实机执行（Windows 不可执行，非本次变更范围）

## 5. 风险/不确定点

1. ParseHourMinute 严格化（旧 Sscanf 接受 "1:2" 等宽松格式）——行为差异仅在非法配置路径，被 config.Validate 拦截前提消除；若未来有绕过 Validate 直接调 archive 的路径需注意（当前无）
2. x/time rate 的滑动窗口与旧 tokenBucket 的精确窗口语义差异——实测限流行为（429 时机/Retry-After）与基线一致，但极端边界（长时间满负荷）未压测

## 6. 证据四态声明

- 已验证：§2.1-§2.8 全部（执行记录落盘 evidence/TEST-ARCH-001/test_execution_evidence.txt；单测输出、curl 状态码、浏览器 DOM 计数、脚本 stdout）
- 已观察：无
- 推断：无
- 未验证：见 §4

## 7. 复现步骤

```powershell
go build -o sentry-agent.exe ./cmd/sentry-agent
# 非 stdout 实例（蜜罐监听 + 集成 + API）
Start-Process .\sentry-agent.exe -ArgumentList '-config','.dev015-test\honeypot_test_config.json'
D:\software\program\miniconda\envs\hack\python.exe .dev015-test\honeypot_integration.py   # ALL_MATCH
D:\software\program\miniconda\envs\hack\python.exe scripts\honeypot_malformed.py          # 畸形 46 用例
# stdout 模式（蜜罐禁用）
Start-Process .\sentry-agent.exe -ArgumentList '-stdout','-config','.dev015-test\honeypot_stdout_config.json'
# 限流（heavy_limit_rps=1 实例）
Start-Process .\sentry-agent.exe -ArgumentList '-config','.dev015-test\honeypot_rl_config.json'
curl.exe -s -D - -o NUL http://127.0.0.1:18097/api/v1/attacks/geo   # 429 + Retry-After
# hSummary DB 故障
go test -count=1 -v -run TestSummaryDBDown ./internal/api/
```

## 8. 交接摘要

- DEV-ARCH-002 全部 8 项回归点通过：行为变更（hSummary 500 + stdout 蜜罐禁用）、x/time 等价性、蜜罐零回归（含 utf16 代理对）、dbdsn/HH:MM 收敛、死代码/死配置清理、全量回归、前端/API 冒烟
- 无缺陷；1 Note（stdout web 既有设计）
- 测试资产：.dev015-test/honeypot_stdout_config.json / honeypot_rl_config.json / emoji_check.py（临时产物，未入库）；scripts/honeypot_malformed.py 复用既有
- 候选基线：`0b5e36f`
