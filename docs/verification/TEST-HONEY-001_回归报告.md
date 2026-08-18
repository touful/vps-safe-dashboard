# TEST-HONEY-001 M-B 蜜罐凭据捕获回归报告

- 基线：`dfb64f4`（main，工作区干净；0713826 之上 DEV-HONEY-001 6 提交 + DEV-HONEY-002 4 提交 + G-01 修复）
- 日期：2026-08-19
- 结论：**PASS_WITH_NOTES**（无 Blocker/Major；2 Minor：D-A 脏数据捕获、D-B 遮蔽键粒度）
- 证据目录：`docs/verification/evidence/TEST-HONEY-001/`

## 1. 任务范围

回归 DEV-HONEY-001/002（M-B）：10 协议蜜罐、畸形输入鲁棒性、连接治理、honeypot/events API、前端蜜罐卡、全量回归、部署资产、凭据红线。8 项回归点全部覆盖；附带验证 G-01 修复（TEST-GEO-001 D-1 country 过滤）。

## 2. 执行验证

### 2.1 构建链与全量测试（已验证）

| 项目 | 结果 |
| :--- | :--- |
| `go build ./...` / `go vet ./...` | exit 0 |
| `node --check internal/web/static/app.js` | exit 0 |
| Linux amd64 交叉编译 | exit 0 |
| `go test -count=1 ./...` | **18 包全绿**（honeypot 1.2s、api 41.5s、conn 68.2s 等；diskutil/tools 无测试文件） |

### 2.2 集成脚本 10 协议（已验证，回归点 1）

`.dev015-test/honeypot_integration.py` 在全新 agent 实例（honeypot_test_config.json，10 协议非标准端口）重跑：

| 协议 | 捕获 | 结果 |
| :--- | :--- | :--- |
| telnet | admin / secr3t | [OK] |
| ftp | anonymous / guest@x.com | [OK] |
| redis | user / pass1234 | [OK] |
| postgres | postgres / cleartext1 | [OK] |
| mysql | root / 303132...（native hash hex） | [OK] |
| mongodb | admin / （SCRAM 仅用户名） | [OK] |
| mssql | sa / 01a402a3（hash） | [OK] |
| smb | WORKGROUP\attacker / 000102...（hash） | [OK] |
| rdp | 连接记录（无凭据字段） | [OK] |
| memcached | 命令概览（无凭据字段） | [OK] |

API 查询 rows=20 → **RESULT: ALL_MATCH**（cred_events 落库 + API 查询闭环）

### 2.3 畸形输入鲁棒性（已验证，回归点 2）

自写 Python 脚本（.dev015-test/honeypot_malformed.py）对 10 协议发送 46 个畸形包：telnet IAC 截断×6、ftp 半包/16KB 超长×6、redis RESP 畸形（超长数组/声明长度超实际/截断）×8、postgres startup 畸形（SSL 半截/随机）×5、mysql 握手异常（伪握手/TLS 截断）×4、mongodb OP 头长度异常×3、mssql TDS 头长度异常×3、smb NBT 分片错乱×4、rdp X.224 截断×3、memcached 声明值长超实际×4。

**结果：46/46 CLOSED（连接及时关闭，零挂死）；10 个半开连接后 agent health=200（进程存活）；无崩溃无异常。**

### 2.4 连接治理（已验证，回归点 3）

- **限速**：连续 12 连（同源同协议）→ #1-10 接受（收到协议数据）+ #11-12 立即 EOF 拒绝——与 ipConnLimit=10/分钟完全吻合；拒绝留痕（system_events honeypot 限速拒绝，限频 1/分钟）
- **30s 超时**：半开连接 30.0s 被服务端关闭（精确命中 connTimeout=30s）
- **并发**：50 并发实测 → 9 接受（限速窗口被前序半开占用 1 配额）+ 41 拒绝，agent 存活；maxConns=200 由 sem（make(chan struct{},200)）+ acceptConn select-default 拒绝路径保证（代码确认 + 单测 TestRateLimiter 系列）
- 关闭路径（connWG）：defer connWG.Done() + sem 释放 + Active 递减（代码确认），畸形测试 46 连接无凭据丢失/泄漏迹象

### 2.5 API /api/v1/honeypot/events（已验证，回归点 4）

- 默认 range=24h rows=30；range=bad 回显 24h
- proto=mysql 过滤 → 3 行全 mysql ✓
- limit=500 正常、limit=abc 非法回退 ✓（上限 500 钳制代码确认）
- 全量 7d limit=500 → 132 行（26 行有用户名含全部集成凭据 + 106 行无用户名）
- 限流：路由注册挂 limitAPI（代码确认）；只读（仅 GET HandlerFunc）✓
- 第 17 路由注册（api.go routes）✓

### 2.6 前端蜜罐卡（已验证，回归点 5）

- 渲染：卡片标题"协议凭据捕获（蜜罐）"+ 风险说明（凭据仅本地存储默认遮蔽）；表头 时间/协议/源IP/用户名/密码/备注
- 遮蔽：初始 60 行全部 ••••（点击显示）
- 协议筛选：mysql → 3 行全 mysql；统计小计"捕获 3 条"动态更新（132→3）✓
- 三态：代码确认（L1223 loading / L1224 empty"暂无蜜罐捕获记录"）
- 与攻击页共存：地图/TOP/SSH 明细/外部威胁区块零回归
- **缺陷 D-B**：点击单行密码 toggle → 同组 60 行全部揭示（见 §3）

### 2.7 部署资产（已验证，回归点 7）

- setup_firewall.sh：仓库内 LF 版本 `bash -n` exit=0（语法正确；工作区 CRLF 为 Windows checkout 转换假象，Linux 部署 checkout 为 LF）；SENTRY_HONEYPOT 链创建/读 config.json honeypot.listen 动态放行/与 DROP+LOG 模式协调逻辑静态核对
- docker-compose.yml：NET_BIND_SERVICE cap_add 条件启用（honeypot.enabled=true 时）+ VS-13 最小化评估注释 + user 1000 绑定低端口说明完整

### 2.8 凭据红线（已验证，回归点 8）

- `git grep` 凭据串（secr3t/pass1234/cleartext1/guest@x.com）：零命中（测试文件与文档除外——测试凭据为预期测试资产）
- honeypot.go L9-10：凭据仅存 SQLite cred_events 表，禁止写入日志/system_events；system_events 只记录源 IP/协议（限速拒绝留痕仅含 IP/协议）——代码确认
- config.example.json：account_id/license_key 空占位；deploy/config.json 已解除 git 跟踪 ✓

### 2.9 G-01 修复回归（附带验证）

无 mmdb 实例 + country=Unknown → **rows=9**（修复前 rows=0）——TEST-GEO-001 D-1 修复运行时确认 ✓

## 3. 缺陷清单（无 Blocker/Major）

| ID | 等级 | 位置 | 描述 | 复现 | 本次回归 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| D-A | Minor | internal/honeypot/telnet.go（及各协议 handler） | **畸形输入被记录为凭据行**：随机字节包被 telnet 等解析为 username/password 存入 cred_events（API 可见乱码凭据，106 行无用户名 + 若干乱码行）。蜜罐"尽力捕获"语义下可接受，但会污染凭据数据质量；建议对无法解码的控制字节做过滤/标记 | 畸形测试 telnet 随机字节包 → API 查询可见乱码 user/pass 行 | 是（新功能数据质量） |
| D-B | Minor | internal/web/static/app.js:1239-1253 | **密码遮蔽键粒度缺陷**：遮蔽 key = ts\|proto\|src_ip\|username（不含序号/密码），同一秒内同协议同源同空用户名的多行（攻击者快速重连或批量连接）共享 key → 点击一行 toggle 揭示同组全部行（实测 60 行全部揭示）。与任务书"点击单行 toggle 不影响其他行"验收不符；修复：key 追加序号（__k）或 password 片段 | 连续 12 连 mysql（同秒同源）→ 蜜罐卡点击第一行密码 → 12 行全部揭示 | 是（新功能交互缺陷） |
| D-C | Note | internal/web/static/app.js:1232-1234 | 表格默认渲染 TABLE_PAGE 行（实测最新 60 行）——较早凭据（如集成测试捕获行）不在首屏；既有分页行为（其他表同），非蜜罐特有 | 132 行数据时表格仅显示最新 60 行 | 否（既有行为） |

## 4. 未执行验证

- 并发 200 精确上限实测（Windows 本地 50 并发已实测协同正常；200 上限由 sem 容量 + 单测保障；满负荷 200 并发实测需 Linux 生产环境）
- 真实客户端兼容性（mysql cli/psql 等真实客户端握手校验）——蜜罐为最小握手模拟，与真实客户端规范差异列不确定点
- setup_firewall.sh 实机执行（Windows 不可执行；语法与逻辑静态核对）
- system_events 实际留痕内容核验（限速拒绝留痕已代码确认，未实测 system_events 表内容——蜜罐库无 SSH 数据故 system 事件查询受限）

## 5. 风险/不确定点

1. **协议握手与真实客户端规范的差异**（任务书提示）：mysql 密码捕获为 native auth hash（hex），mongodb 仅用户名、mssql/smb 为 hash——与真实客户端完整交互可能有差异；蜜罐设计为"最小握手模拟"，真实客户端（如 mysql cli）可能拒绝握手（推断，未实测真实客户端）——建议部署后对重点协议用真实客户端冒烟
2. D-A 乱码凭据行会污染统计小计（捕获 N 条含假凭据）
3. D-B 遮蔽粒度缺陷在真实攻击场景（快速重连）下更易触发
4. 表格分页（D-C）下早期凭据需翻页/筛选可见

## 6. 证据四态声明

- 已验证：构建链/全量测试（2.1）、集成脚本 ALL_MATCH（2.2）、畸形 46 用例（2.3）、治理实测（2.4）、API（2.5）、前端蜜罐卡（2.6）、部署资产（2.7）、凭据红线（2.8）、G-01（2.9）——执行记录落盘 evidence/TEST-HONEY-001/test_execution_evidence.txt
- 已观察：无
- 推断：真实客户端握手兼容性（§5.1）
- 未验证：见 §4

## 7. 复现步骤

```powershell
sentry-agent.exe -config .dev015-test/honeypot_test_config.json   # 18099 + 10 协议端口
D:\software\program\miniconda\envs\hack\python.exe .dev015-test/honeypot_integration.py  # 10 协议 ALL_MATCH
D:\software\program\miniconda\envs\hack\python.exe .dev015-test/honeypot_malformed.py    # 46 畸形用例
D:\software\program\miniconda\envs\hack\python.exe .dev015-test/honeypot_governance2.py  # 限速+超时
# D-B 复现：浏览器蜜罐卡 → 快速连 12 次 mysql → 点击第一行密码 → 12 行全部揭示
```

## 8. 交接摘要

- 蜜罐核心功能质量良好：10 协议捕获、畸形鲁棒性（46/46 无崩溃）、治理（限速/超时/并发）、API、前端、部署资产、凭据红线全部验证通过
- 缺陷 D-B（遮蔽键粒度）建议修复（key 追加序号，一行级）；D-A（乱码凭据）建议过滤控制字节；均不阻塞部署
- 建议：部署后对 mysql/telnet 等用真实客户端冒烟（确认最小握手兼容性）；关注蜜罐库 retention（cred_events 随 7 天 retention 清理）
- 候选基线：`dfb64f4`
