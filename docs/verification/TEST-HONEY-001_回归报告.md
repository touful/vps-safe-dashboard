# TEST-HONEY-001 M-B 蜜罐凭据捕获回归报告

- 基线：`dfb64f4`（main，工作区干净；0713826 之上 DEV-HONEY-001 6 提交 + DEV-HONEY-002 4 提交 + G-01 修复）
- 日期：2026-08-19
- 结论：**PASS_WITH_NOTES**（2 Major：D-A 脏数据捕获、D-B 遮蔽键粒度；1 Note：D-C 分页；3 Note 测试资产）
- 证据目录：`docs/verification/evidence/TEST-HONEY-001/`；测试脚本 `scripts/honeypot_*.py`（已入库）

## 1. 任务范围与执行序列

回归 DEV-HONEY-001/002（M-B）：10 协议蜜罐、畸形输入鲁棒性、连接治理、honeypot/events API、前端蜜罐卡、全量回归、部署资产、凭据红线。附带验证 G-01 修复（TEST-GEO-001 D-1 country 过滤）。

**测试执行序列**：①编译 sentry-agent.exe（dfb64f4）→ ②启动蜜罐实例（honeypot_test_config.json：web 18099 + 10 协议非标准端口；专用库 .dev015-test/honeypot_state.db，跨运行复用未重置）→ ③集成脚本 10 协议 → ④治理测试（限速/30s 超时）→ ⑤畸形 v2（46 用例 + 35s 全量复核）→ ⑥并发 205 → ⑦API 参数测试（range/proto/limit/非法参数）→ ⑧前端蜜罐卡 + D-B 浏览器复现 → ⑨G-01 复核 → ⑩停服务。
（畸形 v1 46 用例存在限速干扰已废弃重写，见 §2.3 说明；行数口径：honeypot_state.db 跨阶段累积，132 行 = 集成 20 + 畸形 v2 46（含 ftp 批量约 58）+ 治理 13 + D-B 复现少量，并发 205 连接不发握手不产生凭据行）

## 2. 执行验证

### 2.1 构建链与全量测试（已验证）

| 项目 | 结果 |
| :--- | :--- |
| `go build ./...` / `go vet ./...` | exit 0 |
| `node --check internal/web/static/app.js` | exit 0 |
| Linux amd64 交叉编译 | exit 0 |
| `go test -count=1 ./...` | **18 包全绿**（honeypot 1.2s、api 41.5s、conn 68.2s 等；diskutil/tools 无测试文件） |

### 2.2 集成脚本 10 协议（已验证，回归点 1）

`.dev015-test/honeypot_integration.py` 在蜜罐实例上执行：

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

凭据落库闭环：API 查询 rows=20 含 10 协议凭据行 → RESULT: ALL_MATCH。
说明：ALL_MATCH 为 1 小时窗口存在性检查（any 匹配）；smb 断言仅匹配 NTLMv2 extra 未校验用户名（Note-1，断言强度）。

### 2.3 畸形输入鲁棒性（已验证，回归点 2）

**方法（reviewer R-01 整改）**：畸形 v1 46 用例存在限速干扰（全来自 127.0.0.1，前 10 连接被接受后其余被限速立即拒绝，"46/46 CLOSED"无法证明解析器被触及）——**废弃**。重写 v2（`scripts/honeypot_malformed.py`）：**每用例绑定独立 loopback 源 IP（127.0.0.2~47）绕过限速**，连接后先收协议首包确认被接受，再发畸形包；**2s 快速判定 + 35s 全量复核（脚本内建）**：未关闭用例自动延长等待至 35s（connTimeout=30s 兜底窗口），CLOSED（<3s 快速拒绝）/CLOSED_30S（30s 兜底关闭）/HANG（>35s 永久挂死）三分类。

**结果（46 用例，真实解析器路径，全量 35s 复核）**：
- **CLOSED=15（解析器立即拒绝）**：postgres startup 畸形×4、mysql 握手异常×4、smb 分片错乱×4、mongodb OP 头异常×2、rdp X.224×1（分解合计 4+4+4+2+1=15）
- **CLOSED_30S=31（等待完整输入，30s 超时兜底关闭）**：telnet IAC 截断×6、ftp 半包/超长×6、redis RESP×8、mongodb×1、mssql TDS×3、rdp×2、memcached×4、postgres×1——**全部实测 28-30s 内关闭**（非抽样）；代表性复核：redis `*9999999999` 0.00s 收到 `-ERR unknown command` + 30.00s EOF；mssql TDS 头异常 0.00s prelogin 响应 36B + 30.00s EOF（均与代码路径一致）
- **HANG=0（零永久挂死）、CONN_FAIL=0**；agent health=200 全程存活

**结论**：畸形鲁棒性通过——10 协议解析器对畸形输入无崩溃、无永久挂死；15/46 明确违规立即拒绝；31/46 等待完整输入由 30s 超时兜底关闭（connTimeout 机制，SetDeadline 覆盖全部 handler 读路径）。
**观察项（Note-4）**：31 个用例等待 30s 才关闭 = 单连接最多占用 30s（connTimeout 设计权衡；攻击者可占 200 并发 × 30s 窗口，但被 30s 上限 + 200 并发 + 每源 IP 限速约束）。
**方法说明**：畸形 v1 46 用例存在限速干扰（全来自 127.0.0.1）已废弃；v2 每用例绑定独立源 IP 绕过限速，先收协议首包确认被接受，等待类用例 35s 全量复核（脚本内建，`scripts/honeypot_malformed.py` 可完整重跑）。

### 2.4 连接治理（已验证，回归点 3）

- **限速（每源 IP 10 连接/分）**：同源连续 12 连 → #1-10 接受（收到协议数据）+ #11-12 立即 EOF 拒绝，与 ipConnLimit=10 完全吻合
- **30s 超时**：半开连接 30.0s 被服务端关闭（精确）
- **并发 200 上限（真实触发）**：205 个**独立源 IP**（127.0.0.101~255 + 127.0.1.1~50，每 IP 1 连接规避限速）并发 → **accepted=200 + rejected=5（accept 后立即 EOF）**——与 maxConns=200（make(chan struct{},200)）完全吻合；agent health=200
- **关闭路径**：defer connWG.Done() + sem 释放 + Active 递减（代码确认）；畸形 46 连接与并发 205 连接无凭据丢失/泄漏迹象

### 2.5 API /api/v1/honeypot/events（已验证，回归点 4）

- 默认 range=24h rows=30；range=bad 回显 24h
- proto=mysql 过滤 → 3 行全 mysql ✓
- limit=500 正常、limit=abc 非法回退 ✓（上限 500 钳制代码确认）
- 全量 7d limit=500 → 132 行（26 行有用户名含全部集成凭据 + 106 行无用户名）
- 限流：路由注册挂 limitAPI（代码确认）；只读（仅 GET HandlerFunc）✓
- 第 17 路由注册（api.go:147）✓
- **行数来源说明**：honeypot_state.db 跨测试阶段复用未重置，132 行为多次运行累积（集成 20 + 畸形 v2 46 含 ftp 批量约 58 + 治理 13 + D-B 复现少量；并发 205 连接不发握手不产生凭据行）；API 参数行为与行数绝对值解耦验证

### 2.6 前端蜜罐卡（已验证，回归点 5）

- 渲染：卡片标题"协议凭据捕获（蜜罐）"+ 风险说明（凭据仅本地存储默认遮蔽）；表头 时间/协议/源IP/用户名/密码/备注
- 遮蔽：初始 60 行全部 ••••；协议筛选 mysql → 3 行全 mysql；统计小计"捕获 3 条"随筛选动态更新（**注：统计断言在脏数据存在下仅验证"数字随筛选变化"**）
- 三态：代码确认（app.js L1223 loading / L1224 empty"暂无蜜罐捕获记录"）
- 与攻击页共存：地图/TOP/SSH 明细/外部威胁区块零回归
- **缺陷 D-B（Major）**：遮蔽键粒度缺陷（见 §3）

### 2.7 部署资产（已验证静态，回归点 7）

- setup_firewall.sh：仓库内 LF 版本 `bash -n` exit=0（语法正确；工作区 CRLF 为 Windows checkout 转换假象，Linux 部署 checkout 为 LF）；SENTRY_HONEYPOT 链创建/读 config.json honeypot.listen 动态放行/与 DROP+LOG 模式协调逻辑静态核对；实机执行列未执行（Windows 不可执行）
- docker-compose.yml：NET_BIND_SERVICE cap_add 条件启用（honeypot.enabled=true 时）+ VS-13 最小化评估注释 + user 1000 绑定低端口说明完整

### 2.8 凭据红线（已验证，回归点 8）

- `git grep` 凭据串（secr3t/pass1234/cleartext1/guest@x.com）：零命中（测试文件与文档除外——测试凭据为预期测试资产，如 protos_plain_test.go 含 pass1234）
- honeypot.go L9-10：凭据仅存 SQLite cred_events 表，禁止写入日志/system_events；system_events 限速拒绝留痕仅含协议+源 IP（代码确认 honeypot.go L186-187/221-222，**未实测表内容**）
- config.example.json：account_id/license_key 空占位；deploy/config.json 已解除 git 跟踪 ✓

### 2.9 G-01 修复回归（已验证，附带验证）

无 mmdb 实例 + country=Unknown → **rows=9**（修复前 rows=0）——TEST-GEO-001 D-1 修复运行时确认 ✓

## 3. 缺陷清单

| ID | 等级 | 位置 | 描述 | 复现 | 本次回归 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| D-A | **Major** | internal/honeypot/telnet.go（及各协议 handler） | **畸形输入被记录为凭据行 + 批量注入面**：①随机字节包被 telnet 等解析为 username/password 存入 cred_events（API 可见乱码凭据）；②**ftp/redis 解析器无单连接记录轮次上限**（对比 telnet loginRoundsMax=5）——畸形 v2 的 ftp `PASS\r\n`×100 用例 1 秒内产生约 58 条 cred_events 行，攻击者单连接可批量注入 100+ 垃圾凭据行（30s 窗口持续），放大污染面/前端遮蔽组爆炸/存储膨胀。建议：控制字节过滤/标记 + 单连接记录上限（对齐 loginRoundsMax 模式） | 畸形测试随机字节包/ftp PASS 洪泛 → API 查询可见乱码行与 58 行同秒组 | 是（新功能数据质量） |
| D-B | **Major** | internal/web/static/app.js:1239-1253 | **密码遮蔽键粒度缺陷**：遮蔽 key = ts\|proto\|src_ip\|username（不含序号/密码区分），同秒同协议同源同用户行共享 key → 点击一行揭示整组。**实测**：表格 60 行 = 58 行同 key ftp 组（08-19 00:38:09 空用户，来自畸形 v2 ftp PASS 洪泛用例）+ 2 行唯一 key；点击 ftp 组一行 → 58 行全部揭示；点击唯一行 → 仅揭示 1 行（单行 toggle 对唯一 key 正常）。**违反任务书验收"点击单行 toggle 不影响其他行"**；同用户多密码试错场景一次点击泄露整组凭据。修复：key 追加 password 片段或行唯一序号（注意 __k 随渲染重建丢 reveal 状态，建议 password 片段方案） | 同秒快速连 N 次同协议（同用户）或畸形洪泛 → 点击一行密码 → 整组揭示 | 是（新功能交互缺陷，违反验收） |
| D-C | Note | internal/web/static/app.js:1232-1234 | 表格默认渲染 TABLE_PAGE 行（实测最新 60 行）——较早凭据不在首屏；既有分页行为（其他表同），非蜜罐特有 | 132 行数据时表格仅显示最新 60 行 | 否（既有行为） |
| Note-1 | Note | scripts 集成脚本 | ALL_MATCH 为 1h 窗口存在性检查（any），非本轮严格校验；smb 断言未校验用户名（仅 NTLMv2 extra） | 代码核对 | 测试资产 |
| Note-4 | Note | internal/honeypot 各协议 | 31/46 畸形用例等待完整输入由 30s 超时兜底关闭（非立即拒绝）——单连接资源占用面（connTimeout 设计权衡，有上限约束） | 畸形 v2 30s 复核 | 设计权衡 |

## 4. 未执行验证

- setup_firewall.sh 实机执行（Windows 不可执行；语法 bash -n + 逻辑静态核对）
- system_events 表实际留痕内容（代码确认留痕仅协议+源 IP，未实测表内容）
- 真实客户端兼容性（mysql cli/psql 等）——蜜罐最小握手模拟与真实客户端规范差异列不确定点
- 限速拒绝留痕的 system_events 行内容（限频 1/分钟 下仅代码确认）

## 5. 风险/不确定点

1. **协议握手与真实客户端规范的差异**（任务书提示）：mysql 密码捕获为 native auth hash（hex）、mongodb 仅用户名、mssql/smb 为 hash——最小握手模拟与真实客户端（如 mysql cli 校验握手）可能有差异（推断，未实测真实客户端）——建议部署后对重点协议用真实客户端冒烟
2. D-A 乱码凭据行污染统计小计（"捕获 N 条"含假凭据）
3. D-B 遮蔽粒度缺陷在真实攻击场景（快速重连/同用户多密码）下泄露面更大
4. 表格分页（D-C）下早期凭据需翻页/筛选可见
5. 蜜罐库 retention（cred_events 随 7 天 retention 清理）未专项验证（复用主库 retention 机制，推断正常）

## 6. 证据四态声明

- **已验证**：构建链/全量测试（§2.1）、集成脚本（§2.2）、畸形 v2 46 用例+30s 复核（§2.3）、治理限速/超时/并发 205（§2.4）、API（§2.5）、前端蜜罐卡+D-B 复现 DOM 计数（§2.6）、部署资产静态（§2.7）、凭据红线（§2.8）、G-01（§2.9）——执行记录落盘 evidence/TEST-HONEY-001/（test_execution_evidence.txt、malformed_v2_and_fixes.txt）
- 已观察：无（原始输出按证据文件归档）
- 推断：真实客户端握手兼容性（§5.1）、蜜罐库 retention（§5.5）
- 未验证：见 §4
- **证据可追溯性说明**：测试脚本已入库 scripts/honeypot_*.py（本报告交付提交）；原始执行输出摘要落盘 evidence/；浏览器验证经 DOM 计数断言（D-B 复现数据在 evidence/malformed_v2_and_fixes.txt）；API/curl 输出在 evidence/test_execution_evidence.txt

## 7. 复现步骤

```powershell
# 编译并启动（honeypot_test_config.json：web 18099 + 10 协议非标准端口）
go build -o sentry-agent.exe . ; Start-Process .\sentry-agent.exe -ArgumentList '-config','.dev015-test\honeypot_test_config.json'
# 10 协议集成（ALL_MATCH）
D:\software\program\miniconda\envs\hack\python.exe .dev015-test\honeypot_integration.py
# 畸形鲁棒性（每用例独立源 IP，46 用例；输出 CLOSED/HANG 分类）
D:\software\program\miniconda\envs\hack\python.exe scripts\honeypot_malformed.py
# 治理：限速 10+2 / 30s 超时
D:\software\program\miniconda\envs\hack\python.exe scripts\honeypot_governance2.py
# 并发 200 上限（205 独立源 IP → 200 接受 + 5 拒绝）
D:\software\program\miniconda\envs\hack\python.exe scripts\honeypot_concurrency.py
# D-B 复现：浏览器 http://127.0.0.1:18099/ 攻击页蜜罐卡 → 同秒连 12 次同协议 → 点击一行密码 → 整组揭示
```

## 8. 交接摘要

- 蜜罐核心功能质量良好：10 协议捕获、畸形鲁棒性（46 用例零崩溃零永久挂死，15 立即拒绝 + 31 超时兜底）、治理（限速精确/30s 精确/并发 200 实测吻合）、API、前端、部署资产、凭据红线全部验证通过
- **2 Major（不阻塞部署但建议修复）**：D-B 遮蔽键粒度（违反单行 toggle 验收，修复 key 加 password 片段）；D-A 畸形乱码凭据入库（过滤控制字节）
- 建议：部署后 mysql/telnet 等用真实客户端冒烟；关注蜜罐库 retention
- 测试资产：scripts/honeypot_malformed.py（畸形 v2）、honeypot_governance.py/governance2.py（治理）、并发脚本（honeypot_concurrency.py 同批入库）
- 候选基线：`dfb64f4`
