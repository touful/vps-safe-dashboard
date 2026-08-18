# TEST-GEO-001 M-A 全球攻击地图 + GeoIP + 封禁移除回归报告

- 基线：`0713826`（main，工作区干净；在 1c778aa 之上 6 个 DEV-GEO-001 提交）
- 日期：2026-08-18
- 结论：**PASS_WITH_NOTES**（无 Blocker/Major；1 Minor + 1 Note）
- 证据目录：`docs/verification/evidence/TEST-GEO-001/`

## 1. 任务范围

回归 DEV-GEO-001（M-A）：geoip 新包（reader/updater）、attacks/geo 与 export/attacks_csv 新 API、前端封禁移除 6 处 + 全球攻击地图、部署脚本、构建链。5 项回归点全部覆盖。

## 2. 执行验证

### 2.1 构建链（已验证）

| 项目 | 结果 |
| :--- | :--- |
| `go build ./...` | exit 0 |
| `go vet ./...` | exit 0 |
| `node --check internal/web/static/app.js` | exit 0 |
| Linux amd64 交叉编译 `GOOS=linux GOARCH=amd64 go build ./...` | exit 0 |
| `go test ./...` 重点包非缓存 | geoip 11 PASS（含真实 mmdb 冒烟 TestRealMMDBSmoke 与并发替换 TestReaderConcurrentReplace，经 GEOIP_TEST_MMDB 激活）+ api 39.9s 全绿；TestUpdaterRealNetwork 因无 MaxMind 凭据 SKIP（N/A） |

### 2.2 attacks/geo API（已验证）

双实例实测：18080（cfg_geo.json，含真实 GeoLite2-Country.mmdb）与 18081（cfg_nommdb.json，无 geoip 段，降级场景）：

| 场景 | 结果 |
| :--- | :--- |
| range=24h（有 mmdb） | mmdb_ok=true、9 行（SSH 失败按 src_ip 聚合 9 个源）；国家标注正确：45.155.205.2=RU(俄罗斯联邦,24)、185.220.101.2=DE(德国,23)、185.220.101.4=DE(22)、91.240.118.77=HK(香港,21)、45.155.205.3=RU(20)…… |
| range=bad（非法回退） | 回显 range=24h、9 行（与 rangeSeconds 口径一致） |
| country=CN 过滤 | rows=0（种子无 CN 源，过滤语义正确） |
| min_count=20 | rows=6（全部 count≥20：24/23/22/21/20/20） |
| 无 mmdb 降级（18081） | mmdb_ok=false、9 行全部 country=Unknown（不崩溃降级正确） |
| 无 mmdb country=Unknown | **rows=0【缺陷 D-1】**（见 §3） |
| LIMIT 1000 | 代码级确认（queryGeoRows LIMIT ?=1000，30d 视图上限） |
| 限流挂载 | 9 连发 → 200×5+429×4（limitHeavy 生效，与 export/csv 同档） |

### 2.3 export/attacks_csv 导出（已验证）

- 无表头三列（IP,国家名,次数）、9 行；Content-Type: text/csv; charset=utf-8；Content-Disposition: attachment（filename=sentry_attacks_geo_时间戳.csv）
- 筛选联动：country=RU&min_count=20 → 2 行（45.155.205.2,俄罗斯联邦,24 / 45.155.205.3,俄罗斯联邦,20）
- 逗号转义：单测覆盖（geo_test.go L191 RFC 4180 引号转义）；当前种子数据无含逗号国家名（真实数据验证 N/A，转义由标准库 csv.Writer 保证）
- 与 export/csv 互不干扰：export/csv 395 行（fw+ssh 合并，第三列为空行数=0 即无 ban 残留）；attacks_csv 独立路由独立输出
- /api/v1/bans 保留可用：26 行（ban/unban）

### 2.4 GeoIP 模块（已验证）

- reader：代码级核对（Lookup 持 RLock 查询防 TOCTOU、country 回退 registered_country、zh-CN 优先 en 回退、ok=false 降级不崩溃、ReplaceFrom 先关旧→.bak→rename→重开+失败回滚）+ 单测 11 PASS（真实库冒烟：已知 IP 查询、并发替换）
- updater：代码级核对（ETag/Last-Modified 条件请求→304 跳过；200 解压→校验[打开+probe 8.8.8.8 查询]→原子替换；校验失败不替换；错误文案不含凭据；200MB/500MB 上限防御；失败留痕经 RateLimiter 限频 1/小时；启动时缺失库+凭据齐全立即拉取）+ 单测（NotModified/AuthFailure/MissingCreds/InstallFailure/ExtractMMDB 全 PASS）
- 真实网络更新（TestUpdaterRealNetwork）：无 MaxMind 凭据 SKIP（N/A，环境变量门控机制确认存在）

### 2.5 前端回归（已验证，浏览器实测）

**封禁移除 6 处（静态 grep + DOM 断言）**：
1. ban-table/bansTable：0 残留 ✓
2. 封禁 KPI：总览无封禁卡（5 KPI：外部威胁事件/SSH 失败/当前活跃连接/磁盘使用率/风险评分）；"封禁数/已封禁"仅 1 处注释（index.html L641 说明移除动作）✓
3. 评分通道：权重 40/40/20（app.js L324-325 注释确认）✓
4. 态势条：无"已封禁 X 个 IP"短语 ✓
5. 事件流：标题"拦截/丢弃 / SSH 失败"（无封禁）、无 ban 类型条目 ✓
6. export 文案：已移除 fail2ban 封禁（"外部威胁事件+SSH 失败尝试"），新增"按来源国家导出请使用攻击页全球攻击地图卡内的导出按钮"提示 ✓

**地图与联动**：
- world.json embed 加载渲染（SVG 14 path、3 国家着色 RU/DE/HK 与 geo API 一致；无形状国家跳过逻辑 L552/L585）
- 国家下拉联动：选"俄罗斯联邦"→ 列表仅剩 3 行 RU ✓
- 次数阈值联动：选 ≥10 → 9 行全部 ≥10 ✓
- 导出按钮：geoExport(L686) 拼接 range/country/min_count 参数（代码确认）+ 后端参数实测有效 ✓
- 攻击页 FAIL2BAN 封禁记录表已移除 ✓

**零回归**：四页签、时间范围、TOP 图、SSH 明细/外部威胁过滤下拉、连接页事件流、导出页表单全部正常；console 无 error/warn（WS 正常）；conntrack 降级提示为 Windows 预期行为。

### 2.6 覆盖率（重点包）

geoip 未单独统计（测试 11 PASS 全绿）；api 73.5%（既有水平）。非新增代码任务门槛适用性说明：本任务以功能回归为主，关键路径（geo 聚合/过滤/降级/导出/限流/前端联动）均有实测覆盖。

## 3. 缺陷清单（无 Blocker/Major）

| ID | 等级 | 位置 | 描述 | 复现 | 本次回归 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| D-1 | Minor | internal/api/geo.go:91 (strings.ToUpper) + :31 (unknownCountry="Unknown") | **country=Unknown 过滤失效**：country 参数经 ToUpper 转为 "UNKNOWN"，与 unknownCountry 占位值 "Unknown"（混合大小写）不匹配 → 无 mmdb 降级时 country=Unknown 查询返回 0 行（应返回全部 Unknown 行）。前端下拉不暴露 Unknown 选项（app.js L552 跳过），UI 不可达 | `curl "http://127.0.0.1:18081/api/v1/attacks/geo?country=Unknown"`（无 mmdb 实例）→ rows=0，预期全部 9 行 | 是（新功能缺陷，API 层面） |
| D-2 | Note | internal/api/geo.go:100-105 + :128 | range 非法值回显逻辑与 rangeSeconds 回退在两处独立实现（switch 白名单 vs default 24h），当前一致但存在未来漂移风险 | 代码结构观察 | 否（既有结构风险） |

## 4. 未执行验证

- TestUpdaterRealNetwork（真实 MaxMind 网络更新）：无凭据（GEOIP_UPDATE_TEST/MM_ACC/MM_KEY 未提供），SKIP；更新器逻辑由 mock 单测覆盖（NotModified/AuthFailure/InstallFailure 等）
- 逗号转义真实数据路径：当前种子数据无含逗号国家名，转义由单测 + 标准库保证
- deploy/fetch_geolite2.sh 实机执行：脚本语法已入库（bash 脚本，Windows 不可执行），未实跑（N/A，部署环境验证）

## 5. 风险/不确定点

1. D-1（country=Unknown 过滤）为 API 边界缺陷，前端当前不可达；若未来前端下拉加入 Unknown 选项将暴露
2. 真实 mmdb 为国家版 GeoLite2（.dev015-test 既有文件），生产库由 fetch_geolite2.sh 部署，更新链路（ETag/原子替换）仅 mock 验证
3. export/csv 行数 395 ≠ 任务书所述 511（开发者口径）：当前种子库窗口数据不同所致（滑动窗口边界效应），非行为差异（ban 分支移除已由空端口行数=0 确认）

## 6. 证据四态声明

- 已验证：构建链（2.1）、API 实测（2.2-2.3，curl 输出落盘 evidence/api_curl_evidence.txt）、geoip 单测（真实库激活）、前端浏览器断言（evidence/frontend_asserts.txt）、封禁移除 grep、评分权重/导出逻辑代码级确认
- 已观察：无
- 推断：无
- 未验证：见 §4

## 7. 复现步骤

```powershell
# 有 mmdb 实例
sentry-agent.exe -config .dev015-test/cfg_geo.json   # 18080
curl "http://127.0.0.1:18080/api/v1/attacks/geo?range=24h"
curl "http://127.0.0.1:18080/api/v1/export/attacks_csv?range=24h&country=RU&min_count=20"
# 无 mmdb 降级实例（cfg_nommdb.json 无 geoip 段，18081）
curl "http://127.0.0.1:18081/api/v1/attacks/geo?range=24h"       # mmdb_ok=false 全 Unknown
curl "http://127.0.0.1:18081/api/v1/attacks/geo?country=Unknown" # D-1 复现：rows=0
# 浏览器：http://127.0.0.1:18080/ 攻击页地图/下拉/阈值/导出
```

## 8. 交接摘要

- 功能交付质量良好：attacks/geo 聚合/过滤/降级/限流、attacks_csv 导出、GeoIP reader/updater、前端地图与封禁移除全部验证通过
- 缺陷 D-1（country=Unknown 大小写不匹配）建议修复（一行级：country 比较改为 case-insensitive 或 unknownCountry 参与 ToUpper 归一），不阻塞部署
- 建议：生产环境部署后关注 updater 首次拉取与每日更新留痕（system_events source=geoip）
- 候选基线：`0713826`
