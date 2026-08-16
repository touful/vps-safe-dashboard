
# AUD-FE-001 前端交叉审计报告（sentry-agent Web 面板）

- 审计人：auditor 子 Agent（sci-touful 管辖）
- 任务书：AUD-FE-001（前端交叉审计分析）
- 日期：2026-08-15
- 性质：纯只读审计（零文件变更，Git 提交 N/A）
- 交叉审查对象：`docs/前端优化方案.md`（developer 交付；本报告覆盖两版：早期 190 行诊断版 20:52 与完整 704 行版 21:05）

## 1. 审计范围与方法

### 1.1 候选基线

| 项 | 值 |
| :--- | :--- |
| 候选基线 commit | `64a82f4`（main 分支 HEAD，`docs: DEV-021 reviewer R-08`） |
| 工作区状态 | 干净（nothing to commit, working tree clean），无基线漂移 |
| 受审对象 | `internal/web/static/index.html`（507 行）、`internal/web/static/app.js`（1006 行） |
| 契约对照 | `internal/api/api.go`（265 行）、`internal/api/query.go`（467 行）、`internal/api/ws.go`（236 行）、`internal/event/event.go`、`internal/store/store_batch.go` |
| 参考档案 | `docs/技术方案.md`（§3.7/3.8/8.2/11.3）、`docs/verification/`（TEST-004/006/007、V4_验证报告_M3）、`docs/M4_部署手册.md` |

### 1.2 方法与执行轮次

1. 通读 `index.html` 与 `app.js` 全文（前端主对象）。
2. 对照后端 12 个只读端点 + /ws 的实现（api.go/query.go/ws.go），逐一核对前端 fetch 路径与字段契约。
3. 核查 IP 存储链路（event.go `IPv4ToUint32` → store_batch.go `int(v.SrcIP)` → query.go int64 JSON → 前端 `ip()`），确认 uint32 边界。
4. 逐字段核查 XSS 渲染面（innerHTML 拼接点、textContent 使用、escapeHtml 覆盖）。
5. **第一轮交叉审查**（方案 190 行诊断版）：核对行号引用与事实，评估等级口径。
6. **第二轮交叉审查**（方案 704 行完整版，reviewer R-02 触发）：核对 §9.5 对 D-1~D-6 六条回应的真实性、预审指引 §4.3 六条符合性、§2-§10 建议条款与 §3 约束清单的符合度。
7. reviewer 独立反思两轮：第 1 轮发现 R-01（RB-01 等级校准）/R-02（审计闭环未完成）/R-03（计数）/R-04（请求构成）等；本报告按第 1 轮意见整改后提交第 2 轮复核（§9 回填）。

### 1.3 审计执行摘要

- **现状四维度独立诊断**：1 Major（RB-01 setRange 竞态，reviewer 第 1 轮校准后升级）+ 4 Minor（MA-01/PF-01/PF-04/RB-02）+ 14 Note；安全性（XSS/注入/密钥）核查通过，无漏洞；11 端点 + /ws 契约全部一致。
- **方案交叉审查**：developer 诊断行号引用抽查 8 处全部属实；等级口径偏离 AGENTS.md §4.6（8 项 Major 为体验/效率优化项）——developer 已在方案 §1.6 L181 增加"严重度语义声明"消除歧义；§9.5 对六项分歧逐条回应，经复核**全部真实落地**（详见 §4.4）。
- **审计结论**：方案 PASS_WITH_NOTES（放行条件：P0 实施须落地 RB-01 竞态缓解、RB-02 summary errCb、PF-04 DOM 实测与行数控制，并补充 filter 变更场景的竞态缓解——见 §4.4 新发现 N-1）。

## 2. 现状技术审计结论（四维度独立诊断）

> 审计清单覆盖：①逻辑健壮性 ②安全漏洞 ③性能瓶颈 ④资源生命周期 ⑤异常处理 ⑥架构可维护性 ⑦重复逻辑；科研审查维度 8-11 标记 N/A（前端开发任务，非科研代码）。
> 每条问题含 10 字段：ID / 等级 / 代码位置 / 事实 / 风险推导 / 触发条件 / 影响 / 建议 / 置信度 / 是否阻塞。
> 问题统计：**1 Major + 4 Minor + 14 Note**。

### 2.1 可维护性

| ID | 等级 | 代码位置 | 事实 | 风险推导 | 触发条件 | 影响 | 建议 | 置信度 | 是否阻塞 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| MA-01 | Minor | `app.js:727-844`（pollOverview/pollAttack）、`app.js:877-881`（applyFilter） | 单文件 1006 行 IIFE 内集中数据拉取/渲染/交互/状态；connections 查询构造在 pollOverview（L770-776）与 applyFilter（L877-881）重复两遍 | 双处维护：一处改口径另一处漂移，产生"连接页与过滤后连接数据不一致"的隐性缺陷 | 后续任何对 connections 查询的修改 | 可维护性下降，口径漂移风险 | 提取 `fetchConns()` 单函数收敛；拆分为多个静态 JS 文件（embed 支持，无需构建链） | 高（静态代码比对，两段逻辑高度相似） | 否 |
| MA-02 | Note | `app.js:8`（POLL_MS=5000）、`app.js:716`（RANGE_SEC）、`app.js:851`（minGap 30000）、`app.js:788-826`（limit 10/200/500）、`app.js:221-238`（countUp 300ms）、`app.js:255`（降采样 32） | 魔法数字分散各处，部分有注释（如 RANGE_SEC/风险阈值），部分无上下文说明 | 调参需全局搜索；数值含义依赖注释记忆 | 参数调整/审计 | 维护成本 | 集中为配置对象（如 `const CFG = { pollMs:5000, ... }`） | 高 | 否 |
| MA-03 | Note | `index.html:8-385`（<style> 单块）、`index.html:423/435/436/446/456/471-473`（内联 style） | CSS 385 行全内联于 <style>，布局硬编码内联（grid-column span 2、margin-bottom、height）散落 | 样式与结构耦合，组件级调整成本高 | 布局调整 | 维护成本 | 拆分 CSS 文件（embed 支持）或至少收敛内联样式为类 | 高 | 否 |
| MA-04 | Note | `app.js:601-712`（renderSSH/renderFW/renderBans/renderSnap/renderConns/renderArchive） | 六张表渲染模式高度相似（tbody+三态+排序+逐行 createElement） | 抽象公共表格渲染器可减少重复，但各表字段/行类/转义规则不同，抽象引入间接层风险 | — | 仅重复模式，无实际缺陷 | 保守不合并或仅抽象"三态+排序"骨架（方案 P1 行级 diff 落地时评估） | 中（模式相似度客观，收益/风险需权衡） | 否 |

### 2.2 性能

| ID | 等级 | 代码位置 | 事实 | 风险推导 | 触发条件 | 影响 | 建议 | 置信度 | 是否阻塞 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| PF-01 | Minor | `app.js:939-941`（connectWS + setInterval(pollAll,5000) 恒在）、`app.js:727-844` | WS 正常时全量 5s 轮询照常执行；稳定态请求构成：pollOverview 5 个（summary/resources1h/snapshot/connections/archive，resources24h 仅首轮 sparkLoaded=false 时拉一次）+ pollAttack 7 个（top_ports/top_sources/ssh_timeline/fw_timeline/bans/ssh/fw）≈ 12 请求/5s（30d 降频时攻击轮询 30s 一次）；WS 仅更新 3 个文本字段（active-conns/disk-pct/conn-status） | 技术方案 §3.8 语义为"WS 实时更新、断线降级轮询"，实现为"WS 与轮询并存"；30d 大库下每轮含 2-8s 聚合查询（firewall/timeline 30s 节流已缓解） | 面板打开即发生；30d 视图 + 大库时 CPU 峰值 | 1C1G 上约 2.4 req/s + SQLite 查询冗余；非故障但属无效消耗 | WS 存活时降频低频端点（archive/snapshot）或按页签激活状态挂轮询；总请求数只降不升（方案 7.4 已承接，预期 5→2-3） | 高（代码静态确认） | 否 |
| PF-02 | Note | `app.js:99-121`（renderResource）、`app.js:545-598`（renderAttacks） | 全部 setOption notMerge=true；隐藏面板（display:none）对应图表每轮仍被 setOption 重绘，无可见性判断 | 浪费隐藏图表渲染；当前数据点 ≤100（1h 资源 60 点/攻击趋势 24 桶/TOP 10），ECharts 内部仍做 diff，实际开销有限 | 连接/归档页激活时总览 4 图+攻击页 3 图持续重绘 | 轻微 CPU 浪费（量级需实测） | 切页后跳过隐藏面板图表 setOption（方案 7.4 可见性门控已承接） | 中（方向真实，程度需实测） | 否 |
| PF-03 | Note | `app.js:609-618`（renderSSH）、`app.js:630-639`（renderFW）、`app.js:514`（renderEventStream box.innerHTML=''） | 每轮 tbody.innerHTML='' 后逐行 createElement（最多 200 行/表）；事件流全量重建 | 每 5s 数千 DOM 节点创建/销毁 + GC；现代浏览器量级约 1-2ms/千节点，INP 恶化需实测支撑 | 面板打开即发生 | 主线程轻微抖动 | 先实测再决定；行级 diff 复杂度高（方案 P1 排期合理，7.4） | 中（需 Performance 实测确认程度） | 否 |
| PF-04 | Minor | `app.js:826`（ssh limit=200）、`app.js:835`（fw limit=200）、`app.js:815`（bans limit=500）、`index.html:357-370`（表格布局） | 最大行数 ssh 200×7td + fw 200×8td + conn 100×6 + ban 500×4 + snap + archive 估算 DOM 元素 6000+ | 技术方案 §11.3 M3 验收要点"1 个前端页面 DOM 元素 <2000（轻量）"；当前估算超限约 3 倍 | 攻击页全量数据渲染时 | 首屏 DOM 构建与内存开销；轻量验收线超标 | 实测 DOM 数确认；若超标：攻击页默认行数限 100 + 滚动加载（方案 7.4 已承接，P0） | 中（静态估算，需浏览器实测确认） | 否 |

### 2.3 健壮性

| ID | 等级 | 代码位置 | 事实 | 风险推导 | 触发条件 | 影响 | 建议 | 置信度 | 是否阻塞 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| RB-01 | Major | `app.js:885-908`（setRange）、`app.js:806-812`（fwTimeline 回调）、`app.js:786/790/797`（pollAttack 失败标志）、`app.js:720-725`（fetchJSON 无 AbortController/序列号） | setRange 重置 state 后发出新请求；旧 range 在途响应无序列号/abort/回显校验，直接覆盖新 state（firewall/timeline 响应虽回显 range 字段但前端不校验，query.go L434） | 旧 range 的 fwTimeline/summary 迟到 → 与新 range 数据混合渲染态势条/双通道图/风险评分——**混合口径态势结论**；30d 聚合最长 30s 超时窗口（query.go L383-385，DEV-018 已实测同类聚合 2-8s），30d 视图下错误窗口最长 30s，非"短暂" | 切换时间范围后旧请求晚于新请求返回（30d 视图下旧 fwTimeline 在途 2-8s 必然晚于新 range 快响应） | 安全面板显示混合口径结论（旧范围攻击数据混入新范围），值班误读风险；自愈但窗口可达 30s | 方案 A（请求序号 state.rangeSeq + 回调校验 + firewall/timeline range 回显字段叠加校验）或方案 B（AbortController 取消旧请求）；**同时覆盖 applyFilter 变更场景**（filter 竞态同源，见 §4.4 N-1） | 高（竞态路径静态成立：旧响应晚到必然覆盖新 state） | **是**（逻辑错误影响态势结论正确性；方案 P0 已承诺修复） |
| RB-02 | Minor | `app.js:729-739`（summary 无 errCb）、`internal/api/query.go:378-386`（hFirewallTimeline 30d 放宽 30s 超时）、`internal/api/api.go:208`（hSummary 固定 5s 超时） | summary 请求未传 errCb，失败静默保留旧值；hSummary 30d 未像 hFirewallTimeline 放宽超时（30d COUNT 千万行级可能超 5s） | 30d 大库下 summary 周期 500 → KPI/迷你榜/态势条数据长期冻结且无失败指示（D-20 设计仅覆盖攻击数据源，summary 为权威源但无失败态） | 30d 范围 + 大库 | 态势数据过期展示，值班误判 | 前端 P0 补 summary errCb（summaryFailed 标志 + 全局错误横幅，方案 7.4 已承接）；后端 30d 放宽 summary 超时为 P2 建议项 | 中（30d COUNT 性能为推断，需运行确认 U-1） | 否 |
| RB-03 | Note | `app.js:325-327`（renderKPI fwEl/sshEl 无 null 防御） | fwEl/sshEl 直接赋值 className/textContent 无存在性检查（同函数其他元素均有防御） | DOM 静态存在时无实际风险；防御一致性缺失 | 未来 DOM 重构移除元素 | 抛 TypeError 中断 renderKPI 链 | 统一 null 防御 | 高 | 否 |
| RB-04 | Note | `app.js:929-935`（onclose 固定 3s 重连） | 断线重连固定 3s 无退避、无最大次数限制 | 后端长期停机时每 3s 一次握手尝试（浏览器无惩罚，资源消耗小）；重连风暴在 agent 重启瞬间多客户端同时重连 | agent 长时间离线 | 可接受；无实际故障 | 可选：指数退避（3s→30s 封顶） | 高 | 否 |
| RB-05 | Note | `app.js:858-861`（renderIf 三源全真才渲染） | 单源失败（ports 失败、sources 成功）时 renderIf 不执行 → sources 图保留旧数据直到下轮全成功；态势条已显示失败态 | 失败轮次中部分图旧数据 + 态势条失败态并存 | 攻击数据源偶发失败 | 短暂旧图展示，下轮自愈 | 已由 R-03/D-24 部分缓解；可接受，记录即可 | 高（代码路径确认） | 否 |

### 2.4 安全性

| ID | 等级 | 代码位置 | 事实 | 风险推导 | 触发条件 | 影响 | 建议 | 置信度 | 是否阻塞 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| SC-01 | —（核查通过，无缺陷） | `app.js:130-134`（escapeHtml）、各 render 函数 | 逐字段核查全部外部字符串渲染路径：username/auth_method/fingerprint/detail（L614-616）、action/chain/raw（L634-637）、type/jail（L655-656）、proto/state/ip（L672-674）、type/proto（L692-693）、month/file（L709）均经 escapeHtml；状态文本/事件流文本/态势条经 textContent（L289-316/514-536）；IP/端口/数字经 ip() 与数字拼接（无注入面）；WS system 帧 setStatus textContent（L925-927）；表格三态占位为代码常量（L150-155） | 无未转义外部数据进入 innerHTML；无敏感信息（密钥/凭据）前端存储；无外部请求注入面 | — | 无 | 保持 R-08 纪律；新增渲染字段必须走 escapeHtml/textContent | 高（全字段静态核查） | 否 |
| SC-02 | Note | `internal/web/embed.go:14-19`（Handler 无安全头） | 静态服务未设置 CSP/X-Frame-Options 等安全头 | 本机回环监听（127.0.0.1:8080）+ 无外部资源 + 无写接口场景下风险低；纵深防御缺失 | 用户改 0.0.0.0 公网暴露时（D-03 暴露面自担） | 防御纵深不足 | 可选：embed.go 增加 `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'unsafe-inline'`（style 内联需 unsafe-inline）与 X-Content-Type-Options；属后端小改动，须走独立任务与回归 | 中（风险与部署形态相关） | 否 |
| SC-03 | Note | `app.js:636`（raw title 属性完整原文） | raw 截断 60 字符展示 + title 完整原文（hover 可见） | raw 含防火墙日志原文（IP/端口/时间），hover 展示完整内容；仅本机回环场景可控 | 用户 hover raw 单元格 | 信息暴露面（本机场景低） | 维持现状或 title 也截断；由访问通道隔离兜底（技术方案 §8.2 口径） | 高 | 否 |
| SC-04 | Note | `index.html`（无 favicon link） | /favicon.ico 404（TEST-007 D-25 既有记录） | 控制台唯一 404，无功能影响 | 浏览器自动请求 | 无 | 可选：内联 data URI favicon（方案 8.3 已列为 P1 顺手项） | 高（已验证记录） | 否 |

### 2.5 契约一致性（审计重点 5）

| ID | 等级 | 位置 | 结论 |
| :--- | :--- | :--- | :--- |
| CT-01 | —（一致，无缺陷） | `app.js` fetch 路径 vs `api.go:65-78`/`query.go` | 前端使用 11/12 端点（health 未用）+ /ws，全部字段逐一核对一致：summary{active_conns,fw_events,ssh_fail,top_ports[],disk_percent}、resources{points[ts,cpu,mem,disk,net_rx_bps,net_tx_bps]}、connections{rows[ts,ev_type,proto,src_ip,src_port,dst_ip,dst_port,packets,bytes]}（前端未用 mark/src_ip6/dst_ip6，JSON 多余字段无碍）、ssh{rows[ts,src_ip,username,auth_method,result,fingerprint,detail]}、firewall{rows[ts,chain,action,proto,src_ip,src_port,dst_ip,dst_port,raw]}、top_ports{rows[dst_port,hits]}、top_sources{rows[src_ip,hits]}、ssh/timeline{rows[ts,hits]}、firewall/timeline{buckets[ts,drop,accept]}、bans{rows[ts,ip,type,jail]}、archive{rows[file,month,size_mb,gzip]}、snapshot{rows[proto,src_ip,src_port,dst_ip,dst_port,state,pid]} |
| CT-02 | Note | `ws.go:117-165` vs `docs/技术方案.md:383` | 技术方案 §3.7 定义 `attack` 帧（1s 爆发期聚合），ws.go 实际仅实现 resource/conn_stats/system/heartbeat 四类；前端不依赖 attack 帧 → 文档与实现差异，无功能影响（方案 10.3 已列入已知限制） |
| CT-03 | Note | `query.go:81-82/101-102`（src_ip6/dst_ip6 字段）vs `app.js:678-697`（renderConns） | connections 表 IPv6 字段（src_ip6/dst_ip6）后端返回但前端未渲染；IPv6 连接显示 '-:port'；技术方案 §4.1 已声明 IPv6 占比低（方案 10.3 已列入已知限制） |
| CT-04 | Note | `api.go:63-82`（HandleFunc 全方法匹配） | POST 也会执行只读查询返回 200（TEST-004 R-08 既有 Note）；前端只发 GET，无安全影响；严格 MethodNotAllowed 可作后续优化 |
| CT-05 | —（IP 边界确认） | `event.go:139-145` → `store_batch.go:81-90` → `query.go` int64 → `app.js:125-128` | IP 以 uint32 位模式经 int() 写入（0..4294967295 恒正），JSON 正数序列化；前端 `ip()` 位运算（>>>24/&255）对 uint32 全部正确；v≤0 返回 '-' 对应未知 IP（0）语义正确；**无负数/溢出问题** |


## 3. 方案约束清单（优化方案必须遵守的边界）

### 3.1 硬约束（来自任务书 + 技术方案既有承诺）

| # | 约束 | 来源 | 审计判定基线 |
| :--- | :--- | :--- | :--- |
| C-1 | 零 CDN、零外部资源 | 硬约束 1 + 技术方案 §3.8 | 新增资源必须 go:embed 本地化；禁止远程字体/图标/统计脚本；echarts.min.js 5.5.1 本地 1,030,855 B（已验证）维持或替换为体积更小的本地包；字体维持系统栈（index.html L38-39）；图标维持内联 SVG |
| C-2 | 轻量化 1C1G | 硬约束 2 + 技术方案 L33 + index.html L12（"禁止持续循环动画（1C1G 性能红线）"） | 不得默认引入重型框架（Vue/React 运行时与轻量基线冲突）；原生 JS 可拆分多静态文件（embed 兼容，无需构建链）；渲染频率保持 ≥5s 级；无持续动画；**轮询请求数只降不升**（现状 12 请求/5s 为上限基线） |
| C-3 | 数据不出 VPS | 硬约束 3 + 技术方案 §8.2/992 行 | 禁止任何外发功能（遥测/统计/外部 API/远程资源）；面板保持无写操作；"导出/分享"类功能超范围 |
| C-4 | 面板监听 127.0.0.1:8080 | 硬约束 4 + D-03 | 安全增强（CSP/安全头）需后端 `internal/web/embed.go` 配合（属后端小改动，须走开发任务与回归）；**不得引入登录/鉴权方案**（D-03 定稿）；WS Origin 白名单（ws.go L77-88）不得削弱 |
| C-5 | 架构形态 | 技术方案 §3.8（无构建工具链 + embed 打包） | 若拆分 JS/CSS 文件：embed 目录全部打包 ✓ 无兼容问题；不得引入 npm/webpack/vite；方案不得依赖"构建步骤" |
| C-6 | 契约冻结 | 后端 12 端点 + /ws 为冻结面（api.go L65-78） | 前端新交互优先复用既有参数（ssh/firewall/connections 已支持 src_ip/dst_port/action/result 过滤 ✓）；如需新端点/新字段须走独立开发任务与测试回归（方案 8.3 P2 标注"需用户拍板"合规） |
| C-7 | 既有验证资产 | TEST-006（D-23/D-24 已修复）/ TEST-007（13 项回归点） | 方案落地后必须覆盖：四页签/时间范围/TOP 联动 chip/排序/过滤/三态/WS 断线重连/窄屏无溢出/控制台零错误；**R-03/R-16 安全误报纪律**（数据源失败不得显示"无攻击记录"/正常态）必须保持；tester DOM 断言依赖的既有 id 必须保留（方案 9.3 已承诺） |
| C-8 | XSS 纪律 | R-08（escapeHtml 全覆盖） | 所有新增渲染字段必须走 escapeHtml/textContent；禁止 innerHTML 直插外部数据；新交互（如过滤输入框）输入值只作查询参数，不得回显进 DOM |
| C-9 | 动效与兼容 | DEV-019 既有纪律（index.html L68-77、L269-275） | prefers-reduced-motion 必须支持；:has() 依赖已有回退；focus-visible 保持；不得引入持续循环动画 |

### 3.2 风险预判（针对优化方案的方向性风险）

| # | 风险 | 说明 | 缓解 |
| :--- | :--- | :--- | :--- |
| R-1 | 信息架构重组回归面大 | 联动链 applyFilter→pollAttack→connections/ssh/firewall 多出口（app.js L868-882）；删/并模块（IA-3 事件流）会牵动态势条/风险评分/事件流三处数据源 | 增量式：先合并重复出口（同源一出口），再调布局；每步跑 TEST-007 回归基线（方案 3.3 采用"概览→明细"入口化而非删除，符合） |
| R-2 | 差异化刷新引入新竞态 | 分档轮询（PF-01/PF-02 方向）若按"页签激活"挂载，切换逻辑与 setRange 竞态（RB-01）叠加，状态机复杂度上升 | 一并引入请求序列号/range 回显校验（firewall/timeline 已回显 range，前端可直接用；方案 7.4 方案 A/B 已承接） |
| R-3 | ECharts 替换/按需构建 | 替换图表库需重写 baseOption/lineSeries/gauge/legend/LinearGradient（app.js L37-88/364-421）且全量回归 7 图；按需构建版需预打包（无构建链） | 方案未提议替换 ECharts（6 章仅配置层优化），符合 |
| R-4 | 表格虚拟化/分页复杂度 | 与轻量约束（C-2）冲突：虚拟化库 ~10KB+ 但逻辑复杂；1C1G 上 PF-03/PF-04 实际影响未量化 | 方案 8.3 明确"虚拟滚动不建议（YAGNI）"、采用"默认行数 100 + 滚动加载"轻量方案，符合 |
| R-5 | 新交互与后端契约 | 过滤输入框需 IP 文本→uint32 转换（前端无 `ipToUint32`）；方案 3.5/7.5 采用**表格行点击过滤**（直接复用 int64 参数）而非输入框——R-5 预审不适用（developer §9.5 声明属实） | 若未来引入输入框须含 IP 文本解析/校验函数；输入值仅作查询参数不落 DOM 回显 |

## 4. 方案交叉审查意见

> 审查对象：`docs/前端优化方案.md`。第一轮（190 行诊断版）结论见 §4.1-4.3；第二轮（704 行完整版）复核结论见 §4.4-4.5。

### 4.1 诊断事实准确性核查（第一轮，抽查结论）

- 行号引用抽查 8 处（IA-1 L409-459、IA-2 L411-421、IA-3 L491-537、VI-1 L80-110、IN-1 L581-596、PF-1 L727-782、PF-2 L99-107/L558-576、MA-1 L770-776/L877-881）**全部与代码实际一致**，无虚构证据。
- 资源事实（ECharts 5.5.1 本地 1.03MB、四层 chrome、六表三态、notMerge 全量重绘、connections 双处重复）**全部属实**（本报告 §2 独立核查结果一致）。
- 诊断结论方向（信息架构过载 + 同源多出口 + 无差别刷新 = "冗杂/不直观"根源）与用户反馈及代码事实相符，作为优化主轴成立。

### 4.2 分歧点列表（第一轮，D-1~D-6）

| # | developer 观点 | 审计观点 | 依据 |
| :--- | :--- | :--- | :--- |
| D-1 | 8 项 Major（IA-1/IA-3/VI-1/IN-1/PF-1/PF-2/PF-3/MA-1） | **等级口径偏离 AGENTS.md §4.6**：Major = "重大缺陷但非完全不可用/关键证据缺失/逻辑断裂影响结论"；8 项均为体验/效率/可维护优化项，功能完整可用（TEST-004/006/007 验证全过），无一属于"必须修复才能交付" | AGENTS.md §4.6 + 既有验证档案 |
| D-2 | IA-3：事件流"边际价值低，可收敛" | 事件流（最新 20 条跨三类时序叙事，L491-537）与攻击页明细表（检索/取证工具）**用途不同**；"冗余"应限定为"同一信息层级重复呈现"，而非"模块无用" | app.js L491-537 分组时序逻辑 + 明细表检索语义 |
| D-3 | PF-1：connections/archive/snapshot 为总览轮询"无效请求" | **connections 非无效**：它服务于连接页 5s 刷新（连接页无独立轮询源，L770-776 是 conn-table 唯一数据源）；正确处置是"按呈现位归属挂轮询"（连接页激活才拉）；archive（月级变更 5s 查）与 snapshot（20s 采集 5s 查）判断成立 | app.js L770-776 与连接页 renderConns 依赖链 |
| D-4 | PF-2/PF-3 为 Major（"开销无谓放大""INP 恶化风险"） | 方向真实但**程度未量化**：ECharts notMerge 内部仍做 diff 且各图数据点 ≤100；数千 DOM 节点创建在现代浏览器约 1-2ms/千节点量级；"INP 恶化"需 Performance 实测支撑——列为"待实测确认"而非直接 Major | 数据点规模 + ECharts diff 机制 |
| D-5 | VI-1：chrome 占用 + 态势条权重不足合并为一项 Major | 两个独立问题（chrome 纵向占用 vs 结论视觉权重）合并稍混；方向认可，建议拆两条分别跟踪 | index.html L80-110/L217-228 |
| D-6 | （遗漏）诊断未覆盖 6 项：RB-01 竞态、RB-02 summary 无 errCb、PF-04 DOM 超线、CT-03 IPv6、CT-02 attack 帧、SC-04 favicon | 前两项影响态势正确性（安全面板核心），建议补入诊断；③直接关系 C-2 轻量验收 | 本报告 §2 各条目 |

### 4.3 对方案建议部分（第一轮预审指引）

待 developer 补交优化建议时，按以下条目审查（与 §3 约束一一对应）：
1. **信息架构重组**：须说明事件流去留理由（D-2）；须保证 R-03/R-16 失败态纪律；新增/删除模块必须列出对态势条/风险评分/联动链的影响面。
2. **差异化刷新**：必须解决 RB-01 竞态（请求序列/range 回显校验）；分档频率不得低于现状关键数据 5s 基线；WS 存活时轮询降频方案须列出具体端点清单。
3. **交互增强**：须含 IP 文本→uint32 解析与非法输入处理（若引入输入框）；输入值不得 DOM 回显（C-8）。
4. **视觉再细化**：不得引入持续动画（C-2/C-9）；:has() 回退与 reduced-motion 保持；若改 KPI/事件流结构须过 TEST-007 回归基线（C-7）。
5. **可维护性重构**：拆分 JS 文件不违反 embed/无构建链约束（C-5）；connections 查询必须收敛单函数。
6. **性能项**：PF-02/PF-03 的实施前提是实测量化（D-4）；若引入行级 diff/虚拟化须先证明 1C1G 收益。

### 4.4 方案建议部分（§2-§10 完整版）复核结论

**复核方法**：对方案 §9.5 声称的六条分歧回应逐条回查代码与方案文本；对预审指引六条逐条对照；对 §2-§10 建议条款按 §3 约束清单核验。

**§9.5 六条回应真实性核对——全部属实：**

| 分歧 | developer 声称的处置 | 复核结果 |
| :--- | :--- | :--- |
| D-1 | §1.6 增加严重度语义声明（Major = 对三诉求达成度影响优先级，非 AGENTS.md 阻塞语义） | **属实**：方案 L181 已加声明；8 项 Major 修复目标排入 P0/P1（8.1/8.2） |
| D-2 | IA-3 表述修正为"同一信息层级重复呈现"，处置改为"概览→明细"入口化而非删除 | **属实**：方案 L48/L266 已修正；3.3 保留理由完整 |
| D-3 | PF-1 修正为"按呈现位归属挂轮询（连接页激活才拉）" | **属实**：方案 L137 已修正；7.4 低频档落地 |
| D-4 | 风险表补"实测前置"；行级 diff 排入 P1 并明确"保持排序/过滤逻辑不变" | **属实**：9.2 表 + 8.2 + 10.1 第 3 条 |
| D-5 | P0 改动面拆为两个独立改动点（chrome 压缩 / 态势头提权） | **属实**：8.1 CSS 行 + index.html 行 |
| D-6 | RB-01/RB-02/PF-04 补入 7.4 与 9.2（P0）；CT-03/CT-02 列入 10.3 已知限制；SC-04 favicon 列入 8.3 | **属实**：7.4 L531-538、9.2 表、10.3 L692、8.3 L589 |

**预审指引六条符合性——全部符合：**
1. IA 重组：3.2/3.3 事件流"概览→明细"入口化 + 保留理由；7.2 错误态表保持 attackDataFailed/sshTimelineOk 机制（R-03/R-16 不弱化）✓
2. 差异化刷新：7.4 三档表（高频 WS/中频 5s/低频 30s 或页签激活）+ RB-01 缓解（方案 A 请求序号 / 方案 B AbortController）+ 端点清单明确 ✓
3. 交互增强：3.5/7.5 表格行点击过滤复用既有 int64 参数（零 API 变更）；**方案未引入过滤输入框，R-5 预审（IP 解析）不适用——developer 声明属实** ✓
4. 视觉细化：7.3 动效节奏（页签 150ms 淡入、折叠 220ms 过渡、零攻击徽章去遮罩）均一次性/交互型，无循环动画；reduced-motion 关闭 ✓
5. 可维护性：8.2 `fetchConns()` 收敛双处重复（MA-01）✓
6. 性能项：PF-02/PF-03 实测前置（10.1 第 3 条性能对比）✓

**新发现（建议部分审查中补充，均非阻塞）：**

| ID | 等级 | 位置（方案） | 事实与建议 |
| :--- | :--- | :--- | :--- |
| N-1 | Note | 方案 7.4（RB-01 缓解） | 竞态缓解只覆盖 range 变更；**applyFilter 变更同样存在旧响应迟到覆盖**（旧 filter 的 ssh/fw/connections 响应晚于新 filter 响应返回时混合渲染）。建议方案 A 的请求序号同时覆盖 filter 变更（seq 在 setRange 与 applyFilter 中均自增），或对 filter 响应同样做校验 |
| N-2 | Note | 方案 3.5（表格行点击过滤） | 封禁表（ban-table）行点击 IP → applyFilter({type:'src'}) 后，bans 端点不支持 src_ip 参数（query.go L438-447 仅 range/limit），封禁表仍显示全部——chip 语义与实际过滤范围不一致。建议：封禁表行点击仅跳转攻击页并高亮，或 chip 文案注明"过滤明细（封禁表不受影响）" |
| N-3 | Note | 方案 8.1（P0 工作量） | P0 改动面（index.html DOM 重组 + app.js 刷新策略/竞态缓解/errCb/行点击过滤 + CSS 补充）1-2 人日偏乐观；工作量估计属 developer 责任，仅提示排期风险 |
| N-4 | Note | 方案 9.2 风险表 | 9.2 将 RB-01/RB-02 标为 Major 与本报告 §2.3 等级一致（RB-01 Major / RB-02 Minor——方案将 RB-02 标 Major 偏高，但不影响实施优先级 P0） |
| N-5 | Note | 方案 4.1（色板收敛） | TI.chart 6 色→4 色：方案 4.1 为前 4 色保留（仅降饱和改值）、后 2 色（#b877d9/#6ed0e0）删除——保持前 4 色顺序不变则现有索引引用（chart[1] 橙 = net Tx/disk、chart[2] 绿 = mem）无需调整；若实施时重排色序则须注意索引一致性；6.6 表已列各图优化项 |

### 4.5 与审计 §3 约束清单的符合性总评

方案 P0/P1 全部为现有技术栈内改动：零 CDN 保持（C-1 ✓）、无新框架（C-2 ✓，8.3 P2 明确"不建议"+需拍板）、无外发功能（C-3 ✓）、未触碰 WS Origin/无写操作（C-4 ✓）、无构建链（C-5 ✓）、零 API 变更（C-6 ✓，P2 标注需拍板）、保留既有 id 与 TEST-007 回归路径（C-7 ✓，10.1 承接）、XSS 纪律保持（C-8 ✓，未新增 innerHTML 直插）、动效纪律保持（C-9 ✓，7.3 全部一次性动画 + reduced-motion）。


## 5. 审计结论

| 项 | 结论 |
| :--- | :--- |
| 现状技术审计（四维度） | **1 Major（RB-01 setRange 竞态）+ 4 Minor（MA-01/PF-01/PF-04/RB-02）+ 14 Note**。安全性（XSS/注入/密钥/敏感暴露）核查通过；契约 11 端点 + /ws 全部一致。RB-01 影响态势结论正确性（混合口径窗口最长 30s），**阻塞现状基线签收**——但它是前端展示层缺陷，修复路径明确（请求序号/AbortController），且 developer 方案 P0 已承诺修复。 |
| 方案交叉审查（两轮） | **PASS_WITH_NOTES**：诊断事实准确（行号引用抽查全部属实）；等级口径偏离已由 developer 在 §1.6 声明澄清（D-1 收敛）；六条分歧回应（§9.5）复核全部真实落地；预审指引六条全部符合；新发现 N-1~N-5 均为 Note 级补充建议。 |
| 整体放行建议 | **放行（PASS_WITH_NOTES）**，附带条件：① P0 实施必须落地 RB-01 竞态缓解（含 filter 变更场景 N-1）、RB-02 summary errCb、PF-04 DOM 实测与行数控制；② P0/P1 落地后以 TEST-007 13 项回归点为基线全量回归（C-7）；③ 安全纪律（R-03/R-16/R-08）不弱化；④ 建议部分实施的基线一致性由后续 tester/auditor 复核（§4.9 一致候选基线）。 |

**审计结论：方案放行 PASS_WITH_NOTES（现状基线存在 1 项需修复的 Major——RB-01，已纳入方案 P0 修复范围；方案整体与硬约束符合，可进入实施排期）。**

## 6. 未验证假设清单（待确认，不混入问题清单）

| # | 假设描述 | 待验证方法 | 把握度 |
| :--- | :--- | :--- | :--- |
| U-1 | 30d + 大库下 hSummary 5s 超时导致 summary 周期失败（RB-02 的程度） | 30d 数据量实测（VPS 或种子库 30d+ 规模）观察 summary 响应时间 | 中（后端 30d 聚合性能为静态推断；DEV-018 已证实 firewall/timeline 30d 需 2-8s 同类查询） |
| U-2 | DOM 元素数超技术方案 §11.3 <2000 验收线（PF-04） | 浏览器运行时 `document.getElementsByTagName('*').length` 实测（全量数据渲染） | 中（静态估算 6000+，行数上限来自 app.js limit 参数） |
| U-3 | ECharts 隐藏面板重绘 + 全量 setOption 在 1C1G 上的实际开销（D-4 分歧） | Performance panel 实测（隐藏面板激活 vs 未激活对比 CPU/长任务） | 中（数据点规模小，推测开销有限但未实测） |
| U-4 | setRange 竞态（RB-01）在实际网络中的触发频率 | 网络节流（DevTools Slow 3G）+ 快速切换 range 观察态势条口径（方案 10.1 第 5 条已纳入 tester 验收路径） | 高（竞态路径静态成立，触发概率与响应时延正相关） |

## 7. 风格偏好清单（Note，不作为正式缺陷）

| # | 偏好 | 建议方向 |
| :--- | :--- | :--- |
| S-1 | `setStatus`/`setStatusError` 双函数 + state.wsMode 双状态源（app.js L30-35/L10-27） | 可统一为单一状态机（ws 状态枚举 + 渲染函数），现状可读性尚可 |
| S-2 | `renderXxx` 命名均为"渲染"，但数据源（state.*Rows）与请求函数（poll*）命名可更对称 | 如 `loadXxx`/`renderXxx` 语义对齐；纯命名偏好 |
| S-3 | index.html 注释含多轮 DEV 迭代编号历史（L9-17/L181/L269） | 可选：收敛为当前设计系统说明，历史留 git log；文档维护偏好 |

## 8. 自检结果

- 审查清单 7 项：全部覆盖（逻辑健壮性 RB-01~05/安全漏洞 SC-01~04/性能瓶颈 PF-01~04/资源生命周期：前端无文件/连接资源泄漏，ECharts 实例单页生命周期无需 dispose（N/A 项已在 §1.2 说明）/异常处理 RB-02 失败态/架构可维护性 MA-01~04/重复逻辑 MA-01/MA-04 合并评估）。
- 科研审查维度 4 项：N/A（前端开发任务，非科研代码），理由已声明。
- 每条问题含完整 10 字段（ID/等级/位置/事实/风险推导/触发条件/影响/建议/置信度/是否阻塞）✓。
- 等级使用统一标准（Blocker/Major/Minor/Note），未用旧称 ✓；阻塞性问题 1 项（RB-01 Major）已明确标记并给出修复路径 ✓。
- 风格偏好单列 §7（Note），未升级为正式缺陷 ✓；未验证假设单列 §6（待确认），未定性为缺陷 ✓。
- 候选基线 `64a82f4` 已记录；审查全程工作区干净无漂移 ✓。
- 纯只读审计 + 交付物报告写入：Git 提交项 N/A（报告归属运营官统一提交处理）。
- reviewer 第 1 轮意见（R-01~R-06）已全部整改：RB-01 升 Major（R-01）、第二轮复核完整方案并回填（R-02）、计数修正为 1/4/14（R-03）、PF-01 请求构成修正为 5+7（R-04）、R-05/R-06 已吸收（RB-03 同模式说明保留、自检表述改为核验说明）。

## 9. reviewer 反思结论

**第 1 轮（2026-08-15）**：REVISE。问题：R-01（RB-01 等级校准偏低，安全面板语境应升 Major）、R-02（审计闭环未完成——方案已更新至 704 行完整版，含 developer 对分歧的回应，报告审查对象为 190 行旧版）、R-03（Minor/Note 计数 4/12 与清单实际 5/14 不符）、R-04（PF-01 请求构成"6+6"与代码实际"5+7"不符，总数碰巧正确）、R-05/R-06（Note 级补充与自检表述）。评分 7/10。

**第 2 轮整改情况**：R-01 已整改（RB-01 升 Major，10 字段更新，§2.3）；R-02 已整改（对 704 行完整方案执行第二轮复核，§9.5 六条回应真实性全部核实、预审指引六条全部对照、新发现 N-1~N-5 补入 §4.4，§5 结论与 §9 回填）；R-03 已整改（计数统一为 1 Major + 4 Minor + 14 Note）；R-04 已整改（PF-01 构成修正为 pollOverview 5 + pollAttack 7，含首轮 13 与 30d 降频口径说明）；R-05/R-06 已吸收。

**第 2 轮 reviewer 复核结论**：PASS_WITH_NOTES。第 1 轮 2 项 Major（R-01 RB-01 升 Major、R-02 审计闭环）已整改到位并经独立抽查核实（方案 §9.5 六条回应落地属实、计数 1/4/14 与请求构成 5+7 修正准确、§9 回填完整）；本轮仅 2 项 Note 级表述瑕疵（R2-01 N-5 措辞、R2-02 措辞）——均已顺手修正；无 Blocker/Major 遗留；第 3 轮无需再复核。评分 9/10。



