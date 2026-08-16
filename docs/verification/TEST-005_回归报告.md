# TEST-005 回归报告（M3 修复回归，DEV-007）

- 测试人：B2（测试 Agent）
- 基线：commit `a7b56f0`（DEV-007 修复后冻结基线，main 分支）
- 回归日期：2026-08-14
- 环境：Windows（Go 1.26.2）+ WSL Ubuntu-22.04（Go 1.26.2 linux/amd64）；源码部署 WSL `/path/to/src`（与基线 a7b56f0 一致），二进制 `/path/to/sentry-agent/sentry-agent` 由 WSL 内 Go 构建
- 回归范围：W-01 conn_stats 相位、M-01 overrun 双通道、M-02 Origin/回环、M-03 磁盘水位首轮同步、全包健康、覆盖率抽查

## 1. 执行汇总（10 项验证）

| 用例 ID | 目标 | 结果 | 证据 |
| :--- | :--- | :--- | :--- |
| W01-1 | TestFrameConnStatsCursors 复跑（双游标/晚落库/失败不推进） | ✅ PASS（Windows + WSL Linux） | §3.1 |
| W01-2 | W-01 相位实测（30 SYN 注入 → 帧累计 vs DB 增量） | ✅ PASS（帧累计 34 == DB 增量 34，**偏差 0**） | §3.1 + evidence/m3/w01_phase.txt |
| M01-1 | health overrun_total 与 store 留痕双通道独立完整（白盒） | ✅ PASS（共享 atomic 单累加者 + API 只读 + store 单消费者） | §3.2 |
| M02-1 | TestIsLoopbackListen（9 用例含空 host） | ✅ PASS（Windows + WSL） | §3.3 |
| M02-2 | TestWSNoOrigin（严格/宽松） | ✅ PASS（Windows + WSL） | §3.3 |
| M02-3 | 运行级：0.0.0.0 无 Origin → 403、白名单 → 101 | ✅ PASS（实测 status=403 / WS 连接成功 101） | §3.3 + evidence/m3/m3_noorigin_strict.txt |
| M03-1 | TestFirstCheckLevelSync | ✅ PASS（Windows + WSL） | §3.4 |
| HB-1 | Windows 全包 go test + vet | ✅ 13 包全绿 + vet 通过 | §3.5 |
| HB-2 | WSL Linux 全包 go test + vet | ✅ 13 包全绿 + vet 通过 | §3.5 |
| CV-1 | 覆盖率抽查（api/diskmon/cmd 纯函数 §2.2） | ✅ 达标（api 100%、diskmon 100%、isLoopbackListen 100%） | §3.6 |

## 2. 回归结果

### 3.1 W-01 conn_stats 相位回归 ✅

**单测 TestFrameConnStatsCursors**（api_test.go L397-456，双环境 PASS）：
- 首轮游标 0：5 条连接（2 NEW + 2 UPDATE + 1 DESTROY）→ new=2/dest=1 ✅
- 游标推进后无新事件 → 0/0 ✅
- 晚落库 NEW（插入后旧游标）→ 计到 1（不永久排除）✅
- 跨类型互漏：NEW 插入不影响 DESTROY 游标 → dest=0 ✅
- DESTROY 晚落库（R-02）：NEW 游标已推进后新 DESTROY 仍被 DESTROY 游标计到 → dest=1 ✅
- 失败路径（DB 关闭）：ok=false 且返回值 = 入参原值（123/456）——单测验证 frameConnStats 返回值语义；**PushLoop 的"仅 ok 时推进游标"由代码审查确认**（ws.go L145-147 `if ok { lastNewID = newMax; lastDestID = destMax }`）✅

**相位实测**（m3_r04_r05_verify.sh，证据 evidence/m3/w01_phase.txt）：
- 窗口起点 DB NEW 总数：3 → 注入 30 SYN（hping3）→ 40s WS 帧收集
- **帧累计 new: 34 == DB NEW 增量 34（含背景流量）→ 偏差 0 → PASS（无低报）** ✅
- **验证语义边界（reviewer R-03 披露）**：帧 new 计数与 DB 增量**同源**（均查 connections 表），本实测验证"推送游标窗口计数之和 == DB 全量增量"（游标无漏无重）；采集端漏采由 DB 增量 34 ≥ 注入 30 间接佐证无显著漏采（若采集漏采会同步反映在两者，偏差仍为 0，故本方法不直接验证采集端）。客户端连接前背景计数由脚本容差 max(3, 5%) 吸收边界效应；本次偏差恰 0。

### 3.2 M-01 overrun 双通道独立完整 ✅（白盒）

- **counter 传递链**：main.go L96 `var overrunTotal atomic.Uint64` → L184 `RunConntrackListener(..., &overrunTotal)`（conn 模块直接累加）→ L158 `srv.SetOverrunCounter(&overrunTotal)`（API 只读展示同一 counter）
- **单消费者修复**（M-01）：API 不再有独立 AddOverrun 通道累加（api.go L106 注释"共享 atomic：conn 模块直接累加，API 只展示"），无双消费者重复计数
- **双通道独立完整**：
  - 通道 1（实时）：health 的 `conntrack_overrun_total` = 内存 atomic 值（API 只读）
  - 通道 2（持久）：store.go L255 overrun 通道 → 单写线程消费 → 落 system_events（R-10 留痕）
- **结论：两通道各自独立且完整（内存计数 + 持久留痕），无双消费者、无遗漏路径**

### 3.3 M-02 Origin/回环回归 ✅

**TestIsLoopbackListen**（main_test.go 9 用例，双环境 PASS）：
- 回环：127.0.0.1:8080 / localhost:8080 / [::1]:8080 → true ✅
- 非回环：0.0.0.0:8080 / [::]:8080 / **:8080（空 host = 监听全部接口，R-01 修复点）** / <LAN_IP>:8080 → false ✅
- 非法输入："bad" / "" → 保守判非回环 ✅

**TestWSNoOrigin**（双环境 PASS）：非回环模式无 Origin → 403；回环模式无 Origin → 非 403 ✅

**运行级实测**（m3_r04_r05_verify.sh，listen=0.0.0.0:8080）：
- 无 Origin WS 握手 → **status=403** ✅
- 白名单 Origin http://<LAN_IP>:8080 → **WS 连接成功（101 升级）** ✅
- 证据：evidence/m3/m3_noorigin_strict.txt

### 3.4 M-03 磁盘水位首轮同步 ✅

**TestFirstCheckLevelSync**（双环境 PASS）：高水位 95%（emergency）下 RunDiskMonitorWithUsage 运行 250ms（50ms ticker，实际约 5 个周期 + 首轮立即检查；测试注释"200ms/约 4 周期"为笔误，代码实际 250ms）→ disk error 告警**恰 1 条**（首轮立即检查），后续同级别周期因 lastLevel 同步被抑制（10 分钟限频）——M-03 修复点（首轮状态同步防重复告警）✅

### 3.5 全包健康 ✅

| 环境 | go test ./... | go vet ./... |
| :--- | :--- | :--- |
| Windows | 13 包 ok（cmd 新增 main_test.go） | ✅ 通过 |
| WSL Linux | 13 包 ok（含 //go:build linux 文件） | ✅ 通过 |

### 3.6 覆盖率抽查（§2.2 口径）✅

| 包 | 纳入纯函数 | 加权 | 达标 |
| :--- | :--- | :--- | :--- |
| api | rangeSeconds 100 / parseUintParam 100 / urlPathEscape 100 / ipToDotted 100 / **frameConnStats 100（新增修复函数）** | 100% | ✅ |
| diskmon | Classify 100 | 100% | ✅ |
| cmd | **isLoopbackListen 100**（新增；main 其余为 IO/信号编排豁免） | 100% | ✅ |

（frameSystem 0% 为 DB IO 豁免类，与 TEST-004 口径一致；覆盖证据：`evidence/m3/m3fix_cover.txt`——rangeSeconds/parseUintParam/urlPathEscape/ipToDotted/frameConnStats/Classify/isLoopbackListen 全 100%。）

## 4. 缺陷清单

**本次回归引入的新缺陷：0 项。既有失败：0 项（双环境单测全绿）。** W-01/M-01/M-02/M-03 修复均通过单测 + 实测回归；无新增缺陷。

## 5. 未覆盖项与原因

| 未覆盖项 | 原因 |
| :--- | :--- |
| W-01 相位实测在高峰值速率（flood 级）下的对账 | 零丢失语义由 store 层排空验证（TEST-002/003）覆盖；相位对齐关注低报，30 SYN 注入 + 背景流量偏差 0 已证 |
| M-01 运行级 overflow 实测 | WSL conntrack 溢出难自然触发（R-10 留痕路径已由 TEST-002 V3 实测 system_events 覆盖）；白盒确认传递链完整 |
| M-02 浏览器端 CORS 全链路 | httptest 单测 + curl/websockets 运行级实测覆盖；浏览器场景 VPS 复验 |

## 6. 结论

**整体结论：PASS（基线 `a7b56f0` 放行）**

- 验收 1（W-01 相位回归）：✅ PASS（偏差 0；单测含晚落库/失败路径/跨类型互漏）
- 验收 2（M-01/M-02/M-03 回归）：✅ 全部通过（白盒 + 单测 + 运行级实测）
- 验收 3（双环境全包）：✅ 13 包全绿 + vet 双环境通过
- 验收 4（回归报告结论明确）：✅ **M3 整体闭环，放行 M4**

无 Blocker/Major 遗留；无新缺陷；DEV-007 四项修复全部回归通过。

## 7. 交付物清单

- 回归报告（本文件）：`docs/verification/TEST-005_回归报告.md`
- 执行证据：`docs/verification/evidence/m3/w01_phase.txt`（相位偏差 0）、`m3_noorigin_strict.txt`（403/101）、`m3fix_cover.txt`（覆盖率，TEST-005 补档）
- Git：test 类型提交
