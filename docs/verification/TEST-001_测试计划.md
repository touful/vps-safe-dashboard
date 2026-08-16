# TEST-001 测试计划（M1 里程碑 Q3 独立验证）

- 测试人：B2（测试 Agent）
- 基线：commit `9e4e3b2`（工作区仅 AGENTS.md 未跟踪，不影响受测代码）
- 日期：2026-08-13
- 环境：Windows（Go 1.26.2 单测/交叉编译）+ WSL Ubuntu-22.04（内核 6.18.33.2-microsoft-standard-WSL2，集成实测）

## 1. 测试范围与用例清单

| 用例 ID | 目标 | 验证方法 | 验收口径 |
| :--- | :--- | :--- | :--- |
| UT-01 | 全包单元测试通过率 | `go test -count=1 ./...` | 无失败 |
| UT-02 | 覆盖率（全语句口径） | `go test -cover ./...` + `cover -func` | 记录数字 |
| UT-03 | 覆盖率（可测纯函数口径） | 从 cover -func 中筛 parse/纯转换函数 | ≥80% |
| FT-01 | M-01 资源采集字段完整性与采样间隔 | agent 运行 + 输出解析：字段完整性、ts 间隔 5s±1s | 字段齐全；间隔均值≈5s，空洞=0 |
| FT-02 | M-02 连接监听与 conntrack -E 一致性 | 同窗口 conntrack -E 对照 + nc 产生 TCP 流 | 五元组/事件类型匹配（抽样） |
| FT-03 | M-03 SSH journald 模式解析 | systemd-cat 注入标准 sshd 行（Failed/Accepted/invalid user） | 行数一致、字段正确 |
| FT-04 | M-03 SSH rsyslog 模式（B1 降级） | 写 auth.log 带 syslog 前缀行，agent 以 rsyslog 源运行 | 正确解析 |
| FT-05 | M-04 防火墙解析 | iptables LOG（SENTRY_FW 前缀）+ hping3 触发，比对 DPT 口径 | 前缀过滤正确、DPT 提取正确 |
| FT-06 | M-05 fail2ban 解析 | 写测试 fail2ban.log（Ban/Unban/Found） | 三类型解析正确 |
| FT-07 | B5 降级（ss 快照 diff） | 单测（diffSnapshots 100%）+ 触发链代码审查 + 条件允许时实测 | 语义验证（首帧全量 NEW） |
| CF-01 | 配置：间隔 <5s 拒绝 | 非法配置运行 agent | 退出码非 0 + 明确错误 |
| CF-02 | 配置：未知字段行为 | 带未知键配置运行 | 记录行为（默认忽略或报错） |
| CF-03 | 配置：缺失必填项 | 配置文件不存在 / 关键项缺失 | 明确错误 |

## 2. 执行顺序

1. UT-01/02/03（Windows，已完成单测通过，补覆盖率口径分析）
2. FT-01~FT-06（WSL 集成，单脚本多通道注入）
3. FT-07（单测证据 + 触发链审查；实测条件评估）
4. CF-01~03（WSL 运行基线二进制）
5. 缺陷清单 + 报告

## 3. 环境准备

- WSL Ubuntu-22.04：sudo root（密码由测试者本地保管，仅 sudo -S 使用，不改动）
- 工具：conntrack v1.4.6、hping3、iptables（nf_tables 后端）、ss、journalctl 均已确认存在
- 基线二进制：Windows 交叉编译（GOOS=linux GOARCH=amd64）→ `/path/to/test_m1/sentry-agent`
- 已知环境限制：WSL2 下 veth 跨 netns 流量不产生主 netns conntrack 事件（V1 报告 2.3 轮 B），本次 M-02 对照采用本机流量场景；Docker Desktop 容器（--network host）作为容器形态补充

## 4. 覆盖目标

- 关键路径：五通道采集主链路、配置校验、B1/B5 降级入口
- 风险场景：WSL 环境差异（A-02）、DPT 口径（A-05/C-03）、R-03 配置下限
- 科研维度：N/A（非科研任务）
