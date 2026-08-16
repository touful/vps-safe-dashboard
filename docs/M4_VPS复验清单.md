# M4 VPS 复验清单（用户自行部署后逐项执行，结论回传）

- 目的：将本地（WSL/Docker Desktop）无法完成的验证项在真实 VPS（1C1G 基线）闭环
- 前置：部署完成（deploy/deploy.sh）且健康检查通过
- 每项含：操作步骤与判定标准；结果记录：PASS / FAIL / 备注

## P0-1 面板访问通道红线确认（AUD-VPS-001 §6 P0-1）

- 操作：确认面板访问方式为 SSH 隧道或带鉴权反代（Basic Auth/客户端证书）；核对 `/etc/sentry-agent/config.json` 的 `web.listen` 仍为 127.0.0.1:8080（未改 0.0.0.0）
- 判定：无公网直曝路径（含反代无鉴权）；`web.listen` 保持回环监听；WS Origin 白名单与访问方式一致（见部署手册 WS Origin 说明）

## P0-2 数据目录权限收权核验（AUD-VPS-001 §6 P0-2 / VS-01）

- 操作：`chmod 700 /var/lib/sentry-agent && chmod 600 /var/lib/sentry-agent/state.db` 后执行 `ls -ld /var/lib/sentry-agent && ls -l /var/lib/sentry-agent/state.db`
- 判定：目录权限 drwx------（0700）、state.db -rw-------（0600）；archive 下归档副本（.db.gz）同受目录 0700 保护（无独立 0644 暴露）

## P0-3 宿主防火墙默认策略确认（AUD-VPS-001 §6 P0-3 / VS-14）

- 操作：`nft list ruleset | head` 或 `iptables -S INPUT | head`，核对默认策略与开放端口清单；确认规则已持久化（nftables 落盘配置/iptables-persistent）
- 判定：INPUT 默认策略为 DROP（或存在兜底全拒绝规则）；仅 22（+面板隧道源 IP）开放；重启后规则仍生效

## P0-4 SSH 加固确认（AUD-VPS-001 §6 P0-4 / VS-07）

- 操作：`grep -E '^PasswordAuthentication|^PermitRootLogin' /etc/ssh/sshd_config`；`fail2ban-client status sshd`；`systemctl is-active ssh fail2ban`
- 判定：PasswordAuthentication no（仅密钥认证）；fail2ban sshd jail active（Banned IP 列表非空或随爆破增长）

## V-01 B5 降级端到端（ss 快照 diff 近似通道）

- 操作：`lsmod | grep nf_conntrack` 若可卸载则 `modprobe -r nf_conntrack_netlink`（不可卸载则临时用无 conntrack 的容器网络命名空间模拟）→ 重启 agent → 观察 `system_events` 出现"降级为 ss 快照 diff 近似模式（B5）"→ 制造连接活动
- 判定：system_event 留痕存在；面板连接事件有 NEW/DESTROY 近似事件产出（近似通道标注）；恢复 conntrack 后重启 agent 回到主通道

## V-02 真实 sshd 暴力破解计数（A-04 计数比对）

- 操作：配置 sshd LogLevel VERBOSE（setup_system.sh 已做）→ 从另一主机用 hydra/脚本对 22 端口发起 1000 次失败登录 → 比对 `ssh_attempts` 表 result=0 行数 vs 实际尝试数（journald RateLimit 5s/5000 已调高）
- 判定：计数一致（±journal 侧确认无丢行）；面板"SSH 失败时间线"呈现攻击曲线

## V-03 容器形态复测（--network host + NET_ADMIN，cap_drop ALL 后必验）

- 操作：宿主侧先确认工具可用（`command -v conntrack`；Debian/Ubuntu 未装则 `apt install -y conntrack`，RHEL 系 `yum install -y conntrack-tools`）；随后宿主侧 `conntrack -E -p tcp`（conntrack-tools 未装入容器镜像，容器内无此命令）与面板/API 连接事件（`/api/v1/connections` 与 health 通道状态）对照；agent 自身的 netlink 订阅即验证对象；`conntrack -L` 只读查询在宿主侧执行
- 判定：容器 agent 采集的连接事件与宿主侧 `conntrack -E` 一致（抽样）——cap_drop: ALL 落地后，本条同时验证纯 NET_ADMIN 能力面下 conntrack 正常（DEV-VPS-001 C1 风险确认项）

## D-09 容器能力面专项验证（AUD-VPS-001 §8 U-1，**需 VPS 实测**）

- 操作：区分执行用户与工具可用性，分别尝试并记录：①`docker exec --user root sentry-agent ip link add dummy-test type dummy` 与 `ip route add 198.51.100.0/24 dev lo`——root 继承容器 bounding set 中的 NET_ADMIN，是能力面的真实触达路径（iproute2 已装入镜像）；验证后清理 `ip link del dummy-test` 与 `ip route del 198.51.100.0/24 dev lo`（ip link add 失败时跳过 del 步骤）；②`docker exec --user 1000:1000 sentry-agent ip link add dummy-test2 type dummy`——容器默认 USER 1000 无 effective cap，预期 EPERM，**该结果与非 root 身份有关，不作为能力面证据**；若②意外成功，记录事实并排查部署配置（如误配 privileged）且清理 dummy-test2；③`docker exec sentry-agent nft add rule ...` 预期 command not found（镜像未装 nftables 包）——**命令缺失 ≠ cap 受限**，单独记录
- 判定：① root 执行预期**成功**（NET_ADMIN + host netns 具备修改宿主网络接口/路由能力）→ R-14 能力面风险由推断升级为实测确认，须回写技术方案 8.1 与审计结论；若①意外失败，记录受限证据并排查原因；②记录 EPERM 事实（仅印证非 root 无 effective cap）；③记录"命令不存在"事实

## read_only + tmpfs 运行时行为验证（VS-13/C2，**需 VPS 实测**）

- 操作：compose 落地（read_only: true + tmpfs /tmp:16m、/home/sentry:1m）后运行 ≥24h；`docker logs sentry-agent` 检索 "Read-only file system" 类错误；确认 SSH/fw/f2b 三通道数据正常；随后触发一次 30d 大范围聚合查询（面板 30d 视图），聚合后 `docker exec sentry-agent df -h /tmp` 观测占用
- 判定：三通道数据完整（journalctl 子进程在只读 rootfs 下工作正常）；无 rootfs 写失败告警；30d 聚合后 /tmp 占用未达 16MB 上限（若达上限，调大 tmpfs size 并回传运营官）；/home/sentry 无写失败迹象

## V-04 netlink Drops 计数（R-10 双通道留痕）

- 操作：SYN flood 压测（hping3 --flood 到未监听端口）→ 观察 health 的 conntrack_overrun_total 非零 + system_events 溢出留痕
- 判定：overrun 计数 >0（验证 /proc/net/netlink Drops 路径在标准内核生效——WSL2 未观测到的问题在 VPS 复核）；溢出后 agent 自动重启恢复（R-10 恢复路径）

## V-05 外部源 DROP 事件（V1 步骤 1 真实外部源复测）

- 操作：宿主机加 `iptables -A INPUT -p tcp --dport 9999 -j DROP`（或 nft 等价）→ 从外部主机向 9999 发包 → 观察 conntrack NEW 事件与 connections 表
- 判定：被 DROP 的包产生 NEW 事件（V1 轮 A 结论在标准内核复核）；面板连接事件可见

## V1b-1 root 免 cap-add 行为

- 操作：`docker run` 不带 `--cap-add=NET_ADMIN`（root 容器）→ 观察 conntrack 事件是否可见
- 判定：记录行为（可见则 6.4.2 备注可简化；不可见则保持 cap-add 必需）；结论回写方案 6.4.2/8.1（R-14）

## V1b-2 journal 挂载验证

- 操作：compose 挂载 /var/log/journal 与 /etc/machine-id → 检查 `journalctl -f` 备选路径（当前实现为 journalctl 子进程，容器内无 journalctl 二进制时的行为记录）；纯 Go 解析器（M4 前未实现）的挂载路径预留
- 判定：SSH/fw 通道有真实数据（journald 源）；记录容器内 journal 读取权限（systemd-journal 组 GID 匹配）

## fail2ban 真实库 bans 表联调

- 操作：触发真实封禁（`fail2ban-client set sshd banip <IP>` 或真实暴力破解触发）→ 观察面板封禁记录（ban_events 落库）与 f2b 查询（QueryBanned 无告警）
- 判定：ban/unban/found 事件正确；QueryBanned 读取 bans 表成功（无"库结构兼容性"告警）；面板封禁列表与 `fail2ban-client status sshd` 一致

## fail2ban.sqlite3 WAL 一致性检查（AUD-VPS-001 §8 U-8，**需 VPS 实测**）

- 操作：宿主侧 `sqlite3 /var/lib/fail2ban/fail2ban.sqlite3 "PRAGMA journal_mode;"` 查看 journal 模式；若为 WAL，检查只读挂载（仅挂主库文件）下容器侧 QueryBanned 是否有滞后/不一致（对照 `fail2ban-client status sshd` 的 Banned IP 集合），并确认容器侧 f2b 查询无 SQLITE_BUSY 告警（f2b.go 只读 DSN 未设 busy_timeout，fail2ban 写库瞬间可能报错，限频 5min 告警）
- 判定：记录 journal_mode 实值（delete/wal）；WAL 模式下列出一致性结论（主库文件只读挂载时 WAL 未 checkpoint 的滞后范围）与是否需调整挂载方式（如加挂 -wal 文件或改挂副本）；结论回传运营官决定是否需代码/部署侧调整

## 1C1G 真实硬件资源实测（E-01~E-03）

- 操作：agent 运行 24h，`top`/`ps` 采样（10s 间隔）记录 CPU/RSS；`docker stats sentry-agent` 对照
- 判定：采集端 RSS <70MB、CPU 典型 <2%（方案 12.5 E-01/E-02）；全栈（含 fail2ban）记录入档对照 5.1（E-03）

## 大库建索引耗时

- 操作：制造大库（压测或正常积累至百万行 connections）→ 重启 agent → 观察启动时 `CREATE INDEX IF NOT EXISTS` 的耗时（或手动 `sqlite3 state.db "CREATE INDEX..."` 计时）
- 判定：耗时记录（预期秒级~分钟级）；启动超时兜底 60s 内完成（否则需评估离线建索引策略）

## M-01 overrun 非零累加压测（AUD-005 条件①）

- 操作：SYN flood 高强度压测（超过 8MB netlink 缓冲上限的爆发速率）→ 观察 health `conntrack_overrun_total` 持续累加（非零）且与 system_events 溢出留痕条数一致性
- 判定：overrun_total >0 且单调递增；health 计数与 store 留痕双通道各自完整（M-01 修复验证）；压测后 agent 无崩溃

## V-06 防火墙 action 口径（DEV-009 M4B-01 放行条件）

- 操作：`setup_firewall.sh` 生成规则后，`journalctl -k | grep SENTRY_FW | head -5` 抽查日志前缀，确认格式为 `SENTRY_FW:<chain>:<action> `（如 `SENTRY_FW:input:drop `）；随后检查面板/API `GET /api/v1/attacks/top_ports?range=1h` 的 rows 非空
- 判定：日志前缀含 `<chain>:<action> ` 结构；top_ports 返回非空（该接口仅统计 action='drop' 事件，rows 非空即隐含 drop 事件生效；R-08 措辞修订）

## V-07 setup_firewall 幂等与回滚（DEV-009 F-01 放行条件）

- 操作：连续执行 `setup_firewall.sh` 两次 → 对比 SENTRY_FW 规则数（应不变，第二次输出"幂等：跳过插入"）；随后 `setup_firewall.sh --rollback` → 再对比（应归零）且原有 drop 规则保留
- 判定：重复执行规则数不变（幂等）；回滚精确删除全部 SENTRY_FW 规则且不误删用户规则

## V-08 iptables 首规则即 DROP 场景（DEV-009 M4B-02 放行条件）

- 操作：iptables-legacy 环境（C-07 判定为 iptables 时）构造"INPUT 链首条规则即 DROP"（如 `iptables -I INPUT -p tcp --dport 8888 -j DROP`）→ 执行 `setup_firewall.sh` → `iptables -S INPUT` 回读
- 判定：LOG 规则位于 DROP 规则之前（首条规则即 DROP 时 LOG 编号为 1、DROP 为 2）；触发流量后内核日志含 `SENTRY_FW:input:drop `（LOG 在 DROP 前生效）

---

## 复验结果记录

| 项 | 结果 | 备注 |
| :--- | :--- | :--- |
| P0-1 | | |
| P0-2 | | |
| P0-3 | | |
| P0-4 | | |
| V-01 | | |
| V-02 | | |
| V-03 | | |
| V-04 | | |
| V-05 | | |
| V-06 | | |
| V-07 | | |
| V-08 | | |
| V1b-1 | | |
| V1b-2 | | |
| fail2ban bans | | |
| f2b WAL | | |
| D-09 | | |
| read_only/tmpfs | | |
| 1C1G 资源 | | |
| 建索引耗时 | | |
| overrun 压测 | | |

完成人/日期：＿＿＿＿＿＿＿＿＿＿
