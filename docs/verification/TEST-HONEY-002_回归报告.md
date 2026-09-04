# TEST-HONEY-002 凭据字典与 mssql 明文还原回归报告

- 基线：`e8e06e9`（main；DEV-HONEY-002 功能提交 `82808d1`，部署链 `1efd38c`~`ad6a999`，生产镜像 sentry-agent:2.2.1 = 46b9425a2baa）
- 日期：2026-09-03
- 结论：**PASS_WITH_NOTES**（2 Note：公网凭据端点无认证待用户裁定、前端协议下拉为静态清单未纳入单一来源）
- 测试脚本：`scripts/dev_honey_creds_e2e.py`（已入库）

## 1. 任务范围

回归 DEV-HONEY-002：mssql TDS 混淆密码明文还原（nibble-swap + XOR 0xA5 可逆，impacket 双源交叉验证）、凭据字典去重聚合端点 /api/v1/honeypot/creds、三格式导出端点 /api/v1/export/creds（csv/pairs/passwords）、前端凭据字典卡、VPS 生产部署（蜜罐 10 端口启用 + 防火墙放行）与公网端到端验证。

## 2. 执行验证

### 2.1 单元与协议级测试（已验证）

| 项 | 证据 |
| :--- | :--- |
| TestDeobfuscateTDSPassword / Rejects | PASS（Python 独立实现生成混淆向量与 impacket encryptPassword 同构交叉验证；先 XOR 后 swap 运算顺序经向量实证——swap 与 XOR 0xA5 不可交换；畸形输入拒绝：空/奇数字节/非 ASCII 可打印） |
| TestMSSQLCapture / DeobfFallback | PASS（协议级：真实混淆向量 "P@ssw0rd!" 还原明文捕获 + extra 注明已还原；畸形混淆字节回退 hex "01a402a3" + extra 注明还原失败） |
| TestHoneypotCredsAgg | PASS（8 条种子去重 6 组；count/src_ip_cnt/first/last；kind 分类 plaintext/hash/none + mssql 还原失败降级 hash；proto 过滤） |
| TestExportCredsFormats | PASS（pairs 仅明文且 count 降序、不含摘要条目；passwords 跨协议去重；csv 表头 + kind 标注；非法 format 400；缺时间窗 400） |
| 全量回归 | `go test ./...` 17 包全绿（多轮执行） |

### 2.2 本地端到端集成（已验证）

`scripts/dev_honey_creds_e2e.py` 真实客户端模拟攻击 7 协议 10 连接 → **19/19 断言全过**：

- 去重聚合：telnet root/toor2025 ×3 连接聚 count=3、ftp ×2 聚 count=2；首见/最近时间戳有效；
- kind 分类：telnet/ftp/redis/postgres plaintext、mysql hash、mssql sa/P@ssw0rd! **还原明文** plaintext、memcached none；
- 导出：pairs 5 行含全部明文凭据且不含 mysql 摘要；passwords 跨协议去重无重复行；csv 表头 + mssql 明文条目 + mysql hash 条目；非法 format 400。

### 2.3 生产部署与公网端到端（已验证）

| 项 | 证据 |
| :--- | :--- |
| 蜜罐 10 端口监听 | VPS `ss -tln` 10/10（ftp:21、telnet:23、smb:445、mssql:1433、postgres:5432、mysql:3306、rdp:3389、redis:6379、memcached:11211、mongodb:27017） |
| 防火墙放行 | `setup_firewall.sh` 配置驱动插入 SENTRY_HONEYPOT ACCEPT（DROP 前），nft ruleset 确认在位 |
| 公网攻击模拟 | 本机 → 公网 6 协议全到达（含低端口 21/23，云安全组已放行）：telnet/ftp/redis/postgres 明文捕获、mysql hash、mssql VpsSql#2025 还原明文 |
| 字典与导出 | /honeypot/creds 6 组（5 plaintext + 1 hash）；pairs/passwords 导出内容逐行核对一致 |
| 前端 | 生产面板 DOM 断言：凭据字典卡渲染、去重 6 组（明文 5）、类型徽标正确、密码默认遮蔽点击显示（浏览器实测截图） |
| 真实外部流量 | 上线即捕获外部扫描：37.27.141.182 探测 rdp；次日字典累计 198 组去重凭据（真实爆破流入） |

### 2.4 部署链缺陷修复（本基线内闭环）

低端口绑定 permission denied（runc 对 --user 1000 + --cap-add 不置入进程 effective 集，host 网络不可改全局 sysctl）→ Dockerfile `setcap cap_net_bind_service=+ep` 文件能力（与 no-new-privileges 互斥，compose 已移除 NNP 并留档评估）；镜像构建 GOPROXY（goproxy.cn）；部署脚本 CRLF（.gitattributes eol=lf）；聚合端点冷启动超时分档（aggTimeout 24h/30d 放宽）。

## 3. Note 与遗留

1. **公网凭据端点无认证**：safeboard.touful.cn 面板整体公网可访问，/api/v1/honeypot/* 与 /api/v1/export/creds 随之暴露（内容为攻击者失败尝试凭据，不含本机真实凭据）。README 已加披露，建议反代层加 Access List——待用户裁定。
2. **协议下拉静态例外**：index.html 的 10 协议 option 为静态内嵌资源，未纳入 honeypot.ProtoKinds 单一来源（后端清单已单一化并有守卫测试，前端属已知例外）。
