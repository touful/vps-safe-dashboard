-- dev030_cleanup_internal_fw.sql
-- DEV-031 优化②（B.2.4）：一次性清理存量内网来源防火墙事件（按需手动执行，非自动）。
--
-- 背景：升级启用 fw.exclude_internal 后，新采集事件自动排除内网/自身来源；但
-- 存量 firewall_events 已含历史内网事件（如 NPM 容器 172.19.0.2、阿里云 CGNAT
-- 100.100.30.25 来源），面板统计仍会包含它们。
--
-- 使用前提（重要）：
--   1) 先停止 agent（避免写入竞争）：docker compose -f deploy/docker-compose.yml stop sentry-agent
--   2) 备份主库：cp /var/lib/sentry-agent/state.db /var/lib/sentry-agent/state.db.bak.$(date +%F)
--   3) 执行：sqlite3 /var/lib/sentry-agent/state.db < scripts/dev030_cleanup_internal_fw.sql
--      （无 sqlite3 CLI 时可用 python3 sqlite3 模块逐条执行）
--   4) 重启 agent：docker compose -f deploy/docker-compose.yml start sentry-agent
--
-- 清理范围：仅按 src_ip 命中内置默认内网网段（与采集层过滤列表一致，reviewer R-05：
-- DST 不参与存量清理，与默认 SRC 过滤语义一致）；IPv6 行（src_ip=0）不受影响。
-- 幂等：重复执行无副作用（行已删）。
-- 可选：删除前先统计影响行数（去掉 DELETE 前的注释即可）。

-- SELECT COUNT(*) FROM firewall_events WHERE src_ip BETWEEN 0x7F000000 AND 0x7FFFFFFF;   -- 127.0.0.0/8 回环
-- SELECT COUNT(*) FROM firewall_events WHERE src_ip BETWEEN 0x0A000000 AND 0x0AFFFFFF;   -- 10.0.0.0/8
-- SELECT COUNT(*) FROM firewall_events WHERE src_ip BETWEEN 0xAC100000 AND 0xAC1FFFFF;   -- 172.16.0.0/12
-- SELECT COUNT(*) FROM firewall_events WHERE src_ip BETWEEN 0xC0A80000 AND 0xC0A8FFFF;   -- 192.168.0.0/16
-- SELECT COUNT(*) FROM firewall_events WHERE src_ip BETWEEN 0x64400000 AND 0x647FFFFF;   -- 100.64.0.0/10 CGNAT
-- SELECT COUNT(*) FROM firewall_events WHERE src_ip BETWEEN 0xA9FE0000 AND 0xA9FEFFFF;   -- 169.254.0.0/16 链路本地
-- SELECT COUNT(*) FROM firewall_events WHERE src_ip BETWEEN 0xE0000000 AND 0xEFFFFFFF;   -- 224.0.0.0/4 组播

DELETE FROM firewall_events WHERE src_ip BETWEEN 0x7F000000 AND 0x7FFFFFFF;   -- 127.0.0.0/8
DELETE FROM firewall_events WHERE src_ip BETWEEN 0x0A000000 AND 0x0AFFFFFF;   -- 10.0.0.0/8
DELETE FROM firewall_events WHERE src_ip BETWEEN 0xAC100000 AND 0xAC1FFFFF;   -- 172.16.0.0/12
DELETE FROM firewall_events WHERE src_ip BETWEEN 0xC0A80000 AND 0xC0A8FFFF;   -- 192.168.0.0/16
DELETE FROM firewall_events WHERE src_ip BETWEEN 0x64400000 AND 0x647FFFFF;   -- 100.64.0.0/10
DELETE FROM firewall_events WHERE src_ip BETWEEN 0xA9FE0000 AND 0xA9FEFFFF;   -- 169.254.0.0/16
DELETE FROM firewall_events WHERE src_ip BETWEEN 0xE0000000 AND 0xEFFFFFFF;   -- 224.0.0.0/4
