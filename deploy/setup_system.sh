#!/bin/bash
# 系统配套配置写入（方案 6.5.1/6.5.2/7.1）：journald RateLimit + 4G 上限、
# sshd LogLevel VERBOSE、logrotate rotate 9999——全部带回读校验
# 用法：sudo bash setup_system.sh [--apply]
# 默认 dry-run 显示将写入内容；--apply 实际写入
set -u
APPLY=0
[ "${1:-}" = "--apply" ] && APPLY=1

do_write() { # do_write <文件> <内容>——dry-run 或实际写入
  if [ "$APPLY" = 1 ]; then
    mkdir -p "$(dirname "$1")"
    printf '%s\n' "$2" > "$1"
    echo "[已写入] $1"
  else
    echo "[dry-run] $1 <- $2"
  fi
}

echo "===== 系统配套配置（方案 6.5.1/6.5.2/7.1） ====="

# 6.5.1 journald：Storage=persistent + RateLimit 调高（R-11）+ SystemMaxUse=4G（7.1）
do_write "/etc/systemd/journald.conf.d/99-sentry.conf" \
'[Journal]
Storage=persistent
RateLimitIntervalSec=5s
RateLimitBurst=5000
SystemMaxUse=4G
Compress=yes'

# 6.5.2 sshd：LogLevel VERBOSE（公钥指纹，R 指纹字段）
do_write "/etc/ssh/sshd_config.d/99-sentry.conf" \
'LogLevel VERBOSE'

# 7.1 logrotate：fail2ban 与 syslog 日志轮转不删除（rotate 9999 保留历史档，R-12）
do_write "/etc/logrotate.d/sentry-f2b" \
'/var/log/fail2ban.log {
    daily
    rotate 9999
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        /usr/bin/systemctl kill -s HUP fail2ban.service 2>/dev/null || true
    endscript
}'

if [ "$APPLY" = 1 ]; then
  echo "--- 应用后重载与回读校验 ---"
  systemctl daemon-reload 2>/dev/null
  # F-07（DEV-009）：journald 重启失败显式告警（不再静默）
  if systemctl restart systemd-journald 2>/dev/null; then
    echo "[OK] journald 已重启"
  else
    echo "[警告] journald 重启失败（systemctl status systemd-journald 排查）——新配置可能未生效"
  fi
  sshd -t >/dev/null 2>&1 && systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null
  echo "--- 回读 journald 配置 ---"
  grep -E 'RateLimitBurst|SystemMaxUse' /etc/systemd/journald.conf.d/99-sentry.conf 2>/dev/null || echo "[FAIL] journald 配置回读失败"
  echo "--- 回读 sshd 配置 ---"
  sshd -T 2>/dev/null | grep -i loglevel | head -1
  echo "--- 回读 logrotate ---"
  logrotate -d /etc/logrotate.d/sentry-f2b 2>&1 | head -2
else
  echo "--- dry-run 完成：执行 sudo bash setup_system.sh --apply 实际写入 ---"
fi
echo "===== 系统配置完成 ====="
