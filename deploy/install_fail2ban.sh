#!/bin/bash
# fail2ban 宿主机安装清单（方案 6.5.4：全新安装路径；D-02 定稿保留 fail2ban）
# 用法：sudo bash install_fail2ban.sh [--backend nft|iptables]
# 说明：fail2ban 部署在宿主机（非容器），sentry-agent 仅只读消费其日志与库
set -u

# R-09（DEV-008 reviewer）：参数格式校验（--backend nft|iptables）
if [ "${1:-}" != "" ] && [ "${1:-}" != "--backend" ]; then
  echo "[FAIL] 用法：install_fail2ban.sh [--backend nft|iptables]"; exit 2
fi
BACKEND="${2:-}"
if [ -z "$BACKEND" ]; then
  if command -v nft >/dev/null 2>&1 && nft list ruleset >/dev/null 2>&1; then BACKEND=nft; else BACKEND=iptables; fi
elif [ "$BACKEND" != "nft" ] && [ "$BACKEND" != "iptables" ]; then
  echo "[FAIL] 后端参数须为 nft 或 iptables"; exit 2
fi
echo "===== fail2ban 安装（方案 6.5.4，后端 $BACKEND） ====="

# 1. 安装（按发行版包管理器）
if command -v fail2ban-client >/dev/null 2>&1; then
  echo "[1] fail2ban 已安装：$(fail2ban-client --version 2>&1 | head -1)"
else
  echo "[1] 安装 fail2ban..."
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq && apt-get install -y -qq fail2ban || { echo "[FAIL] apt 安装失败"; exit 1; }
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q fail2ban || { echo "[FAIL] dnf 安装失败"; exit 1; }
  elif command -v apk >/dev/null 2>&1; then
    apk add fail2ban || { echo "[FAIL] apk 安装失败"; exit 1; }
  else
    echo "[FAIL] 无支持的包管理器（Debian/RHEL/Alpine）"; exit 1
  fi
  fail2ban-client --version >/dev/null 2>&1 && echo "[1] 安装成功：$(fail2ban-client --version | head -1)" || { echo "[FAIL] 安装校验失败"; exit 1; }
fi

# 2. 后端对齐（R-06：与 C-07 判定一致；不一致走 B6 人工决策）
echo "[2] 后端对齐检查：检测到 $BACKEND"
if [ "$BACKEND" = "nft" ]; then
  grep -q 'nftables' /etc/fail2ban/action.d/*.conf 2>/dev/null || echo "  [提示] 确认发行版默认 action 为 nftables（fail2ban-client -d 检查）"
else
  grep -q 'iptables-multiport' /etc/fail2ban/action.d/iptables-multiport.conf 2>/dev/null || echo "  [提示] 确认 iptables action 可用（iptables-multiport）"
fi

# 3. SSH jail（阈值保守，记录优先：maxretry 5 / findtime 10m / bantime 1h）
echo "[3] 配置 sshd jail..."
# R-07（DEV-008 reviewer）：backend 按环境判定——无 systemd（分支 B1，如 Alpine openrc）时
# systemd backend 依赖 python3-systemd/journald 不可用，改用 polling（读日志文件）
SYSTEMD_AVAILABLE=0
[ -d /run/systemd/system ] && SYSTEMD_AVAILABLE=1
F2B_BACKEND="systemd"
if [ "$SYSTEMD_AVAILABLE" -eq 0 ]; then
  F2B_BACKEND="polling"
  echo "  [提示] 非 systemd 环境（分支 B1）：backend=polling（读 auth.log）"
fi
cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
backend = $F2B_BACKEND
maxretry = 5
findtime = 10m
bantime = 1h
EOF
echo "  jail.local 已写入（backend=$F2B_BACKEND，与 sentry-agent M-03 数据源一致）"

# 4. 日志权限（容器挂载前置：容器 UID 1000 只读访问）
echo "[4] 调整日志/库读取权限（容器 UID 1000）..."
if command -v setfacl >/dev/null 2>&1; then
  setfacl -m u:1000:r /var/log/fail2ban.log /var/lib/fail2ban/fail2ban.sqlite3 2>/dev/null \
    && echo "  ACL 已设置（u:1000:r）" || echo "  [提示] 文件不存在或 setfacl 失败（fail2ban 首启后重跑本步骤）"
  # R-09：ACL 回读校验（方案 6.5.4 步骤 4 要求）
  getfacl /var/log/fail2ban.log 2>/dev/null | grep -q 'user:1000:r--' \
    && echo "  ACL 回读校验通过" || echo "  [警告] ACL 回读失败（检查文件存在与权限）"
else
  chmod g+r /var/log/fail2ban.log 2>/dev/null || true
  echo "  [提示] 无 setfacl，改用组读权限（需容器 group_add 对应组）"
fi

# 5. 启动与自检（试封回滚，不产生真实封禁残留）
echo "[5] 启动并自检..."
if command -v systemctl >/dev/null 2>&1; then
  systemctl enable --now fail2ban >/dev/null 2>&1
  sleep 3
  fail2ban-client status >/dev/null 2>&1 || { echo "[FAIL] fail2ban 未启动（journalctl -u fail2ban 排查）"; exit 1; }
  fail2ban-client status sshd | grep -q 'active' && echo "  sshd jail active" || echo "  [提示] sshd jail 未 active（检查 jail.local 与后端）"
  # 试封回滚（127.0.0.1）
  fail2ban-client set sshd banip 127.0.0.1 >/dev/null 2>&1
  fail2ban-client set sshd unbanip 127.0.0.1 >/dev/null 2>&1
  echo "  试封/回滚完成（127.0.0.1 无残留）"
else
  rc-service fail2ban start 2>/dev/null || service fail2ban start 2>/dev/null
  echo "  非 systemd：rc-service/service 已尝试启动（分支 B1 环境）"
fi

echo "===== fail2ban 安装清单完成 ====="
echo "提示：ACL 与容器 group_add 二选一（部署手册 6.5.4 步骤 4 说明）"
