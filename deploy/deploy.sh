#!/bin/bash
# sentry-agent 一键部署入口（供用户在 VPS 执行；方案 6.x/11.4）
# 流程：环境检查 → 系统配置 → fail2ban 安装 → 模式 B 防火墙规则 → 数据目录 → docker compose 启动
# 用法：sudo bash deploy.sh
set -u
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
echo "===== sentry-agent 部署入口 ====="
date -u +"%Y-%m-%d %H:%M:%S UTC"

# 0. 参数
CONFIG_PATH="${SENTRY_CONFIG:-/etc/sentry-agent/config.json}"

# 1. 环境检查（C-01~C-14；FAIL 项不允许继续）
echo "--- [1/6] 环境检查 ---"
bash "$SCRIPT_DIR/check_env.sh" || { echo "[FAIL] check_env.sh 执行失败"; exit 1; }
echo "[提示] 请人工确认上方输出：FAIL 项必须处理后重新检查；BRANCH 项按指引继续"

# 2. 系统配置（journald/sshd/logrotate）
echo "--- [2/6] 系统配置 ---"
bash "$SCRIPT_DIR/setup_system.sh" --apply

# 3. fail2ban 安装（按环境检查 C-08 分支；未安装时执行）
echo "--- [3/6] fail2ban ---"
if ! command -v fail2ban-client >/dev/null 2>&1; then
  bash "$SCRIPT_DIR/install_fail2ban.sh" || echo "[警告] fail2ban 安装未完全成功（M-05 通道降级，仅影响封禁视图）"
else
  echo "fail2ban 已安装，跳过（如需后端对齐检查请手动执行 install_fail2ban.sh）"
fi

# 4. 模式 B 防火墙 LOG 规则
echo "--- [4/6] 模式 B 防火墙规则 ---"
bash "$SCRIPT_DIR/setup_firewall.sh"

# 5. 数据目录与配置
echo "--- [5/6] 数据目录与配置 ---"
mkdir -p /var/lib/sentry-agent /etc/sentry-agent
# R-07（reviewer 第 3 轮 ESCALATE 项）：chown 失败时显式报错退出，
# 删除原 `|| chmod -R 777` 静默回退（数据目录含主库与归档副本，777 违反权限原则）
if ! chown -R 1000:1000 /var/lib/sentry-agent 2>/dev/null; then
  echo "[FAIL] 数据目录 chown 失败（/var/lib/sentry-agent 属主须为 UID 1000）"
  echo "      请手动执行：chown -R 1000:1000 /var/lib/sentry-agent 后重跑"
  exit 1
fi
echo "  数据目录属主已设为 UID 1000"
if [ ! -f "$CONFIG_PATH" ]; then
  cp "$SCRIPT_DIR/config.json" "$CONFIG_PATH" && echo "已生成默认配置 $CONFIG_PATH（请按需修改 ssh.source/fw.source 等）"
else
  echo "配置已存在：$CONFIG_PATH（保留）"
fi
# journal 与 fail2ban 文件只读挂载权限（R-05/N-02 修订：走 ACL 路径含默认 ACL，
# 与方案 6.4.3"仅通过补充组或 ACL，不 chmod 放宽 journal"一致；容器 UID 1000 读权限；
# -d 默认 ACL 保证 journald 轮转新建文件后权限不失效）
if [ -d /var/log/journal ]; then
  if command -v setfacl >/dev/null 2>&1; then
    setfacl -R -m u:1000:rx,d:u:1000:rx /var/log/journal 2>/dev/null && echo "journal ACL 已设置（u:1000:rx + 默认 ACL）"
    getfacl /var/log/journal 2>/dev/null | grep -q 'user:1000:r-x' && echo "ACL 回读校验通过" || echo "[警告] ACL 回读失败"
    getfacl /var/log/journal 2>/dev/null | grep -q 'default:user:1000:r-x' && echo "默认 ACL 回读通过" || echo "[警告] 默认 ACL 回读失败"
  else
    echo "[FAIL] 无 setfacl：必须改用 --group-add 路径（docker-compose.yml 启用 systemd-journal 组）后重跑"
    exit 1
  fi
fi

# 6. 启动容器
echo "--- [6/6] docker compose 启动 ---"
cd "$SCRIPT_DIR"
if docker compose version >/dev/null 2>&1; then
  docker compose -f docker-compose.yml up -d
else
  echo "[提示] 无 docker compose，使用 docker run（命令见部署手册 6.4.2）"
  docker run -d --name sentry-agent --restart=unless-stopped \
    --network host --cap-add NET_ADMIN --user 1000:1000 \
    # R-06（reviewer）：docker run 回退路径补齐 F-03 纵深防御参数（与 compose 一致）
    --memory 256m --security-opt no-new-privileges \
    -v /var/lib/sentry-agent:/var/lib/sentry-agent \
    # N-01（DEV-008 reviewer）：journal 挂载到容器内代码默认路径 /var/log/journal
    # （与 compose 一致；/host/journal 仅为旧设计，代码未实现 -D 模式）
    -v /var/log/journal:/var/log/journal:ro \
    -v /etc/machine-id:/etc/machine-id:ro \
    -v /var/log/fail2ban.log:/host/fail2ban.log:ro \
    -v /var/lib/fail2ban/fail2ban.sqlite3:/host/fail2ban.sqlite3:ro \
    -v "$CONFIG_PATH":/etc/sentry-agent/config.json:ro \
    sentry-agent:latest
fi

echo "--- 启动后健康检查（30s 内） ---"
HEALTH_OK=0
for i in $(seq 1 15); do
  sleep 2
  if docker ps --filter name=sentry-agent --format '{{.Status}}' | grep -q Up; then
    # D-14/F-02（DEV-009）：debian 镜像无 wget/curl，用 bash /dev/tcp 探活（不动镜像）
    if docker exec sentry-agent bash -c 'exec 3<>/dev/tcp/127.0.0.1/8080 && printf "GET /api/v1/health HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n" >&3 && head -c 200 <&3' 2>/dev/null | grep -q '"ok":true'; then
      echo "[OK] 健康检查通过"
      HEALTH_OK=1
      break
    fi
  fi
done
[ "$HEALTH_OK" -eq 0 ] && echo "[警告] 健康检查未通过（docker logs sentry-agent 排查）"

echo "===== 部署完成 ====="
echo "面板：http://127.0.0.1:8080（访问方式参考部署手册；VPS 复验清单 docs/M4_VPS复验清单.md）"
