#!/bin/bash
# sentry-agent 部署前环境检查（方案 6.1 C-01~C-14；C-07b 含于 setup_firewall.sh）
# 用法：sudo bash check_env.sh [--json]
# 输出：每项 PASS/FAIL/BRANCH + 分支指引；FAIL 项不允许静默继续（方案 6.1）
set -u
JSON=0
[ "${1:-}" = "--json" ] && JSON=1
PASS=0; FAIL=0; BRANCH=0

report() { # report <C编号> <结果> <说明>
  if [ "$JSON" = 1 ]; then
    printf '{"check":"%s","result":"%s","note":"%s"}\n' "$1" "$2" "$3"
  else
    printf '[%-4s] %-8s %s\n' "$1" "$2" "$3"
  fi
  case "$2" in PASS) PASS=$((PASS+1));; FAIL) FAIL=$((FAIL+1));; *) BRANCH=$((BRANCH+1));; esac
}

echo "===== sentry-agent 环境检查（方案 6.1 C-01~C-14） ====="
date -u +"%Y-%m-%d %H:%M:%S UTC"

# C-01 发行版识别
if [ -f /etc/os-release ]; then
  OS_ID=$(grep -E '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
  OS_VER=$(grep -E '^VERSION_ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
  report C-01 PASS "发行版 $OS_ID $OS_VER（未知发行版走分支 B3：通用安装）"
else
  report C-01 BRANCH "无 /etc/os-release，走分支 B3（未知发行版通用安装）"
fi

# C-02 内核版本（要求 >= 3.10）
KVER=$(uname -r | cut -d. -f1-2)
if [ "$(echo "$KVER" | awk -F. '{print $1*100+$2}')" -ge 310 ]; then
  report C-02 PASS "内核 $(uname -r) >= 3.10"
else
  report C-02 BRANCH "内核 $(uname -r) < 3.10，走分支 B4（警告继续，V1 在目标环境重跑）"
fi

# C-03 systemd 可用
if command -v systemd >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  report C-03 PASS "systemd 可用（分支 A：journald 通道）"
else
  report C-03 BRANCH "无 systemd，走分支 B1（rsyslog + auth.log + kmsg）"
fi

# C-04 journald 持久化
if [ -d /var/log/journal ] && [ -n "$(journalctl --disk-usage 2>/dev/null)" ]; then
  report C-04 PASS "journald 持久化（/var/log/journal 存在）"
elif [ "$(grep -E '^#?Storage=' /etc/systemd/journald.conf 2>/dev/null | cut -d= -f2)" = "persistent" ]; then
  report C-04 PASS "journald Storage=persistent"
else
  report C-04 BRANCH "journald 非持久，走分支 B2（setup_system.sh 启用 persistent 或转 B1）"
fi

# C-05 nf_conntrack 模块（DEV-033 调整：模块可用性判定以 sysctl count 文件为准——
# /proc/net/nf_conntrack 不存在可能是 CONFIG_NF_CONNTRACK_PROCFS not set 内核编译配置，
# 非模块缺失；count 文件为 sysctl 接口，模块加载即存在，现场验证可读）
# AUDIT-005 A-07：判定用 -r 测可读性（-f 仅测存在性，权限不足时误判可用）；
# modprobe 分支成功后补 count 文件复查（加载成功但文件仍不可读=权限/挂载问题，不误报 PASS）。
if [ -r /proc/sys/net/netfilter/nf_conntrack_count ] || [ -r /proc/net/nf_conntrack ]; then
  report C-05 PASS "nf_conntrack 模块已加载（count 文件可读）"
elif command -v modprobe >/dev/null 2>&1 && modprobe nf_conntrack 2>/dev/null && [ -r /proc/sys/net/netfilter/nf_conntrack_count ]; then
  report C-05 PASS "nf_conntrack 已通过 modprobe 加载（count 文件可读）"
else
  report C-05 BRANCH "nf_conntrack 不可用（count 文件不可读且 modprobe 失败），走分支 B5（ss 快照近似降级）；若为虚拟化限制无法加载，保持 B5 降级并可在 config.json 设 conntrack.mode=fallback 消除启动告警（DEV-031）"
fi

# C-06 宿主虚拟化形态（容器/OpenVZ 嵌套检测）
VIRT="裸机"
if [ -d /proc/vz ] || grep -qE 'lxc|docker|kubepods' /proc/1/cgroup 2>/dev/null || grep -qE 'overlay|containerd' /proc/self/mountinfo 2>/dev/null; then
  VIRT="容器/嵌套虚拟化"
  report C-06 BRANCH "$VIRT（conntrack 可能受限，走分支 B5 评估；--network host 容器形态见部署手册）"
else
  report C-06 PASS "宿主形态：裸机（conntrack 全功能）"
fi

# C-07 防火墙后端类型（nft / iptables-legacy）
FW_BACKEND="unknown"
if command -v nft >/dev/null 2>&1 && nft list ruleset >/dev/null 2>&1; then
  FW_BACKEND="nft"
elif command -v iptables >/dev/null 2>&1 && iptables -S >/dev/null 2>&1 && ! iptables -S 2>/dev/null | grep -q '^# '; then
  FW_BACKEND="iptables"
fi
if [ "$FW_BACKEND" = "nft" ]; then
  report C-07 PASS "防火墙后端：原生 nftables"
elif [ "$FW_BACKEND" = "iptables" ]; then
  report C-07 PASS "防火墙后端：iptables（兼容层或 legacy，setup_firewall.sh 按此生成规则）"
else
  report C-07 FAIL "防火墙后端无法判定"
fi

# C-08 fail2ban 存在性与后端
if command -v fail2ban-client >/dev/null 2>&1; then
  F2B_BACKEND=$(fail2ban-client -d 2>/dev/null | grep -oE 'nftables|iptables' | head -1 || true)
  report C-08 PASS "fail2ban 已安装（后端 ${F2B_BACKEND:-未知}；与 C-07 不一致走分支 B6）"
else
  report C-08 BRANCH "fail2ban 未安装 → install_fail2ban.sh 按 6.5.4 清单安装"
fi

# C-09 磁盘空间（永久保留口径，默认档 >= 80GB）
# 注：/var/lib/sentry-agent 可能尚未创建——目录不存在时直接回退根分区（冒烟发现的 df 管道掩盖问题）
DISK_MB=""
if [ -d /var/lib/sentry-agent ]; then
  DISK_MB=$(df -Pm /var/lib/sentry-agent 2>/dev/null | awk 'NR==2 {print $4}')
fi
if [ -z "${DISK_MB:-}" ]; then
  DISK_MB=$(df -Pm / 2>/dev/null | awk 'NR==2 {print $4}')
fi
if [ "${DISK_MB:-0}" -ge 81920 ]; then
  report C-09 PASS "磁盘可用 ${DISK_MB}MB >= 80GB（永久保留默认档）"
elif [ "${DISK_MB:-0}" -ge 20480 ]; then
  report C-09 BRANCH "磁盘可用 ${DISK_MB}MB（20-80GB：需调整归档档位，见部署手册 7.2）"
else
  report C-09 FAIL "磁盘可用 ${DISK_MB}MB < 20GB（永久保留口径不满足）"
fi

# C-10 内存确认（>= 512MB）
MEM_MB=$(free -m 2>/dev/null | awk '/^Mem:/ {print $2}')
if [ "${MEM_MB:-0}" -ge 512 ]; then
  report C-10 PASS "内存 ${MEM_MB}MB >= 512MB"
else
  report C-10 FAIL "内存 ${MEM_MB}MB < 512MB（全栈预算风险）"
fi

# C-11 SSH 服务可重启（sshd 语法检查）
if command -v sshd >/dev/null 2>&1 && sshd -t >/dev/null 2>&1; then
  report C-11 PASS "sshd 语法检查通过"
else
  report C-11 FAIL "sshd 语法检查失败（终止安装，人工介入）"
fi

# C-12 日志源可读性（journal 属组，容器挂载前置）
if [ -d /var/log/journal ]; then
  JGID=$(getent group systemd-journal | cut -d: -f3)
  report C-12 PASS "journal 目录存在（systemd-journal GID=${JGID:-未知}，compose 挂载用）"
else
  report C-12 BRANCH "journal 目录不存在（分支 B2/B1 处理）"
fi

# C-13 Docker 运行时可用
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  DVER=$(docker --version | grep -oE '[0-9]+\.[0-9]+' | head -1)
  report C-13 PASS "Docker $DVER 可用"
else
  report C-13 FAIL "Docker 不可用（按 6.4 安装或走分支 B8 裸机 systemd 部署）"
fi

# C-14 镜像获取网络
if docker pull hello-world >/dev/null 2>&1; then
  report C-14 PASS "镜像仓库可达（docker pull hello-world 成功）"
else
  report C-14 BRANCH "镜像仓库不可达（离线导入 tarball，见部署手册）"
fi

echo "===== 检查汇总：PASS=$PASS FAIL=$FAIL BRANCH=$BRANCH ====="
# R-02（DEV-008 reviewer）：FAIL 项存在时以非零退出码终止（方案 6.1"FAIL 项不允许静默继续"，
# deploy.sh 依赖该退出码中止后续步骤）
if [ "$FAIL" -gt 0 ]; then
  echo "结论：存在 FAIL 项（$FAIL 项），处理后重新检查"
  exit 1
fi
echo "结论：PASS"
exit 0
