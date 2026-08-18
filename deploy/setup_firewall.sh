#!/bin/bash
# 模式 B 防火墙 LOG 规则生成（方案 6.5.3/D-05 定稿：在现有 DROP 规则前插入限速 LOG，
# 不改变包流向；SENTRY_FW 前缀；限速 5/s 突发 10）
# DEV-040 扩展：新增 filter FORWARD 链防护规则（DNAT 后保护 NPM 容器 172.19.0.2：
# 允许 80/443 对外，拒绝外部访问 81 管理端口，允许同网桥/已建立连接；SENTRY_PROTECT 前缀）
# DEV-HONEY-001 扩展：蜜罐端口入站放行（SENTRY_HONEYPOT：从 DROP 改为 ACCEPT 仍保留
# raw PREROUTING LOG 入站记录——蜜罐流量继续进入防火墙事件；配置驱动：读
# /etc/sentry-agent/config.json 的 honeypot.listen，未启用蜜罐时保持原 DROP 行为）
# 用法：sudo bash setup_firewall.sh [--rollback]
# 依赖：check_env.sh 的 C-07 判定（FW_BACKEND）；C-07b 盘点在脚本内执行
set -u

# M4B-01（DEV-009，auditor Blocker）：LOG 前缀必须为 `SENTRY_FW:<chain>:<action> `
# （解析器 internal/fw/parse.go:43-47 按此前缀结构提取 chain/action，action 恒为 drop/reject）；
# 配置 fw.prefix="SENTRY_FW:" 与解析器均不动，此处仅控制写入内核规则的前缀。
PREFIX_BASE="SENTRY_FW:"
LIMIT="5/s"; BURST=10

echo "===== 模式 B 防火墙 LOG 规则（方案 6.5.3） ====="

# C-07b：盘点现有 drop/reject 规则（nft / iptables）
detect_backend() {
  if command -v nft >/dev/null 2>&1 && nft list ruleset >/dev/null 2>&1; then echo nft; return; fi
  echo iptables
}
BACKEND=$(detect_backend)
echo "防火墙后端: $BACKEND"

if [ "${1:-}" = "--rollback" ]; then
  echo "回滚模式：删除本脚本插入的 SENTRY_FW LOG 规则与 SENTRY_PROTECT 防护规则"
  if [ "$BACKEND" = "nft" ]; then
    # R-04 修订（DEV-008 reviewer）：回滚按上下文跟踪解析 SENTRY_FW 规则的真实
    # family/table/chain/handle 并精确删除单条规则（绝不按 table/chain 删整链）
    nft -a list ruleset > /tmp/sentry_nft_rules.txt
    CUR_FAMILY=""; CUR_TABLE=""; CUR_CHAIN=""; DELETED=0; FAILED=0
    while IFS= read -r line; do
      if echo "$line" | grep -qE '^\s*table [a-z]+ '; then
        CUR_FAMILY=$(echo "$line" | awk '{print $2}'); CUR_TABLE=$(echo "$line" | awk '{print $3}')
        CUR_CHAIN=""; continue
      fi
      if echo "$line" | grep -qE '^\s*chain [A-Za-z0-9_-]+ \{'; then
        CUR_CHAIN=$(echo "$line" | sed -E 's/^\s*chain ([A-Za-z0-9_-]+) \{.*/\1/'); continue
      fi
      # DEV-040/DEV-HONEY-001：同时匹配 SENTRY_FW（LOG）、SENTRY_PROTECT（防护）与
      # SENTRY_HONEYPOT（蜜罐放行）规则
      if echo "$line" | grep -qE 'SENTRY_FW|SENTRY_PROTECT|SENTRY_HONEYPOT' && echo "$line" | grep -q 'handle [0-9]'; then
        handle=$(echo "$line" | grep -oE 'handle [0-9]+' | awk '{print $2}')
        if [ -n "$handle" ] && [ -n "$CUR_FAMILY" ] && [ -n "$CUR_TABLE" ] && [ -n "$CUR_CHAIN" ]; then
          if nft delete rule "$CUR_FAMILY" "$CUR_TABLE" "$CUR_CHAIN" handle "$handle" 2>/dev/null; then
            # DEV-040/DEV-HONEY-001：区分规则类型文案
            if echo "$line" | grep -q 'SENTRY_PROTECT'; then RULE_KIND="SENTRY_PROTECT 防护规则"
            elif echo "$line" | grep -q 'SENTRY_HONEYPOT'; then RULE_KIND="SENTRY_HONEYPOT 蜜罐放行规则"
            else RULE_KIND="SENTRY_FW LOG 规则"; fi
            echo "已删除 $RULE_KIND（$CUR_FAMILY $CUR_TABLE/$CUR_CHAIN handle $handle）"
            DELETED=$((DELETED+1))
          else
            # F-05（DEV-009）：删除失败显式告警并列出未删规则（不再静默）
            echo "[警告] 删除失败（$CUR_FAMILY $CUR_TABLE/$CUR_CHAIN handle $handle）：$line"
            FAILED=$((FAILED+1))
          fi
        fi
      fi
    done < /tmp/sentry_nft_rules.txt
    echo "回滚删除规则数: $DELETED，删除失败: $FAILED"
    [ "$FAILED" -gt 0 ] && echo "[警告] 存在未删除的 SENTRY_FW/SENTRY_PROTECT/SENTRY_HONEYPOT 规则，请人工核对：nft -a list ruleset | grep -E 'SENTRY_FW|SENTRY_PROTECT|SENTRY_HONEYPOT'"
  else
    iptables-save | grep -E 'SENTRY_FW|SENTRY_HONEYPOT' | sed 's/^-A/-D/' | while read -r rule; do
      if iptables $rule 2>/dev/null; then
        echo "已删除: $rule"
      else
        echo "[警告] 删除失败: $rule"
      fi
    done
  fi
  echo "回滚完成（蜜罐放行已移除——恢复原 DROP 行为；蜜罐端口暴露面需人工确认）"
  exit 0
fi

mkdir -p /var/lib/sentry-agent

# ===== DEV-HONEY-001：蜜罐端口入站放行（配置驱动） =====
# 背景：蜜罐监听标准端口（21/23/445/1433/3389 等），若被既有 INPUT DROP 规则拦截
# 则攻击者无法触达蜜罐（连接被静默丢弃）。本段将蜜罐端口从 DROP 改为 ACCEPT——
# 注意语义：raw PREROUTING 入站 LOG（DEV-042）在 conntrack 之前无条件记录，
# 放行后蜜罐流量仍进入 firewall_events（入站观察语义不丢）。
# 配置驱动：读 /etc/sentry-agent/config.json 的 honeypot.listen（enabled=true 时生效）；
# 未启用蜜罐或未配置时保持原 DROP 行为（幂等跳过）。
# 回滚：--rollback 已覆盖 SENTRY_HONEYPOT 规则删除（恢复原 DROP 行为）。
# R-01（DEV-HONEY-003 reviewer Major 整改）：函数定义移到 BACKEND 判定之前（顶层）——
# 原定义在 nft 分支内，BACKEND=iptables 时函数未定义（command not found），
# iptables 后端蜜罐放行从未生效（基线既有缺陷，H-02 修复暴露）。
insert_honeypot_accept() {
  local cfg="${HONEYPOT_CONFIG:-/etc/sentry-agent/config.json}"
  local block ports portlist
  if [ ! -f "$cfg" ]; then
    echo "[提示] 未找到 $cfg——蜜罐放行跳过（保持原 DROP 行为；部署后重跑本脚本）"
    return
  fi
  block=$(sed -n '/"honeypot"/,/^[[:space:]]*}/p' "$cfg")
  if ! echo "$block" | grep -q '"enabled"[[:space:]]*:[[:space:]]*true'; then
    echo "[提示] 蜜罐未启用（honeypot.enabled != true）——保持原 DROP 行为"
    return
  fi
  ports=$(echo "$block" | grep -oE ':[0-9]{1,5}' | grep -oE '[0-9]{1,5}' | sort -un)
  if [ -z "$ports" ]; then
    echo "[提示] 蜜罐启用但未解析到监听端口——保持原 DROP 行为（人工核对 honeypot.listen 配置）"
    return
  fi
  # H-02（audit Major 修复）：原 `echo $ports | tr '\n' ','` 生成空格分隔 + 尾逗号列表
  # （`echo $ports` 未加引号导致换行变空格），iptables multiport 不接受空格、
  # nft 集合语法不接受尾逗号——两后端插入必然失败且脚本 exit 0 掩盖。
  # paste -sd, 生成纯逗号分隔无尾逗号列表。
  portlist=$(echo "$ports" | paste -sd, -)
  echo "--- 蜜罐端口入站放行（SENTRY_HONEYPOT，从 DROP 改为 ACCEPT 仍保留 LOG 记录）---"
  echo "蜜罐端口: $portlist"
  FAILED=0
  if [ "$BACKEND" = "nft" ]; then
    if nft list chain ip filter INPUT 2>/dev/null | grep -q 'SENTRY_HONEYPOT'; then
      echo "[提示] INPUT 链已含 SENTRY_HONEYPOT 规则（幂等：跳过插入）"
    else
      nft add table ip filter 2>/dev/null || true
      nft add chain ip filter INPUT '{ type filter hook input priority 0 ; policy accept ; }' 2>/dev/null || true
      # insert 到链首（先于既有 DROP）；raw PREROUTING LOG 不受影响（hook 更早）
      if nft insert rule ip filter INPUT tcp dport { $portlist } accept comment \"SENTRY_HONEYPOT:accept\" 2>/dev/null; then
        echo "已插入: 放行蜜罐端口（$portlist）"
      else
        echo "[警告] 插入失败: 蜜罐端口放行（人工核对 nft list chain ip filter INPUT | grep SENTRY_HONEYPOT）"
        FAILED=1
      fi
    fi
  else
    if iptables -S INPUT | grep -q 'SENTRY_HONEYPOT'; then
      echo "[提示] INPUT 链已含 SENTRY_HONEYPOT 规则（幂等：跳过插入）"
    else
      if iptables -I INPUT -p tcp -m multiport --dports "$portlist" -j ACCEPT -m comment --comment "SENTRY_HONEYPOT:accept" 2>/dev/null; then
        echo "已插入: 放行蜜罐端口（$portlist）"
      else
        echo "[警告] 插入失败: 蜜罐端口放行（人工核对 iptables -S INPUT | grep SENTRY_HONEYPOT）"
        FAILED=1
      fi
    fi
  fi
  if [ "$FAILED" -eq 1 ]; then
    echo "[错误] 蜜罐端口放行插入失败——规则未生效（攻击者无法触达蜜罐端口），请修复后重跑"
    return 1
  fi
  # 验证命令（双后端）：nft list chain ip filter INPUT | grep SENTRY_HONEYPOT /
  # iptables -S INPUT | grep SENTRY_HONEYPOT
}

if [ "$BACKEND" = "nft" ]; then
  echo "--- nftables：在现有 drop/reject 规则前插入限速 LOG ---"
  # M4B-01：前缀带 <chain>:<action>（nft 分支 chain 取自跟踪链名，action 取自规则行）
  # F-01（DEV-009）：幂等保护——规则集已含 SENTRY_FW 时跳过（重复执行不叠加）
  # 边界披露（reviewer R-03）：检查为全局粒度——若部分链首轮插入失败后重跑将整体跳过；
  # 此时依赖回读校验告警人工介入；链级幂等评估列入 V-08 复验。

  # ===== DEV-040：filter FORWARD 防护规则（DNAT 后保护 NPM 容器） =====
  # 背景：raw PREROUTING 中 2 条 drop 规则（保护 172.19.0.2 与 127.0.0.1:81）因 raw hook
  # 早于 DNAT（-300 < -100）且 127.0.0.1 必走 lo 而永不匹配（counter=0）。本段在 filter
  # FORWARD 链（DNAT 之后，daddr 已是容器 IP 172.19.0.2）重新设计防护：
  #   允许外部→172.19.0.2:80/443（NPM 反代必须对外）；拒绝外部→172.19.0.2:81（管理界面，
  #   仅允许本地/同网桥）；放行已建立连接与同网桥流量。
  # 127.0.0.1:81 由内核 martian 过滤天然保护（非 lo 接口到达 127.0.0.0/8 的包被内核丢弃），
  # 无需额外规则。标识 comment "SENTRY_PROTECT:..."（不含 SENTRY_FW 子串，避免误触 LOG 幂等检查）。
  # 提取为函数：LOG 幂等检查 exit 0 前也调用（reviewer R-01 整改——LOG 已存在但防护缺失时仍补插）。
  insert_protect_rules() {
    echo "--- filter FORWARD 防护规则（DEV-040） ---"
    if nft list chain ip filter FORWARD 2>/dev/null | grep -q 'SENTRY_PROTECT'; then
      echo "[提示] FORWARD 链已含 SENTRY_PROTECT 防护规则（幂等：跳过插入）"
    else
      # 确保 filter 表与 FORWARD 链存在（已存在则忽略报错；不改变既有 policy）
      nft add table ip filter 2>/dev/null || true
      nft add chain ip filter FORWARD '{ type filter hook forward priority 0 ; policy accept ; }' 2>/dev/null || true
      # 逆序 insert（nft insert 插到链首），最终顺序：
      #   established → 同网桥81 → 80/443 → 81 drop
      nft insert rule ip filter FORWARD ip daddr 172.19.0.2 tcp dport 81 drop comment \"SENTRY_PROTECT:81\" 2>/dev/null \
        && echo "已插入: 拒绝外部→172.19.0.2:81" \
        || echo "[警告] 插入失败: 拒绝外部→172.19.0.2:81"
      nft insert rule ip filter FORWARD ip daddr 172.19.0.2 tcp dport '{ 80, 443 }' accept comment \"SENTRY_PROTECT:80-443\" 2>/dev/null \
        && echo "已插入: 允许→172.19.0.2:80/443" \
        || echo "[警告] 插入失败: 允许→172.19.0.2:80/443"
      nft insert rule ip filter FORWARD iifname "br-bbdb2d12d511" ip daddr 172.19.0.2 tcp dport 81 accept comment \"SENTRY_PROTECT:bridge81\" 2>/dev/null \
        && echo "已插入: 允许同网桥→172.19.0.2:81" \
        || echo "[警告] 插入失败: 允许同网桥→172.19.0.2:81"
      nft insert rule ip filter FORWARD ct state established,related accept comment \"SENTRY_PROTECT:established\" 2>/dev/null \
        && echo "已插入: 允许已建立连接" \
        || echo "[警告] 插入失败: 允许已建立连接"
      # 回读校验
      PROTECT_CNT=$(nft list chain ip filter FORWARD 2>/dev/null | grep -c 'SENTRY_PROTECT' || true)
      echo "SENTRY_PROTECT 防护规则数: $PROTECT_CNT"
      [ "$PROTECT_CNT" -ge 4 ] || echo "[警告] 防护规则数 < 4：插入未完全生效（人工核对 nft list chain ip filter FORWARD）"
    fi
  }

  # ===== DEV-042：raw PREROUTING 入站 LOG（记录所有入站流量） =====
  # 背景：DOCKER/f2b-sshd 链 LOG 只记录 drop/reject，而 drop/reject counter 全 0，
  # 导致 firewall_events 几乎无数据（"外部威胁"不可见）。本段在 raw PREROUTING
  # （conntrack/DNAT 之前，记录所有入站流量）插入 1 条限速 LOG，配合采集层过滤
  # （exclude_internal/exclude_ips/SSH 成功登录动态白名单）避免爆表。
  # 前缀 SENTRY_FW:PREROUTING:inbound（区别于 drop/reject 语义；解析器按
  # SENTRY_FW:<chain>:<action> 提取 chain=PREROUTING action=inbound）。
  # 设计决策：保留 DOCKER/f2b-sshd 链 LOG（拦截记录语义）——raw 为入站观察（所有流量），
  # 两者语义不同；且 DOCKER/f2b-sshd drop counter 全 0（无实际拦截），不产生重复记录。
  # 幂等：独立检查（先于全局 SENTRY_FW 检查——升级场景旧版已有 DOCKER/f2b-sshd LOG
  # 时仍补插 raw LOG）。
  insert_raw_prerouting_log() {
    echo "--- raw PREROUTING 入站 LOG（DEV-042） ---"
    if nft list chain ip raw PREROUTING 2>/dev/null | grep -q 'SENTRY_FW:PREROUTING:inbound'; then
      echo "[提示] raw PREROUTING 已含入站 LOG（幂等：跳过插入）"
    else
      # 确保 raw 表与 PREROUTING 链存在（已存在则忽略报错；不改变既有 policy）
      nft add table ip raw 2>/dev/null || true
      nft add chain ip raw PREROUTING '{ type filter hook prerouting priority -300 ; policy accept ; }' 2>/dev/null || true
      # insert 到链首：LOG 无条件记录所有入站包（含后续被 drop 的），不改变包流向
      if nft insert rule ip raw PREROUTING log prefix \"SENTRY_FW:PREROUTING:inbound \" flags all limit rate 5/second burst $BURST packets 2>/dev/null; then
        echo "已插入: raw PREROUTING 入站 LOG（前缀 SENTRY_FW:PREROUTING:inbound）"
      else
        echo "[警告] 插入失败: raw PREROUTING 入站 LOG（人工核对 nft list chain ip raw PREROUTING）"
      fi
    fi
  }

  # DEV-042：raw PREROUTING 入站 LOG（独立幂等检查，先于全局 SENTRY_FW 检查——
  # 升级场景旧版已有 DOCKER/f2b-sshd LOG 时仍补插 raw LOG）
  insert_raw_prerouting_log

  # DEV-042：幂等检查排除 raw PREROUTING 入站 LOG——raw LOG 已独立插入，
  # 不应触发 DOCKER/f2b-sshd LOG 的跳过（否则首次运行 raw LOG 插入后 DOCKER LOG 被跳过）。
  if nft list ruleset 2>/dev/null | grep -v 'SENTRY_FW:PREROUTING:inbound' | grep -q 'SENTRY_FW'; then
    echo "[提示] 规则集已含 SENTRY_FW LOG 规则（幂等：跳过插入）"
    nft list ruleset | grep -v 'SENTRY_FW:PREROUTING:inbound' | grep -c 'SENTRY_FW' | xargs echo "现有 SENTRY_FW 规则数（不含 raw 入站 LOG）:"
    # DEV-040（reviewer R-01 整改）：LOG 已存在时仍检查/补插防护规则
    insert_protect_rules
    # DEV-HONEY-001：蜜罐放行独立幂等检查（LOG 已存在时仍补插）
    # H-02：插入失败非零退出（不再 exit 0 掩盖）
    insert_honeypot_accept || exit 1
    exit 0
  fi
  nft -a list ruleset > /tmp/sentry_nft_rules.txt
  CUR_FAMILY=""; CUR_TABLE=""; CUR_CHAIN=""
  INSERTED=0
  LOGGED_CHAIN=""   # A-01（DEV-039）：已插入 LOG 的链标识（family/table/chain）
  while IFS= read -r line; do
    # 跟踪 family/table/chain 上下文
    if echo "$line" | grep -qE '^\s*table [a-z]+ '; then
      CUR_FAMILY=$(echo "$line" | awk '{print $2}')
      CUR_TABLE=$(echo "$line" | awk '{print $3}')
      CUR_CHAIN=""
      continue
    fi
    if echo "$line" | grep -qE '^\s*chain [A-Za-z0-9_-]+ \{'; then
      CUR_CHAIN=$(echo "$line" | sed -E 's/^\s*chain ([A-Za-z0-9_-]+) \{.*/\1/')
      continue
    fi
    # 规则行含 drop/reject 且带 handle；提取 action（M4B-01 前缀用）
    if echo "$line" | grep -qE '\b(drop|reject)\b' && echo "$line" | grep -q 'handle [0-9]'; then
      [ -z "$CUR_FAMILY" ] || [ -z "$CUR_TABLE" ] || [ -z "$CUR_CHAIN" ] && continue
      # A-01（DEV-039，auditor Major）：同一链只插 1 条 LOG（在该链第一条 drop 前）。
      # 根因：LOG 规则无条件（无匹配条件），同链多条 LOG 会对同一包重复记录
      # （auditor A-01：事件量/DB/统计指标翻倍）。LOG 无条件记录该链全部流量——
      # 首条 drop 前的 1 条 LOG 即可覆盖匹配后续 drop 规则的所有包（不漏报），
      # 故同链 1 条 LOG 足够。跨链仍各插 1 条（互不重叠）。
      if [ "$LOGGED_CHAIN" = "$CUR_FAMILY/$CUR_TABLE/$CUR_CHAIN" ]; then
        continue
      fi
      HANDLE=$(echo "$line" | grep -oE 'handle [0-9]+' | awk '{print $2}')
      if echo "$line" | grep -qE '\breject\b'; then ACTION="reject"; else ACTION="drop"; fi
      # R-07 边界记录：action 判定为先 reject 后 drop——规则行同时含两词（极端注释场景）时
      # 取 reject；概率极低，如出现可人工核对前缀（nft -a list ruleset 回读）。
      LOGPREFIX="${PREFIX_BASE}${CUR_CHAIN}:${ACTION} "
      if nft insert rule "$CUR_FAMILY" "$CUR_TABLE" "$CUR_CHAIN" position "$HANDLE" log prefix "\"$LOGPREFIX\"" flags all limit rate 5/second burst $BURST packets 2>/dev/null; then
        echo "已插入 LOG（$CUR_FAMILY $CUR_TABLE/$CUR_CHAIN 于 handle $HANDLE 前，前缀 $LOGPREFIX）"
        INSERTED=$((INSERTED+1))
        LOGGED_CHAIN="$CUR_FAMILY/$CUR_TABLE/$CUR_CHAIN"
      else
        echo "[警告] 插入失败（$CUR_FAMILY $CUR_TABLE/$CUR_CHAIN handle $HANDLE）：规则可能已变，人工核对 nft -a list ruleset"
      fi
    fi
  done < /tmp/sentry_nft_rules.txt
  # R-08：无 drop/reject 规则时提示（C-07b 文案）
  if [ "$INSERTED" -eq 0 ]; then
    echo "[提示] 未发现任何 drop/reject 规则（C-07b）：防火墙通道数据将稀疏，攻击统计依赖 conntrack + fail2ban 日志"
  fi
  echo "--- 回读校验 ---"
  CNT=$(nft list ruleset | grep -c 'SENTRY_FW' || true)
  echo "SENTRY_FW 规则数: $CNT"
  [ "$CNT" -gt 0 ] || echo "[警告] 回读为 0：插入未生效（检查后端判定与规则集格式）"

  # DEV-040：filter FORWARD 防护规则（幂等插入）
  insert_protect_rules

  # DEV-HONEY-001：蜜罐端口放行（幂等；配置驱动；H-02：失败非零退出）
  insert_honeypot_accept || exit 1
else
  echo "--- iptables：在 INPUT 链 DROP 规则前插入限速 LOG ---"
  # F-01（DEV-009）：幂等保护
  if iptables -S INPUT | grep -q 'SENTRY_FW'; then
    echo "[提示] INPUT 链已含 SENTRY_FW LOG 规则（幂等：跳过插入）"
    iptables -S INPUT | grep -c 'SENTRY_FW' | xargs echo "现有 SENTRY_FW 规则数:"
    # DEV-HONEY-001：蜜罐放行独立幂等检查（LOG 已存在时仍补插）
    # H-02：插入失败非零退出（不再 exit 0 掩盖）
    insert_honeypot_accept || exit 1
  fi
  # M4B-02（DEV-009，auditor Major）：`iptables -S INPUT` 首行为 `-P INPUT <policy>`，
  # grep 行号 = 规则编号 + 1——插入位置须减 1（否则"首条规则即 DROP"时 LOG 插到 DROP 之后）。
  # A-01（DEV-039）：INPUT 链只插 1 条 LOG（在第一条 DROP 前）——多条无条件 LOG 会对
  # 同一包重复记录（auditor A-01）。取编号最小的 DROP/REJECT 规则行号。
  FIRST_LINE=$(iptables -S INPUT | grep -nE '\-j (DROP|REJECT)' | awk -F: '{print $1}' | sort -n | head -1)
  INSERTED=0
  if [ -n "$FIRST_LINE" ]; then
    RULE_NO=$((FIRST_LINE - 1))   # M4B-02：排除 -P 行后为真实规则编号
    # 取原始规则行判定 action（从 -S 输出按行号取）
    ORIG=$(iptables -S INPUT | sed -n "${FIRST_LINE}p")
    if echo "$ORIG" | grep -qE '\-j REJECT'; then ACTION="reject"; else ACTION="drop"; fi
    LOGPREFIX="${PREFIX_BASE}input:${ACTION} "   # M4B-01：INPUT 链映射为 input
    if iptables -I INPUT "$RULE_NO" -m limit --limit "$LIMIT" --limit-burst "$BURST" -j LOG --log-prefix "$LOGPREFIX" 2>/dev/null; then
      echo "已插入 LOG（INPUT 第 ${RULE_NO} 条 DROP 前，前缀 $LOGPREFIX）"
      INSERTED=$((INSERTED+1))
    fi
  fi
  # C-07b：无 drop/reject 规则时提示（与 nft 分支一致）
  if [ "$INSERTED" -eq 0 ]; then
    echo "[提示] 未发现任何 drop/reject 规则（C-07b）：防火墙通道数据将稀疏，攻击统计依赖 conntrack + fail2ban 日志"
  fi
  # DEV-HONEY-001：蜜罐端口放行（iptables 后端；幂等；配置驱动；H-02：失败非零退出）
  insert_honeypot_accept || exit 1
  echo "--- 回读校验 ---"
  iptables -S INPUT | grep -c 'SENTRY_FW' | xargs echo "SENTRY_FW 规则数:"
fi

echo "===== 规则生成完成（LOG 仅记录不拦截；DEV-040 filter FORWARD 防护规则按设计拦截） ====="
echo "提示：规则持久化（nft: /etc/nftables.d/ 导出；iptables: iptables-persistent/firewalld direct）见部署手册"
echo "提示：多条 LOG 规则对同一连接重复计数属 D-05 设计固有语义（面板 top_ports 为采样视图）"
