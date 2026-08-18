#!/bin/bash
# 下载 GeoLite2-Country 离线库（DEV-GEO-001）——供攻击页"全球攻击地图"国家归属查询。
# 用法：
#   sudo bash deploy/fetch_geolite2.sh                                    # 从 deploy/config.json 读取 geoip 配置
#   sudo bash deploy/fetch_geolite2.sh --account-id X --license-key Y --db-path /var/lib/sentry-agent/GeoLite2-Country.mmdb
# 幂等：重复执行将原子替换为最新版本（旧库保留 .bak 一份）。
# 凭据安全：仅从 deploy/config.json（gitignore 保护）或命令行参数读取，不写入任何文件；
#           错误输出不含凭据明文。
# 说明：agent 内置每日 02:30 UTC 自动更新（geoip.update_enabled=true 且凭据已配置）；
#       本脚本用于部署时首次拉取或手动强制刷新。
set -u
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG_PATH="${SENTRY_CONFIG:-$SCRIPT_DIR/config.json}"

ACCOUNT_ID=""
LICENSE_KEY=""
DB_PATH=""

# 命令行参数（优先于 config.json）
while [ $# -gt 0 ]; do
  case "$1" in
    --account-id) ACCOUNT_ID="$2"; shift 2 ;;
    --license-key) LICENSE_KEY="$2"; shift 2 ;;
    --db-path) DB_PATH="$2"; shift 2 ;;
    *) echo "[FAIL] 未知参数: $1（仅支持 --account-id/--license-key/--db-path）"; exit 1 ;;
  esac
done

# 从 config.json 的 geoip 段补齐缺失项（需 python3）
if [ -z "$ACCOUNT_ID" ] || [ -z "$LICENSE_KEY" ] || [ -z "$DB_PATH" ]; then
  if ! command -v python3 >/dev/null 2>&1; then
    echo "[FAIL] 缺少参数且无 python3 解析 config.json"
    echo "      请改用命令行参数：bash deploy/fetch_geolite2.sh --account-id X --license-key Y --db-path Z"
    exit 1
  fi
  read -r C_ACC C_KEY C_DB <<< "$(python3 - "$CONFIG_PATH" <<'PYEOF'
import json, sys
try:
    with open(sys.argv[1], encoding="utf-8") as f:
        g = json.load(f).get("geoip", {})
    print(g.get("account_id", ""), g.get("license_key", ""), g.get("db_path", ""))
except Exception:
    print("", "", "")
PYEOF
)"
  [ -z "$ACCOUNT_ID" ] && ACCOUNT_ID="$C_ACC"
  [ -z "$LICENSE_KEY" ] && LICENSE_KEY="$C_KEY"
  [ -z "$DB_PATH" ] && DB_PATH="$C_DB"
fi

if [ -z "$ACCOUNT_ID" ] || [ -z "$LICENSE_KEY" ]; then
  echo "[FAIL] 未配置 MaxMind 凭据"
  echo "      请在 deploy/config.json 的 geoip.account_id / geoip.license_key 填写"
  echo "      （MaxMind 官网注册后免费获取 GeoLite2 License Key），或使用命令行参数"
  exit 1
fi
if [ -z "$DB_PATH" ]; then
  DB_PATH="/var/lib/sentry-agent/GeoLite2-Country.mmdb"
fi

TMP_DIR="$(mktemp -d)"
TMP_TGZ="$TMP_DIR/geolite.tar.gz"
URL="https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "--- 下载 GeoLite2-Country（MaxMind，约 4-10MB）---"
if ! curl -fsSL --user "$ACCOUNT_ID:$LICENSE_KEY" -o "$TMP_TGZ" "$URL"; then
  echo "[FAIL] 下载失败（检查网络连通性与凭据是否正确）"
  exit 1
fi

echo "--- 解压 ---"
if ! tar -xzf "$TMP_TGZ" -C "$TMP_DIR"; then
  echo "[FAIL] 解压失败（下载内容异常）"
  exit 1
fi
MMDB="$(find "$TMP_DIR" -name 'GeoLite2-Country.mmdb' | head -n 1)"
if [ -z "$MMDB" ]; then
  echo "[FAIL] 压缩包内未找到 GeoLite2-Country.mmdb"
  exit 1
fi

echo "--- 原子替换（旧库备份 .bak）---"
mkdir -p "$(dirname "$DB_PATH")"
[ -f "$DB_PATH" ] && mv -f "$DB_PATH" "$DB_PATH.bak"
mv -f "$MMDB" "$DB_PATH"
chmod 644 "$DB_PATH"

echo "[OK] GeoLite2-Country.mmdb 已就位：$DB_PATH（$(du -h "$DB_PATH" | cut -f1)）"
echo "提示：agent 每日 02:30 UTC 自动更新（geoip.update_enabled=true 且配置了凭据）；重跑本脚本可手动强制刷新"
