"""在 VPS 上为本次前端发布准备隔离数据副本，不修改生产配置或数据。"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backup", required=True)
    parser.add_argument("--stage", required=True)
    args = parser.parse_args()
    backup = Path(args.backup).resolve(strict=True)
    stage = Path(args.stage).resolve()
    if backup.parent != Path("/opt/sentry-backups"):
        raise SystemExit("备份路径必须直接位于 /opt/sentry-backups")
    if stage.parent != Path("/opt/sentry-staging") or stage.exists():
        raise SystemExit("测试路径必须是 /opt/sentry-staging 下尚不存在的目录")
    os.umask(0o077)
    stage.mkdir(parents=True)
    subprocess.run(["tar", "-xf", str(backup / "data.tar"), "-C", str(stage)], check=True)
    data = stage / "sentry-agent"
    db = sqlite3.connect(str(data / "state.db"))
    result = db.execute("PRAGMA quick_check").fetchall()
    if result != [("ok",)]:
        raise SystemExit("数据副本完整性检查失败")
    counts = {}
    for table in ("connections", "ssh_attempts", "firewall_events", "cred_events", "resources"):
        counts[table] = db.execute('SELECT count(*) FROM "' + table + '"').fetchone()[0]
    db.close()
    cfg_path = backup / "config" / "config.json"
    cfg = json.loads(cfg_path.read_text())
    cfg["web"].update(listen="0.0.0.0:4002", ws_origin_allow="http://127.0.0.1:14002")
    cfg["db"].update(path="/var/lib/sentry-agent/state.db", archive_dir="/var/lib/sentry-agent/archive", retention_days=0, cred_retention_days=0)
    cfg.setdefault("archive", {})["copy_after_days"] = 99999
    cfg.setdefault("honeypot", {})["enabled"] = False
    cfg.setdefault("f2b", {})["enabled"] = False
    cfg.setdefault("geoip", {}).update(update_enabled=False, account_id="", license_key="")
    cfg.setdefault("conntrack", {}).update(mode="fallback", enable_acct=False)
    cfg.setdefault("fw", {})["ssh_learn_enabled"] = False
    (stage / "config.json").write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n")
    os.chmod(stage / "config.json", 0o644)
    # 副本归测试容器的非 root 用户所有，生产目录始终不参与这些操作。
    subprocess.run(["chown", "-R", "1000:1000", str(data)], check=True)
    report = {"snapshot_quick_check": "ok", "snapshot_counts": counts,
              "production_config_sha256": hashlib.sha256(cfg_path.read_bytes()).hexdigest(),
              "stage": str(stage), "honeypot_enabled": False, "retention_enabled": False}
    (stage / "prepare-result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
