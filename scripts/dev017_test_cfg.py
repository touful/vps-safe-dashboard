# DEV-017 回归测试：构造 API 测试配置（TEST-006）
# 用法：python scripts/dev017_test_cfg.py <state_db_path> <port>
import json, os, sys, tempfile

db = sys.argv[1] if len(sys.argv) > 1 else os.path.join(tempfile.gettempdir(), "opencode", "dev015", "state.db")
port = int(sys.argv[2]) if len(sys.argv) > 2 else 8099

cfg = {
    "collect": {"resource_interval_seconds": 5},
    "ss": {"snapshot_interval_s": 20},
    "conntrack": {"buffer_size_kb": 2048, "enable_acct": True, "overrun_warn_interval_s": 60, "fallback_interval_s": 5},
    "ssh": {"source": "journald", "verbose_fingerprint": True},
    "fw": {"source": "journald-kernel", "prefix": "SENTRY_FW:", "rate_limit_pkt_s": 5},
    "f2b": {"enabled": False, "log_path": "/tmp/f2b.log", "db_path": "/tmp/f2b.sqlite3"},
    "db": {"path": db, "batch_interval_ms": 500, "batch_size": 200,
           "archive_dir": os.path.join(os.path.dirname(db), "archive")},
    "archive": {"monthly_hour": "02:00", "gzip_level": 6, "copy_after_days": 60},
    "web": {"listen": "127.0.0.1:%d" % port, "ws_origin_allow": "http://127.0.0.1:%d" % port},
    "disk": {"warn_percent": 80, "critical_percent": 90, "emergency_percent": 95},
    "log": {"level": "info"},
}
os.makedirs(os.path.join(os.path.dirname(db), "archive"), exist_ok=True)
out = os.path.join(os.path.dirname(db), "cfg.json")
json.dump(cfg, open(out, "w", encoding="utf-8"), ensure_ascii=False)
print("CFG OK:", out)
