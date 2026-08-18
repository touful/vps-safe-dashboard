# DEV-017 自测：构造"无攻击"测试库（验证零攻击庆祝态与态势正常分支）。
# 输出：.dev015-test/state_noidle.db（仓库相对路径，目录被 .gitignore 忽略；
# 可用 DEV017_NOIDLE_DB 环境变量覆盖）。
import sqlite3, os, time

DB = os.environ.get("DEV017_NOIDLE_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".dev015-test", "state_noidle.db"))
os.makedirs(os.path.dirname(DB), exist_ok=True)
if os.path.exists(DB):
    os.remove(DB)
conn = sqlite3.connect(DB)
cur = conn.cursor()
cur.executescript("""
CREATE TABLE resources (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, cpu_percent REAL NOT NULL, mem_used_mb REAL NOT NULL, mem_percent REAL NOT NULL, disk_used_mb REAL NOT NULL, disk_percent REAL NOT NULL, net_rx_bps INTEGER NOT NULL DEFAULT 0, net_tx_bps INTEGER NOT NULL DEFAULT 0);
CREATE TABLE connections (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, ev_type INTEGER NOT NULL, proto INTEGER NOT NULL, src_ip INTEGER NOT NULL, src_port INTEGER NOT NULL, dst_ip INTEGER NOT NULL, dst_port INTEGER NOT NULL, packets INTEGER NOT NULL DEFAULT 0, bytes INTEGER NOT NULL DEFAULT 0, mark INTEGER NOT NULL DEFAULT 0, src_ip6 TEXT NOT NULL DEFAULT '', dst_ip6 TEXT NOT NULL DEFAULT '');
CREATE TABLE ssh_attempts (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, src_ip INTEGER NOT NULL, username TEXT NOT NULL DEFAULT '', auth_method TEXT NOT NULL DEFAULT '', result INTEGER NOT NULL, fingerprint TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT '');
CREATE TABLE firewall_events (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, chain TEXT NOT NULL, action TEXT NOT NULL, proto INTEGER NOT NULL, src_ip INTEGER NOT NULL, src_port INTEGER NOT NULL, dst_ip INTEGER NOT NULL, dst_port INTEGER NOT NULL, raw TEXT NOT NULL DEFAULT '');
CREATE TABLE ban_events (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, ip INTEGER NOT NULL, type TEXT NOT NULL, jail TEXT NOT NULL DEFAULT '');
CREATE TABLE system_events (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, source TEXT NOT NULL, level TEXT NOT NULL, message TEXT NOT NULL);
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
""")
cur.execute("INSERT INTO meta VALUES('schema_version','1')")
now = int(time.time())
# 少量资源数据（磁盘 sparkline 有数据可画）
for i in range(24):
    cur.execute(
        "INSERT INTO resources(ts,cpu_percent,mem_used_mb,mem_percent,disk_used_mb,disk_percent,net_rx_bps,net_tx_bps) VALUES(?,?,?,?,?,?,?,?)",
        (now - 3600 + i * 150, 5 + i % 3, 200, 30, 8000, 55 + i % 5, 1000, 500))
# 仅正常 SSH 登录（result=1，非攻击），无防火墙 drop、无封禁
cur.execute(
    "INSERT INTO ssh_attempts(ts,src_ip,username,auth_method,result,detail) VALUES(?,?,?,?,?,?)",
    (now - 100, 0x0A000008, "deploy", "publickey", 1, "Accepted"))
conn.commit()
conn.close()
print("NOIDLE DB OK")
