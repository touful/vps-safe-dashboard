# DEV-015 自测：构造前端验证用测试数据库（schema 与 store.go 一致，IP 为 uint32 大端序）。
# 用法：python scripts/dev015_seed_db.py
# 输出：.dev015-test/state.db（仓库相对路径，目录被 .gitignore 忽略；可用 DEV015_DB 环境变量覆盖）。
import sqlite3, os, time, random

DB = os.environ.get("DEV015_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".dev015-test", "state.db"))
os.makedirs(os.path.dirname(DB), exist_ok=True)
if os.path.exists(DB):
    os.remove(DB)
if os.path.exists(DB + "-wal"):
    os.remove(DB + "-wal")
if os.path.exists(DB + "-shm"):
    os.remove(DB + "-shm")

conn = sqlite3.connect(DB)
cur = conn.cursor()

schema = """
CREATE TABLE resources (
    id INTEGER PRIMARY KEY, ts INTEGER NOT NULL,
    cpu_percent REAL NOT NULL, mem_used_mb REAL NOT NULL, mem_percent REAL NOT NULL,
    disk_used_mb REAL NOT NULL, disk_percent REAL NOT NULL,
    net_rx_bps INTEGER NOT NULL DEFAULT 0, net_tx_bps INTEGER NOT NULL DEFAULT 0);
CREATE INDEX idx_resources_ts ON resources(ts);
CREATE TABLE connections (
    id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, ev_type INTEGER NOT NULL,
    proto INTEGER NOT NULL, src_ip INTEGER NOT NULL, src_port INTEGER NOT NULL,
    dst_ip INTEGER NOT NULL, dst_port INTEGER NOT NULL,
    packets INTEGER NOT NULL DEFAULT 0, bytes INTEGER NOT NULL DEFAULT 0,
    mark INTEGER NOT NULL DEFAULT 0, src_ip6 TEXT NOT NULL DEFAULT '', dst_ip6 TEXT NOT NULL DEFAULT '');
CREATE INDEX idx_conn_ts ON connections(ts);
CREATE INDEX idx_conn_dport ON connections(dst_port);
CREATE INDEX idx_conn_src ON connections(src_ip);
CREATE INDEX idx_conn_evid ON connections(ev_type, id);
CREATE TABLE ssh_attempts (
    id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, src_ip INTEGER NOT NULL,
    username TEXT NOT NULL DEFAULT '', auth_method TEXT NOT NULL DEFAULT '',
    result INTEGER NOT NULL, fingerprint TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT '');
CREATE INDEX idx_ssh_ts ON ssh_attempts(ts);
CREATE INDEX idx_ssh_src ON ssh_attempts(src_ip);
CREATE INDEX idx_ssh_user ON ssh_attempts(username);
CREATE TABLE firewall_events (
    id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, chain TEXT NOT NULL, action TEXT NOT NULL,
    proto INTEGER NOT NULL, src_ip INTEGER NOT NULL, src_port INTEGER NOT NULL,
    dst_ip INTEGER NOT NULL, dst_port INTEGER NOT NULL, raw TEXT NOT NULL DEFAULT '');
CREATE INDEX idx_fw_ts ON firewall_events(ts);
CREATE INDEX idx_fw_dport ON firewall_events(dst_port);
CREATE INDEX idx_fw_action ON firewall_events(action);
CREATE TABLE ban_events (
    id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, ip INTEGER NOT NULL,
    type TEXT NOT NULL, jail TEXT NOT NULL DEFAULT '');
CREATE INDEX idx_ban_ts ON ban_events(ts);
CREATE INDEX idx_ban_ip ON ban_events(ip);
CREATE TABLE system_events (
    id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, source TEXT NOT NULL,
    level TEXT NOT NULL, message TEXT NOT NULL);
CREATE INDEX idx_se_ts ON system_events(ts);
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""
cur.executescript(schema)
now = int(time.time())

# meta
cur.execute("INSERT INTO meta VALUES('schema_version','1')")
cur.execute("INSERT INTO meta VALUES('created_at',?)", (str(now),))
cur.execute("INSERT INTO meta VALUES('hostname','dev015-test')")

# IP 工具：点分十进制 → uint32
def ipp(a, b, c, d):
    return (a << 24) | (b << 16) | (c << 8) | d

ATTACKERS = [ipp(185, 220, 101, x) for x in range(1, 6)] + [ipp(45, 155, 205, x) for x in range(1, 4)] + [ipp(91, 240, 118, 77)]
VPS_IP = ipp(203, 0, 113, 10)

# resources：近 1h，60s 步长
random.seed(42)
t = now - 3600
while t < now:
    cpu = round(random.uniform(3, 25), 1)
    if t % 1800 < 300:  # 偶发尖峰
        cpu = round(random.uniform(60, 95), 1)
    cur.execute("INSERT INTO resources(ts,cpu_percent,mem_used_mb,mem_percent,disk_used_mb,disk_percent,net_rx_bps,net_tx_bps) VALUES(?,?,?,?,?,?,?,?)",
                (t, cpu, round(random.uniform(200, 500), 1), round(random.uniform(25, 60), 1),
                 round(random.uniform(8000, 9000), 1), round(random.uniform(55, 65), 1),
                 random.randint(500, 200000), random.randint(200, 80000)))
    t += 60

# connections：近 30h
PT = {6: 'tcp', 17: 'udp'}
for i in range(300):
    ts = now - random.randint(0, 30 * 3600)
    ev = random.choice([1, 1, 1, 2, 3])
    proto = random.choice([6, 17])
    if ev == 3:
        # DESTROY：多为外部攻击者 → VPS
        sip, sport = random.choice(ATTACKERS), random.randint(1024, 65535)
        dip, dport = VPS_IP, random.choice([22, 22, 22, 3306, 8080, 6379, 80, 443])
    else:
        if random.random() < 0.4:
            sip, sport = random.choice(ATTACKERS), random.randint(1024, 65535)
            dip, dport = VPS_IP, random.choice([22, 22, 3306, 8080])
        else:
            sip, sport = VPS_IP, random.randint(1024, 65535)
            dip, dport = ipp(8, 8, 8, 8), 443
    cur.execute("INSERT INTO connections(ts,ev_type,proto,src_ip,src_port,dst_ip,dst_port,packets,bytes) VALUES(?,?,?,?,?,?,?,?,?)",
                (ts, ev, proto, sip, sport, dip, dport, random.randint(1, 500), random.randint(100, 500000)))

# ssh_attempts：近 30h，失败为主
for i in range(250):
    ts = now - random.randint(0, 30 * 3600)
    src = random.choice(ATTACKERS + [ipp(10, 0, 0, 8)])
    result = 0 if src in ATTACKERS else 1
    user = random.choice(['root', 'root', 'admin', 'ubuntu', 'postgres', 'oracle']) if result == 0 else 'deploy'
    meth = random.choice(['password', 'password', 'publickey', 'keyboard-interactive'])
    fp = '' if meth != 'publickey' else 'SHA256:' + ''.join(random.choice('abcdef0<WSL_ROOT_PASSWORD>789') for _ in range(43))
    det = 'Failed password for invalid user ' + user if result == 0 else 'Accepted password for ' + user
    cur.execute("INSERT INTO ssh_attempts(ts,src_ip,username,auth_method,result,fingerprint,detail) VALUES(?,?,?,?,?,?,?)",
                (ts, src, user, meth, result, fp, det))

# firewall_events：近 30h，drop 为主
for i in range(350):
    ts = now - random.randint(0, 30 * 3600)
    action = 'drop' if random.random() < 0.85 else 'accept'
    src = random.choice(ATTACKERS) if action == 'drop' else ipp(10, 0, 0, 8)
    dport = random.choice([22, 22, 22, 3306, 8080, 6379, 80, 443, 4444, 445])
    proto = random.choice([6, 6, 17])
    raw = 'IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=%d.%d.%d.%d DST=%d.%d.%d.%d LEN=52 TOS=0x00' % (
        src >> 24 & 255, src >> 16 & 255, src >> 8 & 255, src & 255,
        VPS_IP >> 24 & 255, VPS_IP >> 16 & 255, VPS_IP >> 8 & 255, VPS_IP & 255)
    cur.execute("INSERT INTO firewall_events(ts,chain,action,proto,src_ip,src_port,dst_ip,dst_port,raw) VALUES(?,?,?,?,?,?,?,?,?)",
                (ts, 'INPUT', action, proto, src, random.randint(1024, 65535), VPS_IP, dport, raw))

# ban_events：近 30h
for i in range(30):
    ts = now - random.randint(0, 30 * 3600)
    cur.execute("INSERT INTO ban_events(ts,ip,type,jail) VALUES(?,?,?,?)",
                (ts, random.choice(ATTACKERS), random.choice(['ban', 'ban', 'unban']), 'sshd'))

# system_events
for i in range(10):
    ts = now - random.randint(0, 24 * 3600)
    cur.execute("INSERT INTO system_events(ts,source,level,message) VALUES(?,?,?,?)",
                (ts, 'api', 'info', 'API 服务启动'))

conn.commit()
conn.close()
print("SEED OK:", DB)
