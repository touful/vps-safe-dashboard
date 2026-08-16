# DEV-017 回归：firewall/timeline 聚合与明细 SQL 对照（TEST-006）
import sqlite3, time, os, tempfile

DB = os.environ.get("DEV015_DB", os.path.join(tempfile.gettempdir(), "opencode", "dev015", "state.db"))
db = sqlite3.connect(DB)
now = int(time.time())
from_ = now - 86400
fb = (from_ // 3600) * 3600
rows = db.execute(
    "SELECT (ts/3600)*3600 AS hour, "
    "SUM(CASE WHEN action='drop' THEN 1 ELSE 0 END), "
    "SUM(CASE WHEN action='accept' THEN 1 ELSE 0 END) "
    "FROM firewall_events WHERE ts>=? GROUP BY hour ORDER BY hour", (fb,)).fetchall()
print("SQL 有数据桶数:", len(rows))
for r in rows[:5]:
    print(" ", r[0], "drop=", r[1], "accept=", r[2])
# 全部桶 drop/accept 合计 vs 明细 COUNT
total_drop = sum(r[1] for r in rows)
total_accept = sum(r[2] for r in rows)
cnt_drop = db.execute("SELECT COUNT(*) FROM firewall_events WHERE ts>=? AND action='drop'", (fb,)).fetchone()[0]
cnt_accept = db.execute("SELECT COUNT(*) FROM firewall_events WHERE ts>=? AND action='accept'", (fb,)).fetchone()[0]
print("聚合合计 drop/accept:", total_drop, total_accept)
print("明细 COUNT drop/accept:", cnt_drop, cnt_accept)
print("一致性:", "PASS" if (total_drop == cnt_drop and total_accept == cnt_accept) else "FAIL")
# 补零验证：期望桶数 = (now_floor - fb)/3600 + 1
now_floor = (now // 3600) * 3600
expect = (now_floor - fb) // 3600 + 1
print(f"期望桶数(含当前小时): {expect}")
db.close()
