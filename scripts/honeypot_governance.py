# TEST-HONEY-001 连接治理实测：限速(10/分/IP) + 30s 超时
import socket
import time
import sys

BASE = "127.0.0.1"   # 监听地址（窗口已过 1 分钟重置期，配额已清）
PORT = 13306          # mysql 端口


def try_conn(idx):
    try:
        s = socket.create_connection((BASE, PORT), timeout=3)
        s.close()
        return "ACCEPT"
    except Exception as e:
        return "REJECT:" + str(e)[:30]


print("=== 限速：127.0.0.1 连续 12 连 mysql（窗口 1 分钟）===")
r = [try_conn(i) for i in range(12)]
for i, x in enumerate(r):
    print("  #%d %s" % (i + 1, x))
accepts = sum(1 for x in r if x == "ACCEPT")
print("ACCEPT=%d（预期 10） REJECT=%d（预期 2）" % (accepts, len(r) - accepts))
rl_ok = accepts == 10

print("=== 30s 超时：半开连接等待服务端关闭 ===")
s = socket.create_connection((BASE, PORT), timeout=5)
s.settimeout(40)
t0 = time.time()
closed = False
try:
    while True:
        d = s.recv(4096)
        if not d:
            closed = True
            break
except socket.timeout:
    closed = False
except Exception:
    closed = True
elapsed = time.time() - t0
s.close()
print("半开连接在 %.1fs 后被%s（预期 ~30s 服务端关闭）" % (elapsed, "服务端关闭" if closed else "超时未关(挂死)"))
timeout_ok = closed and 28 <= elapsed <= 33

print("限速=%s 超时=%s" % ("PASS" if rl_ok else "FAIL", "PASS" if timeout_ok else "FAIL"))
sys.exit(0 if rl_ok and timeout_ok else 1)
