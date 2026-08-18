# TEST-HONEY-001 连接治理实测 v2：限速(10/分/IP) + 30s 超时（修正判定）
# 判定方法：限速拒绝 = accept 后立即 Close → 客户端 recv 立即 EOF(≈0s)
#           正常接受 = 蜜罐等待客户端数据 → recv 超时(2s) 或收到协议数据
import socket
import time
import sys

BASE = "127.0.0.1"
PORT = 13306


def classify(idx, wait=2.0):
    s = socket.create_connection((BASE, PORT), timeout=5)
    s.settimeout(wait)
    t0 = time.time()
    try:
        d = s.recv(4096)
        if d == b"":
            elapsed = time.time() - t0
            s.close()
            return ("REJECT", elapsed)  # 立即 EOF = 限速/并发拒绝
        elapsed = time.time() - t0
        s.close()
        return ("DATA", elapsed)  # 收到协议数据 = 已接受
    except socket.timeout:
        elapsed = time.time() - t0
        s.close()
        return ("ACCEPT", elapsed)  # 超时无 EOF = 已接受等待客户端
    except Exception:
        s.close()
        return ("ERR", time.time() - t0)


print("=== 限速：连续 12 连（窗口内）===")
res = [classify(i) for i in range(12)]
for i, (k, t) in enumerate(res):
    print("  #%d %s (%.1fs)" % (i + 1, k, t))
accepts = sum(1 for k, _ in res if k in ("ACCEPT", "DATA"))
rejects = sum(1 for k, _ in res if k == "REJECT")
print("ACCEPT=%d（预期 10） REJECT=%d（预期 2）" % (accepts, rejects))
rl_ok = accepts == 10 and rejects == 2

print("=== 30s 超时：等待被接受连接的超时关闭 ===")
# 需要先在已接受连接上验证：当前窗口配额已满（10 已用）——等待窗口重置再测超时
print("等待限速窗口重置（65s）...")
time.sleep(65)
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
print("半开连接在 %.1fs 后%s（预期 ~30s 服务端超时关闭）" % (elapsed, "服务端关闭" if closed else "超时未关"))
timeout_ok = closed and 28 <= elapsed <= 33

print("限速=%s 超时=%s" % ("PASS" if rl_ok else "FAIL", "PASS" if timeout_ok else "FAIL"))
sys.exit(0 if rl_ok and timeout_ok else 1)
