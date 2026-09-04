# TEST-HONEY-001 并发 200 上限真实测试（reviewer R-02 整改）
# 205 个独立 loopback 源 IP（127.0.0.101~255 + 127.0.1.1~50）各 1 连接
# → 每源 IP 1 连接不触发限速（10/分/IP），205 个同时活跃 → 触发蜜罐 maxConns=200 上限
# 判定：被 sem 拒绝（accept 后立即关闭）→ recv 立即返回 b''（EOF）；被接受 → recv 超时（服务端等待客户端数据）
# 预期：accepted=200 + rejected=5（与 maxConns=200 吻合）；agent health=200
import socket
import time
import sys
import urllib.request

PORT = 13306  # mysql 蜜罐端口（honeypot_test_config.json）
HEALTH = "http://127.0.0.1:18099/api/v1/health"

sources = ['127.0.0.%d' % i for i in range(101, 256)] + ['127.0.1.%d' % i for i in range(1, 51)]
assert len(sources) == 205, len(sources)

conns = []
for i, src in enumerate(sources):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.bind((src, 0))
        s.connect(('127.0.0.1', PORT))
        conns.append(s)
    except Exception as e:
        print('conn #%d (%s) fail: %s' % (i, src, str(e)[:40]))
print('TCP 建立=%d' % len(conns))

time.sleep(0.5)
accepted = 0
rejected = 0
other = 0
for s in conns:
    s.settimeout(2)
    try:
        d = s.recv(4096)
        if d == b'':
            rejected += 1
        else:
            accepted += 1
    except socket.timeout:
        accepted += 1
    except Exception:
        other += 1
print('accepted=%d rejected(立即EOF)=%d other=%d' % (accepted, rejected, other))
print('（预期 accepted=200（sem 上限） rejected=5）')

for s in conns:
    s.close()
try:
    h = urllib.request.urlopen(HEALTH, timeout=3).status
except Exception as e:
    h = "DOWN:" + str(e)[:30]
print('agent health=%s' % h)
sys.exit(0 if accepted == 200 else 1)
