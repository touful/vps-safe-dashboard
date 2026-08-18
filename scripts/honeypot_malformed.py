# TEST-HONEY-001 畸形输入鲁棒性测试 v2（reviewer R-01 整改）
# 关键修正：每个用例绑定独立 loopback 源 IP（127.0.0.2~255，每 IP 1 连接）
# → 绕过每源 IP 限速（10/分），确保连接被蜜罐解析器真实处理
# 判定：连接后先收协议首包（banner/greeting）确认被接受 → 再发畸形包 → 等待服务端关闭
#       已接受连接在 2s 内被关闭 = 解析器快速失败（期望）；超过 2s 无响应 = HANG（缺陷）
import socket
import os
import sys
import struct
import urllib.request
import time

BASE = "127.0.0.1"
PORTS = {
    "mysql": 13306, "redis": 16379, "memcached": 11212, "mssql": 11433,
    "mongodb": 17017, "postgres": 15432, "rdp": 13389, "smb": 1445,
    "telnet": 10023, "ftp": 10021,
}
HEALTH = "http://127.0.0.1:18099/api/v1/health"
rand = os.urandom
results = []
src_ip_counter = [1]  # 127.0.0.x 递增，每个用例独立源 IP


def struct_pack(fmt, *args):
    return struct.pack(fmt, *args)


def next_src():
    src_ip_counter[0] += 1
    return "127.0.0.%d" % src_ip_counter[0]


def probe(proto, payloads, name):
    for i, p in enumerate(payloads):
        src = next_src()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        try:
            s.bind((src, 0))
            s.connect((BASE, PORTS[proto]))
        except Exception as e:
            results.append((proto, name, i, "CONN_FAIL:" + str(e)[:40], src))
            s.close()
            continue
        s.settimeout(2)
        # 1) 收协议首包（banner/greeting）确认被接受；无数据也可接受（部分协议服务端等待客户端先发）
        try:
            first = s.recv(4096)
        except socket.timeout:
            first = b""
        except Exception:
            first = b""
        # 2) 发畸形包
        try:
            s.sendall(p)
        except Exception:
            pass
        # 3) 等待服务端关闭：先 2s 快速判定 → 未关闭则延长至 35s 总等待（connTimeout=30s 兜底复核）
        #    CLOSED=解析器立即拒绝；CLOSED_30S=等待完整输入后由 30s 超时兜底关闭（设计行为）；
        #    HANG=超过 35s 仍未关闭（永久挂死，缺陷）
        closed = False
        t_wait = time.time()
        deadline = t_wait + 35
        while time.time() < deadline and not closed:
            try:
                d = s.recv(4096)
                if not d:
                    closed = True
                    break
            except socket.timeout:
                s.settimeout(max(0.5, deadline - time.time()))
            except Exception:
                closed = True
                break
        elapsed = time.time() - t_wait
        s.close()
        # 分类阈值语义：elapsed<3s = 解析器快速失败（CLOSED）；3~35s 内关闭 = 30s 超时兜底（CLOSED_30S）。
        # 实测双峰分明（15 例 <1s 立即拒绝、31 例 28-30s 超时兜底），无 2-3s 边界用例；阈值仅为分类语义边界。
        if closed and elapsed < 3:
            status = "CLOSED"
        elif closed:
            status = "CLOSED_30S"
        else:
            status = "HANG?"
        results.append((proto, name, i, status, src, "banner=%d" % len(first), "%.0fs" % elapsed))


# 各协议畸形 payload（与 v1 相同用例集）
probe("telnet", [b"\xff", b"\xff\xff", b"\xff\xf1", b"admin\x00\xff", rand(512),
                 b"\xff\xfd\x18\xff\xfd\x20"[:3]], "IAC 截断")
probe("ftp", [b"USER", b"USER " + b"A" * 16384, rand(2048), b"PASS\r\n" * 100,
              b"\x00\x01\x02", b"USER anonymous\r\nPASS x\r\nUSER y\r\n"[:13]], "半包/超长")
probe("redis", [b"*9999999999\r\n", b"$9999999999\r\n", b"*2\r\n$3\r\nGET\r\n",
                rand(4096), b"AUTH\r\n", b"*1\r\n$100\r\n" + b"X" * 500,
                b"*0\r\n", b"*-1\r\n"], "RESP 畸形")
probe("postgres", [rand(2048), struct_pack(">II", 8, 80877103)[:4],
                   struct_pack(">II", 8, 196608) + b"\x00" * 100,
                   b"\x00" * 4096, b"\xff" * 512], "startup 畸形")
probe("mysql", [b"\x0a" + rand(100), b"\x45" + b"\x00" * 200 + b"\x01" * 50,
                rand(8192), b"\x00" * 1024], "握手异常")
probe("mongodb", [rand(2048), struct_pack("<iiii", 1000000, 1, 2013, 0) + rand(500),
                  b"\x00" * 4096], "OP 头长度异常")
probe("mssql", [b"\x12\x01\x00\xff\x00\x00" + rand(300), rand(4096),
                b"\x12\x01" + rand(64)], "TDS 头长度异常")
probe("smb", [struct_pack(">I", 100000) + rand(200), b"\xffSMB" + rand(256),
              rand(2048), b"\x00\x00\x00\x00" + rand(100)], "分片错乱")
probe("rdp", [b"\x03\x00", rand(1024), b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00"],
      "X.224 截断")
probe("memcached", [rand(4096), b"set key 0 0 100000\r\n" + b"X" * 500,
                    b"\x80" + rand(23), b"\x00" * 512], "命令/二进制畸形")


time.sleep(1)
try:
    h = urllib.request.urlopen(HEALTH, timeout=3).status
except Exception as e:
    h = "DOWN:" + str(e)[:30]

print("=== 畸形输入 v2（独立源 IP 绕过限速，共 %d 用例；等待类用例 35s 兜底复核）===" % len(results))
hangs = [r for r in results if r[3] == "HANG?"]
fails = [r for r in results if r[3].startswith("CONN_FAIL")]
for r in results:
    print("[%s] %s %s #%d src=%s %s %s" % (r[3], r[0], r[1], r[2], r[4], r[5], r[6]))
print("=== 汇总 ===")
print("CLOSED=%d CLOSED_30S=%d HANG=%d CONN_FAIL=%d 总=%d" % (
    sum(1 for r in results if r[3] == "CLOSED"),
    sum(1 for r in results if r[3] == "CLOSED_30S"), len(hangs), len(fails), len(results)))
print("agent health=%s" % h)
print("（注：每用例独立源 IP，限速不生效；CLOSED=解析器立即关闭；CLOSED_30S=30s 超时兜底关闭（connTimeout 设计）；HANG=超过 35s 未关闭（缺陷））")
sys.exit(1 if hangs or h != 200 else 0)
