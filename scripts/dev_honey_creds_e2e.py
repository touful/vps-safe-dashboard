# -*- coding: utf-8 -*-
"""DEV-HONEY-002 端到端验证：模拟攻击客户端 → 蜜罐捕获 → 凭据字典聚合（去重）→ 导出三格式。

前置：
  1. 用 .dev015-test/cfg_honey2.json 启动 sentry-agent（蜜罐启用，web 127.0.0.1:18199）；
  2. hack 环境 Python 3.8 直接运行本脚本。

验证点：
  - 明文协议（telnet/ftp/redis/postgres）捕获明文凭据，重复尝试聚合去重（count/首见/最近）；
  - mssql TDS 混淆密码还原明文（nibble-swap + XOR 0xA5，与 impacket 同构混淆）；
  - mysql 仅捕获不可逆摘要（kind=hash）；
  - memcached 无认证（kind=none）；
  - /api/v1/export/creds 三格式：csv 全量 / pairs 仅明文 / passwords 跨协议去重。
"""
import json
import socket
import struct
import sys
import time
import urllib.request

BASE = "127.0.0.1"
PORTS = {
    "mysql": 13306, "redis": 16379, "memcached": 11212, "mssql": 11433,
    "postgres": 15432, "telnet": 10023, "ftp": 10021,
}
API = "http://127.0.0.1:18199"

FAILS = []


def check(cond, msg):
    if cond:
        print("  [PASS] %s" % msg)
    else:
        print("  [FAIL] %s" % msg)
        FAILS.append(msg)


# ---------- 协议攻击客户端（凭据参数化；重复调用=同一凭据多次尝试） ----------

def recv_until(s, marker, timeout=5):
    """读至出现 marker（TCP 分包时序无关；超时返回已收内容）。"""
    s.settimeout(timeout)
    buf = b""
    while marker not in buf:
        chunk = s.recv(256)
        if not chunk:
            break
        buf += chunk
    return buf


def attack_telnet(user, pw):
    s = socket.create_connection((BASE, PORTS["telnet"]), timeout=5)
    recv_until(s, b"login: ")
    s.sendall((user + "\r\n").encode())
    recv_until(s, b"Password: ")
    s.sendall((pw + "\r\n").encode())
    recv_until(s, b"incorrect")
    s.close()


def attack_ftp(user, pw):
    s = socket.create_connection((BASE, PORTS["ftp"]), timeout=5)
    recv_until(s, b"220")
    s.sendall(("USER " + user + "\r\n").encode())
    recv_until(s, b"331")
    s.sendall(("PASS " + pw + "\r\n").encode())
    recv_until(s, b"530")
    s.close()


def attack_redis(user, pw):
    s = socket.create_connection((BASE, PORTS["redis"]), timeout=5)
    s.sendall(("*3\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n"
               % (len(user), user, len(pw), pw)).encode())
    s.recv(128)
    s.close()


def recv_exact(s, n, timeout=5):
    """定长读满（防 TCP 短读）。"""
    s.settimeout(timeout)
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def attack_postgres(user, pw):
    s = socket.create_connection((BASE, PORTS["postgres"]), timeout=5)
    params = b"user\x00" + user.encode() + b"\x00database\x00db\x00\x00"
    startup = struct.pack(">I", 8 + len(params)) + struct.pack(">I", 196608) + params
    s.sendall(startup)
    recv_exact(s, 9)       # AuthenticationCleartextPassword
    pmsg = b"p" + struct.pack(">I", len(pw) + 1) + pw.encode() + b"\x00"
    s.sendall(pmsg)
    s.recv(256)            # ErrorResponse
    s.close()


def attack_mysql(user, pw_hex):
    s = socket.create_connection((BASE, PORTS["mysql"]), timeout=5)
    hdr = recv_exact(s, 4)  # HandshakeV10 头
    body_len = hdr[0] | hdr[1] << 8 | hdr[2] << 16
    recv_exact(s, body_len)  # greeting
    auth = bytes.fromhex(pw_hex)
    payload = struct.pack("<IIB23x", 0x0000C800, 1 << 24, 45)
    payload += user.encode() + b"\x00" + bytes([len(auth)]) + auth + b"\x00mysql_native_password\x00"
    s.sendall(struct.pack("<I", len(payload))[0:3] + b"\x01" + payload)
    s.recv(256)            # ERR 1045
    s.close()


def tds_obfuscate(pw):
    """[MS-TDS] 2.2.6.3 混淆：UTF-16LE → 每字节 nibble-swap → XOR 0xA5（impacket 同构）。"""
    raw = pw.encode("utf-16le")
    return bytes((((b & 0x0F) << 4) | ((b & 0xF0) >> 4)) ^ 0xA5 for b in raw)


def attack_mssql(user, pw):
    s = socket.create_connection((BASE, PORTS["mssql"]), timeout=5)

    def tds_pkt(ptype, payload):
        return bytes([ptype, 0x01]) + struct.pack(">H", 8 + len(payload)) + b"\x00\x00\x01\x00" + payload

    def read_tds():
        hdr = recv_exact(s, 8)
        if len(hdr) < 8:
            return b""
        ln = struct.unpack(">H", hdr[2:4])[0] - 8
        return hdr[:1] + recv_exact(s, ln) if ln > 0 else hdr[:1]

    # Prelogin 请求（VERSION 选项）→ 读 Prelogin Response
    pre = b"\x00\x00\x00\x0a\x00\x00" + b"\x00\x00\x00\x00" + b"\x07\x04\x00\x00\x00\x00"
    s.sendall(tds_pkt(0x12, pre))
    read_tds()
    obf = tds_obfuscate(pw)
    host, user16 = b"PC1", user.encode("utf-16le")
    data_off = 36 + 20
    login = bytearray(36 + 20 + len(host) + len(user16) + len(obf))
    login[4:8] = b"\x04\x00\x00\x74"
    def put(off, v):
        struct.pack_into(">H", login, off, v)
    put(36, dataOff := data_off); put(38, len(host))
    put(40, data_off + len(host)); put(42, len(user16))
    put(44, data_off + len(host) + len(user16)); put(46, len(obf))
    pos = data_off
    login[pos:pos + len(host)] = host; pos += len(host)
    login[pos:pos + len(user16)] = user16; pos += len(user16)
    login[pos:pos + len(obf)] = obf
    struct.pack_into(">I", login, 0, len(login))
    s.sendall(tds_pkt(0x10, bytes(login)))
    read_tds()            # ERROR 18456
    s.close()


def attack_memcached():
    s = socket.create_connection((BASE, PORTS["memcached"]), timeout=5)
    s.sendall(b"get foo\r\n")
    s.recv(64)
    s.close()


# ---------- API 断言 ----------

def api_get(path):
    """GET 返回 (status, body)；4xx 不抛异常（负向断言需要读状态码）。"""
    try:
        with urllib.request.urlopen(API + path, timeout=10) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def wait_creds(expected_groups, timeout_s=15):
    """轮询聚合 API 直至组数达到期望（批量落库 500ms 间隔 + 轮询缓冲）。"""
    deadline = time.time() + timeout_s
    rows = []
    while time.time() < deadline:
        _, body = api_get("/api/v1/honeypot/creds?range=1h&limit=500")
        rows = json.loads(body).get("rows") or []
        if len(rows) >= expected_groups:
            return rows
        time.sleep(0.5)
    return rows


def main():
    print("== 1. 模拟攻击（明文协议重复尝试 → 去重验证）==")
    attack_telnet("root", "toor2025")
    attack_telnet("root", "toor2025")
    attack_telnet("root", "toor2025")     # 同凭据 3 次 → 聚合 count=3
    attack_ftp("ftpadmin", "Ftp@123")
    attack_ftp("ftpadmin", "Ftp@123")     # 同凭据 2 次 → count=2
    attack_redis("redis", "Redis#456")
    attack_postgres("pguser", "Pg$789")
    attack_mysql("root", "aabbccddeeff00112233445566778899aabbccdd")  # SHA1 摘要（hash）
    attack_mssql("sa", "P@ssw0rd!")       # TDS 混淆 → 还原明文
    attack_memcached()                    # 无认证 → none
    print("  攻击完成：7 协议 10 连接")

    print("== 2. 聚合字典 API（去重 + kind 分类）==")
    # 期望组数：telnet 1 + ftp 1 + redis 1 + pg 1 + mysql 1 + mssql 1 + memcached 1 = 7
    rows = wait_creds(7)
    check(len(rows) == 7, "聚合组数 = %d（期望 7）" % len(rows))
    by = {}
    for r in rows:
        by[(r["proto"], r["username"], r["password"])] = r
    t = by.get(("telnet", "root", "toor2025"))
    actual_t = (t["count"], t["kind"]) if t else None
    check(t is not None and t["count"] == 3 and t["kind"] == "plaintext",
          "telnet root/toor2025 聚合 count=3 kind=plaintext（实际 %s）" % (actual_t,))
    check(t is not None and t["first_ts"] > 0 and t["last_ts"] >= t["first_ts"], "first_ts/last_ts 字段有效")
    f = by.get(("ftp", "ftpadmin", "Ftp@123"))
    check(f is not None and f["count"] == 2, "ftp ftpadmin/Ftp@123 count=2（实际 %s）" % (f and f["count"]))
    r3 = by.get(("redis", "redis", "Redis#456"))
    check(r3 is not None and r3["kind"] == "plaintext", "redis 明文捕获")
    p = by.get(("postgres", "pguser", "Pg$789"))
    check(p is not None and p["kind"] == "plaintext", "postgres 明文捕获")
    m = by.get(("mysql", "root", "aabbccddeeff00112233445566778899aabbccdd"))
    check(m is not None and m["kind"] == "hash", "mysql kind=hash（摘要不可逆）")
    ms = by.get(("mssql", "sa", "P@ssw0rd!"))
    actual_ms = (ms["username"], ms["password"], ms["kind"]) if ms else None
    check(ms is not None and ms["kind"] == "plaintext",
          "mssql sa/P@ssw0rd! 还原明文捕获（实际 %s）" % (actual_ms,))
    mem = None
    for r in rows:
        if r["proto"] == "memcached":
            mem = r
    check(mem is not None and mem["kind"] == "none", "memcached kind=none")

    print("== 3. 导出三格式 ==")
    _, pairs = api_get("/api/v1/export/creds?format=pairs&range=1h")
    lines = [ln for ln in pairs.split("\n") if ln]
    check("root:toor2025" in lines and "sa:P@ssw0rd!" in lines and "ftpadmin:Ftp@123" in lines,
          "pairs 含全部明文凭据（%d 行）" % len(lines))
    check(not any(":aabbccdd" in ln for ln in lines), "pairs 不含 mysql 摘要条目")
    _, passwords = api_get("/api/v1/export/creds?format=passwords&range=1h")
    plines = [ln for ln in passwords.split("\n") if ln]
    check("toor2025" in plines and "P@ssw0rd!" in plines, "passwords 含明文密码（%d 行）" % len(plines))
    check(len(plines) == len(set(plines)), "passwords 无重复行")
    code, _ = api_get("/api/v1/export/creds?format=bogus&range=1h")
    check(code == 400, "非法 format 返回 400（实际 %d）" % code)
    _, csv_body = api_get("/api/v1/export/creds?format=csv&range=1h")
    check(csv_body.startswith("username,password,protocol,kind"), "csv 表头正确")
    check("P@ssw0rd!,mssql,plaintext" in csv_body, "csv 含 mssql 明文条目")
    check(",mysql,hash" in csv_body, "csv 含 mysql hash 条目")

    print()
    if FAILS:
        print("结果：FAIL（%d 项）" % len(FAILS))
        sys.exit(1)
    print("结果：全部通过")


if __name__ == "__main__":
    main()
