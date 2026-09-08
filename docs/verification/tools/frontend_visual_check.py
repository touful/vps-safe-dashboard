"""前端视觉回归：受控 API 样例 + 真实 Chromium，不连接生产采集服务。"""
import argparse
import base64
import hashlib
import json
import math
import threading
import time
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from playwright.sync_api import sync_playwright, expect


def fixture(path, query, empty=False):
    now = int(time.time())
    ports = [{"dst_port": p, "hits": n} for p, n in [(22, 1824), (443, 936), (3306, 642), (6379, 418), (8080, 216)]]
    sources = [{"src_ip": 3405803777 + i, "hits": n} for i, n in enumerate([1482, 864, 531, 276, 128])]
    ssh = [{"ts": now - (23-i)*3600, "hits": 0 if empty else int(18+12*math.sin(i)+i*2)} for i in range(24)]
    firewall = [{"ts": r["ts"], "inbound": 0 if empty else int(72+40*math.sin(i*.8)+i*6), "drop": 0 if empty else i % 5, "reject": 0} for i, r in enumerate(ssh)]
    if path.endswith("/health"):
        return {"retention_days": 7}
    if path.endswith("/summary"):
        return {"active_conns": 37, "fw_events": 0 if empty else 4036, "ssh_fail": 0 if empty else 86, "disk_percent": 42.8, "top_ports": [] if empty else ports}
    if path.endswith("/resources"):
        return {"points": [{"ts": now-(59-i)*60, "cpu": 14+9*math.sin(i*.6), "mem": 38+math.sin(i)*2, "disk": 42.8, "net_rx_bps": 45000+i*100, "net_tx_bps": 18000+i*60} for i in range(60)]}
    if path.endswith("/top_ports"):
        return {"rows": [] if empty else ports}
    if path.endswith("/top_sources"):
        return {"rows": [] if empty else sources}
    if path.endswith("/ssh/timeline"):
        return {"rows": ssh}
    if path.endswith("/firewall/timeline"):
        return {"range": query.get("range", ["24h"])[0], "buckets": firewall}
    if path.endswith("/attacks/geo"):
        return {"mmdb_ok": True, "rows": [] if empty else [{"ip": "203.0.113."+str(i+1), "country_code": code, "country_name": name, "count": n} for i, (code, name, n) in enumerate([("US", "美国", 52), ("CN", "中国", 24), ("DE", "德国", 10)])]}
    if path.endswith("/bans/active"):
        return {"rows": [] if empty else ["203.0.113.1", "198.51.100.42"]}
    if path.endswith("/channels"):
        return {"now": now, "retention_days": 7, "db_size_mb": 18.6, "overrun_total": 0, "tables": [{"name": name, "last_ts": now-8-i*6} for i, name in enumerate(["connections", "ssh_attempts", "firewall_events", "ban_events", "cred_events", "resources", "system_events"])], "recent_warnings": []}
    if path.endswith("/ip"):
        return {"country": {"name": "文档示例地址"}, "ssh": {"total": 14, "failed": 14}, "connections": {"total": 28}, "banned_now": True}
    if empty:
        return {"rows": []}
    if path.endswith("/snapshot"):
        return {"rows": [{"proto": "tcp", "state": "ESTAB", "src_ip": "203.0.113.1", "src_port": 52432, "dst_ip": "192.0.2.10", "dst_port": 443, "pid": 1024}]}
    if path.endswith("/connections"):
        return {"rows": [{"ts": now, "src_ip": 3405803777, "dst_ip": 3221225994, "src_port": 52432, "dst_port": 443, "proto": 6, "ev_type": 1, "packets": 8, "bytes": 4096}]}
    if path.endswith("/ssh"):
        return {"rows": [{"ts": now-i*90, "src_ip": 3405803777+i, "username": "root", "auth_method": "password", "result": 0, "detail": "认证失败", "fingerprint": ""} for i in range(5)]}
    if path.endswith("/firewall"):
        return {"rows": [{"ts": now-i*65, "src_ip": 3405803777+i, "dst_ip": 3221225994, "src_port": 50234, "dst_port": 22, "proto": 6, "chain": "INPUT", "action": "drop", "raw": "示例外部探测事件"} for i in range(5)]}
    if path.endswith("/honeypot/creds"):
        return {"rows": [{"proto": "redis", "username": "default", "password": "example-only", "kind": "plaintext", "count": 6, "first_ts": now-3600, "last_ts": now-60, "src_ip_cnt": 2}]}
    if path.endswith("/honeypot/events"):
        return {"rows": [{"ts": now, "proto": "redis", "src_ip": "203.0.113.1", "username": "default", "password": "example-only", "extra": "示例捕获数据"}]}
    raise AssertionError("未覆盖的 API：" + path)


def run(base, output):
    output.mkdir(parents=True, exist_ok=True)
    checks, errors, console_errors, requests = [], [], [], []
    mode = {"empty": False, "error": False}
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce", accept_downloads=True)
        def api(route):
            parsed = urlparse(route.request.url)
            requests.append(parsed.path + "?" + parsed.query)
            if mode["error"]:
                route.fulfill(status=503, json={"error": "受控失败场景"})
            elif "/export/" in parsed.path:
                route.fulfill(status=200, content_type="text/csv", headers={"Content-Disposition": "attachment; filename=fixture.csv"}, body="203.0.113.1,2026-09-08 12:00:00,22\n")
            else:
                route.fulfill(json=fixture(parsed.path, parse_qs(parsed.query), mode["empty"]))
        context.route("**/api/v1/**", api)
        page = context.new_page()
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)
        page.goto(base, wait_until="networkidle")
        expect(page.locator("#today-fw")).to_have_text("4036")
        expect(page.locator("#conn-status")).to_have_text("WS 实时")
        assert page.locator("#chart-attack-trend canvas").count() == 1
        checks.append("受控数据加载、WS 连接状态与 ECharts 渲染")
        expect(page.locator('nav button[data-panel="overview"]')).to_have_attribute("aria-current", "page")
        page.screenshot(path=str(output / "overview-desktop.png"), full_page=True)
        page.screenshot(path=str(output / "overview-viewport.png"))

        def panel(name):
            page.locator('nav button[data-panel="' + name + '"]').click()
            expect(page.locator("#panel-" + name)).to_be_visible()
            expect(page.locator("#panel-" + name + " h2")).to_be_focused()

        panel("conn")
        expect(page.locator("#snap-table tbody")).to_contain_text("203.0.113.1")
        page.locator("#fold-toggle-conn-table").click()
        expect(page.locator("#conn-table tbody")).to_contain_text("NEW")
        page.screenshot(path=str(output / "connections-desktop.png"), full_page=True)
        panel("attack")
        for table in ["ssh-table", "fw-table", "hp-table"]:
            page.locator("#fold-toggle-" + table).click()
            expect(page.locator("#" + table + " tbody tr").first).to_be_visible()
        expect(page.locator("#hp-table .hp-pw.masked")).to_be_visible()
        page.locator("#hp-table .hp-pw").click()
        expect(page.locator("#hp-table .hp-pw")).to_have_text("example-only")
        page.locator("#hp-table .hp-pw").click()
        page.locator("#ssh-table .ip-prof").first.click()
        expect(page.locator("#ip-prof-modal")).to_be_visible()
        expect(page.locator("#ip-prof-body")).to_contain_text("14")
        page.get_by_role("button", name="关闭画像", exact=True).click()
        expect(page.locator("#ip-prof-modal")).to_be_hidden()
        page.locator("#geo-country-filter").select_option("US")
        expect(page.locator("#geo-sources-list")).to_contain_text("美国")
        page.locator("#geo-country-filter").select_option("")
        checks.append("四页导航焦点、明细展开、密码遮蔽、IP 画像与国家筛选")
        page.screenshot(path=str(output / "attack-desktop.png"), full_page=True)

        panel("overview")
        page.locator("#top-ports-mini li").first.click()
        expect(page.locator("#panel-attack")).to_be_visible()
        expect(page.locator("#filter-chip")).to_contain_text(":22")
        page.locator("#filter-chip").focus()
        page.keyboard.press("Enter")
        expect(page.locator("#filter-chip")).to_be_hidden()
        for name in ["1h", "7d", "30d", "24h"]:
            page.locator('[data-range="' + name + '"]').click()
            expect(page.locator('[data-range="' + name + '"]')).to_have_attribute("aria-pressed", "true")
        checks.append("端口跨页联动、键盘清除过滤与四档时间范围")
        panel("export")
        page.locator('[data-export-range="7d"]').click()
        expect(page.locator('[data-export-range="7d"]')).to_have_attribute("aria-pressed", "true")
        page.locator('[data-export-range="24h"]').click()
        page.screenshot(path=str(output / "export-desktop.png"), full_page=True)
        with page.expect_download() as info:
            page.locator("#export-btn").click()
        assert info.value.suggested_filename.endswith(".csv")
        expect(page.locator("#export-msg")).to_contain_text("成功")
        page.locator("#export-from").fill("2026-09-08T14:00")
        page.locator("#export-to").fill("2026-09-08T13:00")
        expect(page.locator('.export-range[aria-pressed="true"]')).to_have_count(0)
        page.locator("#export-btn").click()
        expect(page.locator("#export-msg")).to_contain_text("开始时间不能晚于结束时间")
        checks.append("CSV 下载与自定义时间范围校验（受控下载内容）")

        for width in [1920, 1440, 1024, 900, 768, 640, 390, 375, 360, 320]:
            page.set_viewport_size({"width": width, "height": 900})
            for name in ["overview", "conn", "attack", "export"]:
                panel(name)
                dimensions = page.evaluate("({width: innerWidth, scroll: document.documentElement.scrollWidth})")
                assert dimensions["scroll"] <= width, (width, name, dimensions)
                assert page.locator(".panel.active").count() == 1
            checks.append(str(width) + "px 四页无整页横向溢出")
        page.set_viewport_size({"width": 390, "height": 844})
        panel("overview")
        page.screenshot(path=str(output / "overview-mobile.png"), full_page=True)
        mode["empty"] = True
        page.reload(wait_until="networkidle")
        expect(page.locator("#zero-attack-badge")).to_be_visible()
        expect(page.locator("#today-fw")).to_have_text("0")
        checks.append("零攻击状态与零值展示")
        mode["error"] = True
        page.reload(wait_until="networkidle")
        expect(page.locator("#today-fw")).to_have_text("--")
        expect(page.locator("#error-banner")).to_be_visible()
        checks.append("HTTP 503 失败状态，不误呈现正常零值")
        assert not errors, errors
        unexpected = [e for e in console_errors if "503" not in e]
        assert not unexpected, unexpected
        checks.append("无未捕获 JS 错误、无 CSP 错误；预期 503 已单列")
        report = {"status": "PASS", "browser": browser.version, "data": "受控样例，非生产数据", "checks": checks, "page_errors": errors, "expected_503_count": len(console_errors), "request_count": len(requests)}
        (output / "results.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps(report, ensure_ascii=False, indent=2))
        browser.close()


class PreviewHandler(SimpleHTTPRequestHandler):
    """仅用于本机预览的静态服务器，支持真实 WebSocket 握手。"""
    def end_headers(self):
        # 与正式 Handler 一致的 CSP，验证内嵌样式与本地资源兼容性。
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws://127.0.0.1:18765; font-src 'self'")
        super().end_headers()

    def do_GET(self):
        if self.path == "/ws" and self.headers.get("Upgrade", "").lower() == "websocket":
            key = self.headers["Sec-WebSocket-Key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
            self.send_response(101)
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", base64.b64encode(hashlib.sha1(key.encode()).digest()).decode())
            self.end_headers()
            self.connection.settimeout(60)
            try:
                while self.connection.recv(4096):
                    pass
            except (OSError, TimeoutError):
                pass
            return
        super().do_GET()

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:18765")
    parser.add_argument("--output", type=Path, default=Path(".dev-fe-test"))
    parser.add_argument("--serve", action="store_true", help="启动仅监听本机的临时静态 / WS 握手服务器")
    args = parser.parse_args()
    server = None
    if args.serve:
        static = Path(__file__).resolve().parents[3] / "internal/web/static"
        server = ThreadingHTTPServer(("127.0.0.1", 18765), partial(PreviewHandler, directory=str(static)))
        threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        run(args.base_url.rstrip("/"), args.output)
    finally:
        if server:
            server.shutdown()
            server.server_close()
