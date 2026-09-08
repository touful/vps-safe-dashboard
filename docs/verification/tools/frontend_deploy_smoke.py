"""真实服务前端发布复验：不替换 API，区分脚本异常与 HTTP 故障。"""
import argparse
import hashlib
import json
from pathlib import Path
import urllib.request

from playwright.sync_api import sync_playwright


def run(args):
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    report = {"target": args.url, "revision": args.revision, "checks": [],
              "failures": [], "http_errors": [], "page_errors": [], "console_errors": [],
              "viewports": [], "ws_messages": 0}
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    def check(name, condition):
        report["checks" if condition else "failures"].append(name)
    for path, expected in (("/", args.index_sha), ("/app.js", args.app_sha)):
        with opener.open(args.url + path, timeout=20) as response:
            check("asset_hash:" + path, response.status == 200 and hashlib.sha256(response.read()).hexdigest() == expected)
    with opener.open(args.url + "/api/v1/health", timeout=20) as response:
        check("health", json.load(response).get("ok") is True)
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce", accept_downloads=True)
        def websocket(ws):
            ws.on("framereceived", lambda _: report.update(ws_messages=report["ws_messages"] + 1))
        def response_received(response):
            if "/api/" in response.url and response.status >= 400:
                # 只记录路径、查询范围和状态，不记录任何响应数据或凭据。
                report["http_errors"].append({"path": response.url.split("/api/", 1)[1], "status": response.status})
        page.on("websocket", websocket)
        page.on("response", response_received)
        page.on("pageerror", lambda error: report["page_errors"].append(str(error)))
        page.on("console", lambda message: report["console_errors"].append(message.text) if message.type == "error" else None)
        page.goto(args.url, wait_until="domcontentloaded")
        # 真实点击切换到轻量窗口；初始默认 24h 请求仍原样执行并记录其错误。
        page.locator('#range-bar [data-range="1h"]').click()
        page.wait_for_load_state("networkidle", timeout=40000)
        page.wait_for_timeout(2000)
        report["startup_http_errors"] = len(report["http_errors"])
        check("range_1h", page.locator('#range-bar [data-range="1h"]').get_attribute("aria-pressed") == "true")
        check("ws_live", report["ws_messages"] > 0 and "WS" in page.locator("#conn-status").inner_text())
        check("overview_summary_loaded", page.locator("#today-fw").inner_text().strip().isdigit())
        for width in (1440, 900, 390, 320):
            page.set_viewport_size({"width": width, "height": 1000})
            for panel in ("overview", "conn", "attack", "export"):
                page.locator('nav [data-panel="' + panel + '"]').click()
                page.wait_for_timeout(2000)
                check("visible:" + panel + ":" + str(width), page.locator("#panel-" + panel).is_visible())
                size = page.evaluate("({width:innerWidth, scroll:Math.max(document.documentElement.scrollWidth,document.body.scrollWidth)})")
                check("overflow:" + panel + ":" + str(width), size["scroll"] <= width + 1)
                if panel == "overview":
                    cards = page.locator(".stat .kpi").evaluate_all("els => els.map(e => {const r=e.getBoundingClientRect();return {x:r.x,y:r.y,width:r.width,height:r.height}})")
                    report["viewports"].append({"width": width, "cards": cards})
                    if width == 1440:
                        check("desktop_kpi_five_columns", len(cards) == 5 and max(c["y"] for c in cards) - min(c["y"] for c in cards) < 2)
                    if width in (390, 320):
                        check("mobile_kpi_two_columns:" + str(width), abs(cards[0]["y"] - cards[1]["y"]) < 2 and cards[1]["x"] > cards[0]["x"])
                if args.screenshots and (width == 1440 or (width == 390 and panel == "overview")):
                    page.screenshot(path=str(output / (panel + "-" + str(width) + ".png")), full_page=True)
        # 导出使用一小时范围，下载只在浏览器临时目录中，不进入交付证据。
        page.locator('[data-export-range="1h"]').click()
        if args.export_from and args.export_to:
            page.locator("#export-from").fill(args.export_from)
            page.locator("#export-from").dispatch_event("change")
            page.locator("#export-to").fill(args.export_to)
            page.locator("#export-to").dispatch_event("change")
        try:
            with page.expect_download(timeout=30000) as download:
                page.locator("#export-btn").click()
            check("csv_download", download.value.suggested_filename.endswith(".csv") and download.value.failure() is None)
        except Exception:
            check("csv_download", False)
            report["export_error"] = page.locator("#export-msg").inner_text()
        check("no_uncaught_js_errors", not report["page_errors"])
        check("no_missing_api", not any(e["status"] == 404 for e in report["http_errors"]))
        report["later_http_errors"] = report["http_errors"][report["startup_http_errors"]:]
        browser.close()
    report["status"] = "FAIL" if report["failures"] else ("PASS_WITH_NOTES" if report["http_errors"] else "PASS")
    (output / "results.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: report[key] for key in ("status", "revision", "failures", "http_errors", "page_errors", "ws_messages")}, ensure_ascii=False, indent=2))
    return bool(report["failures"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--index-sha", required=True)
    parser.add_argument("--app-sha", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--screenshots", action="store_true")
    parser.add_argument("--export-from", help="选择快照内确有记录的本地时间窗口")
    parser.add_argument("--export-to")
    raise SystemExit(run(parser.parse_args()))
