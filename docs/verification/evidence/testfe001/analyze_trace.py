# -*- coding: utf-8 -*-
"""TEST-FE-001 trace 分析 v3：
- 窗口起点 TracingStartedInBrowser，排除 ts=0 与窗口外事件
- 长任务按进程归属分组：ResourceSendRequest tid 关联端口（8080 旧实例 / 8090 受测）
- 输出页面时间线（FCP、8090 首载 summary）与窗口界定说明
"""
import json, collections, os

TRACE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "trace_attack30s.json")
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "perf_trace_analysis.txt")

def main():
    with open(TRACE, "r", encoding="utf-8") as f:
        data = json.load(f)
    events = data.get("traceEvents", [])
    n = len(events)

    win_start = None
    for e in events:
        if e.get("name") in ("TracingStartedInBrowser", "TracingStarted") and e.get("ph") == "I":
            win_start = e.get("ts")
            break
    if win_start is None:
        win_start = min(e.get("ts", 0) for e in events if e.get("ts", 0) > 0)
    win_end = max(e.get("ts", 0) for e in events if e.get("ts", 0) > 0)
    dur_ms = (win_end - win_start) / 1000.0

    in_win = [e for e in events if 0 < e.get("ts", 0) <= win_end and e.get("ts", 0) >= win_start]

    # tid -> 端口（ResourceSendRequest URL）
    tid_port = {}
    for e in in_win:
        if e.get("name") == "ResourceSendRequest":
            url = str(e.get("args", {}).get("data", {}).get("url", ""))
            if ":8080" in url:
                tid_port[e.get("tid")] = "8080"
            elif ":8090" in url:
                tid_port[e.get("tid")] = "8090"

    # 长任务（RunTask/Task >=50ms）按 tid 分组
    tasks = []
    for e in in_win:
        if e.get("ph") == "X" and e.get("name") in ("RunTask", "Task"):
            d = e.get("dur", 0) / 1000.0
            if d >= 50:
                port = tid_port.get(e.get("tid"), "unknown")
                tasks.append((d, e.get("ts", 0), e.get("tid"), e.get("pid"), port))
    tasks.sort(key=lambda t: t[1])

    # Layout 事件
    layouts = []
    for e in in_win:
        if e.get("name") == "Layout" and e.get("ph") in ("X", "B"):
            d = e.get("dur", 0) / 1000.0
            if d >= 1:
                layouts.append(d)
    layout_total = sum(layouts)
    layout_max = max(layouts) if layouts else 0
    layout_cnt = len(layouts)

    # 时间线关键点
    fcp = [e for e in in_win if e.get("name") == "firstContentfulPaint"]
    s8090 = None
    for e in in_win:
        if e.get("name") == "ResourceSendRequest":
            url = str(e.get("args", {}).get("data", {}).get("url", ""))
            if "/api/v1/summary" in url and ":8090" in url:
                s8090 = e.get("ts")
                break

    lines = []
    lines.append("TEST-FE-001 performance trace analysis v3 (trace_attack30s.json)")
    lines.append("window: TracingStartedInBrowser ts=%d -> end ts=%d (source: found event)" % (win_start, win_end))
    lines.append("recording window span: %.1f ms (%.2f s)" % (dur_ms, dur_ms / 1000))
    lines.append("trace events total: %d; in-window events: %d" % (n, len(in_win)))
    lines.append("")
    lines.append("timeline anchors:")
    for e in fcp[:3]:
        lines.append("  firstContentfulPaint ts=%d offset=%.1f ms" % (e.get("ts", 0), (e.get("ts", 0) - win_start) / 1000.0))
    if s8090:
        lines.append("  8090 first /api/v1/summary request ts=%d offset=%.1f ms" % (s8090, (s8090 - win_start) / 1000.0))
    lines.append("")
    lines.append("Long tasks (RunTask/Task >=50ms): %d (windowed)" % len(tasks))
    lines.append("  grouped by page (tid->port):")
    by_port = collections.Counter()
    for d, ts, tid, pid, port in tasks:
        by_port[port] += 1
        lines.append("    dur=%.1f ms offset=%.1f s tid=%d pid=%d page=%s" % (d, (ts - win_start) / 1e6, tid, pid, port))
    lines.append("  page group counts: %s" % dict(by_port))
    lines.append("  note: 8090 = 受测实例（隔离端口）；8080 = 旧实例（非受测，其长任务不计入 PF-2）")
    lines.append("")
    lines.append("Layout events (>=1ms): count=%d total=%.1f ms max=%.1f ms" % (layout_cnt, layout_total, layout_max))
    for d in sorted(layouts, reverse=True)[:10]:
        lines.append("  %.1f ms" % d)

    txt = "\n".join(lines) + "\n"
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(txt)
    print(txt)

if __name__ == "__main__":
    main()
