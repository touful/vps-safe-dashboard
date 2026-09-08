"""本次前端发布的受控切换；启动或资源校验失败时自动回滚旧镜像。"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.request


BACKUP = Path("/opt/sentry-backups/20260908-fe91c6c31")
COMPOSE = Path("/opt/vps-safe-dashboard/deploy/docker-compose.yml")
RELEASE = Path("/opt/sentry-releases/20260908-fe-compat")
BASE_URL = "http://172.18.0.1:4001"
CONFIG_HASH = "0c9ce0aa68d4465d0ea239edd6ef80e057ec0d90a3b754ad3176c3f727578e87"
COMPOSE_HASH = "9e5829a6ac85dd8657e7c7d78771b1f14d3cb79ccf065b97adc766a83d0a5542"
UPSTREAM = "91c6c311e9c8caf32a1e20147d95e503216cbdcc"


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def inspect_container():
    return json.loads(command("docker", "inspect", "sentry-agent"))[0]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def get(path):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(BASE_URL + path, timeout=10) as response:
        return response.read()


def verify_listener(current):
    """host 网络中，监听 socket 必须由目标容器的主进程持有。"""
    assert current["HostConfig"]["NetworkMode"] == "host"
    sockets = command("ss", "-ltnp", "( sport = :4001 )")
    pid = current["State"]["Pid"]
    assert any("172.18.0.1:4001" in row and f"pid={pid}," in row for row in sockets.splitlines()), "探活地址不属于目标容器"


def save_report(report):
    target = BACKUP / "switch-result.json"
    temporary = target.with_suffix(".tmp")
    temporary.write_text(json.dumps(report, indent=2) + "\n")
    temporary.replace(target)


def record_progress(report, stage=None):
    """记录故障不能阻断恢复操作，也不能掩盖原始发布或回滚异常。"""
    if stage:
        report["stages"].append(stage)
    try:
        save_report(report)
    except OSError as error:
        report.setdefault("report_errors", []).append(str(error))
        print("发布记录写入失败：" + str(error), file=sys.stderr)


def override(path, image):
    path.write_text(json.dumps({"services": {"sentry-agent": {"image": image}}}) + "\n")


def compose_up(path):
    subprocess.run(["docker", "compose", "-p", "deploy", "--project-directory", str(COMPOSE.parent),
                    "-f", str(COMPOSE), "-f", str(path), "up", "-d", "--no-build", "--pull", "never",
                    "--no-deps", "sentry-agent"], check=True)


def wait_healthy(image, assets):
    last_error = None
    for _ in range(12):
        try:
            current = inspect_container()
            assert current["Image"] == image, "运行镜像与目标不一致"
            assert current["State"]["Running"] and not current["State"]["Paused"]
            verify_listener(current)
            assert json.loads(get("/api/v1/health"))["ok"] is True
            for url, expected in assets.items():
                assert hashlib.sha256(get(url)).hexdigest() == expected, "线上资源哈希不一致：" + url
            return current
        except Exception as exc:
            last_error = exc
            time.sleep(3)
    raise RuntimeError("服务校验失败：" + str(last_error))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="精确 sha256 镜像 ID")
    parser.add_argument("--revision", required=True, help="已验收的完整候选 commit")
    parser.add_argument("--binary-sha256", required=True, help="已验收候选二进制的 SHA-256")
    parser.add_argument("--apply", action="store_true", help="执行切换；默认只校验准备条件")
    args = parser.parse_args()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", args.image):
        raise SystemExit("必须指定完整镜像 ID")
    if not re.fullmatch(r"[0-9a-f]{40}", args.revision) or not re.fullmatch(r"[0-9a-f]{64}", args.binary_sha256):
        raise SystemExit("必须指定完整候选 commit 和二进制 SHA-256")
    before = json.loads((BACKUP / "container-inspect.json").read_text())[0]
    current = inspect_container()
    assert current["Image"] == before["Image"], "生产镜像已漂移，停止发布"
    verify_listener(current)
    assert digest(COMPOSE) == COMPOSE_HASH, "生产 compose 已漂移"
    assert digest("/etc/sentry-agent/config.json") == CONFIG_HASH, "生产配置已漂移"
    candidate = json.loads(command("docker", "image", "inspect", args.image))[0]
    assert candidate["Id"] == args.image
    revision = command("git", "-C", str(RELEASE), "rev-parse", "HEAD")
    assert revision == args.revision, "候选与已验收 commit 不一致"
    assert candidate["Config"]["Labels"]["org.opencontainers.image.revision"] == revision
    assert candidate["Config"]["Labels"]["sentry.frontend.upstream"] == UPSTREAM
    assert command("git", "-C", str(RELEASE), "status", "--porcelain", "--untracked-files=all") == ""
    changed = set(command("git", "-C", str(RELEASE), "diff", "--name-only", "7b6b8a1", revision).splitlines())
    assert changed == {"internal/web/static/index.html", "internal/web/static/app.js"}, "候选超出纯前端范围"
    base_image = json.loads(command("docker", "image", "inspect", before["Image"]))[0]
    layers = base_image["RootFS"]["Layers"]
    assert candidate["RootFS"]["Layers"][:len(layers)] == layers, "候选未沿用原系统层"
    image_binary = command("docker", "run", "--rm", "--network", "none", "--read-only", "--entrypoint", "sha256sum", args.image, "/usr/local/bin/sentry-agent").split()[0]
    assert image_binary == args.binary_sha256, "镜像内二进制与已验收哈希不一致"
    assets = {"/": digest(RELEASE / "internal/web/static/index.html"),
              "/app.js": digest(RELEASE / "internal/web/static/app.js")}
    forward, rollback = BACKUP / "candidate.override.json", BACKUP / "rollback.override.json"
    override(forward, args.image)
    override(rollback, before["Image"])
    report = {"candidate_image": args.image, "previous_image": before["Image"],
              "source_revision": revision, "binary_sha256": image_binary, "assets": assets, "applied": False}
    if not args.apply:
        print(json.dumps(report, indent=2))
        return
    old_assets = {url: hashlib.sha256(get(url)).hexdigest() for url in assets}
    report.update(status="SWITCHING", stages=[])
    save_report(report)
    try:
        compose_up(forward)
        record_progress(report, "candidate_compose_completed")
        after = wait_healthy(args.image, assets)
        record_progress(report, "candidate_service_verified")
        assert after["Mounts"] == before["Mounts"], "生产挂载发生变化"
        for key in ("NetworkMode", "ReadonlyRootfs", "CapAdd", "CapDrop", "GroupAdd", "Memory", "NanoCpus", "SecurityOpt"):
            assert after["HostConfig"][key] == before["HostConfig"][key], "运行约束发生变化：" + key
        assert after["Config"]["User"] == before["Config"]["User"], "运行用户发生变化"
        assert digest("/etc/sentry-agent/config.json") == CONFIG_HASH
        record_progress(report, "runtime_constraints_verified")
        running_binary = command("docker", "exec", "sentry-agent", "sha256sum", "/usr/local/bin/sentry-agent").split()[0]
        assert running_binary == args.binary_sha256
        record_progress(report, "running_binary_verified")
        # 保持原 compose 的默认 image 引用可用，避免日后常规重建意外回到旧版。
        subprocess.run(["docker", "image", "tag", args.image, "sentry-agent:latest"], check=True)
        record_progress(report, "latest_tag_updated")
        report.update(applied=True, status="PASS", started_at=after["State"]["StartedAt"])
    except Exception as error:
        report.update(status="ROLLING_BACK", error=str(error))
        record_progress(report)
        try:
            compose_up(rollback)
            record_progress(report, "rollback_compose_completed")
            wait_healthy(before["Image"], old_assets)
            record_progress(report, "old_service_verified")
            subprocess.run(["docker", "image", "tag", before["Image"], "sentry-agent:latest"], check=True)
            report.update(status="ROLLED_BACK")
        except Exception as rollback_error:
            report.update(status="ROLLBACK_FAILED", rollback_error=str(rollback_error))
            raise RuntimeError("发布及回滚失败，请检查 switch-result.json") from rollback_error
        finally:
            record_progress(report)
        raise
    record_progress(report)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
