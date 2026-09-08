"""发布异常路径的模拟故障注入，不连接 Docker、不修改服务器。"""
import contextlib
import copy
import io
import json
from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch

import frontend_vps_switch as release


class ReleaseFailureTests(unittest.TestCase):
    def exercise(self, compose_errors, health_error=None, tag_error=False, log_error=False):
        old, new = "sha256:" + "1" * 64, "sha256:" + "2" * 64
        revision, binary = "a" * 40, "b" * 64
        before = {"Image": old, "Mounts": [], "HostConfig": {key: None for key in
                  ("NetworkMode", "ReadonlyRootfs", "CapAdd", "CapDrop", "GroupAdd", "Memory", "NanoCpus", "SecurityOpt")},
                  "Config": {"User": "1000:1000"}, "State": {"StartedAt": "before"}}
        after = copy.deepcopy(before)
        after.update(Image=new, State={"StartedAt": "after"})
        candidate = {"Id": new, "RootFS": {"Layers": ["base", "new"]}, "Config": {"Labels": {
            "org.opencontainers.image.revision": revision, "sentry.frontend.upstream": release.UPSTREAM}}}
        backup = MagicMock()
        backup.__truediv__.return_value.read_text.return_value = json.dumps([before])
        def command(*args):
            if args[:3] == ("docker", "image", "inspect"):
                return json.dumps([candidate if args[3] == new else {"RootFS": {"Layers": ["base"]}}])
            if args[:2] == ("docker", "run") or args[:2] == ("docker", "exec"):
                return binary + "  /usr/local/bin/sentry-agent"
            if "rev-parse" in args:
                return revision
            if "diff" in args:
                return "internal/web/static/app.js\ninternal/web/static/index.html"
            return ""
        def digest(path):
            if Path(path) == release.COMPOSE:
                return release.COMPOSE_HASH
            if str(path) == "/etc/sentry-agent/config.json":
                return release.CONFIG_HASH
            return "c" * 64
        def tag(args, **kwargs):
            if tag_error and args[3] == new:
                raise RuntimeError("candidate tag failed")
        reports = []
        def save(report):
            reports.append(copy.deepcopy(report))
            if log_error and report["status"] != "SWITCHING":
                raise OSError("report disk full")
        def health(image, assets):
            if image == new and health_error:
                raise RuntimeError(health_error)
            return after if image == new else before
        arguments = ["switch", "--image", new, "--revision", revision, "--binary-sha256", binary, "--apply"]
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(release, "BACKUP", backup))
            stack.enter_context(patch.object(release, "command", side_effect=command))
            stack.enter_context(patch.object(release, "inspect_container", return_value=before))
            stack.enter_context(patch.object(release, "verify_listener"))
            stack.enter_context(patch.object(release, "digest", side_effect=digest))
            stack.enter_context(patch.object(release, "get", return_value=b"old asset"))
            stack.enter_context(patch.object(release, "override"))
            stack.enter_context(patch.object(release, "save_report", side_effect=save))
            compose = stack.enter_context(patch.object(release, "compose_up", side_effect=compose_errors))
            stack.enter_context(patch.object(release, "wait_healthy", side_effect=health))
            stack.enter_context(patch.object(release.subprocess, "run", side_effect=tag))
            stack.enter_context(patch("sys.argv", arguments))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            caught = None
            try:
                release.main()
            except Exception as error:
                caught = error
        return reports, compose.call_count, caught

    def test_success_is_recorded(self):
        reports, calls, error = self.exercise([None])
        self.assertIsNone(error)
        self.assertEqual(calls, 1)
        self.assertEqual(reports[-1]["status"], "PASS")

    def test_forward_failure_restores_old_service(self):
        reports, calls, error = self.exercise([RuntimeError("forward failed"), None])
        self.assertIsNotNone(error)
        self.assertEqual(calls, 2)
        self.assertEqual(reports[-1]["status"], "ROLLED_BACK")
        self.assertEqual(reports[-1]["error"], "forward failed")

    def test_rollback_failure_preserves_both_errors(self):
        reports, calls, error = self.exercise([RuntimeError("forward failed"), RuntimeError("restore failed")])
        self.assertIsNotNone(error)
        self.assertEqual(calls, 2)
        self.assertEqual(reports[-1]["status"], "ROLLBACK_FAILED")
        self.assertEqual(reports[-1]["error"], "forward failed")
        self.assertEqual(reports[-1]["rollback_error"], "restore failed")

    def test_health_failure_triggers_rollback(self):
        reports, calls, error = self.exercise([None, None], health_error="wrong asset")
        self.assertIsNotNone(error)
        self.assertEqual(calls, 2)
        self.assertEqual(reports[-1]["status"], "ROLLED_BACK")

    def test_latest_tag_failure_triggers_rollback(self):
        reports, calls, error = self.exercise([None, None], tag_error=True)
        self.assertIsNotNone(error)
        self.assertEqual(calls, 2)
        self.assertEqual(reports[-1]["status"], "ROLLED_BACK")

    def test_listener_rejects_another_process(self):
        current = {"HostConfig": {"NetworkMode": "host"}, "State": {"Pid": 123}}
        with patch.object(release, "command", return_value='LISTEN 172.18.0.1:4001 users:(("other",pid=456,fd=7))'):
            with self.assertRaises(AssertionError):
                release.verify_listener(current)

    def test_report_write_failure_does_not_skip_rollback(self):
        reports, calls, error = self.exercise([RuntimeError("forward failed"), None], log_error=True)
        self.assertIsNotNone(error)
        self.assertEqual(calls, 2)
        self.assertEqual(reports[-1]["status"], "ROLLED_BACK")
        self.assertIn("report disk full", reports[-1]["report_errors"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
