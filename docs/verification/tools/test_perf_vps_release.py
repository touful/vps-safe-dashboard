"""性能发布故障注入：纯内存模拟，不连接 Docker 或服务器。"""
import contextlib
import copy
import hashlib
import io
import json
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

import perf_vps_release as release


class VirtualPath:
    def __init__(self, files, name):
        self.files, self.name = files, name

    def __truediv__(self, name):
        return VirtualPath(self.files, self.name + '/' + name)

    def __str__(self):
        return self.name

    def read_bytes(self):
        return self.files[self.name]

    def read_text(self):
        return self.read_bytes().decode()

    def write_bytes(self, value):
        self.files[self.name] = value


class ReleaseTests(unittest.TestCase):
    def test_mount_order_is_ignored_but_every_field_is_checked(self):
        original = [{'Destination': '/data', 'Source': '/host/data', 'RW': True, 'Propagation': 'rprivate'},
                    {'Destination': '/config', 'Source': '/host/config', 'RW': False, 'Propagation': 'rprivate'}]
        self.assertEqual(release.canonical_mounts(original), release.canonical_mounts(original[::-1]))
        for key, value in [('Source', '/other'), ('RW', False), ('Propagation', 'rshared')]:
            with self.subTest(field=key):
                changed = copy.deepcopy(original)
                changed[0][key] = value
                self.assertNotEqual(release.canonical_mounts(original), release.canonical_mounts(changed))
        self.assertNotEqual(release.canonical_mounts(original), release.canonical_mounts(original[:1]))
        with self.assertRaises(AssertionError):
            release.canonical_mounts(original + [original[0]])

    def test_database_digest_uses_bounded_reads(self):
        for content in (b'', b'snapshot', b'x' * (2 * 1024 * 1024 + 7)):
            with self.subTest(size=len(content)):
                stream = MagicMock(wraps=io.BytesIO(content))
                path = MagicMock()
                path.open.return_value.__enter__.return_value = stream
                self.assertEqual(release.database_digest(path), hashlib.sha256(content).hexdigest())
                path.open.assert_called_once_with('rb')
                path.read_bytes.assert_not_called()
                self.assertTrue(stream.read.call_count >= 1)
                for call in stream.read.call_args_list:
                    self.assertEqual(call.args, (1024 * 1024,))

    def exercise(self, fail_compose=None, fail_health=False, fail_api=False,
                 fail_tag=False, fail_log=False, drift=False):
        image, revision, binary = 'sha256:' + 'a' * 64, 'b' * 40, 'c' * 64
        assets = {'/': 'index', '/app.js': 'app'}
        compose_before = b'services:\n  sentry-agent:\n    tmpfs: [/tmp:size=16m]\n'
        files = {'backup/compose-before.yml': compose_before,
                 'compose': compose_before, 'backup/candidate.compose.json': b'forward',
                 'backup/rollback.compose.json': b'rollback'}
        digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
        prepared = {'image': image, 'revision': revision, 'binary_sha256': binary,
                    'assets': assets, 'old_assets': {'/': 'old-index', '/app.js': 'old-app'},
                    'manifest_sha256': {name: hashlib.sha256(files['backup/' + name]).hexdigest()
                                        for name in ('candidate.compose.json', 'rollback.compose.json')}}
        files['backup/prepared.json'] = json.dumps(prepared).encode()
        if drift:
            files['backup/candidate.compose.json'] = b'changed'
        before = {'Mounts': [{'Destination': '/data', 'Source': '/host/data', 'RW': True},
                             {'Destination': '/config', 'Source': '/host/config', 'RW': False}], 'HostConfig': {key: None for key in
                  ('NetworkMode', 'ReadonlyRootfs', 'CapAdd', 'CapDrop', 'GroupAdd', 'Memory', 'NanoCpus', 'SecurityOpt')},
                  'Config': {key: None for key in ('User', 'Entrypoint', 'Cmd', 'Env', 'WorkingDir')}}
        after = copy.deepcopy(before)
        after['Mounts'].reverse()  # 发布成功路径必须接受相同挂载的不同枚举顺序。
        after['HostConfig']['Tmpfs'] = {'/tmp': 'size=128m', '/home/sentry': 'size=1m'}
        after['State'] = {'StartedAt': 'now'}
        reports = []

        def save(name, report):
            reports.append(copy.deepcopy(report))
            if fail_log and report['status'] != 'SWITCHING':
                raise OSError('report full')

        def ready(target, checked_assets):
            if target == image and fail_health:
                raise RuntimeError('health failed')
            return after if target == image else before

        def command(*args):
            if args[:2] == ('docker', 'exec'):
                return binary + ' binary'
            if args[:3] == ('docker', 'image', 'tag') and args[3] == image and fail_tag:
                raise RuntimeError('tag failed')
            return ''

        response = MagicMock()
        response.__enter__.return_value.status = 200
        response.__enter__.return_value.read.return_value = b'{}'
        caught = None
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(release, 'BACKUP', VirtualPath(files, 'backup')))
            stack.enter_context(patch.object(release.common, 'COMPOSE', VirtualPath(files, 'compose')))
            stack.enter_context(patch.object(release.common, 'COMPOSE_HASH', hashlib.sha256(compose_before).hexdigest()))
            stack.enter_context(patch.object(release.common, 'digest', side_effect=lambda path:
                release.common.CONFIG_HASH if str(path) == '/etc/sentry-agent/config.json' else digest(path)))
            stack.enter_context(patch.object(release.common, 'command', side_effect=command))
            stack.enter_context(patch.object(release, 'wait_ready', side_effect=ready))
            stack.enter_context(patch.object(release, 'save', side_effect=save))
            def replace(path, content, expected):
                assert path.read_bytes() == expected
                path.write_bytes(content)
            stack.enter_context(patch.object(release, 'atomic_replace', side_effect=replace))
            stack.enter_context(patch.object(release.time, 'sleep'))
            stack.enter_context(patch('urllib.request.urlopen', return_value=response,
                                      side_effect=RuntimeError('api failed') if fail_api else None))
            calls = stack.enter_context(patch.object(release, 'compose_up', side_effect=fail_compose))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
            try:
                release.apply(SimpleNamespace(image=image, revision=revision, binary_sha256=binary), before, assets)
            except Exception as error:
                caught = error
        return reports, calls.call_count, caught, files['compose'], compose_before

    def test_success(self):
        reports, calls, error, content, old = self.exercise()
        self.assertIsNone(error)
        self.assertEqual(calls, 1)
        self.assertEqual(reports[-1]['status'], 'PASS')
        self.assertIn(b'/tmp:size=128m', content)

    def test_failure_paths_restore_runtime_and_compose(self):
        for options in ({'fail_compose': [RuntimeError('start failed'), None]},
                        {'fail_health': True}, {'fail_api': True}, {'fail_tag': True}):
            with self.subTest(options=options):
                reports, calls, error, content, old = self.exercise(**options)
                self.assertIsNotNone(error)
                self.assertEqual(calls, 2)
                self.assertEqual(content, old)
                self.assertEqual(reports[-1]['status'], 'ROLLED_BACK')

    def test_record_failure_does_not_block_rollback(self):
        reports, calls, error, content, old = self.exercise(fail_health=True, fail_log=True)
        self.assertIsNotNone(error)
        self.assertEqual(calls, 2)
        self.assertEqual(reports[-1]['status'], 'ROLLED_BACK')

    def test_double_failure_preserves_errors(self):
        reports, calls, error, content, old = self.exercise(fail_compose=[RuntimeError('start failed'), RuntimeError('rollback failed')])
        self.assertEqual(reports[-1]['status'], 'ROLLBACK_FAILED')
        self.assertEqual(reports[-1]['error'], 'start failed')
        self.assertEqual(reports[-1]['rollback_error'], 'rollback failed')

    def test_drift_prevents_mutation(self):
        reports, calls, error, content, old = self.exercise(drift=True)
        self.assertIsNotNone(error)
        self.assertEqual(calls, 0)
        self.assertEqual(content, old)

    def check_atomic(self, write_failure=False, replace_failure=False, drift=False):
        target, temporary = MagicMock(), MagicMock()
        target.name = 'compose.yml'
        target.stat.return_value = SimpleNamespace(st_mode=0o100644, st_uid=0, st_gid=0)
        target.read_bytes.side_effect = [b'old', b'third-party' if drift else b'old']
        target.with_name.return_value = temporary
        temporary.read_bytes.return_value = b'new'
        stream = temporary.open.return_value.__enter__.return_value
        if write_failure:
            stream.write.side_effect = OSError('partial temporary write')
        if replace_failure:
            temporary.replace.side_effect = OSError('replace failed')
        with patch.object(release.os, 'fsync'), patch.object(release.os, 'chown', create=True):
            if write_failure or replace_failure or drift:
                with self.assertRaises((OSError, AssertionError)):
                    release.atomic_replace(target, b'new', b'old')
            else:
                release.atomic_replace(target, b'new', b'old')
        target.write_bytes.assert_not_called()
        if write_failure or drift:
            temporary.replace.assert_not_called()
        else:
            temporary.replace.assert_called_once_with(target)

    def test_partial_temporary_write_keeps_target(self):
        self.check_atomic(write_failure=True)

    def test_replace_failure_never_truncates_target(self):
        self.check_atomic(replace_failure=True)

    def test_third_party_change_prevents_replace(self):
        self.check_atomic(drift=True)

    def test_atomic_replace_success(self):
        self.check_atomic()


if __name__ == '__main__':
    unittest.main(verbosity=2)
