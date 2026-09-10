"""固定基线性能发布：完整备份、精确镜像、受控临时空间调整和失败回滚。"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import time
import uuid

import frontend_vps_switch as common

BACKUP = Path('/opt/sentry-backups/20260909-perf')
RELEASE = Path('/opt/sentry-releases/20260909-perf-final')
OLD_IMAGE = 'sha256:5201f02d13bd199692d7cfbbd37df41b32f687e62a84d117e34d6e35dcf5c806'
BASELINE = 'f886bec891ec3754ccaad62fe355a32b8652f49f'
ALLOWED = {'internal/api/api.go', 'internal/api/query.go', 'internal/api/api_test.go',
           'internal/api/perf_stats_test.go', 'internal/api/stats_limit.go',
           'internal/store/store.go', 'internal/web/static/app.js'}


def save(name, value):
    (BACKUP / name).write_text(json.dumps(value, indent=2) + '\n')


def record(report):
    try:
        save('release-result.json', report)
    except OSError as error:
        print('发布记录写入失败：' + str(error), file=sys.stderr, flush=True)


def atomic_replace(path, content, expected):
    """同目录完整落盘后原子替换，写入失败保留原文件和诊断用临时文件。"""
    assert path.read_bytes() == expected, '目标文件出现第三方变更'
    metadata = path.stat()
    temporary = path.with_name(path.name + '.perf-' + uuid.uuid4().hex)
    with temporary.open('xb') as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.chmod(metadata.st_mode & 0o777)
    os.chown(temporary, metadata.st_uid, metadata.st_gid)
    assert temporary.read_bytes() == content, '临时文件校验失败'
    assert path.read_bytes() == expected, '替换前目标文件出现第三方变更'
    temporary.replace(path)


def compose_up(name):
    subprocess.run(['docker', 'compose', '-p', 'deploy', '--project-directory', str(common.COMPOSE.parent),
                    '-f', str(BACKUP / name), 'up', '-d', '--no-build', '--pull', 'never',
                    '--no-deps', 'sentry-agent'], check=True)


def wait_ready(image, assets):
    deadline = time.monotonic() + 180
    last = ''
    while time.monotonic() < deadline:
        try:
            current = common.inspect_container()
            assert current['Image'] == image and current['State']['Running']
            common.verify_listener(current)
            assert json.loads(common.get('/api/v1/health'))['ok'] is True
            for path, digest in assets.items():
                assert hashlib.sha256(common.get(path)).hexdigest() == digest
            return current
        except Exception as error:
            last = str(error)
            time.sleep(2)
    raise RuntimeError('180 秒内未就绪：' + last)


def preflight(args):
    assert re.fullmatch('sha256:[0-9a-f]{64}', args.image)
    assert re.fullmatch('[0-9a-f]{40}', args.revision)
    assert re.fullmatch('[0-9a-f]{64}', args.binary_sha256)
    current = common.inspect_container()
    assert current['Image'] == OLD_IMAGE, '生产镜像漂移'
    common.verify_listener(current)
    assert common.digest(common.COMPOSE) == common.COMPOSE_HASH
    assert common.digest('/etc/sentry-agent/config.json') == common.CONFIG_HASH
    assert common.command('git', '-C', str(RELEASE), 'rev-parse', 'HEAD') == args.revision
    assert not common.command('git', '-C', str(RELEASE), 'status', '--porcelain', '--untracked-files=all')
    changed = set(common.command('git', '-C', str(RELEASE), 'diff', '--name-only', BASELINE, args.revision).splitlines())
    assert changed == ALLOWED, '候选变更范围不一致'
    image = json.loads(common.command('docker', 'image', 'inspect', args.image))[0]
    assert image['Config']['Labels']['org.opencontainers.image.revision'] == args.revision
    base = json.loads(common.command('docker', 'image', 'inspect', 'sha256:46b9425a2baa8741a2a5471c6fd53160ba889f3b5d0ab2b832dc338963bdf1c8'))[0]
    layers = base['RootFS']['Layers']
    assert image['RootFS']['Layers'][:len(layers)] == layers, '基础系统层改变'
    old_config = json.loads(common.command('docker', 'image', 'inspect', OLD_IMAGE))[0]['Config']
    for key in ('User', 'Entrypoint', 'Cmd', 'Env', 'WorkingDir'):
        assert image['Config'].get(key) == old_config.get(key), '镜像运行入口改变：' + key
    digest = common.command('docker', 'run', '--rm', '--network', 'none', '--read-only', '--entrypoint',
                            'sha256sum', args.image, '/usr/local/bin/sentry-agent').split()[0]
    assert digest == args.binary_sha256
    assets = {'/': common.digest(RELEASE / 'internal/web/static/index.html'),
              '/app.js': common.digest(RELEASE / 'internal/web/static/app.js')}
    return current, assets


def database_digest(path):
    """分块校验大型备份，避免把整库读入低内存 VPS。"""
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_mounts(mounts):
    """Docker 挂载数组顺序非契约；按目标排序，仍比较每项全部字段。"""
    destinations = [mount['Destination'] for mount in mounts]
    assert len(destinations) == len(set(destinations)), '出现重复挂载目标'
    return sorted(mounts, key=lambda mount: mount['Destination'])


def prepare(args, current, assets):
    os.umask(0o077)
    BACKUP.mkdir(exist_ok=False)
    save('before-inspect.json', current)
    (BACKUP / 'compose-before.yml').write_bytes(common.COMPOSE.read_bytes())
    (BACKUP / 'config-before.json').write_bytes(Path('/etc/sentry-agent/config.json').read_bytes())
    manifest = json.loads(common.command('docker', 'compose', '-p', 'deploy', '-f', str(common.COMPOSE), 'config', '--format', 'json'))
    rollback = copy.deepcopy(manifest)
    rollback['services']['sentry-agent']['image'] = OLD_IMAGE
    forward = copy.deepcopy(rollback)
    forward['services']['sentry-agent']['image'] = args.image
    forward['services']['sentry-agent']['tmpfs'] = ['/tmp:size=128m', '/home/sentry:size=1m']
    save('candidate.compose.json', forward)
    save('rollback.compose.json', rollback)
    # 固定的是完整解析后的 Compose，不叠加两个不同 /tmp 条目的列表。
    for name in ('candidate.compose.json', 'rollback.compose.json'):
        common.command('docker', 'compose', '-p', 'deploy', '-f', str(BACKUP / name), 'config', '--quiet')
    common.command('git', '-C', str(RELEASE), 'bundle', 'create', str(BACKUP / 'source.bundle'), '--all')
    common.command('git', '-C', str(RELEASE), 'bundle', 'verify', str(BACKUP / 'source.bundle'))
    common.command('docker', 'image', 'tag', OLD_IMAGE, 'sentry-agent:rollback-perf-20260909')
    common.command('docker', 'image', 'save', '-o', str(BACKUP / 'image-before.tar'), OLD_IMAGE)
    print('开始发布前在线一致备份，生产保持运行。', flush=True)
    src = sqlite3.connect('file:/var/lib/sentry-agent/state.db?mode=ro', uri=True)
    dst = sqlite3.connect(str(BACKUP / 'state-before.db'))
    try:
        src.backup(dst, pages=-1)
        assert dst.execute('PRAGMA quick_check').fetchall() == [('ok',)]
    finally:
        dst.close()
        src.close()
    report = {'image': args.image, 'revision': args.revision, 'binary_sha256': args.binary_sha256,
              'assets': assets, 'old_assets': {path: hashlib.sha256(common.get(path)).hexdigest() for path in assets},
              'backup_db_sha256': database_digest(BACKUP / 'state-before.db'),
              'manifest_sha256': {name: common.digest(BACKUP / name) for name in ('candidate.compose.json', 'rollback.compose.json')},
              'status': 'PREPARED'}
    save('prepared.json', report)
    print(json.dumps(report), flush=True)


def apply(args, before, assets):
    prepared = json.loads((BACKUP / 'prepared.json').read_text())
    assert prepared['image'] == args.image and prepared['revision'] == args.revision
    assert prepared['binary_sha256'] == args.binary_sha256 and prepared['assets'] == assets
    for name, digest in prepared['manifest_sha256'].items():
        assert common.digest(BACKUP / name) == digest
    compose_before = (BACKUP / 'compose-before.yml').read_bytes()
    assert hashlib.sha256(compose_before).hexdigest() == common.COMPOSE_HASH
    assert compose_before.count(b'/tmp:size=16m') == 1
    compose_after = compose_before.replace(b'/tmp:size=16m', b'/tmp:size=128m')
    compose_after = compose_after.replace('17MB 内存开销（16m+1m）'.encode(), '129MB 上限（128m+1m，按需占用）'.encode())
    report = dict(prepared, status='SWITCHING', stages=[])
    save('release-result.json', report)  # 变更前确认审计文件可写。
    started = time.monotonic()
    try:
        compose_up('candidate.compose.json')
        after = wait_ready(args.image, assets)
        report['ready_seconds'] = round(time.monotonic() - started, 3)
        report['stages'].append('candidate_ready')
        record(report)
        assert canonical_mounts(after['Mounts']) == canonical_mounts(before['Mounts']), '挂载字段发生变化'
        for key in ('NetworkMode', 'ReadonlyRootfs', 'CapAdd', 'CapDrop', 'GroupAdd', 'Memory', 'NanoCpus', 'SecurityOpt'):
            assert after['HostConfig'][key] == before['HostConfig'][key], key
        assert after['HostConfig']['Tmpfs'] == {'/tmp': 'size=128m', '/home/sentry': 'size=1m'}
        for key in ('User', 'Entrypoint', 'Cmd', 'Env', 'WorkingDir'):
            assert after['Config'].get(key) == before['Config'].get(key), key
        assert common.digest('/etc/sentry-agent/config.json') == common.CONFIG_HASH
        assert common.command('docker', 'exec', 'sentry-agent', 'sha256sum', '/usr/local/bin/sentry-agent').split()[0] == args.binary_sha256
        # 验证真实长范围查询，不以 health 代替功能验收。各请求串行，避免制造限流。
        for path in ('summary', 'attacks/top_ports', 'attacks/top_sources', 'firewall/timeline'):
            import urllib.request
            with urllib.request.urlopen(common.BASE_URL + '/api/v1/' + path + '?range=30d', timeout=35) as response:
                assert response.status == 200
                json.load(response)
            time.sleep(1.2)
        # 原 Compose 持久化唯一运行配置变化；旧原文保留，失败时恢复。
        assert common.digest(common.COMPOSE) == common.COMPOSE_HASH
        atomic_replace(common.COMPOSE, compose_after, compose_before)
        common.command('docker', 'image', 'tag', args.image, 'sentry-agent:latest')
        report.update(status='PASS', started_at=after['State']['StartedAt'], compose_sha256=common.digest(common.COMPOSE))
    except Exception as error:
        report.update(status='ROLLING_BACK', error=str(error))
        record(report)
        try:
            # 优先恢复运行服务；审计/配置落盘故障不能阻断容器回滚。
            compose_up('rollback.compose.json')
            wait_ready(OLD_IMAGE, prepared['old_assets'])
            common.command('docker', 'image', 'tag', OLD_IMAGE, 'sentry-agent:latest')
            current_text = common.COMPOSE.read_bytes()
            if current_text == compose_after:
                atomic_replace(common.COMPOSE, compose_before, compose_after)
            else:
                assert current_text == compose_before, '回滚时 Compose 出现第三方变更'
            report['status'] = 'ROLLED_BACK'
        except Exception as rollback_error:
            report.update(status='ROLLBACK_FAILED', rollback_error=str(rollback_error))
            raise RuntimeError('发布与回滚失败，需检查恢复状态') from rollback_error
        finally:
            record(report)
        raise
    record(report)
    print(json.dumps(report), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--binary-sha256', required=True)
    parser.add_argument('--mode', choices=['check', 'prepare', 'apply'], default='check')
    args = parser.parse_args()
    current, assets = preflight(args)
    if args.mode == 'prepare':
        prepare(args, current, assets)
    elif args.mode == 'apply':
        apply(args, current, assets)
    else:
        print(json.dumps({'status': 'PREFLIGHT_PASS', 'assets': assets}))
