"""本次 VPS 隔离性能复现：不输出业务明细，不修改生产数据或配置。"""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import time
import urllib.error
import urllib.request

ROOT = Path('/opt/sentry-staging/20260909-perf')
IMAGE = 'sha256:5201f02d13bd199692d7cfbbd37df41b32f687e62a84d117e34d6e35dcf5c806'
BASE = 'http://127.0.0.1:14003'


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def prepare():
    os.umask(0o077)
    ROOT.mkdir(exist_ok=False)
    data = ROOT / 'data'
    data.mkdir()
    (data / 'archive').mkdir()
    started = time.monotonic()
    # SQLite online backup API 获取一致快照；原库只读，不暂停生产采集。
    with sqlite3.connect('file:/var/lib/sentry-agent/state.db?mode=ro', uri=True) as src:
        with sqlite3.connect(str(data / 'state.db')) as dst:
            deadline = time.monotonic() + 180
            def progress(status, remaining, total):
                if time.monotonic() > deadline:
                    raise TimeoutError('在线备份超过 180 秒')
            src.backup(dst, pages=-1, progress=progress, sleep=0.05)
    cfg = json.loads(Path('/etc/sentry-agent/config.json').read_text())
    cfg['web'].update(listen='0.0.0.0:4002', ws_origin_allow='http://127.0.0.1:14003')
    cfg['db'].update(path='/var/lib/sentry-agent/state.db', archive_dir='/var/lib/sentry-agent/archive', retention_days=0, cred_retention_days=0)
    cfg.setdefault('archive', {})['copy_after_days'] = 99999
    cfg.setdefault('honeypot', {})['enabled'] = False
    cfg.setdefault('f2b', {})['enabled'] = False
    cfg.setdefault('geoip', {}).update(update_enabled=False, account_id='', license_key='')
    cfg.setdefault('conntrack', {}).update(mode='fallback', enable_acct=False)
    cfg.setdefault('fw', {})['ssh_learn_enabled'] = False
    (ROOT / 'config.json').write_text(json.dumps(cfg, ensure_ascii=False, indent=2))
    os.chmod(ROOT / 'config.json', 0o644)
    run('chown', '-R', '1000:1000', str(data))
    with sqlite3.connect('file:' + str(data / 'state.db') + '?mode=ro', uri=True) as db:
        report = {'quick_check': db.execute('PRAGMA quick_check').fetchall(),
                  'backup_seconds': round(time.monotonic() - started, 3),
                  'firewall_count': db.execute('SELECT count(*) FROM firewall_events').fetchone()[0],
                  'firewall_max_ts': db.execute('SELECT max(ts) FROM firewall_events').fetchone()[0],
                  'indexes': db.execute("SELECT name,sql FROM sqlite_master WHERE type='index' AND tbl_name='firewall_events'").fetchall()}
    (ROOT / 'prepare.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(report), flush=True)


def start(name, tmp, image):
    if not name.startswith('sentry-perf-20260909-') or tmp not in ('16m', '128m'):
        raise ValueError('仅允许本次隔离容器及预定临时空间')
    # 同一副本绝不被两个运行容器同时写入。
    active = run('docker', 'ps', '--filter', 'name=sentry-perf-20260909-', '--format', '{{.Names}}')
    if active:
        raise RuntimeError('请先停止当前测试容器：' + active)
    print(run('docker', 'run', '-d', '--name', name, '--network', 'bridge',
              '-p', '127.0.0.1:14003:4002', '--memory', '512m', '--cpus', '1.6',
              '--read-only', '--cap-drop', 'ALL', '--cap-add', 'NET_BIND_SERVICE',
              '--tmpfs', '/tmp:size=' + tmp,
              '--tmpfs', '/home/sentry:size=1m',
              '-v', str(ROOT / 'data') + ':/var/lib/sentry-agent:rw',
              '-v', str(ROOT / 'config.json') + ':/etc/sentry-agent/config.json:ro',
              image), flush=True)
    started = time.monotonic()
    for _ in range(180):
        try:
            with urllib.request.urlopen(BASE + '/api/v1/health', timeout=2) as response:
                if json.load(response).get('ok') is True:
                    print(json.dumps({'container_ready_seconds': round(time.monotonic()-started, 3)}), flush=True)
                    return
        except (OSError, ValueError):
            time.sleep(1)
    raise RuntimeError('隔离容器未就绪，不能开始测量')


def request(path):
    started = time.monotonic()
    try:
        with urllib.request.urlopen(BASE + path, timeout=40) as response:
            body = response.read()
            status = response.status
    except urllib.error.HTTPError as exc:
        body, status = exc.read(), exc.code
    except Exception as exc:
        return {'path': path, 'status': 0, 'seconds': round(time.monotonic()-started, 3), 'error': type(exc).__name__}
    return {'path': path, 'status': status, 'seconds': round(time.monotonic()-started, 3),
            'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}


def inspect_stats():
    report = {}
    with sqlite3.connect('file:' + str(ROOT / 'data/state.db') + '?mode=ro', uri=True) as db:
        end = db.execute('SELECT max(ts) FROM firewall_events').fetchone()[0]
        report['firewall_count'] = db.execute('SELECT count(*) FROM firewall_events').fetchone()[0]
        report['anchor'] = end
        report['index_sql'] = db.execute("SELECT sql FROM sqlite_master WHERE name='idx_fw_ts_stats'").fetchone()
        report['index_bytes'] = db.execute("SELECT sum(pgsize) FROM dbstat WHERE name='idx_fw_ts_stats'").fetchone()[0]
        for col in ('dst_port', 'src_ip'):
            query = 'SELECT ' + col + ',count(*) FROM firewall_events INDEXED BY {} WHERE ts>=? GROUP BY ' + col
            old = sorted(db.execute(query.format('idx_fw_ts'), (end-7*86400,)).fetchall())
            new = sorted(db.execute(query.format('idx_fw_ts_stats'), (end-7*86400,)).fetchall())
            report[col + '_equivalent'] = old == new
            report[col + '_groups'] = len(new)
            report[col + '_plan'] = db.execute('EXPLAIN QUERY PLAN ' + query.format('idx_fw_ts_stats'), (end-7*86400,)).fetchall()
        query = "SELECT (ts/3600)*3600,SUM(action='drop'),SUM(action='accept'),SUM(action='reject'),SUM(action='inbound') FROM firewall_events INDEXED BY {} WHERE ts>=? GROUP BY (ts/3600)*3600"
        lower = ((end-7*86400)//3600)*3600
        old = sorted(db.execute(query.format('idx_fw_ts'), (lower,)).fetchall())
        new = sorted(db.execute(query.format('idx_fw_ts_stats'), (lower,)).fetchall())
        report['timeline_equivalent'] = old == new
        report['timeline_buckets'] = len(new)
    (ROOT / 'sql-equivalence.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(report), flush=True)


def probe(label, mode):
    if not label.replace('-', '').isalnum():
        raise ValueError('非法报告标签')
    with sqlite3.connect('file:' + str(ROOT / 'data/state.db') + '?mode=ro', uri=True) as db:
        end = db.execute('SELECT max(ts) FROM firewall_events').fetchone()[0]
    paths = []
    if mode == 'serial':
        for window in ('1h', '24h', '7d', '30d'):
            query = 'range=' + window
            for endpoint in ('summary', 'resources', 'attacks/top_ports', 'attacks/top_sources', 'firewall/timeline'):
                paths.append('/api/v1/' + endpoint + '?' + query)
        results = []
        for path in paths:
            result = request(path)
            results.append(result)
            print(json.dumps(result), flush=True)
            time.sleep(1.2)
    else:
        slow = '/api/v1/firewall/timeline?range=7d'
        results = []
        for count in (1, 2, 4):
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
                futures = [pool.submit(request, slow) for _ in range(count)]
                time.sleep(0.25)
                futures.append(pool.submit(request, '/api/v1/resources?range=1h&step=60s'))
                for future in futures:
                    result = dict(future.result(), concurrent_slow=count)
                    results.append(result)
                    print(json.dumps(result), flush=True)
            time.sleep(7)
    (ROOT / (label + '.json')).write_text(json.dumps(results, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['prepare', 'start', 'probe', 'inspect'])
    parser.add_argument('--name', default='sentry-perf-20260909-base16')
    parser.add_argument('--tmp', default='16m')
    parser.add_argument('--image', default=IMAGE)
    parser.add_argument('--label', default='base16')
    parser.add_argument('--mode', choices=['serial', 'concurrent'], default='serial')
    args = parser.parse_args()
    if args.action == 'prepare':
        prepare()
    elif args.action == 'start':
        start(args.name, args.tmp, args.image)
    elif args.action == 'inspect':
        inspect_stats()
    else:
        probe(args.label, args.mode)
