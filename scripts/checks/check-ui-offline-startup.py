#!/usr/bin/env python3
"""Two sandboxed Wayland starts; read-only observer, no control API or host changes.
Run after `npm --prefix electron run build` in a desktop session. NetLog evidence
covers the first ten seconds of each fresh profile, not arbitrary future activity.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

root = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--observer', default='/run/flowgate-api/daemon.sock.monitor')
args = parser.parse_args()
work = root / '.workspace'
work.mkdir(exist_ok=True)
evidence = Path(tempfile.mkdtemp(prefix='offline-ui-', dir=work))
env = os.environ.copy()
env.update(TMPDIR=str(evidence), XDG_CACHE_HOME=str(evidence / 'cache'))
results = []
for index in range(2):
    net = evidence / f'{index}-net.json'
    log = evidence / f'{index}.log'
    with log.open('w') as out:
        proc = subprocess.Popen([
            str(root / 'electron/node_modules/electron/dist/electron'),
            '--ozone-platform=wayland', '--log-net-log=' + str(net),
            str(root / 'electron'), '--observer', args.observer,
        ], cwd=root, env=env, stdout=out, stderr=out)
        try:
            time.sleep(10)
            assert proc.poll() is None, 'UI exited; inspect ' + str(log)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
    assert 'main window rendered; sandbox enabled; native platform wayland' in log.read_text()
    text = net.read_text().rstrip()
    # SIGTERM leaves the streaming JSON events array open; reject malformed
    # records instead of silently skipping a potentially relevant network event.
    try:
        trace = json.loads(text)
    except json.JSONDecodeError:
        trace = json.loads(text.rstrip(',') + ']}')
    names = {value: key for key, value in trace['constants']['logEventTypes'].items()}
    attempts = []
    for event in trace['events']:
        kind = names[event['type']]
        url = event.get('params', {}).get('url', '')
        if (kind in ('TCP_CONNECT', 'UDP_CONNECT', 'UDP_BYTES_SENT', 'TCP_BYTES_SENT')
                or url.startswith(('http:', 'https:', 'ws:', 'wss:'))):
            attempts.append(event)
    assert not attempts, f'Network attempts in {net}: {attempts[:3]}'
    results.append({'sandboxed_wayland_rendered': True, 'seconds': 10,
                    'network_attempts': len(attempts), 'events': len(trace['events'])})
(evidence / 'result.json').write_text(json.dumps({'passed': True, 'starts': results}, indent=2))
print('PASS', evidence)
