#!/usr/bin/env python3
"""Isolated decision-log demonstration: real serve-lab NFQUEUE enforcement with
receiver evidence, inside lab.sh's disposable user/net/PID namespace. Uses a
separate test binary and private run directory; never the host daemon or DB.

  scripts/lab.sh python3 scripts/acceptance/decision-log-isolated.py --binary B --run DIR [--hold]

--hold keeps the daemon for UI attachment after seeding; commands arrive as
lines on stdin or as the content of DIR/command (consumed): decide-allow,
decide-block, rule-traffic N, restart, quit.
"""
import argparse, json, os, socket, subprocess, sys, time, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import lablib
from lablib import wait, delivered, children
from lablib import localhost_ask_rules

a = argparse.ArgumentParser()
a.add_argument('--binary', required=True); a.add_argument('--run', required=True); a.add_argument('--hold', action='store_true')
a = a.parse_args()
root = pathlib.Path(__file__).resolve().parents[2]
run = pathlib.Path(a.run).resolve(); assert run.is_relative_to(root / '.workspace') and run.is_dir()
os.chmod(run, 0o700)
lablib.BIN, lablib.RUN, lablib.SOCK = str(pathlib.Path(a.binary).resolve()), run, str(run / 'control.sock')
assert lablib.BIN != str(root / '.workspace/flowgate'), 'never use the host daemon executable'
SOCK, DB = lablib.SOCK, str(run / 'decisions.db')
log_lines = []
def log(s):
    print(s, flush=True); log_lines.append(s)
    with (run / 'verification.log').open('a') as f: f.write(s + '\n')
def api(op, **kw):
    s = socket.socket(socket.AF_UNIX); s.settimeout(4); s.connect(SOCK)
    with s:
        s.sendall((json.dumps(dict(version=1, operation=op, **kw)) + '\n').encode()); b = b''
        while b'\n' not in b:
            d = s.recv(1 << 20)
            if not d: raise RuntimeError('API closed')
            b += d
    return json.loads(b)
daemon = None
def start():
    global daemon
    for p in (SOCK, SOCK + '.monitor'):
        if os.path.exists(p): os.unlink(p)
    out = (run / 'daemon.log').open('a')
    daemon = subprocess.Popen([lablib.BIN, 'serve-lab','--rules',localhost_ask_rules('incoming'), '--parent-netns', os.environ['FLOWGATE_PARENT_NETNS'], '--socket', SOCK, '--timeout', '2s', '--decision-log', DB], stdout=out, stderr=out)
    wait(lambda: os.path.exists(SOCK) and api('list').get('generation'), 8)
    return api('list')['generation']
def stop():
    daemon.terminate(); daemon.wait(8)
def records(**q):
    r = api('decision-log', decision_query=dict(dict(after='0', limit=100), **q))
    assert 'error' not in r, r; return r['decision_log']
def by_request(rid, n=2):
    # Records become queryable after a successful batch commit (nominal flush interval ~1 s).
    return wait(lambda: (lambda r: r if len(r) >= n else None)([x for x in records()['records'] if x.get('request_id') == rid]), 5)
def tcp(port):
    return lablib.client(port)
def udp(port, data=b'ONCE'):
    c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); c.sendto(data, ('127.0.0.1', port)); return c

try:
    gen1 = start(); log(f'START serve-lab generation {gen1}; decision log {DB}')
    caps = api('list')['capabilities']; assert 'decision-log-v1' in caps, caps
    # 1. Ask -> user Allow once -> receiver delivery.
    p, path = lablib.server(24601); tcp(24601); v1 = wait(lambda: lablib.pending(24601)); assert not delivered(path)
    lablib.decide(v1, 'allow', 'once'); wait(lambda: delivered(path))
    r = by_request(v1['id']); assert [x['kind'] for x in r] == ['pending', 'final'], r
    assert r[0]['verdict']['state'] == 'held' and r[1]['decision']['source'] == 'user' and r[1]['decision']['scope'] == 'once' and r[1]['decision']['action'] == 'allow'
    log('PASS Ask -> user Allow once -> receiver RECEIVED; records pending(held) + final(user, once, allow), delivery not_observed')
    # 2. Ask -> user Block remembered (application rule); a fresh attempt is blocked by that stored rule.
    p, path2 = lablib.server(24602); tcp(24602); v2 = wait(lambda: lablib.pending(24602))
    d = lablib.decide(v2, 'block', 'application')['decision']; rule_id = d['rule']
    time.sleep(.3); before = path2.read_text().count('RECEIVED'); c = tcp(24602); c.wait(); time.sleep(.3)
    assert path2.read_text().count('RECEIVED') == before == 0
    fresh = wait(lambda: [x for x in records(source='rule')['records'] if x['flow']['local'].endswith(':24602')], 5)
    assert fresh and len({x['request_id'] for x in fresh}) == len(fresh), fresh
    assert all(x['decision']['action'] == 'block' and x['decision']['rule']['id'] == rule_id and x['decision']['rule']['version'] == '1' and x['verdict']['state'] == 'drop_submitted' for x in fresh), fresh
    log(f'PASS fresh TCP attempt blocked by stored rule {rule_id} v1; {len(fresh)} distinct lease evaluations (late retransmission after expiry may re-evaluate); receiver got nothing')
    # 3. UDP request left unanswered expires.
    p, path3 = lablib.server(24603, True); udp(24603).close(); v3 = wait(lambda: lablib.pending(24603)); time.sleep(2.4); lablib.events()
    r = by_request(v3['id']); assert [x['decision']['source'] for x in r] == ['default_ask', 'timeout'] and not delivered(path3), r
    log('PASS unanswered UDP request -> final(timeout, block); receiver got nothing')
    # 4. Restart: history persists; new generation, same log_id.
    time.sleep(1.2); log_id = records(limit=0)['health']['log_id']; n1 = len(records()['records']); stop()
    gen2 = start(); h = records(limit=0)['health']; all2 = records()['records']
    assert gen2 != gen1 and h['log_id'] == log_id and len(all2) == n1 and {x['generation'] for x in all2} == {gen1}, (h, len(all2))
    log(f'PASS restart: generation {gen2} reads {n1} records from {gen1}; same log_id {log_id}')
    page = records(); (run / 'examples.json').write_text(json.dumps(page, indent=2))
    log('EXAMPLES ' + str(run / 'examples.json'))
    if a.hold:
        (run / 'ready.json').write_text(json.dumps(dict(socket=SOCK, monitor_socket=SOCK + '.monitor', generation=gen2, log_id=log_id, decision_log=DB, records=len(all2))))
        log('READY hold ' + SOCK + '; commands via stdin or ' + str(run / 'command'))
        import threading, queue as q_
        cmds = q_.Queue()
        threading.Thread(target=lambda: [cmds.put(l.strip()) for l in sys.stdin], daemon=True).start()
        port = 24700; srv = {}
        while True:
            cmd = None
            f = run / 'command'
            if f.exists(): cmd = f.read_text().strip(); f.unlink()
            else:
                try: cmd = cmds.get(timeout=.3)
                except q_.Empty: continue
            if not cmd: continue
            word, *arg = cmd.split()
            try:
                if word == 'quit': break
                if word in ('decide-allow', 'decide-block'):
                    port += 1; p, pth = lablib.server(port); tcp(port); v = wait(lambda: lablib.pending(port))
                    lablib.decide(v, word.split('-')[1], 'application'); srv[port] = pth; log(f'DONE {word} port {port} request {v["id"]}')
                elif word == 'rule-traffic':
                    target = max(srv) if srv else None; n = int(arg[0]) if arg else 50
                    assert target, 'decide-allow/decide-block first'
                    for _ in range(min(n, 200)): tcp(target).wait()
                    log(f'DONE rule-traffic {n} on port {target}')
                elif word == 'restart':
                    stop(); g = start(); log(f'DONE restart generation {g}')
                else: log('UNKNOWN ' + cmd)
            except Exception as e: log(f'FAILED {cmd}: {e}')
        log('HOLD ended')
finally:
    for p in children:
        if p.poll() is None: p.terminate()
    if daemon and daemon.poll() is None: daemon.terminate(); daemon.wait(8)
