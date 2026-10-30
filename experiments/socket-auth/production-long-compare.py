#!/usr/bin/env python3
"""Real Wine/Proton runtime-census saturation with concurrent native traffic.

Private network/PID namespaces only (run via scripts/checks/check-wine-saturation.sh).
Two copied prefixes, unmodified launcher chain, lab daemon with Wine discovery.

Phase 1 decides real prompts bound to the exact fixture executable and prefix:
native sender Allow, Alpha (prefix A) Allow, Beta (prefix A) Block. Phase 2 has
two rounds (a prefix hosts one launcher session at a time and the launcher is not
safe to start concurrently, so applications start one by one and a file barrier
releases their bursts together): round 1 Alpha/A + Alpha/B (no rule, prompts left
pending), round 2 Beta/A + Alpha/B. Each application opens many cold UDP sockets
while a native sender keeps a timestamped stream running. The measured window
starts just before the barrier is released and ends when every application
reports that all sends completed (before its socket linger). Hard assertions: blocked and
unruled Windows applications deliver nothing (no permission transfer across
applications or prefixes), the allowed application's sockets get through, and
native delivery/latency stay within bounds while censuses are saturated.
Everything else is reported as measurement, not as a performance claim.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import signal
import socket
import sqlite3
import statistics
import subprocess
import sys
import threading
import time
sys.path.insert(0,str(Path.cwd()/'scripts/acceptance'))
from lablib import localhost_ask_rules

if not __debug__:
    raise SystemExit('Optimized Python is unsupported: acceptance checks would be disabled')
ROOT = Path('/home/flowgate-user/Apps/flowgate')
p = argparse.ArgumentParser()
p.add_argument('--binary', required=True)
p.add_argument('--helper', required=True)
p.add_argument('--run', required=True)
p.add_argument('--proton', required=True)
p.add_argument('--data', required=True)
p.add_argument('--prefix-source', required=True)
p.add_argument('--pe', required=True)
p.add_argument('--lwp', required=True)
p.add_argument('--activity-poll-ms', type=int, default=0, help='Poll full Activity snapshots during launch load; 0 disables')
p.add_argument('--sockets', type=int, default=24)
p.add_argument('--datagrams', type=int, default=60)
p.add_argument('--interval-ms', type=int, default=50)
p.add_argument('--native-pps', type=int, default=200)
p.add_argument('--min-native-delivery', type=float, default=0.99)
p.add_argument('--max-native-p99-ms', type=float, default=500.0)
p.add_argument('--min-allowed-socket-share', type=float, default=0.90)
a = p.parse_args()


def require(condition, message):
    if not condition: raise RuntimeError(message)


require(a.activity_poll_ms == 0 or 100 <= a.activity_poll_ms <= 10000, 'activity poll interval must be 0 or 100..10000ms')
require(1 <= a.sockets <= 64, '--sockets must be 1..64')
require(1 <= a.datagrams <= 100000, '--datagrams must be 1..100000')
require(1 <= a.interval_ms <= 10000, '--interval-ms must be 1..10000')
require(1 <= a.native_pps <= 5000, '--native-pps must be 1..5000')
require(0 < a.min_native_delivery <= 1 and a.max_native_p99_ms > 0 and 0 < a.min_allowed_socket_share <= 1, 'invalid thresholds')
require(os.environ.get('FLOWGATE_PARENT_NETNS') and os.environ['FLOWGATE_PARENT_NETNS'] != os.readlink('/proc/self/ns/net'), 'private network namespace required')
# Direct Wine fixture supports private namespace root for complete queue counters.
for value in [a.run, a.proton, a.data, a.prefix_source, a.pe, a.helper]:
    require(Path(value).resolve().is_relative_to(ROOT / '.workspace'), 'outside .workspace: ' + value)
RUN = Path(a.run).resolve(); RUN.mkdir(mode=0o700, parents=True)
TEST_UID=int(os.environ['FLOWGATE_FIXTURE_UID']);TEST_GID=int(os.environ['FLOWGATE_FIXTURE_GID'])
PID_FD=int(os.environ['FLOWGATE_ROOT_PIDNS_FD']);MNT_FD=int(os.environ['FLOWGATE_ROOT_MNTNS_FD'])
DROP=['/usr/bin/setpriv','--reuid='+str(TEST_UID),'--regid='+str(TEST_GID),'--clear-groups','--inh-caps=-all','--ambient-caps=-all','--']
BIN = str(Path(a.binary).resolve()); API = '/run/flowgate-session-test/control/a'
require(len(os.fsencode(API + '.monitor')) < 108, 'API and monitor Unix socket paths exceed sockaddr_un limit')
for d in ['home', 'tmp', 'cache', 'config', 'runtime', 'games', 'steam', 'observer', 'data']:
    (RUN / d).mkdir(mode=0o700)
prefixes = []
for name in ['prefix-a', 'prefix-b']:
    dst = RUN / name
    dst.mkdir(); (dst/'pfx').mkdir()
    for link in dst.rglob('*'):
        if link.is_symlink() and 'drive_c/users/' in str(link) and str(link.readlink()).startswith('/home/'):
            link.unlink(); link.symlink_to(RUN / 'home', target_is_directory=True)
    for link in dst.rglob('*'):
        if link.is_symlink() and '/dwproton-fixture/' in str(link.readlink()):
            suffix=str(link.readlink()).split('/dwproton-fixture/',1)[1]
            link.unlink(); link.symlink_to(RUN / 'home/.steam/steam/compatibilitytools.d/dwproton-fixture' / suffix)
    prefixes.append(dst / 'pfx')
for name in ['SyntheticAlpha.exe', 'SyntheticBeta.exe']:
    subprocess.run(['cp', a.pe, str(RUN / 'games' / name)], check=True)
steam = RUN / 'home/.steam/steam/compatibilitytools.d'; steam.mkdir(parents=True)
subprocess.run(['cp', '-a', '--reflink=auto', a.proton, str(steam / 'dwproton-fixture')], check=True)

# Fixtures run as the selected desktop UID. Only lab controller/daemon stays root.
for basepath,dirs,files in os.walk(RUN):
    os.chown(basepath,TEST_UID,TEST_GID,follow_symlinks=False)
    for name in dirs+files: os.chown(Path(basepath)/name,TEST_UID,TEST_GID,follow_symlinks=False)
(RUN/'profile').mkdir(mode=0o700)
# Root daemon API requires an owner-only root directory, separate from fixtures.
(RUN/'control').mkdir(mode=0o700)
SECURE=Path('/run/flowgate-session-test')
(SECURE/'control').mkdir(mode=0o711)
(SECURE/'data').mkdir(mode=0o700)
assert (RUN/'control').stat().st_uid == os.geteuid() == 0
assert (RUN/'control').stat().st_mode & 0o777 == 0o700
children = []
# Bounded unrelated process population models desktop holder-census cost.
noise=[subprocess.Popen(['/usr/bin/unshare','--mount',*DROP,str(ROOT / '.workspace/census-bottleneck/population')]) for _ in range(128)]
time.sleep(1)
require(all(c.poll() is None for c in noise),'bounded census population failed to start')
children.extend(noise)
lock = threading.Lock()
wine_latency = []
wine_rx = []    # (token, socket, seq, monotonic_ns)
native_rx = []  # (seq, send_ns, recv_ns)
# Receiver sockets live in a second private netns. Their file descriptors retain
# that namespace after this single-threaded setup returns to the sender netns.
peer = subprocess.Popen(['unshare','--net','sleep','400'])
children.append(peer)
original_ns=os.open('/proc/self/ns/net',os.O_RDONLY)
until=time.monotonic()+5
while os.readlink('/proc/%d/ns/net'%peer.pid)==os.readlink('/proc/self/ns/net'):
    require(time.monotonic()<until,'receiver namespace did not start');time.sleep(.01)
for args in [
    ['ip','link','add','fgroute','type','veth','peer','name','fgrxpeer'],
    ['ip','link','set','fgrxpeer','netns',str(peer.pid)],
    ['ip','address','add','198.18.2.1/24','dev','fgroute'],
    ['ip','link','set','fgroute','up'],
    ['nsenter','-t',str(peer.pid),'-n','ip','address','add','198.18.2.2/24','dev','fgrxpeer'],
    ['nsenter','-t',str(peer.pid),'-n','ip','link','set','fgrxpeer','up']]:
    subprocess.run(args,check=True,timeout=5)
peer_ns=os.open('/proc/%d/ns/net'%peer.pid,os.O_RDONLY)
try:
    os.setns(peer_ns,0)
    wine_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); wine_server.bind(('198.18.2.2',0))
    native_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); native_server.bind(('198.18.2.2',0))
finally:
    os.setns(original_ns,0);os.close(original_ns);os.close(peer_ns)

WINE_PORT, NATIVE_PORT = wine_server.getsockname()[1], native_server.getsockname()[1]
pattern = re.compile(rb'^([A-Z_0-9]+)\|(\d+)\|(\d+)\|(\d+)\|x+$')


def receive_wine():
    while True:
        try: data = wine_server.recvfrom(256)[0]
        except OSError: return
        m = pattern.match(data)
        if m:
            with lock:
                wine_rx.append((m[1].decode(), int(m[2]), int(m[3]), time.monotonic_ns()))
                wine_latency.append((m[1].decode(),int(m[2]),int(m[3]),(time.time_ns()-(int(m[4])-116444736000000000)*100)/1e6))


def receive_native():
    while True:
        try: data = native_server.recvfrom(256)[0]
        except OSError: return
        now = time.monotonic_ns()
        try:
            _, seq, sent = data.decode().split('|')
            with lock: native_rx.append((int(seq), int(sent), now))
        except ValueError: pass


for fn in (receive_wine, receive_native): threading.Thread(target=fn, daemon=True).start()


def wait(fn, seconds=30, step=.05):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        v = fn()
        if v: return v
        time.sleep(step)
    raise AssertionError('timeout: ' + getattr(fn, '__name__', str(fn)))


def call_raw(op='list', **kw):
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(15); s.connect(API)
        s.sendall((json.dumps(dict(version=1, operation=op, **kw)) + '\n').encode())
        return json.loads(s.makefile('rb').readline())


api_timeline_lock=threading.Lock()
api_timeline_count=0
def call(op='list', **kw):
    global api_timeline_count
    started=time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    try:
        return call_raw(op,**kw)
    finally:
        ended=time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        with api_timeline_lock:
            if api_timeline_count<4096:
                with (RUN/'api-timeline.jsonl').open('a') as log:
                    log.write(json.dumps(dict(operation=op,start_boot_ns=started,end_boot_ns=ended))+'\n')
            api_timeline_count+=1


activity_stop = threading.Event()
activity_counts = dict(snapshots=0, errors=0)
def poll_activity():
    while not activity_stop.is_set():
        try:
            response = call()
            if response.get('error') or not response.get('activity'):
                activity_counts['errors'] += 1
            else:
                activity_counts['snapshots'] += 1
        except (OSError, ValueError):
            activity_counts['errors'] += 1
        activity_stop.wait(a.activity_poll_ms / 1000)


def save(name, obj): (RUN / name).write_text(json.dumps(obj, indent=2))


def pending(kind=None, key=None):
    out = []
    for e in call().get('events', []):
        app = e.get('attribution', {}).get('application', {})
        if e['state'] == 'awaiting-decision' and (kind is None or app.get('kind') == kind) and (key is None or app.get('key') == key):
            out.append(e)
    return out


def stop_prefix(prefix):
    for d in Path('/proc').iterdir():
        if not d.name.isdigit() or int(d.name) == 1: continue
        try:
            env = (d / 'environ').read_bytes().split(b'\0')
            if any(x.startswith(b'WINEPREFIX=') and Path(x.split(b'=', 1)[1].decode()).resolve() == prefix.resolve() for x in env):
                os.kill(int(d.name), signal.SIGKILL)
        except (OSError, ProcessLookupError): pass


base = dict(PATH='/usr/bin:/bin', LANG='C.UTF-8', USER=os.environ.get('USER', 'tester'), LOGNAME=os.environ.get('LOGNAME', 'tester'),
            HOME=str(RUN / 'home'), TMPDIR=str(RUN / 'tmp'), XDG_RUNTIME_DIR=str(RUN / 'runtime'), XDG_DATA_HOME=str(RUN / 'data'),
            XDG_CACHE_HOME=str(RUN / 'cache'), XDG_CONFIG_HOME=str(RUN / 'config'), PROTONPATH=str(Path(a.proton).resolve()),
            UMU_RUNTIME_UPDATE='0', UMU_LOG='1', PROTONFIXES_DISABLE='1', PROTON_FSR4_UPGRADE='0', PYTHONDONTWRITEBYTECODE='1', WINEDEBUG='-all',
            WINEDLLOVERRIDES='mscoree,mshtml=', DISPLAY='', WAYLAND_DISPLAY='', STEAM_COMPAT_CLIENT_INSTALL_PATH=str(RUN / 'steam'),
            FLOWGATE_TEST_PORT=str(WINE_PORT), FLOWGATE_TEST_HOST='198.18.2.2')


def launch(name, prefix, token, sockets, datagrams, go=None):
    extra = dict(FLOWGATE_TEST_GO='Z:' + str(go).replace('/', '\\')) if go else {}
    env = dict(base, **extra, WINEPREFIX=str(prefix), GAMEID='umu-0', FLOWGATE_TEST_TOKEN=token, FLOWGATE_TEST_SOCKETS=str(sockets),
               FLOWGATE_TEST_DATAGRAMS=str(datagrams), FLOWGATE_TEST_INTERVAL_MS=str(a.interval_ms),
               FLOWGATE_TEST_TRACE='Z:' + str(RUN / (token + '.trace')).replace('/', '\\'))
    lwp = [str(Path(a.lwp).resolve()), str(RUN / 'games' / name), '%command%', str(prefix)]
    cmd = [*DROP, str(RUN / 'home/.steam/steam/compatibilitytools.d/dwproton-fixture/files/bin/wine'), str(RUN / 'games' / name)]
    with (RUN / (token + '.log')).open('w') as f:
        c = subprocess.Popen(cmd, env=env, stdout=f, stderr=f)
    children.append(c)
    fixture_children[token]=c
    return c


trace_observed = set()
fixture_children = {}
fixture_exits = set()
def trace_has(token, marker):
    for name, child in fixture_children.items():
        code=child.poll()
        if code is not None and name not in fixture_exits:
            fixture_exits.add(name)
            with (RUN/'fixture-timeline.jsonl').open('a') as log:
                log.write(json.dumps(dict(token=name,stage='launcher_exit_observed',exit=code,observed_boot_ns=time.clock_gettime_ns(time.CLOCK_BOOTTIME)))+'\n')
    t = RUN / (token + '.trace')
    text = t.read_text(errors='replace') if t.exists() else ''
    for stage in ('SATURATION_READY','SATURATION_BEGIN','SATURATION_SENT','SATURATION_DONE','SATURATION_ERROR'):
        if stage in text and (token,stage) not in trace_observed:
            trace_observed.add((token,stage))
            with (RUN/'fixture-timeline.jsonl').open('a') as log:
                log.write(json.dumps(dict(token=token,stage=stage,observed_boot_ns=time.clock_gettime_ns(time.CLOCK_BOOTTIME),observation='first poll; not exact child event time'))+'\n')
    return marker in text


def received(token):
    with lock: return [r for r in wine_rx if r[0] == token]


SENDER = r'''
import socket,sys,time
port,pps,stop=int(sys.argv[1]),int(sys.argv[2]),sys.argv[3]
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);seq=0;gap=1/pps;nxt=time.monotonic()
log=open(sys.argv[4],'w')
import os
while not os.path.exists(stop):
    now=time.monotonic_ns();s.sendto(b'N|%d|%d'%(seq,now),('198.18.2.2',port));log.write('%d %d\n'%(seq,now));seq+=1
    nxt+=gap;d=nxt-time.monotonic()
    if d>0:time.sleep(d)
log.close()
'''

resources=[]
resource_stop=threading.Event()
def sample_resources():
    while not resource_stop.wait(.1):
        try:
            fields=dict(line.split(':',1) for line in Path('/proc/%d/status'%daemon.pid).read_text().splitlines() if ':' in line)
            resources.append((time.monotonic_ns(),fields.get('VmRSS',''),fields.get('Threads','')))
        except OSError: return

PROTECTION_OFF=os.environ.get('FLOWGATE_PRODUCTION_OFF','0')=='1'
GATE_ENABLED=not PROTECTION_OFF
result = dict(gate_enabled=GATE_ENABLED, passed=False, sockets_per_app=a.sockets, datagrams_per_socket=a.datagrams, interval_ms=a.interval_ms, native_pps=a.native_pps)
try:
    log = (RUN / 'daemon.log').open('w')
    daemon = subprocess.Popen([BIN,'serve','--socket-authorization','--socket',API,
        '--database',str(SECURE/'data/rules.db'),'--uid',str(TEST_UID),'--administrator',
        '--allow-protection','--protection-state',str(SECURE/'data/desired.json'),
        '--evaluation-state',str(SECURE/'state'),'--decision-timeout','30s',
        '--wine-helper',str(Path(a.helper).resolve()),
        *(['--holder-iterator-helper',os.environ['FLOWGATE_TEST_ITERATOR_HELPER']] if os.environ.get('FLOWGATE_TEST_ITERATOR_HELPER') else [])],
        stdout=log,stderr=log,env=dict(os.environ,FLOWGATE_PROFILE_DIR=str(RUN/'profile'),FLOWGATE_PROFILE_MANUAL='1'))
    children.append(daemon); log.close()
    def api_ready():
        if daemon.poll() is not None:
            raise AssertionError('lab daemon exited before API ready: ' + (RUN/'daemon.log').read_text())
        return Path(API).exists() and Path(API + '.monitor').exists()
    wait(api_ready)
    initial=call()
    ack=call('protection-start',generation=initial['generation'],protection_id=initial['protection']['id'],request_id='a'*32,profile='both')
    require(not ack.get('error'),str(ack))
    active=wait(lambda:(lambda x:x if x['protection']['state'] in ('active','failed','degraded') else None)(call()))
    require(active['protection']['state']=='active',str(active))
    require(active.get('socket_authorization',{}).get('route_bound'), 'production route-bound gate absent')
    save('production-start.json',active)
    threading.Thread(target=sample_resources,daemon=True).start()

    if a.activity_poll_ms:
        threading.Thread(target=poll_activity, daemon=True).start()

    # Phase 1a: native sender permission through a real prompt.
    stopfile = RUN / 'native.stop'; sendlog = RUN / 'native-sent.log'
    sender = subprocess.Popen([*DROP, sys.executable, '-c', SENDER, str(NATIVE_PORT), str(a.native_pps), str(stopfile), str(sendlog)]); children.append(sender)
    e = wait(lambda: next(iter(pending('native')), None))
    ack = call('decide', id=e['id'], action='allow', scope='application'); require(ack.get('decision', {}).get('state') == 'allowed', str(ack))
    wait(lambda: len(native_rx) > 20, 10)
    print('PHASE1 native sender allowed', flush=True)

    # Phase 1b: Alpha/A Allow and Beta/A Block through real Wine prompts.
    keys, coverage = {}, []
    for name, prefix, token, action in [('SyntheticAlpha.exe', prefixes[0], 'WARM_ALPHA_A', 'allow'), ('SyntheticBeta.exe', prefixes[0], 'WARM_BETA_A', 'block')]:
        child = launch(name, prefix, token, 1, 600)
        def intended():
            # Decide only the verified fixture executable in the intended prefix.
            for x in pending('wine'):
                app = x['attribution']['application']
                if Path(app.get('executable', '')).resolve() == (RUN / 'games' / name).resolve() and Path(app.get('prefix', '')).resolve() == prefix.resolve():
                    return x
        e = wait(intended, 240)
        keys[token] = e['attribution']['application']['key']
        coverage.append(dict(token=token, action=action, executable=e['attribution']['application']['executable'], prefix=e['attribution']['application']['prefix'], key=keys[token]))
        ack = call('decide', id=e['id'], action=action, scope='application')
        require(ack.get('decision', {}).get('state') == ('allowed' if action == 'allow' else 'blocked'), str(ack))
        if action == 'allow': wait(lambda: received(token), 15)
        else:
            time.sleep(3); require(not received(token), 'blocked warm-up delivered')
        print('PHASE1', token, action, flush=True)
        child.wait(timeout=30)
    require(keys['WARM_ALPHA_A'] != keys['WARM_BETA_A'], 'Alpha and Beta share an application key')
    result['phase1_decisions'] = coverage
    save('phase1-rules.json', call().get('rules', []))

    # Phase 2: concurrent cold-socket bursts with native traffic running. A
    # prefix runs one launcher session at a time, so the blocked application in
    # prefix A gets its own round, each alongside the unruled other-prefix one.
    if PROTECTION_OFF:
        state=call()
        ack=call('protection-stop',generation=state['generation'],protection_id=state['protection']['id'])
        require(not ack.get('error'),str(ack))
        wait(lambda:call()['protection']['state']=='stopped')
        tables=subprocess.check_output(['nft','list','tables'],text=True)
        require('flowgate_host' not in tables and 'flowgate_guard' not in tables,'off arm still intercepted')
        save('off-before-measurement.json',call())
    state=call();require(not GATE_ENABLED or state.get('socket_authorization') is not None,'prototype gate absent');save('gate-start.json',state.get('socket_authorization'))
    ack=call('diagnostic-start',generation=state['generation']);require(not ack.get('error'),str(ack));save('diagnostic-start.json',ack)
    duration = a.datagrams * a.interval_ms / 1000
    rounds = [('round1', [('SyntheticAlpha.exe', prefixes[0], 'SAT_ALPHA_A'), ('SyntheticAlpha.exe', prefixes[1], 'SAT_ALPHA_B1')]),
              ('round2', [('SyntheticBeta.exe', prefixes[0], 'SAT_BETA_A'), ('SyntheticAlpha.exe', prefixes[1], 'SAT_ALPHA_B2')])]
    windows, begin = {}, {}
    first_begin = None
    for label, apps in rounds:
        time.sleep(3)
        # The launcher is not safe to start concurrently (shared runtime setup),
        # so start one at a time, then release every burst through one barrier.
        go = RUN / ('go-' + label)
        for n, pr, t in apps:
            launch(n, pr, t, a.sockets, a.datagrams, go)
            wait(lambda: trace_has(t, 'SATURATION_READY'), 180, .1)
        save(label+'-before.json',call())
        cpu_start=Path('/proc/%d/stat'%daemon.pid).read_text().rsplit(')',1)[1].split(); cpu_start=int(cpu_start[11])+int(cpu_start[12])
        start_ns = time.monotonic_ns()  # host clock just before the barrier release
        go.write_text('go')
        for _, _, t in apps: begin[t] = start_ns
        first_begin = first_begin or start_ns
        wait(lambda: all(trace_has(t, 'SATURATION_BEGIN') for _, _, t in apps), 60, .02)
        # End at "all sends completed" (polled every 20 ms), not after the socket linger.
        wait(lambda: all(trace_has(t, 'SATURATION_SENT') or trace_has(t, 'SATURATION_ERROR') for _, _, t in apps), duration + 120, .02)
        windows[label] = (start_ns, time.monotonic_ns())
        save(label+'-after.json',call())
        cpu_end=Path('/proc/%d/stat'%daemon.pid).read_text().rsplit(')',1)[1].split();cpu_end=int(cpu_end[11])+int(cpu_end[12]);save(label+'-cpu.json',dict(cpu_seconds=(cpu_end-cpu_start)/os.sysconf('SC_CLK_TCK'),elapsed_seconds=(windows[label][1]-start_ns)/1e9))
        wait(lambda: all(trace_has(t, 'SATURATION_DONE') or trace_has(t, 'SATURATION_ERROR') for _, _, t in apps), 60, .1)
        for _, pr, _ in apps: pass # Keep runtime/helper alive between measured rounds.
        print('PHASE2', label, 'done', flush=True)
    # Live policy transitions and stall evidence reused from retained runs.
    time.sleep(3)
    stopfile.write_text('stop'); sender.wait(timeout=10)
    late_pending = [x['attribution']['application'].get('prefix') for x in pending('wine')]

    # The one-shot profile is for this isolated workload, never host gameplay.
    state=call();save('gate-final.json',state.get('socket_authorization'));require(not GATE_ENABLED or state.get('socket_authorization',{}).get('fast_packets',0)>0,'no kernel fast-path deliveries counted')
    require(not (state.get('socket_authorization') or {}).get('failure'),'socket gate failure: '+str(state.get('socket_authorization')))
    # Measurements.
    sent = {}
    for line in sendlog.read_text().split('\n'):
        if line: s_, t_ = line.split(); sent[int(s_)] = int(t_)
    with lock: got = {seq: (snd, rcv) for seq, snd, rcv in native_rx}
    def window(lo, hi):
        ids = [s_ for s_, t_ in sent.items() if lo <= t_ < hi]
        lat = sorted((got[s_][1] - got[s_][0]) / 1e6 for s_ in ids if s_ in got)
        def pct(q): return round(lat[min(len(lat) - 1, int(q * len(lat)))], 3) if lat else None
        return dict(sent=len(ids), delivered=len(lat), delivery=round(len(lat) / len(ids), 4) if ids else None,
                    p50_ms=pct(.5), p95_ms=pct(.95), p99_ms=pct(.99), max_ms=round(lat[-1], 3) if lat else None)
    native = dict(baseline=window(first_begin - 10_000_000_000, first_begin), **{k: window(*v) for k, v in windows.items()})
    wine = {}
    for _, apps in rounds:
        for _, _, t in apps:
            rx = received(t)
            per = {}
            for _, sock, seq, at in rx: per.setdefault(sock, []).append(at)
            first = sorted(round((min(v) - begin[t]) / 1e6, 1) for v in per.values())  # from barrier release
            wine[t] = dict(datagrams=len(rx), sent=a.sockets * a.datagrams, sockets_with_delivery=len(per), sockets=a.sockets,
                           first_delivery_ms=dict(min=first[0] if first else None, median=statistics.median(first) if first else None, max=first[-1] if first else None))
    daemon_log = (RUN / 'daemon.log').read_text(errors='replace')
    drops = {k: sum(int(m) for m in re.findall(r'dropped (\d+) packets: ' + k, daemon_log)) for k in ['census lane capacity exhausted', 'attribution capacity exhausted', 'attribution deadline or shutdown']}
    result.update(activity=dict(activity_counts, interval_ms=a.activity_poll_ms), native=native, wine=wine, queue_drop_logs=drops, pending_unruled_prefixes=late_pending, daemon_alive=daemon.poll() is None,
                  daemon_log_tail=daemon_log.splitlines()[-20:], source=subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
                  # A dirty tree means the tested binary is not exactly the recorded commit.
                  source_dirty=bool(subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no'], text=True).strip()),
                  source_diff_sha256=__import__('hashlib').sha256(subprocess.check_output(['git', 'diff', 'HEAD'])).hexdigest(), proton=dict(version=(Path(a.proton) / 'version').read_text().strip() if (Path(a.proton) / 'version').exists() else None,
                                  proton_sha256=__import__('hashlib').sha256((Path(a.proton) / 'proton').read_bytes()).hexdigest(),
                                  wineserver_sha256=__import__('hashlib').sha256((Path(a.proton) / 'files/bin/wineserver').read_bytes()).hexdigest()),
                  measurement=dict(window='host monotonic just before barrier release .. all apps report SATURATION_SENT', poll_ms=20))

    # Send coverage: every socket must have attempted every datagram, every
    # worker must have exited cleanly; otherwise no-delivery checks are vacuous.
    coverage_failures = []
    for _, apps in rounds:
        for _, _, t in apps:
            text = (RUN / (t + '.trace')).read_text(errors='replace') if (RUN / (t + '.trace')).exists() else ''
            stats = [l.split()[1:] for l in text.splitlines() if l.startswith('STATS ')]
            per = {int(x[0]): dict(attempted=int(x[1]), ok=int(x[2]), failed=int(x[3]), exit=int(x[4])) for x in stats}
            wine[t]['send'] = dict(sockets_reported=len(per), attempted=sum(v['attempted'] for v in per.values()),
                                   ok=sum(v['ok'] for v in per.values()), failed=sum(v['failed'] for v in per.values()),
                                   nonzero_exits=sum(1 for v in per.values() if v['exit']))
            if 'SATURATION_ERROR' in text: coverage_failures.append(t + ' reported SATURATION_ERROR')
            if sorted(per) != list(range(a.sockets)) or any(v['attempted'] != a.datagrams or v['exit'] for v in per.values()):
                coverage_failures.append('%s incomplete send coverage: %s' % (t, wine[t]['send']))
    result['wine'] = wine

    # Hard assertions.
    failures = list(coverage_failures)
    if a.activity_poll_ms and (not activity_counts['snapshots'] or activity_counts['errors']):
        failures.append('Activity polling missing snapshots or returned errors')
    if not PROTECTION_OFF and wine['SAT_BETA_A']['datagrams']: failures.append('blocked Beta/A delivered %d datagrams' % wine['SAT_BETA_A']['datagrams'])
    for t in ['SAT_ALPHA_B1', 'SAT_ALPHA_B2']:
        if not PROTECTION_OFF and wine[t]['datagrams']: failures.append('unruled Alpha/B (other prefix) delivered %d datagrams in %s' % (wine[t]['datagrams'], t))
    share = wine['SAT_ALPHA_A']['sockets_with_delivery'] / a.sockets
    if share < a.min_allowed_socket_share: failures.append('allowed Alpha/A sockets with delivery %.2f < %.2f' % (share, a.min_allowed_socket_share))
    for label in windows:
        b = native[label]
        if not b['delivery'] or b['delivery'] < a.min_native_delivery: failures.append('native delivery during %s %s < %s' % (label, b['delivery'], a.min_native_delivery))
        if b['p99_ms'] is None or b['p99_ms'] > a.max_native_p99_ms: failures.append('native p99 during %s %s ms > %s ms' % (label, b['p99_ms'], a.max_native_p99_ms))
    if daemon.poll() is not None: failures.append('daemon exited')
    result['failures'] = failures
    result['passed'] = not failures
    print(json.dumps(dict(native=native, wine=wine, queue_drop_logs=drops), indent=2), flush=True)
    print('PASS' if not failures else 'FAIL: ' + '; '.join(failures), flush=True)
finally:
    resource_stop.set(); save('resources.json',resources)
    activity_stop.set()
    with lock: save('wine-latency.json', wine_latency); save('raw-native-rx.json', native_rx); save('raw-wine-rx.json', wine_rx)
    save('result.json', result)
    try:
        with sqlite3.connect('file:' + str(SECURE/'data/decisions.db') + '?mode=ro', uri=True) as c:
            save('decision-log.json', [json.loads(r[0]) for r in c.execute('select document from decisions order by seq')])
    except (OSError, sqlite3.Error): pass
    try: save('last-state.json', call())
    except (OSError, ValueError): pass
    try:
        state=call()
        if state['protection']['state']!='stopped':
            ack=call('protection-stop',generation=state['generation'],protection_id=state['protection']['id'])
            require(not ack.get('error'),str(ack))
            wait(lambda:call()['protection']['state']=='stopped')
        save('production-stopped.json',call())
    except Exception as stop_error:
        result['production_stop_error']=str(stop_error)
        result['passed']=False
        save('result.json',result)
    for pr in prefixes: stop_prefix(pr)
    for c in reversed(children):
        if c.poll() is None: c.terminate()
    for c in reversed(children):
        try: c.wait(timeout=5)
        except subprocess.TimeoutExpired: c.kill(); c.wait()
    wine_server.close(); native_server.close()
    print('CLEANED; private PID/network namespace owns remaining runtime descendants', flush=True)
sys.exit(0 if result.get('passed') else 1)
