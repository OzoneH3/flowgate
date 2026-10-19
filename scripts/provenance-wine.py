#!/usr/bin/env python3
"""Launch provenance on REAL Wine processes (Wine 11.19 /usr/bin/wine) under the
SIMULATED umu-run/pv-adverb/proton launcher chain (scripts/provenance-sim).

Run through scripts/lab.sh. Two disposable prefixes are reflink copies of an
initialized workspace prefix; one PE fixture file placed at a Proton-like
runtime path (.../files/lib/wine/x86_64-windows/rundll32.exe) is started in
both prefixes. Checks the CLI `process` and `attribute` JSON (the same
identity/attribution objects the daemon API serves). No daemon, no
enforcement, no game prefixes, no host changes. Not UMU/Proton/pressure-vessel.
"""
import argparse, json, os, pathlib, shutil, signal, subprocess, sys, time
ROOT = pathlib.Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser()
p.add_argument('--binary', required=True); p.add_argument('--run', required=True)
p.add_argument('--prefix-source', required=True, help='initialized workspace Wine prefix (copied, never modified)')
p.add_argument('--pe', required=True, help='PE fixture (fixtures/windows-pe.c build, e.g. alpha.exe)')
a = p.parse_args()
assert os.environ['FLOWGATE_PARENT_NETNS'] != os.readlink('/proc/self/ns/net'), 'run via scripts/lab.sh'
RUN = pathlib.Path(a.run).resolve(); assert RUN.is_relative_to(ROOT / '.workspace'); RUN.mkdir(mode=0o700, parents=True)
BIN = str(pathlib.Path(a.binary).resolve())
SRC = pathlib.Path(a.prefix_source).resolve(); assert SRC.name and (SRC / 'system.reg').exists() and '.workspace' in SRC.parts
RT = 'dwproton-sim-11.0-4'
sim = RUN / 'sim'; rt = sim / 'compat' / RT; win = rt / 'files/lib/wine/x86_64-windows'
win.mkdir(parents=True); (sim / 'bin').mkdir(); (RUN / 'tmp').mkdir(); (RUN / 'cache').mkdir()
for name, dest in [('umu-run', sim / 'bin/umu-run'), ('pv-adverb', sim / 'bin/pv-adverb'), ('proton', rt / 'proton')]:
    shutil.copy2(ROOT / 'scripts/provenance-sim' / name, dest)
shutil.copy2(a.pe, win / 'rundll32.exe')
games = {}
for label, exe in [('a', 'GameA.exe'), ('b', 'GameB.exe')]:
    d = sim / 'games' / label; d.mkdir(parents=True); shutil.copy2(a.pe, d / exe); games[label] = d / exe
    subprocess.run(['cp', '-a', '--reflink=auto', str(SRC), str(sim / ('pfx-' + label))], check=True)

def log(s):
    print(s, flush=True)
    with (RUN / 'verification.log').open('a') as f: f.write(s + '\n')
def wait(fn, seconds=60):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        v = fn()
        if v: return v
        time.sleep(.1)
    raise AssertionError('timeout')
def cli(*args, **env):
    r = subprocess.run([BIN, *args], capture_output=True, text=True, env=dict(os.environ, **env))
    if r.returncode: raise RuntimeError(r.stderr + r.stdout)
    return json.loads(r.stdout)
base_env = dict(os.environ, TMPDIR=str(RUN / 'tmp'), XDG_CACHE_HOME=str(RUN / 'cache'), WINEDEBUG='-all',
                WINEDLLOVERRIDES='mscoree,mshtml=', DISPLAY='', WAYLAND_DISPLAY='', FLOWGATE_SIM_WINE='/usr/bin/wine', PROTONPATH=str(rt))
launches = {}
def launch(label, base):
    env = dict(base_env, WINEPREFIX=str(sim / ('pfx-' + label)) + '/', FLOWGATE_SIM_LOG=str(sim / label),
               FLOWGATE_SIM_GAME_PORT=str(base), FLOWGATE_SIM_HELPER_PORT=str(base + 1))
    u = subprocess.Popen(['python3', str(sim / 'bin/umu-run'), games[label].name], cwd=games[label].parent, env=env,
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=(RUN / f'sim-{label}.log').open('w'), text=True)
    launches[label] = dict(umu=u, port=base + 1, game_port=base)
def find(image, prefix):
    for d in os.listdir('/proc'):
        if not d.isdigit(): continue
        try:
            argv = open(f'/proc/{d}/cmdline', 'rb').read().split(b'\0')
            env = open(f'/proc/{d}/environ', 'rb').read().split(b'\0')
        except OSError: continue
        if argv and argv[0].decode(errors='replace').replace('\\', '/').lower().endswith(image.lower()) and ('WINEPREFIX=' + str(prefix) + '/').encode() in env:
            return int(d)
try:
    launch('a', 24800); launch('b', 24810)
    for label, l in launches.items():
        wait(lambda: 'READY' in l['umu'].stdout.readline())  # helper's own stdout through the chain
    pids = {k: wait(lambda k=k: find('rundll32.exe', sim / ('pfx-' + k))) for k in launches}
    procs = {k: cli('process', str(pid)) for k, pid in pids.items()}
    (RUN / 'wine-process.json').write_text(json.dumps(procs, indent=2))
    for k, pr in procs.items():
        app, prov = pr['application'], pr.get('provenance') or {}
        assert app['kind'] == 'wine' and app['prefix'] == str(sim / ('pfx-' + k)) and app['executable'] == str(win / 'rundll32.exe'), app
        l = prov.get('launch') or {}
        assert prov.get('evidence') == 'verified' and prov['role'] == 'helper' and l['kind'] == 'umu', prov
        assert l['game']['name'] == games[k].name and l['game']['status'] == 'verified-file' and l['prefix'] == app['prefix'] and l['runtime'] == RT, l
        assert {'umu-run', 'proton', 'pressure-vessel'} <= set(l['markers']), l['markers']
        log('PASS real Wine rundll32.exe PID %d in prefix %s: kind wine, provenance verified (%s), launcher %s PID %d, game %s, ancestry %s'
            % (pids[k], 'pfx-' + k, prov['reason'], l['launcher_name'], l['launcher_pid'], l['game']['name'], ' > '.join(x['name'] + ('[' + x['marker'] + ']' if x.get('marker') else '') for x in prov['ancestry'])))
    assert procs['a']['application']['key'] != procs['b']['application']['key'] and procs['a']['application']['revision'] == procs['b']['application']['revision']
    log('PASS same rundll32.exe file (same revision) in prefix A and prefix B -> different application keys (uid+wine+prefix+path)')
    # Attribution JSON (as served in API events) for an incoming UDP flow to each helper.
    for k, l in launches.items():
        at = cli('attribute', '--protocol', 'udp', '--direction', 'incoming', '--local', '127.0.0.1:%d' % l['port'], '--remote', '127.0.0.1:40000', FLOWGATE_WINE_BROKER='/usr/bin/wineserver')
        (RUN / f'wine-attribution-{k}.json').write_text(json.dumps(at, indent=2))
        t, pv = at.get('permission_target') or {}, at.get('provenance') or {}
        assert at['status'] == 'corroborated-broker-client' and at['application']['key'] == procs[k]['application']['key'], at['status']
        assert pv.get('evidence') == 'verified' and pv['launch']['game']['name'] == games[k].name, pv
        assert t['kind'] == 'helper' and t['label'].startswith('rundll32.exe in prefix ') and t['label'].endswith('pfx-%s (shared by every game using this prefix)' % k), t
        assert t['for_a_while'].startswith('Unavailable: 2 visible socket holders'), t
        log('PASS attribution (broker model, 2 holders) prefix %s: game %s via rundll32.exe; Remember "%s"; For a while "%s"' % (k, pv['launch']['game']['name'], t['label'], t['for_a_while']))
    (RUN / 'provenance-wine-result.json').write_text(json.dumps(dict(passed=True, wine='11.19 /usr/bin/wine', launcher='simulated umu-run/pv-adverb/proton scripts'), indent=2))
finally:
    for label, l in launches.items():
        open(str(sim / label) + '-stop', 'w').close()
        subprocess.run(['wineserver', '-k'], env=dict(base_env, WINEPREFIX=str(sim / ('pfx-' + label))), capture_output=True)
        u = l['umu']
        try: u.wait(10)
        except subprocess.TimeoutExpired: u.kill()
    log('CLEANED disposable prefixes/processes; host untouched')
