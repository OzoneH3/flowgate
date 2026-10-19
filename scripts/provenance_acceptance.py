"""Launch provenance / game grouping acceptance (SIMULATION, native fixtures).

Imported only by scripts/process-rules-isolated.py --provenance inside
scripts/lab.sh. Two simultaneous simulated "Proton launches" reproduce the
process shape and argv of the observed host launch
  python3 umu-run GAME.exe -> pv-adverb -> python3 .../proton waitforexitandrun
  GAME.exe -> {GAME.exe, intermediate -> files/lib/wine/x86_64-windows/rundll32.exe}
with distinct WINEPREFIX directories under the run directory. Every "Windows"
image is the native process-rule fixture renamed/placed at Proton-like paths:
this is NOT real Wine/Proton/pressure-vessel (see scripts/provenance-wine.py
for the real-Wine prefix-key case). Real private receivers, same primary API
as Electron, never the host.
"""
import json, os, shutil, signal, subprocess, sys, time

SIM_RUNTIME = 'dwproton-sim-11.0-4'


def check(g):
    api, wait, log, RUN, ask, NATIVE = [g[k] for k in ('api', 'wait', 'log', 'RUN', 'ask', 'NATIVE')]
    ROOT = g['ROOT']
    gen = lambda: api()['generation']
    out = {}

    def save(name, v):
        (RUN / name).write_text(json.dumps(v, indent=2) + '\n'); out[name] = v

    def peer():
        p = RUN / 'peer-received.log'; return p.read_text().splitlines() if p.exists() else []

    def delivered_after(before, seconds=4):
        try:
            wait(lambda: len(peer()) > before, seconds); return True
        except AssertionError:
            return False

    def events_pid(pid, state=None):
        return [v for v in api().get('events', []) if any(o['pid'] == pid for o in v['attribution'].get('owners', [])) and (state is None or v['state'] == state)]

    def new_event(pid, known, seconds=8):
        return wait(lambda: next((v for v in events_pid(pid) if v['id'] not in known), None), seconds)

    def decide(ev, action, scope, **kw):
        return api('decide', generation=gen(), id=ev['id'], action=action, scope=scope, **kw)

    # ---- simulated install: runtime, games, prefixes ----
    sim = RUN / 'sim'
    rt = sim / 'compat' / SIM_RUNTIME
    win = rt / 'files/lib/wine/x86_64-windows'
    win.mkdir(parents=True)
    (sim / 'bin').mkdir()
    for name, dest in [('umu-run', sim / 'bin/umu-run'), ('pv-adverb', sim / 'bin/pv-adverb'), ('proton', rt / 'proton')]:
        shutil.copy2(ROOT / 'scripts/provenance-sim' / name, dest)
    for exe in ['rundll32.exe', 'crs-handler.exe']:
        shutil.copy2(NATIVE, win / exe)
    games = {}
    for label, exe in [('a', 'GameA.exe'), ('b', 'GameB.exe')]:
        d = sim / 'games' / label; d.mkdir(parents=True); shutil.copy2(NATIVE, d / exe); games[label] = d / exe
        (sim / ('pfx-' + label)).mkdir()
    launches = {}

    def launch(label, base, orphan=False):
        """Start a simulated umu-run launch; returns its handle (helper stdin/stdout via the chain)."""
        logp = str(sim / f'{label}{base}')
        env = dict(os.environ, WINEPREFIX=str(sim / ('pfx-' + label[0])) + '/', PROTONPATH=str(rt),
                   FLOWGATE_SIM_LOG=logp, FLOWGATE_SIM_GAME_PORT=str(base), FLOWGATE_SIM_HELPER_PORT=str(base + 10),
                   FLOWGATE_FIXTURE_TIMEOUT_SECONDS='10', SteamAppId='0', UMU_ID='umu-sim-' + label[0])
        fifo = None
        if orphan:
            fifo = sim / f'{label}-orphan'; os.mkfifo(fifo)
            env.update(FLOWGATE_SIM_ORPHAN=str(fifo), FLOWGATE_SIM_ORPHAN_PORT=str(base + 20))
            fifo_fd = os.open(fifo, os.O_RDWR)  # never blocks; the orphan reads from it
        umu = subprocess.Popen(['python3', str(sim / 'bin/umu-run'), games[label[0]].name], cwd=games[label[0]].parent, env=env,
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=(RUN / f'sim-{label}.log').open('a'), text=True)
        helper = json.loads(umu.stdout.readline())
        gamefile = logp + '-game.json'
        wait(lambda: os.path.exists(gamefile) and open(gamefile).read().strip())
        h = dict(label=label, umu=umu, log=logp, helper=helper, game=json.loads(open(gamefile).readline()), base=base)
        if orphan:
            outp = str(fifo) + '.out'
            wait(lambda: os.path.exists(outp) and open(outp).read().strip())
            h.update(orphan=json.loads(open(outp).readline()), orphan_fd=fifo_fd, orphan_out=outp)
        launches[label] = h
        return h

    def helper_send(h, proto='tcp', host='10.79.0.2', port=43000):
        known = {v['id'] for v in events_pid(h['helper']['pid'])}
        h['umu'].stdin.write(json.dumps(dict(op='send', protocol=proto, host=host, port=port)) + '\n'); h['umu'].stdin.flush()
        json.loads(h['umu'].stdout.readline())
        return new_event(h['helper']['pid'], known)

    def stop(h):
        open(h['log'] + '-stop', 'w').close()
        if h['umu'].poll() is None:
            h['umu'].stdin.close()  # helper sees EOF and exits
            h['umu'].wait(10)

    def ppid(pid):
        s = open(f'/proc/{pid}/stat').read(); return int(s[s.rindex(')') + 2:].split()[1])

    def activity_process(pid):
        procs = api()['activity']['processes']
        return next((p for p in procs.values() if p['pid'] == pid), None)

    # 1. Two simultaneous launches + an unrelated native python3.
    A, B = launch('a', 45200), launch('b', 45300, orphan=True)
    py = subprocess.Popen(['python3', '-c', 'import socket,sys\nfor _ in sys.stdin:\n'
                           ' try:\n  s=socket.create_connection(("10.79.0.2",44000),timeout=4);s.sendall(b"py");s.recv(8);s.close()\n'
                           ' except OSError:pass\n print("sent",flush=True)'],
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    # 2. Activity (the API snapshot the UI groups): provenance per process.
    def verified(pid):
        p = activity_process(pid)
        return p if p and (p.get('provenance') or {}).get('evidence') == 'verified' else None
    ha, ga, hb, gb = [wait(lambda pid=pid: verified(pid)) for pid in (A['helper']['pid'], A['game']['pid'], B['helper']['pid'], B['game']['pid'])]
    save('activity-provenance.json', dict(helper_a=ha, game_a=ga, helper_b=hb, game_b=gb))
    save('activity-snapshot.json', api()['activity'])  # input for the Electron grouping check
    pa, pga, pb, pgb = [x['provenance'] for x in (ha, ga, hb, gb)]
    for prov, label, role in [(pa, 'a', 'helper'), (pga, 'a', 'game'), (pb, 'b', 'helper'), (pgb, 'b', 'game')]:
        l = prov['launch']
        assert prov['role'] == role and l['kind'] == 'umu' and l['game']['name'] == games[label].name and l['game']['status'] == 'verified-file', prov
        assert l['game']['executable'] == str(games[label]) and l['prefix'] == str(sim / ('pfx-' + label)) and l['prefix_id'], l
        assert l['runtime'] == SIM_RUNTIME and {'umu-run', 'proton', 'pressure-vessel'} <= set(l['markers']) and l['game_id'] == 'umu-sim-' + label, l
        assert l['launcher_name'].startswith('python3') and l['launcher_name'].endswith('umu-run'), l
    assert pa['group'] == pga['group'] and pb['group'] == pgb['group'] and pa['group'] != pb['group']
    # The renamed native image at .../files/lib/wine/x86_64-windows/rundll32.exe with an
    # explicit WINEPREFIX takes FlowGate's Wine identity branch (argv[0] == mapped image):
    # key = uid + wine + prefix + path, exactly the formula used for real Proton helpers.
    assert ha['application']['kind'] == hb['application']['kind'] == 'wine', (ha['application'], hb['application'])
    assert ha['application']['executable'] == hb['application']['executable'] and ha['application']['key'] != hb['application']['key']
    orphan = activity_process(B['orphan']['pid'])
    assert orphan and (orphan.get('provenance') or {}).get('evidence') == 'none' and not orphan['provenance'].get('launch'), orphan
    log('PASS SIMULATION Activity: two simultaneous launches -> groups %s (GameA.exe: helper rundll32.exe + game) and %s (GameB.exe); prefixes %s / %s, runtime %s, markers %s; orphaned crs-handler.exe (adopted by init before first sight) has no launch'
        % (pa['group'], pb['group'], pa['launch']['prefix'], pb['launch']['prefix'], SIM_RUNTIME, ','.join(pa['launch']['markers'])))

    # 3. Unrelated python3: same interpreter as umu-run, no provenance.
    known = {v['id'] for v in events_pid(py.pid)}
    py.stdin.write('go\n'); py.stdin.flush()
    ev = new_event(py.pid, known); save('unrelated-python-event.json', ev)
    a = ev['attribution']
    assert a.get('provenance', {}).get('evidence') == 'none' and not a['provenance'].get('launch'), a.get('provenance')
    assert a['permission_target']['kind'] == 'interpreter', a['permission_target']
    assert not decide(ev, 'block', 'once').get('error'); py.stdout.readline()
    log('PASS unrelated native %s: provenance evidence "none", no launch/group; Remember target "%s"' % (a['application']['name'], a['permission_target']['label']))

    # 4. The umu-run launcher's own connection (case a: python3.x = umu-run).
    known = {v['id'] for v in events_pid(A['umu'].pid)}
    A['umu'].send_signal(signal.SIGUSR1)
    ev = new_event(A['umu'].pid, known); save('launcher-event.json', ev)
    pr, t = ev['attribution']['provenance'], ev['attribution']['permission_target']
    assert pr['evidence'] == 'verified' and pr['role'] == 'launcher' and pr['group'] == pa['group'] and pr['launch']['game']['name'] == 'GameA.exe', pr
    assert t['kind'] == 'interpreter' and 'not only python3' in t['shared_with_note'] and 'umu-run' in t['shared_with_note'], t
    assert not decide(ev, 'block', 'once').get('error')
    log('PASS launcher %s PID %d: provenance verified role launcher, game GameA.exe (same group); Remember target: "%s — %s"' % (ev['attribution']['application']['name'], A['umu'].pid, t['label'], t['shared_with_note']))

    # 5. Helper event: provenance retained with the event; explicit targets.
    before = len(peer()); ev = helper_send(A); save('helper-a-event.json', ev)
    pr, t = ev['attribution']['provenance'], ev['attribution']['permission_target']
    assert ev['state'] == 'awaiting-decision' and pr['evidence'] == 'verified' and pr['role'] == 'helper' and pr['group'] == pa['group'], ev
    assert t['kind'] == 'helper' and t['label'].startswith('rundll32.exe in prefix ') and t['label'].endswith('(shared by every game using this prefix)') and 'not only GameA.exe' in t['shared_with_note'], t
    assert t['key_basis'].startswith('uid+wine+prefix+executable path') and t['prefix'] == str(sim / 'pfx-a'), t
    assert 'This process instance only: rundll32.exe PID %d' % A['helper']['pid'] in t['for_a_while'], t
    r = decide(ev, 'allow', 'for-a-while'); assert not r.get('error'), r; lease = r['decision']['lease']
    assert delivered_after(before)
    log('PASS helper rundll32.exe PID %d (GameA launch) prompt targets: Once "%s" | For a while "%s" | Remember "%s — %s"' % (A['helper']['pid'], t['once'], t['for_a_while'], t['label'], t['shared_with_note']))
    ev_old = ev

    # 6. Process-instance scope: sibling helper in launch B and a RELAUNCHED A both prompt
    #    while the lease of the first helper is still inside its window.
    sb = helper_send(B); assert sb['state'] == 'awaiting-decision' and not sb['rule'].startswith('while:'), sb
    assert not decide(sb, 'block', 'once').get('error')
    stop(A); wait(lambda: not os.path.exists('/proc/%d' % A['helper']['pid']))
    A2 = launch('a2', 45400)
    p2 = wait(lambda: verified(A2['helper']['pid']))['provenance']
    assert p2['group'] != pa['group'] and p2['launch']['launcher_pid'] == A2['umu'].pid and p2['launch']['game']['name'] == 'GameA.exe', p2
    rel = helper_send(A2); save('relaunch-event.json', rel)
    assert rel['state'] == 'awaiting-decision' and not rel['rule'].startswith('while:'), rel
    leases = api().get('process_leases', [])
    assert all(x['id'] != lease['id'] for x in leases), ('lease of the exited helper still listed', leases)
    assert not decide(rel, 'block', 'once').get('error')
    # The ended helper's request keeps its captured provenance.
    kept = next(v for v in api()['events'] if v['id'] == ev_old['id'])
    assert kept['attribution']['provenance']['group'] == pa['group'] and not os.path.exists('/proc/%d' % A['helper']['pid']), kept['state']
    log('PASS For a while on helper PID %d covers only that instance: helper in launch B prompted, relaunched GameA (new launcher PID %d, new group %s) helper PID %d prompted; ended request kept provenance group %s'
        % (A['helper']['pid'], A2['umu'].pid, p2['group'], A2['helper']['pid'], pa['group']))

    # 7. Remember (app-wide: address/port/protocol unchecked) on the helper in prefix A.
    #    Stated scope: rundll32.exe in prefix A. The same rundll32.exe file in prefix B
    #    (launch B) is another application key and is NOT covered; a new connection
    #    of the (relaunched) helper in prefix A is.
    fields = dict(address=False, port=False, protocol=False, process=False)
    ev = helper_send(A2); z = api()['network_zones']['revision']
    pv = api('decision-preview', generation=gen(), id=ev['id'], action='allow', scope='persistent', network_zone='any', zone_revision=z, remember=fields)
    assert not pv.get('error'), pv; pv = pv['decision_preview']; save('remember-preview.json', pv)
    before = len(peer())
    r = decide(ev, 'allow', 'persistent', network_zone='any', zone_revision=z, remember=fields, preview_token=pv['token']); assert not r.get('error'), r
    assert delivered_after(before)
    # Destination-specific receiver counts: earlier held retransmissions cannot confound them.
    dest = lambda line: sum(1 for x in peer() if x == line)
    before = dest("tcp ('10.79.0.3', 44000)"); other = helper_send(B, host='10.79.0.3', port=44000); save('remember-other-prefix.json', other)
    assert other['state'] == 'awaiting-decision' and other['attribution']['application']['key'] != ev['attribution']['application']['key'], other
    r = decide(other, 'block', 'once'); assert not r.get('error'), r
    time.sleep(1.0); assert dest("tcp ('10.79.0.3', 44000)") == before, 'prefix-B helper delivered after Deny'
    before = dest("udp ('10.79.0.3', 44001)"); same = helper_send(A2, proto='udp', host='10.79.0.3', port=44001); save('remember-same-prefix.json', same)
    assert same['state'] == 'allowed' and not same['rule'].startswith('while:'), same
    wait(lambda: dest("udp ('10.79.0.3', 44001)") > before, 4)
    for rule in api()['rules']:
        assert not api('rule-delete', generation=gen(), id=rule['id'], expected_version=rule['version']).get('error')
    log('PASS SIMULATION Remember on rundll32.exe in prefix A (app-wide): same rundll32.exe file in prefix B prompted (different key) and was not delivered; a new UDP connection of the prefix-A helper was allowed by the rule')

    # 8. Reparenting after first sight: release the intermediate, helper adopted by init,
    #    later request still carries the provenance captured at first sight.
    open(A2['log'] + '-release', 'w').close()
    wait(lambda: ppid(A2['helper']['pid']) == 1)
    ev = helper_send(A2); save('reparented-event.json', ev)
    pr = ev['attribution']['provenance']
    assert pr['evidence'] == 'verified' and pr['group'] == p2['group'], pr
    assert not decide(ev, 'block', 'once').get('error')
    log('PASS helper PID %d reparented to init (ppid 1) after first sight keeps verified provenance group %s (captured per PID+start)' % (A2['helper']['pid'], p2['group']))

    # 9. Orphan never seen under its launcher (case b analogue): no game identity invented.
    known = {v['id'] for v in events_pid(B['orphan']['pid'])}
    os.write(B['orphan_fd'], (json.dumps(dict(op='send', protocol='tcp', host='10.79.0.2', port=43000)) + '\n').encode())
    ev = new_event(B['orphan']['pid'], known); save('orphan-event.json', ev)
    pr, t = ev['attribution'].get('provenance') or {}, ev['attribution']['permission_target']
    assert pr.get('evidence') == 'none' and not pr.get('launch') and pr.get('stop') == 'init', pr
    # Wine identity without provenance: still the prefix-wide helper scope, no game named.
    assert t['kind'] == 'helper' and t['label'].startswith('crs-handler.exe in prefix ') and 'shared by every game' in t['label'] and 'not only' not in t['shared_with_note'], t
    assert not decide(ev, 'block', 'once').get('error')
    log('PASS orphaned crs-handler.exe PID %d (parent exited before first sight): provenance "none", game unknown, target "%s"' % (B['orphan']['pid'], t['label']))

    py.stdin.close(); py.wait(5)
    for h in launches.values():
        stop(h)
    os.close(B['orphan_fd'])
    try:
        os.kill(B['orphan']['pid'], signal.SIGTERM)
    except ProcessLookupError:
        pass
    (RUN / 'provenance-result.json').write_text(json.dumps(dict(passed=True, simulation='native fixtures renamed to Proton-like paths', host_actions=False), indent=2) + '\n')
