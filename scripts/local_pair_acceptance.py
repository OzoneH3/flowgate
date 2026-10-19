"""Local (same-host) connection pairs: acceptance with real private receivers.

Imported only by scripts/process-rules-isolated.py --local-pair inside
scripts/lab.sh (private network namespace, profile both: outgoing AND
incoming interception). A native fixture instance renamed "cupsd-sim" listens
on 127.0.0.1/::1 (and the existing fixtures on the lab's own address
10.79.0.1); other fixture instances and two SIMULATED Proton launches
(scripts/provenance-sim; native fixture images at Proton-like paths, not real
Wine) connect to it. Same primary API as Electron. Never touches the host.
"""
import json, os, shutil, signal, subprocess, time

SIM_RUNTIME = 'dwproton-sim-11.0-4'


def check(g):
    api, wait, log, RUN, ask, infos, children, NATIVE, ROOT = [g[k] for k in ('api', 'wait', 'log', 'RUN', 'ask', 'infos', 'children', 'NATIVE', 'ROOT')]
    gen = lambda: api()['generation']
    out = {}

    def save(name, v):
        (RUN / name).write_text(json.dumps(v, indent=2) + '\n'); out[name] = v

    def events(): return api().get('events', [])
    def event(i): return next((v for v in events() if v['id'] == i), None)
    def owned(v, pid): return any(o['pid'] == pid for o in v['attribution'].get('owners') or [])

    def outgoing_from(pid, known, port):
        return wait(lambda: next((v for v in events() if v['id'] not in known and v['flow']['direction'] == 'outgoing'
                                  and owned(v, pid) and v['flow']['remote'].endswith(':%d' % port)), None), 8)

    def incoming_for(local, remote, seconds=8):
        return wait(lambda: next((v for v in events() if v['flow']['direction'] == 'incoming'
                                  and v['flow']['local'] == local and v['flow']['remote'] == remote), None), seconds)

    def no_incoming(local, remote, seconds=1.0):
        time.sleep(seconds)
        return not any(v['flow']['direction'] == 'incoming' and v['flow']['local'] == local and v['flow']['remote'] == remote for v in events())

    def send(child, pid, proto, host, port, v6=False, **kw):
        known = {v['id'] for v in events()}
        ask(child, 'send', protocol=proto, v6=v6, host=host, port=port, **kw)
        return outgoing_from(pid, known, port)

    def received(key): return ask(server, 'counts')['counts'].get(key, 0)

    def delivered(key, before, seconds=5):
        try:
            wait(lambda: received(key) > before, seconds); return True
        except AssertionError:
            return False

    def decide(ev, action, scope='once'): return api('decide', generation=gen(), id=ev['id'], action=action, scope=scope)
    def pair(ids, action, scope='once'): return api('decide-pair', generation=gen(), event_ids=ids, action=action, scope=scope)

    first = api()
    assert 'local-pair-v1' in first['capabilities'], first['capabilities']
    assert first['enforcement']['profile'] == 'both', first['enforcement']

    # Server: the native fixture renamed cupsd-sim, bound to loopback only.
    exe = str(RUN / 'cupsd-sim'); shutil.copy2(NATIVE, exe)
    server = subprocess.Popen([exe, '46000', '127.0.0.1', '::1'], env=dict(os.environ, FLOWGATE_FIXTURE_TIMEOUT_SECONDS='10'),
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=(RUN / 'cupsd-sim.log').open('w'), text=True)
    sinfo = json.loads(server.stdout.readline()); spid = sinfo['pid']; ports = sinfo['ports']
    alpha, apid = children['alpha'], infos['alpha']['pid']
    beta, bpid = children['beta'], infos['beta']['pid']
    log('PASS capability local-pair-v1; profile both; cupsd-sim PID %d listens on 127.0.0.1/::1 TCP %d/%d UDP %d/%d'
        % (spid, ports['tcp4'], ports['tcp6'], ports['udp4'], ports['udp6']))

    # 1. Matched pair (IPv6 loopback TCP, like rundll32.exe -> [::1]:631): one review, both sides.
    port = ports['tcp6']; before = received('tcp6')
    o = send(alpha, apid, 'tcp', '::1', port, v6=True, timeout_ms=12000)
    lp = o.get('local_peer') or {}
    assert o['state'] == 'awaiting-decision' and lp.get('state') == 'verified' and lp['role'] == 'server' and lp['owner']['pid'] == spid, lp
    assert lp['socket']['kind'] == 'listener' and lp['socket']['local'] == '[::1]:%d' % port, lp
    assert no_incoming('[::1]:%d' % port, o['flow']['local'], .5) and received('tcp6') == before, 'incoming side must wait behind the held SYN'
    r = pair([o['id']], 'allow'); save('pair-decision.json', r)
    assert not r.get('error'), r
    p = r['pair']; adm = p['incoming_admission']
    assert [e['state'] for e in p['events']] == ['allowed'] and adm['outcome'] == 'pair' and adm['server']['pid'] == spid and adm['action'] == 'allow', p
    i = incoming_for('[::1]:%d' % port, o['flow']['local']); save('pair-incoming-event.json', i)
    ip, op = i['local_peer'], event(o['id'])['local_peer']
    assert i['state'] == 'allowed' and ip['state'] == 'verified' and ip['role'] == 'client' and ip['owner']['pid'] == apid, i
    assert ip['correlated_event_id'] == o['id'] and op['correlated_event_id'] == i['id'], (ip, op)
    cookie = o['attribution']['sockets'][0]['cookie']
    assert ip['socket']['cookie'] == cookie and ip['socket']['local'] == o['flow']['local'] and ip['socket']['remote'] == o['flow']['remote'], (ip['socket'], cookie)
    assert i['attribution']['owners'][0]['pid'] == spid and i['attribution']['permission_target']['label'].startswith('cupsd-sim'), i['attribution']['permission_target']
    # Permission targets stay explicit per side: the incoming rule is for the server, the outgoing one for the client.
    assert not o['attribution']['permission_target']['label'].startswith('cupsd-sim') and o['attribution']['owners'][0]['pid'] == apid, o['attribution']['permission_target']
    assert delivered('tcp6', before), 'server did not receive after both sides were allowed'
    log('PASS matched pair TCP %s -> [::1]:%d: outgoing names server cupsd-sim PID %d (listener); decide-pair Allow -> outgoing allowed + incoming admitted; incoming %s client PID %d cookie %s = outgoing socket; both reference each other; server received'
        % (o['flow']['local'], port, spid, i['id'][:8], apid, cookie))

    # 2. One side at a time: server receives only when BOTH sides are allowed.
    port = ports['tcp4']; before = received('tcp4')
    o = send(alpha, apid, 'tcp', '127.0.0.1', port, timeout_ms=12000)
    assert not decide(o, 'allow').get('error')
    i = incoming_for('127.0.0.1:%d' % port, o['flow']['local'])
    assert i['state'] == 'awaiting-decision' and i['local_peer']['correlated_event_id'] == o['id'] and event(o['id'])['state'] == 'allowed', i
    time.sleep(.6); assert received('tcp4') == before, 'delivered with only the outgoing side allowed'
    r = pair([o['id'], i['id']], 'block'); save('pair-one-side-pending.json', r)
    assert not r.get('error') and [e['state'] for e in r['pair']['events']] == ['allowed', 'blocked'], r
    time.sleep(.8); assert received('tcp4') == before, 'delivered although the incoming side was denied'
    o2 = send(alpha, apid, 'tcp', '127.0.0.1', port, timeout_ms=12000)
    assert not decide(o2, 'allow').get('error')
    i2 = incoming_for('127.0.0.1:%d' % port, o2['flow']['local'])
    assert i2['state'] == 'awaiting-decision' and not delivered('tcp4', before, 0.6)
    assert not decide(i2, 'allow').get('error') and delivered('tcp4', before)
    log('PASS outgoing allowed alone: incoming %s stays pending and is shown as the pair (correlated), nothing delivered; decide-pair with one side decided returned both verdicts [allowed, blocked] and nothing was delivered; allowing the second side delivered' % i['id'][:8])

    # 3. Concurrent clients to the same server port; mismatched tuples never pair.
    port = ports['tcp4']; before = received('tcp4')
    oa = send(alpha, apid, 'tcp', '127.0.0.1', port, timeout_ms=12000)
    ob = send(beta, bpid, 'tcp', '127.0.0.1', port, timeout_ms=12000)
    assert oa['flow']['local'] != ob['flow']['local']
    r = pair([oa['id']], 'allow'); assert not r.get('error'), r
    ia = incoming_for('127.0.0.1:%d' % port, oa['flow']['local'])
    assert ia['state'] == 'allowed' and ia['local_peer']['owner']['pid'] == apid and ia['local_peer']['correlated_event_id'] == oa['id']
    assert delivered('tcp4', before); before = received('tcp4')
    assert event(ob['id'])['state'] == 'awaiting-decision' and no_incoming('127.0.0.1:%d' % port, ob['flow']['local'], .3)
    assert not decide(ob, 'allow').get('error')
    ib = incoming_for('127.0.0.1:%d' % port, ob['flow']['local']); save('concurrent-beta-incoming.json', ib)
    assert ib['state'] == 'awaiting-decision', ('pair admission of alpha leaked to beta', ib)
    assert ib['local_peer']['owner']['pid'] == bpid and ib['local_peer']['correlated_event_id'] == ob['id'] and ib['local_peer']['socket']['cookie'] != ia['local_peer']['socket']['cookie'], ib['local_peer']
    bad = pair([oa['id'], ib['id']], 'allow'); assert bad.get('error_code') == 'not_a_pair', bad
    assert event(ib['id'])['state'] == 'awaiting-decision'
    assert not decide(ib, 'block').get('error'); time.sleep(.6); assert received('tcp4') == before
    log('PASS two concurrent clients to 127.0.0.1:%d (alpha %s, beta %s): each incoming pairs only with its own client socket/PID; alpha pair admission did not answer beta; decide-pair across connections refused not_a_pair; beta denied -> not delivered'
        % (port, oa['flow']['local'], ob['flow']['local']))

    # 4. UDP connected peer (IPv4 and IPv6 loopback) and a non-loopback local address.
    for key, host, v6 in (('udp4', '127.0.0.1', False), ('udp6', '::1', True)):
        port = ports[key]; before = received(key)
        o = send(beta, bpid, 'udp', host, port, v6=v6, timeout_ms=8000)
        assert o['local_peer']['state'] == 'verified' and o['local_peer']['socket']['kind'] == 'bound' and o['local_peer']['owner']['pid'] == spid, o['local_peer']
        r = pair([o['id']], 'allow'); assert not r.get('error'), r
        i = incoming_for(o['flow']['remote'], o['flow']['local'])
        assert i['state'] == 'allowed' and i['local_peer']['socket']['kind'] == 'client' and i['local_peer']['owner']['pid'] == bpid and i['local_peer']['correlated_event_id'] == o['id'], i
        assert delivered(key, before)
    target = infos['alpha']['ports']['tcp4']  # alpha listens on the lab's own 10.79.0.1
    o = send(beta, bpid, 'tcp', '10.79.0.1', target, timeout_ms=12000)
    assert o['local_peer']['state'] == 'verified' and o['local_peer']['owner']['pid'] == apid, o.get('local_peer')
    assert not pair([o['id']], 'allow').get('error')
    i = incoming_for('10.79.0.1:%d' % target, o['flow']['local'])
    assert i['state'] == 'allowed' and i['local_peer']['owner']['pid'] == bpid, i
    log('PASS UDP connected client socket paired exactly on 127.0.0.1 and ::1 (bound receiver cupsd-sim, client beta) and delivered; non-loopback local address 10.79.0.1 (via lo) paired beta -> alpha')

    # 5. Short-lived client. With both directions intercepted the SYN is held at
    #    OUTPUT, so the client socket exists until the outgoing decision; a
    #    client that exits first ends its request and nothing reaches the server.
    port = ports['tcp4']; before = received('tcp4')
    py = subprocess.Popen(['python3', '-c', 'import socket,sys,time\ns=socket.socket();s.settimeout(30)\n'
                           'try:s.connect(("127.0.0.1",%d))\nexcept OSError:pass' % port])
    o = wait(lambda: next((v for v in events() if v['flow']['direction'] == 'outgoing' and owned(v, py.pid)), None), 8)
    py.kill(); py.wait(5)
    r = pair([o['id']], 'allow'); save('short-lived-refusal.json', r)
    assert r.get('error_code') and r['error_code'] != 'not_a_pair', r
    assert no_incoming('127.0.0.1:%d' % port, o['flow']['local'], .8) and received('tcp4') == before
    log('PASS short-lived client PID %d exited while its outgoing request was held: decide-pair refused (%s), no incoming request, nothing delivered. The incoming "Local client unknown" state cannot be reached with both directions intercepted; it is covered by real-socket unit tests (TestLocalPeerShortLivedClientUnknown) - SIMULATED here, not a receiver result'
        % (py.pid, r['error_code']))

    # 6. Two simulated Proton launches: helpers (rundll32.exe, different prefixes)
    #    connect to cupsd-sim on [::1]; the incoming side names each game.
    sim = RUN / 'sim'; rt = sim / 'compat' / SIM_RUNTIME; win = rt / 'files/lib/wine/x86_64-windows'
    win.mkdir(parents=True); (sim / 'bin').mkdir()
    for name, dest in [('umu-run', sim / 'bin/umu-run'), ('pv-adverb', sim / 'bin/pv-adverb'), ('proton', rt / 'proton')]:
        shutil.copy2(ROOT / 'scripts/provenance-sim' / name, dest)
    shutil.copy2(NATIVE, win / 'rundll32.exe')
    launches = []

    def launch(label, base):
        d = sim / 'games' / label; d.mkdir(parents=True); game = d / ('Game%s.exe' % label.upper()); shutil.copy2(NATIVE, game)
        (sim / ('pfx-' + label)).mkdir()
        logp = str(sim / label)
        env = dict(os.environ, WINEPREFIX=str(sim / ('pfx-' + label)) + '/', PROTONPATH=str(rt), FLOWGATE_SIM_LOG=logp,
                   FLOWGATE_SIM_GAME_PORT=str(base), FLOWGATE_SIM_HELPER_PORT=str(base + 10), FLOWGATE_FIXTURE_TIMEOUT_SECONDS='10',
                   SteamAppId='0', UMU_ID='umu-sim-' + label)
        umu = subprocess.Popen(['python3', str(sim / 'bin/umu-run'), game.name], cwd=d, env=env, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=(RUN / ('sim-%s.log' % label)).open('a'), text=True)
        helper = json.loads(umu.stdout.readline())
        h = dict(label=label, umu=umu, log=logp, helper=helper, game=game); launches.append(h); return h

    A, B = launch('a', 45200), launch('b', 45300)
    port = ports['tcp6']; results = []
    for h in (A, B):
        before = received('tcp6'); known = {v['id'] for v in events()}
        h['umu'].stdin.write(json.dumps(dict(op='send', protocol='tcp', v6=True, host='::1', port=port, timeout_ms=12000)) + '\n'); h['umu'].stdin.flush()
        json.loads(h['umu'].stdout.readline())
        o = outgoing_from(h['helper']['pid'], known, port)
        r = pair([o['id']], 'allow'); assert not r.get('error'), r
        i = incoming_for('[::1]:%d' % port, o['flow']['local']); save('proton-%s-incoming.json' % h['label'], i)
        c = i['local_peer']; prov = c['owner'].get('provenance') or {}
        assert c['state'] == 'verified' and c['owner']['pid'] == h['helper']['pid'] and c['correlated_event_id'] == o['id'], c
        assert c['owner']['application']['name'] == 'rundll32.exe' and c['owner']['application']['kind'] == 'wine', c['owner']['application']
        assert prov.get('evidence') == 'verified' and prov['role'] == 'helper' and prov['launch']['game']['name'] == h['game'].name, prov
        assert i['attribution']['owners'][0]['pid'] == spid and delivered('tcp6', before)
        results.append((h['label'], c['owner']['pid'], prov['group'], prov['launch']['game']['name'], c['socket']['local']))
    assert results[0][2] != results[1][2]
    log('PASS SIMULATION two Proton launches -> cupsd-sim [::1]:%d: %s' % (port, '; '.join(
        'game %s helper rundll32.exe PID %d (group %s) from %s' % (g, pid, grp, src) for _, pid, grp, g, src in results)))

    for h in launches:
        open(h['log'] + '-stop', 'w').close()
        if h['umu'].poll() is None:
            h['umu'].stdin.close(); h['umu'].wait(10)
    server.terminate(); server.wait(5)
    (RUN / 'local-pair-result.json').write_text(json.dumps(dict(passed=True, host_actions=False, simulation='Proton launches are native fixtures at Proton-like paths'), indent=2) + '\n')
