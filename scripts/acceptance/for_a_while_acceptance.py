"""For a while (decision-for-a-while-v1) acceptance with real private receivers.

Imported only by scripts/acceptance/process-rules-isolated.py --for-a-while inside
scripts/lab.sh. Same primary API as Electron. Never touches the host.
"""
import json,os,subprocess,time

def check(g):
    api,wait,log,RUN,ask,remote,infos,children,NATIVE=[g[k] for k in ('api','wait','log','RUN','ask','remote','infos','children','NATIVE')]
    gen=lambda:api()['generation']
    out={}
    def save(name,v):(RUN/name).write_text(json.dumps(v,indent=2)+'\n');out[name]=v
    def peer():
        p=RUN/'peer-received.log';return p.read_text().splitlines() if p.exists() else []
    def events_pid(pid,state=None,direction=None):
        return [v for v in api().get('events',[]) if any(o['pid']==pid for o in v['attribution'].get('owners',[])) and (state is None or v['state']==state) and (direction is None or v['flow']['direction']==direction)]
    def new_event(pid,known,direction='outgoing'):
        return wait(lambda:next((v for v in events_pid(pid,direction=direction) if v['id'] not in known),None),6)
    def send(child,pid,proto,host,port,v6=False):
        """One new outgoing connection (new socket/source port); returns its first event."""
        known={v['id'] for v in events_pid(pid)}
        ask(child,'send',protocol=proto,v6=v6,host=host,port=port)
        return new_event(pid,known)
    def delivered_after(before,seconds=4):
        try:wait(lambda:len(peer())>before,seconds);return True
        except AssertionError:return False
    def decide(ev,action,scope):
        return api('decide',generation=gen(),id=ev['id'],action=action,scope=scope)
    def leases():
        r=api();assert 'process_leases' in r,'list lacks process_leases';return r['process_leases']
    launched=[]
    def launch(port):
        c=subprocess.Popen([NATIVE,str(port)],env=dict(os.environ,FLOWGATE_FIXTURE_TIMEOUT_SECONDS='10'),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=(RUN/'launch.log').open('a'),text=True)
        info=json.loads(c.stdout.readline());launched.append(c);return c,info
    def quit(c):
        if c.poll() is None:c.terminate();c.wait(5)
    alpha,apid=children['alpha'],infos['alpha']['pid']
    beta,bpid=children['beta'],infos['beta']['pid']
    caps=api()['capabilities'];assert 'decision-for-a-while-v1' in caps,caps
    assert not api().get('rules') and leases()==[]

    # 1. Prompt, For a while Allow: current connection delivered, lease listed, no rule.
    before=len(peer());ev=send(alpha,apid,'tcp','10.79.0.2',43000)
    assert ev['state']=='awaiting-decision' and 'for-a-while' in ev.get('scope_previews',{}),ev
    assert not delivered_after(before,0.8),'held request delivered before a decision'
    r=decide(ev,'allow','for-a-while');assert not r.get('error'),r
    d=r['decision'];save('allow-decision.json',d)
    lease=d['lease'];assert lease['seconds']==15 and lease['id'] and d['rule']=='once:'+ev['id'],d
    t0=time.monotonic()
    assert delivered_after(before),'For a while Allow did not deliver the current connection'
    ls=leases();save('allow-leases.json',ls)
    assert len(ls)==1 and ls[0]['id']==lease['id'] and ls[0]['pid']==apid and ls[0]['action']=='allow' and ls[0]['direction']=='outgoing' and ls[0]['event_id']==ev['id'] and 0<ls[0]['remaining_ms']<=15000,ls
    assert not api().get('rules'),'For a while created a rule'
    log('PASS For a while Allow delivered the prompted TCP connection; lease %s listed for PID %d (15 s); no rule created'%(lease['id'],apid))

    # 2. Same live process, same direction, new TCP and UDP (IPv4/IPv6) connections: delivered, no prompt.
    covered=[]
    for proto,host,port,v6 in [('tcp','10.79.0.3',44000,False),('udp','10.79.0.2',43001,False),('udp','fd79::3',44001,True),('tcp','fd79::2',43000,True)]:
        before=len(peer());v=send(alpha,apid,proto,host,port,v6)
        assert v['state']=='allowed' and v['rule']=='while:'+lease['id'] and 'For a while (allow) for process %d'%apid in v['reason'],v
        assert delivered_after(before),('lease-covered connection not delivered',proto,host)
        covered.append(v)
    assert not events_pid(apid,'awaiting-decision'),'lease-covered connection prompted'
    save('allow-covered-events.json',covered)
    log('PASS same process within %.1f s: TCP+UDP IPv4/IPv6 to other destinations delivered by while:%s without a new prompt'%(time.monotonic()-t0,lease['id']))

    # 3. Sibling instance of the same executable prompts.
    before=len(peer());sib=send(beta,bpid,'tcp','10.79.0.2',43000)
    assert sib['state']=='awaiting-decision' and not sib['rule'].startswith('while:'),sib
    assert not decide(sib,'block','once').get('error');save('sibling-prompt.json',sib)
    assert not delivered_after(before,1.0),'sibling delivered after Deny once'
    # 4. Incoming to the same process: outgoing lease does not cover it.
    port=infos['alpha']['ports']['udp4'];known={v['id'] for v in events_pid(apid)}
    remote('udp',port=port,v6=False);inc=new_event(apid,known,'incoming')
    assert inc['state']=='awaiting-decision' and not inc['rule'].startswith('while:'),inc
    assert not decide(inc,'block','once').get('error');save('incoming-prompt.json',inc)
    ls=leases();assert len(ls)==1 and ls[0]['id']==lease['id'] and ls[0]['remaining_ms']>0,('checks not inside the window',ls)
    log('PASS inside the window (%d ms left): sibling PID %d of the same executable prompted; incoming to PID %d prompted (lease is outgoing only)'%(ls[0]['remaining_ms'],bpid,apid))

    # 5. Relaunched process: a lease for an exited instance never covers its successor.
    gc,gi=launch(45100);before=len(peer())
    gev=send(gc,gi['pid'],'tcp','10.79.0.2',43000);assert gev['state']=='awaiting-decision',gev
    gr=decide(gev,'allow','for-a-while');assert not gr.get('error'),gr;glease=gr['decision']['lease']
    assert delivered_after(before)
    quit(gc);wait(lambda:not os.path.exists('/proc/%d'%gi['pid']))
    gc2,gi2=launch(45110);assert gi2['pid']!=gi['pid']
    rel=send(gc2,gi2['pid'],'tcp','10.79.0.2',43000)
    assert rel['state']=='awaiting-decision' and not rel['rule'].startswith('while:'),rel
    ls=leases();assert all(x['id']!=glease['id'] for x in ls),('lease of exited process still listed',ls)
    assert not decide(rel,'block','once').get('error');save('relaunch-prompt.json',rel);quit(gc2)
    log('PASS relaunched executable PID %d -> %d prompted although lease %s was still within its 15 s; exited lease pruned from list'%(gi['pid'],gi2['pid'],glease['id']))

    # 6. Expiry: after the fixed duration the same process is prompted again.
    remaining=[x for x in leases() if x['id']==lease['id']]
    if remaining:time.sleep(remaining[0]['remaining_ms']/1000+0.5)
    assert not any(x['id']==lease['id'] for x in leases()),'expired lease still listed'
    before=len(peer());exp=send(alpha,apid,'tcp','10.79.0.2',43000)
    assert exp['state']=='awaiting-decision' and not exp['rule'].startswith('while:'),exp
    assert not delivered_after(before,0.8);save('expired-prompt.json',exp)
    log('PASS after %.1f s the lease expired; the same process PID %d was prompted again'%(time.monotonic()-t0,apid))

    # 7. For a while Deny: current and later connections of this process are not delivered, no prompt.
    r=decide(exp,'block','for-a-while');assert not r.get('error'),r;deny=r['decision']['lease']
    assert r['decision']['state']=='blocked'
    # A decided (no longer awaiting) request cannot be decided again.
    stale=decide(exp,'allow','for-a-while');assert stale.get('error_code')=='stale_decision',stale.get('error')
    assert not delivered_after(before,2.0),'For a while Deny delivered the current connection'
    for proto,host,port in [('tcp','10.79.0.3',44000),('udp','10.79.0.2',43001)]:
        v=send(alpha,apid,proto,host,port)
        assert v['state']=='blocked' and v['rule']=='while:'+deny['id'],v
    assert not delivered_after(before,2.0),'For a while Deny delivered a later connection'
    assert not events_pid(apid,'awaiting-decision','outgoing'),'Deny lease left a prompt'
    log('PASS For a while Deny: current TCP and later TCP+UDP connections not delivered, no prompt (while:%s)'%deny['id'])

    # 8. A decided request cannot be decided again (stale), and Decision Log attribution.
    gone=decide(ev,'allow','for-a-while');assert gone.get('error') and not gone.get('decision'),'ended request decided'
    def records(source):
        r=api('decision-log',decision_query={'limit':100,'source':source});assert not r.get('error'),r.get('error');return r['decision_log']['records']
    user=[x for x in records('user') if x['kind']=='final' and x['decision'].get('scope')=='for-a-while']
    by=[x for x in records('for_a_while') if x['kind']=='final']
    assert any(x['decision'].get('lease_id')==lease['id'] for x in user) and any(x['decision'].get('lease_id')==deny['id'] for x in user),user
    assert any(x['decision'].get('lease_id')==lease['id'] and x['decision']['action']=='allow' for x in by) and any(x['decision'].get('lease_id')==deny['id'] and x['decision']['action']=='block' for x in by),by
    save('decision-log-user.json',user[0]);save('decision-log-lease.json',by[0])
    log('PASS re-decision of a decided request refused (stale_decision) and of an ended request refused; Decision Log: user final scope for-a-while with lease_id, lease-admitted/blocked connections source for_a_while')

    # 9. Not persisted: a daemon restart forgets the lease; no rules at any time.
    wait(lambda:not any(x['id']==deny['id'] for x in leases()),20)
    p=send(alpha,apid,'udp','10.79.0.2',43001);assert p['state']=='awaiting-decision',p
    r=decide(p,'allow','for-a-while');assert not r.get('error'),r;assert len(leases())==1
    g['stop']();g['start']()
    assert leases()==[] and not api().get('rules'),'lease survived restart'
    before=len(peer());p2=send(alpha,apid,'udp','10.79.0.2',43001)
    assert p2['state']=='awaiting-decision',('lease survived restart',p2)
    assert not decide(p2,'block','once').get('error')
    log('PASS lease is memory only: after daemon restart no lease is listed and the same process is prompted; rules list stayed empty')
    for c in launched:quit(c)
    (RUN/'for-a-while-result.json').write_text(json.dumps(dict(passed=True,lease_seconds=15,host_actions=False),indent=2)+'\n')
