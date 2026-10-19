"""Queue reconciliation, Once retransmission, ended-request For a while and
For a while durations: acceptance with real private receivers.

Imported only by scripts/process-rules-isolated.py --queue-reconcile inside
scripts/lab.sh. Same primary API as Electron. Never touches the host.
"""
import json,os,shutil,subprocess,time

def check(g):
    api,wait,log,RUN,ask,infos,children,NATIVE=[g[k] for k in ('api','wait','log','RUN','ask','infos','children','NATIVE')]
    gen=lambda:api()['generation']
    def save(name,v):(RUN/name).write_text(json.dumps(v,indent=2)+'\n')
    def peer():
        p=RUN/'peer-received.log';return p.read_text().splitlines() if p.exists() else []
    def events():return api().get('events',[])
    def owned(v,pid):return any(o['pid']==pid for o in v['attribution'].get('owners') or [])
    def events_pid(pid,state=None,direction='outgoing'):
        return [v for v in events() if owned(v,pid) and (state is None or v['state']==state) and v['flow']['direction']==direction]
    def send(child,pid,proto,host,port,v6=False,**kw):
        """One new outgoing connection (new socket/source port); returns its event."""
        known={v['id'] for v in events_pid(pid)}
        ask(child,'send',protocol=proto,v6=v6,host=host,port=port,**kw)
        return wait(lambda:next((v for v in events_pid(pid) if v['id'] not in known),None),6)
    def tuple_events(ev):
        f=ev['flow'];return [v for v in events() if v['flow']['local']==f['local'] and v['flow']['remote']==f['remote'] and v['flow']['protocol']==f['protocol']]
    def state(ev):return next((v['state'] for v in events() if v['id']==ev['id']),None)
    def event(ev):return next((v for v in events() if v['id']==ev['id']),None)
    def delivered_after(before,n=1,seconds=4):
        try:wait(lambda:len(peer())>=before+n,seconds);return True
        except AssertionError:return False
    def decide(ev,action,scope='once',**kw):return api('decide',generation=gen(),id=ev['id'],action=action,scope=scope,**kw)
    def deny(*evs):
        for ev in evs:
            if state(ev)=='awaiting-decision':r=decide(ev,'block');assert not r.get('error') or r.get('error_code') in ('connection_ended','stale_decision'),r
    def leases():return api()['process_leases']
    def settled_ids(r):return {x['id']:x for x in r.get('settled') or []}
    launched=[]
    def launch(executable,port):
        c=subprocess.Popen([executable,str(port)],env=dict(os.environ,FLOWGATE_FIXTURE_TIMEOUT_SECONDS='10'),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=(RUN/'launch.log').open('a'),text=True)
        info=json.loads(c.stdout.readline());launched.append(c);return c,info
    def quit(c,pid):
        if c.poll() is None:c.terminate();c.wait(5)
        wait(lambda:not os.path.exists('/proc/%d'%pid))
    alpha,apid=children['alpha'],infos['alpha']['pid']
    beta,bpid=children['beta'],infos['beta']['pid']
    other,opid=children['other'],infos['other']['pid']
    first=api();caps=first['capabilities']
    for c in ('queue-reconcile-v1','request-for-a-while-v1','decision-for-a-while-durations-v1','decision-for-a-while-v1'):assert c in caps,(c,caps)
    assert first.get('for_a_while_durations')==[15,60,300,600,1800,3600],first.get('for_a_while_durations')
    assert not first.get('rules') and leases()==[]
    log('PASS capabilities queue-reconcile-v1, request-for-a-while-v1, decision-for-a-while-durations-v1; durations [15,60,300,600,1800,3600]')

    # 1. Several pending TCP/UDP from one process, SYN retransmissions, repeated
    #    datagrams of one UDP tuple, another destination and a sibling.
    t1=send(alpha,apid,'tcp','10.79.0.2',43000,timeout_ms=12000)
    t2=send(alpha,apid,'tcp','10.79.0.2',43000,timeout_ms=12000)
    t3=send(alpha,apid,'tcp','10.79.0.3',44000,timeout_ms=12000)
    u1=send(alpha,apid,'udp','10.79.0.2',43001,timeout_ms=12000,repeat=16,interval_ms=500)
    sb=send(beta,bpid,'tcp','10.79.0.2',43000,timeout_ms=12000)
    assert t1['flow']['local']!=t2['flow']['local'] and t1['request_group']==t2['request_group'],(t1['flow'],t2['flow'])
    time.sleep(3.4) # kernel SYN retransmits at ~1 s and ~3 s; ~6 more datagrams
    for ev in (t1,t2,t3,u1,sb):
        assert len(tuple_events(ev))==1 and state(ev)=='awaiting-decision',('retransmission created a new request',tuple_events(ev))
    assert len(events_pid(apid,'awaiting-decision'))==4,events_pid(apid,'awaiting-decision')
    save('queue-initial.json',[event(x) for x in (t1,t2,t3,u1,sb)])
    log('PASS 4 pending requests of PID %d (TCP %s and %s to the same destination are distinct, TCP to another destination, UDP %s) + sibling; SYN retransmits and 7+ datagrams of the held UDP tuple created no new request'%(apid,t1['flow']['local'],t2['flow']['local'],u1['flow']['local']))
    before=len(peer());r=decide(t1,'allow');assert not r.get('error') and r['decision']['state']=='allowed',r
    assert not r.get('settled'),('Once settled other requests',r.get('settled'))
    assert delivered_after(before),'Allow Once did not deliver its flow'
    time.sleep(1.2)
    assert len(tuple_events(t1))==1 and state(t1)=='allowed'
    for ev in (t2,t3,u1,sb):assert state(ev)=='awaiting-decision',('Once covered another connection',event(ev))
    udp_before=sum(1 for x in peer() if x.startswith('udp'))
    r=decide(u1,'allow');assert not r.get('error') and not r.get('settled'),r
    wait(lambda:sum(1 for x in peer() if x.startswith('udp'))>=udp_before+3,8)
    assert len(tuple_events(u1))==1 and state(u1)=='allowed',tuple_events(u1)
    udp_delivered=sum(1 for x in peer() if x.startswith('udp'))-udp_before
    log('PASS Allow Once delivered only its TCP flow (no settled ids); retransmits never re-prompted; Once on the UDP tuple delivered %d later datagrams of that tuple within its 30 s lease with no new request; distinct connection %s, other destination and sibling stayed pending'%(udp_delivered,t2['flow']['local']))
    tcp=lambda:sum(1 for x in peer() if x.startswith('tcp'))
    before=tcp();deny(t2,t3,sb);time.sleep(1.0)
    assert tcp()==before,'Deny once delivered a TCP connection'
    # Let the allowed UDP tuple finish its datagrams before counting deliveries again.
    ask(alpha,'settle')

    # 2. For a while settles the queued same-process requests; sibling still prompts.
    a1=send(alpha,apid,'tcp','10.79.0.2',43000,timeout_ms=12000)
    a2=send(alpha,apid,'udp','10.79.0.3',44001,timeout_ms=12000)
    a3=send(alpha,apid,'tcp','fd79::2',43000,v6=True,timeout_ms=12000)
    s1=send(beta,bpid,'tcp','10.79.0.2',43000,timeout_ms=12000)
    before=len(peer());r=decide(a1,'allow','for-a-while');assert not r.get('error'),r
    lease=r['decision']['lease'];s=settled_ids(r);save('for-a-while-settled.json',r.get('settled'))
    assert set(s)=={a2['id'],a3['id']} and all(x['state']=='allowed' and x['rule']=='while:'+lease['id'] for x in s.values()),r.get('settled')
    assert delivered_after(before,3),'lease-settled requests not delivered'
    assert state(s1)=='awaiting-decision',event(s1)
    log('PASS For a while Allow: response settled exactly %s (UDP 10.79.0.3 and TCP IPv6 of PID %d, rule while:%s), all 3 delivered; sibling PID %d request still pending'%(sorted(s),apid,lease['id'],bpid))
    deny(s1)

    # 3. Remember settles the covered queued requests (same executable "other").
    o1=send(other,opid,'tcp','10.79.0.2',43000,timeout_ms=12000)
    o2=send(other,opid,'tcp','10.79.0.2',43000,timeout_ms=12000)
    o3=send(other,opid,'tcp','10.79.0.3',44000,timeout_ms=12000)
    fields=dict(address=True,port=True,protocol=True,process=False);rev=api()['network_zones']['revision']
    pv=api('decision-preview',generation=gen(),id=o1['id'],action='allow',scope='application',network_zone='any',zone_revision=rev,remember=fields,duration_seconds=3600);assert not pv.get('error'),pv
    before=len(peer())
    r=api('decide',generation=gen(),id=o1['id'],action='allow',scope='application',network_zone='any',zone_revision=rev,remember=fields,duration_seconds=3600,preview_token=pv['decision_preview']['token']);assert not r.get('error'),r
    s=settled_ids(r);save('remember-settled.json',r.get('settled'))
    assert set(s)=={o2['id']} and s[o2['id']]['state']=='allowed' and s[o2['id']]['rule']==r['saved_rule']['id'],r.get('settled')
    assert delivered_after(before,2) and state(o3)=='awaiting-decision'
    log('PASS Remember (Allow, address+port+protocol) settled exactly the covered queued request %s; uncovered destination stayed pending'%o2['id'])
    deny(o3);d=api('rule-delete',generation=gen(),id=r['saved_rule']['id'],expected_version=r['saved_rule']['version']);assert not d.get('error'),d
    # Regression: SYN retransmissions (~1/3/7 s) of answered (Deny once) connections
    # after a rule change must not create new requests.
    time.sleep(7.5)
    for ev in (t2,t3,sb,s1,o3):
        assert len(tuple_events(ev))==1 and state(ev)=='blocked',('answered connection prompted again after a rule change',tuple_events(ev))
    log('PASS after a rule save+delete, later SYN retransmissions of 5 Deny-once connections stayed blocked with no new request')

    # 4. Socket ends while the process lives: For a while Deny (60 s) on the ended request.
    wait(lambda:not any(l['pid']==apid for l in leases()),20)
    e1=send(alpha,apid,'tcp','10.79.0.2',43000,timeout_ms=1500)       # socket closes after 1.5 s
    q1=send(alpha,apid,'tcp','10.79.0.2',43000,timeout_ms=15000)      # "+1 similar request" still waiting
    assert e1['request_group']==q1['request_group']
    time.sleep(2.2)
    r=decide(e1,'allow');assert r.get('error_code')=='connection_ended',r  # what the UI sees on Allow
    ended=event(e1);save('ended-request.json',ended)
    rr=ended['request_rule'];assert ended['state']=='expired' and rr['process_state']=='running' and rr['process_lease_available'] and rr['pid']==apid,ended
    before=len(peer());r=api('request-for-a-while',generation=gen(),id=e1['id'],action='block',duration_seconds=60);save('ended-for-a-while.json',r)
    assert not r.get('error') and r['request_ended'] and not r.get('decision'),r
    l=r['process_lease'];assert l['pid']==apid and l['seconds']==60 and l['action']=='block' and l['event_id']==e1['id'] and l['direction']=='outgoing',l
    assert 'This ended request was not delivered' in r['scope_preview'],r['scope_preview']
    s=settled_ids(r);assert set(s)=={q1['id']} and s[q1['id']]['state']=='blocked',r.get('settled')
    assert state(e1)=='expired' and not api().get('rules')
    created=time.monotonic()
    log('PASS socket closed while PID %d runs: Allow refused connection_ended; request-for-a-while Deny 60 s created lease %s for that live process only; ended request stayed %s (not delivered); queued "+1 similar" request %s settled blocked'%(apid,l['id'],state(e1),q1['id']))
    for proto,host,port in [('tcp','10.79.0.3',44000),('udp','10.79.0.2',43001),('tcp','10.79.0.2',43000)]:
        v=send(alpha,apid,proto,host,port,timeout_ms=3000);assert v['state']=='blocked' and v['rule']=='while:'+l['id'],v
    assert not events_pid(apid,'awaiting-decision'),'Deny lease left a prompt'
    sib=send(beta,bpid,'tcp','10.79.0.2',43000,timeout_ms=3000);assert sib['state']=='awaiting-decision',sib
    deny(sib)
    assert not delivered_after(before,1,1.5),'ended request or lease-blocked connection delivered'
    log('PASS within the lease: next TCP+UDP attempts of PID %d blocked by while:%s without a prompt and not delivered; sibling PID %d prompted independently'%(apid,l['id'],bpid))
    left=[x for x in leases() if x['id']==l['id']];assert left and 50000<left[0]['remaining_ms']<=60000,left
    time.sleep(max(0,60-(time.monotonic()-created))+0.7)
    assert not any(x['id']==l['id'] for x in leases())
    again=send(alpha,apid,'tcp','10.79.0.2',43000,timeout_ms=3000);assert again['state']=='awaiting-decision',again
    deny(again)
    log('PASS after 60 s the lease expired and the original live PID %d prompted again'%apid)

    # 5. The process exits: For a while refused; Remember still saves for future launches.
    gc,gi=launch(NATIVE,45100)
    x=send(gc,gi['pid'],'tcp','10.79.0.2',43000,timeout_ms=9000)
    quit(gc,gi['pid'])
    r=decide(x,'allow');assert r.get('error_code') in ('connection_ended','identity_changed'),r
    xe=event(x);assert xe['request_rule']['process_state']=='ended' and not xe['request_rule']['process_lease_available'],xe['request_rule']
    r=api('request-for-a-while',generation=gen(),id=x['id'],action='block');save('exited-refusal.json',r)
    assert r.get('error_code')=='process_ended' and not r.get('process_lease'),r
    assert not any(l2['pid']==gi['pid'] for l2 in leases())
    q=dict(generation=gen(),id=x['id'],action='block',scope='persistent',network_zone='any',zone_revision=api()['network_zones']['revision'],remember=dict(address=False,port=False,protocol=False,process=False))
    p=api('request-rule-preview',**q);assert not p.get('error'),p
    sv=api('request-rule-save',preview_token=p['request_rule_preview']['token'],**q);assert not sv.get('error'),sv
    rule=sv['saved_rule'];assert any(r2['id']==rule['id'] for r2 in api()['rules'])
    log('PASS exited PID %d: request-for-a-while refused process_ended (no lease); Remember saved rule %s for future launches'%(gi['pid'],rule['id']))
    d=api('rule-delete',generation=gen(),id=rule['id'],expected_version=rule['version']);assert not d.get('error'),d

    # 6. Updated executable: previous_revision_rules shown, never applied.
    upd=str(RUN/'native-upd');shutil.copy2(NATIVE,upd)
    uc,ui=launch(upd,45120)
    y=send(uc,ui['pid'],'tcp','10.79.0.2',43000,timeout_ms=9000)
    fields=dict(address=False,port=False,protocol=False,process=False);rev=api()['network_zones']['revision']
    pv=api('decision-preview',generation=gen(),id=y['id'],action='allow',scope='persistent',network_zone='any',zone_revision=rev,remember=fields);assert not pv.get('error'),pv
    r=api('decide',generation=gen(),id=y['id'],action='allow',scope='persistent',network_zone='any',zone_revision=rev,remember=fields,preview_token=pv['decision_preview']['token']);assert not r.get('error'),r
    old=r['saved_rule'];quit(uc,ui['pid'])
    tmp=str(RUN/'native-upd.new');shutil.copy2(NATIVE,tmp);os.utime(tmp,(time.time()+5,time.time()+5));os.replace(tmp,upd) # "self-update": new inode
    uc2,ui2=launch(upd,45130)
    z=send(uc2,ui2['pid'],'tcp','10.79.0.2',43000,timeout_ms=9000)
    assert z['state']=='awaiting-decision',('rule for the earlier revision applied',z)
    ze=event(z);save('previous-revision-event.json',ze)
    prev=ze.get('previous_revision_rules') or [];assert [p2['id'] for p2 in prev]==[old['id']] and prev[0]['action']=='allow' and prev[0]['revision']==old['filter']['revision']!=ze['attribution']['application']['revision'],prev
    deny(z);quit(uc2,ui2['pid'])
    d=api('rule-delete',generation=gen(),id=old['id'],expected_version=old['version']);assert not d.get('error'),d
    log('PASS executable replaced: new revision prompted (old rule %s not applied); event.previous_revision_rules named it (display only)'%old['id'])
    for c in launched:
        if c.poll() is None:c.terminate();c.wait(5)
    (RUN/'queue-reconcile-result.json').write_text(json.dumps(dict(passed=True,host_actions=False),indent=2)+'\n')
