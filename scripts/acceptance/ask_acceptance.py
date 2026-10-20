"""Stored Ask (stored-ask-v1) acceptance with real private receivers.

Uses the same primary API as Electron. Private namespaces only (scripts/lab.sh).
"""
import json,time

def check(g):
    api,wait,log,target,infos,children,RUN,ask,remote=g['api'],g['wait'],g['log'],g['target'],g['infos'],g['children'],g['RUN'],g['ask'],g['remote']
    gen=lambda:api()['generation']
    peer=lambda:((RUN/'peer-received.log').read_text().splitlines() if (RUN/'peer-received.log').exists() else [])
    def events(name,state=None):
        pid=infos[name]['pid']
        return [v for v in api().get('events',[]) if any(o['pid']==pid for o in v['attribution']['owners']) and (state is None or v['state']==state)]
    def start(name,proto,host,port,v6=False):
        """Begin one outgoing attempt (held while pending); return the new pending/decided event."""
        known={v['id'] for v in events(name)}
        ask(children[name],'send',protocol=proto,v6=v6,host=host,port=port)
        return wait(lambda:next((v for v in events(name) if v['id'] not in known),None),6)
    def hits(host=None,port=None):
        return len([l for l in peer() if host is None or "'%s', %d"%(host,port) in l])
    def delivered_after(before,seconds=4,host=None,port=None):
        try:wait(lambda:hits(host,port)>before,seconds);return True
        except AssertionError:return False
    def draft(direction,action,**over):
        d=dict(target_scope='application',direction=direction,protocol='*',action=action,remote_address='*',local_port=0,remote_port=0,disabled=False,expires='0001-01-01T00:00:00Z',application_policy=True);d.update(over);return d
    def save(name,d):
        pv=api('observed-rule-preview',generation=gen(),observed_target=target(name),observed_draft=d);assert not pv.get('error'),pv
        sv=api('observed-rule-save',generation=gen(),preview_token=pv['observed_preview']['token'],observed_draft=d);assert not sv.get('error'),sv
        return pv['observed_preview'],sv['saved_rule']
    def decide(ev,action,scope='once'):
        r=api('decide',generation=gen(),id=ev['id'],action=action,scope=scope);assert not r.get('error'),r
    def remember(ev,action,fields):
        zr=api()['network_zones']['revision'];q=dict(generation=gen(),id=ev['id'],action=action,scope='persistent',network_zone='any',zone_revision=zr,remember=fields)
        p=api('decision-preview',**q);assert not p.get('error'),p;p=p['decision_preview']
        r=api('decide',preview_token=p['token'],**q);assert not r.get('error'),r
        return p,r['saved_rule']
    caps=api()['capabilities'];assert 'stored-ask-v1' in caps,caps
    out={}
    # 1. Application Out Ask is created and persisted as the app's own rule.
    _,askr=save('alpha',draft('outgoing','ask'))
    assert askr['action']=='ask' and any(r['id']==askr['id'] and r['action']=='ask' for r in api()['rules'])
    view=api('policy-view',generation=gen())['policy_view']
    o=[x for x in view['applications'] if x['identity']['key']==askr['filter']['application']][0]['outgoing']
    assert o['application_rule']['action']=='ask',o
    # 2. TCP and UDP requests prompt with source-rule attribution (event + Decision Log).
    for proto,port in [('tcp',43000),('udp',43001)]:
        before=len(peer());ev=start('alpha',proto,'10.79.0.2',port)
        assert ev['state']=='awaiting-decision' and ev['rule']==askr['id'] and ev.get('ask_rule',{}).get('id')==askr['id'],ev
        assert not delivered_after(before,1.0),'held Ask request delivered before a decision'
        decide(ev,'allow')  # Allow Once delivers
        assert delivered_after(before),('Allow Once did not deliver',proto)
    recs=api('decision-log',decision_query={'limit':100})['decision_log']['records']
    src=[x for x in recs if x['kind']=='pending' and x['decision']['source']=='rule_ask' and x['decision'].get('rule',{}).get('id')==askr['id']]
    assert len(src)>=2,'Decision Log lacks rule_ask attribution';out['decision_log_pending']=src[0]
    log('PASS application Out Ask persisted; TCP+UDP prompts attributed to the Ask rule (event + Decision Log rule_ask); Allow Once delivers')
    # 3. Deny Once does not deliver; a new independent attempt prompts again; rule unchanged.
    before=hits('10.79.0.3',44000);ev=start('alpha','tcp','10.79.0.3',44000);decide(ev,'block')
    assert not delivered_after(before,2.5,'10.79.0.3',44000),'Deny Once delivered'
    ev2=start('alpha','tcp','10.79.0.3',44000)
    assert ev2['state']=='awaiting-decision' and ev2['rule']==askr['id'],('new attempt did not prompt again',ev2)
    assert [r for r in api()['rules'] if r['id']==askr['id']][0]['action']=='ask'
    log('PASS Deny Once blocks; next independent attempt prompts again; Once never replaced the Ask rule')
    # 4. Incoming independent; other application and out-of-zone attempts are not the Ask rule's.
    port=infos['alpha']['ports']['udp4'];remote('udp',port=port,v6=False)
    inc=wait(lambda:next((v for v in events('alpha') if v['flow']['direction']=='incoming'),None),6)
    assert inc['rule']!=askr['id'] and not inc.get('ask_rule'),inc
    oth=start('other','tcp','10.79.0.2',43000)
    assert oth['rule']!=askr['id'] and not oth.get('ask_rule'),oth
    log('PASS incoming and another executable are independent of the application Out Ask rule')
    # 5. Narrow Remember (address+port+protocol) beats the broader Ask for its destination only.
    p,narrow=remember(ev2,'allow',{'address':True,'port':True,'protocol':True,'process':False})
    assert p['replaces'] is None and narrow['id']!=askr['id']
    before=len(peer());ask(children['alpha'],'send',protocol='tcp',v6=False,host='10.79.0.3',port=44000)
    assert delivered_after(before),'narrow remembered Allow did not beat Ask'
    ev3=start('alpha','tcp','10.79.0.2',44000)
    assert ev3['state']=='awaiting-decision' and ev3['rule']==askr['id'],'narrow remember widened'
    log('PASS narrow Remember Allow beats the Ask rule for its destination only (equal weight Allow > Ask)')
    # 6. Application-only Remember replaces the Ask rule, settles waiting requests, later connections pass.
    waiting=start('alpha','udp','10.79.0.3',44001)
    before=len(peer())
    p,saved=remember(ev3,'allow',{'address':False,'port':False,'protocol':False,'process':False})
    assert p['replaces']['id']==askr['id'] and saved['id']==askr['id'] and saved['action']=='allow',p
    assert delivered_after(before,6),'waiting/decided requests not delivered after application Remember'
    left=[(v['flow']['direction'],v['flow']['remote'],v['rule']) for v in events('alpha','awaiting-decision') if v['flow']['direction']=='outgoing']
    assert not left,('obsolete outgoing Ask prompts remained',left)
    before=len(peer());ask(children['alpha'],'send',protocol='udp',v6=True,host='fd79::3',port=44001)
    assert delivered_after(before),'later connection prompted after application Remember'
    log('PASS application Remember replaced the Ask rule (exposed in preview), settled waiting requests, later connections pass')
    # 7. Tie/weight: scoped Deny beats Ask at equal weight; disable/delete; out-of-zone with a zone-scoped Ask.
    _,askr=save('alpha',draft('outgoing','ask'))  # back to Ask (updates the same rule)
    pv=api('observed-rule-preview',generation=gen(),observed_target=target('alpha'),observed_draft=dict(target_scope='application',direction='outgoing',protocol='tcp',action='block',remote_address='10.79.0.2',local_port=0,remote_port=43000,disabled=False,expires='0001-01-01T00:00:00Z'))
    api('observed-rule-save',generation=gen(),preview_token=pv['observed_preview']['token'],observed_draft=dict(target_scope='application',direction='outgoing',protocol='tcp',action='block',remote_address='10.79.0.2',local_port=0,remote_port=43000,disabled=False,expires='0001-01-01T00:00:00Z'))
    before=hits('10.79.0.2',43000);ev=start('alpha','tcp','10.79.0.2',43000)
    assert ev['state']=='blocked' and ev['rule']!=askr['id'] and not delivered_after(before,1.5,'10.79.0.2',43000),('scoped Deny did not beat Ask',ev['state'],ev['rule'])
    cur=[r for r in api()['rules'] if r['id']==askr['id']][0]
    r=api('rule-save',generation=gen(),id=cur['id'],expected_version=cur['version'],rule=dict(cur,disabled=True));assert not r.get('error'),r
    ev=start('alpha','udp','10.79.0.2',44001)
    assert ev['rule']!=askr['id'] and not ev.get('ask_rule'),'disabled Ask rule still attributed'
    cur=[r for r in api()['rules'] if r['id']==askr['id']][0]
    assert not api('rule-delete',generation=gen(),id=cur['id'],expected_version=cur['version']).get('error')
    zr=api()['network_zones']['revision'];_,zask=save('alpha',draft('outgoing','ask',network_zone='local',zone_revision=zr))
    inz=start('alpha','udp','10.79.0.3',43001);outz=start('alpha','udp','fd79::2',43001,True)
    assert inz['rule']==zask['id'] and outz['rule']!=zask['id'],('zone-scoped Ask scope',inz['rule'],outz['rule'])
    log('PASS scoped Deny beats Ask (equal weight); disabled/deleted Ask stops attributing; Local-zone Ask leaves Internet traffic independent')
    # 8. Read-only denial and restart persistence.
    ro=api('observed-rule-preview',readonly=True,generation=gen(),observed_target=target('alpha'),observed_draft=draft('outgoing','ask'))
    assert ro.get('error'),'read-only endpoint accepted an Ask rule'
    rules=sorted((r['id'],r['version'],r['action']) for r in api()['rules'])
    g['stop']();g['start']()
    assert sorted((r['id'],r['version'],r['action']) for r in api()['rules'])==rules,'Ask rules changed across restart'
    ev=start('alpha','udp','10.79.0.3',43001)
    assert ev['rule']==zask['id'] and ev['state']=='awaiting-decision','Ask not enforced after restart'
    log('PASS read-only endpoint refuses Ask creation; Ask rules identical and enforced after daemon restart')
    (RUN/'ask-result.json').write_text(json.dumps(dict(passed=True,**out),indent=2))
