"""NetLimiter-style application Allow/Deny acceptance with real private receivers.

Driven through the same primary API the Electron setter uses. Private namespaces
only (scripts/lab.sh); never touches host policy.
"""
import json,time

def check(g):
    api,wait,log,target,infos,children,RUN,ask,remote=g['api'],g['wait'],g['log'],g['target'],g['infos'],g['children'],g['RUN'],g['ask'],g['remote']
    gen=lambda:api()['generation']
    peer_lines=lambda:((RUN/'peer-received.log').read_text().splitlines() if (RUN/'peer-received.log').exists() else [])
    def send(name,proto,host,port,v6=False):
        """One outgoing attempt to an explicit fixture destination; returns delivered?"""
        before=len(peer_lines())
        ask(children[name],'send',protocol=proto,v6=v6,host=host,port=port);ask(children[name],'settle')
        try:
            wait(lambda:len(peer_lines())>before,3);return True
        except AssertionError:return False
    def events(name,state=None):
        pid=infos[name]['pid']
        return [v for v in api().get('events',[]) if any(o['pid']==pid for o in v['attribution']['owners']) and (state is None or v['state']==state)]
    def draft(direction,action,app_policy=True,**over):
        d=dict(target_scope='application',direction=direction,protocol='*',action=action,remote_address='*',local_port=0,remote_port=0,disabled=False,expires='0001-01-01T00:00:00Z')
        if app_policy:d['application_policy']=True
        d.update(over);return d
    def save(name,d):
        pv=api('observed-rule-preview',generation=gen(),observed_target=target(name),observed_draft=d);assert not pv.get('error'),pv
        sv=api('observed-rule-save',generation=gen(),preview_token=pv['observed_preview']['token'],observed_draft=d);assert not sv.get('error'),sv
        return pv['observed_preview'],sv['saved_rule']
    caps=api()['capabilities'];assert 'application-policy-v1' in caps and 'decision-remember-fields-v1' in caps,caps
    out={}
    # 1. A remembered single-destination rule (UDP 10.79.0.2:43001) exists first.
    _,scoped=save('alpha',draft('outgoing','allow',app_policy=False,protocol='udp',remote_address='10.79.0.2',remote_port=43001))
    assert send('alpha','udp','10.79.0.2',43001) and not send('alpha','tcp','10.79.0.3',44000),'scoped baseline'
    # 2. Application → Out → Allow: whole-application rule, never the scoped one.
    pv,app=save('alpha',draft('outgoing','allow'))
    f=app['filter'];assert pv['replaces'] is None and app['id']!=scoped['id'] and f['protocol']=='*' and f['remote_address']=='*' and not f.get('remote_port') and not f.get('network_zone'),app
    out['application_rule']=app
    # 3. Different destinations, ports, protocols and families deliver, without prompts.
    for proto,host,port,v6 in [('tcp','10.79.0.2',43000,False),('tcp','10.79.0.3',44000,False),('udp','10.79.0.3',44001,False),('udp','10.79.0.2',44001,False),('tcp','fd79::3',44000,True),('udp','fd79::2',43001,True)]:
        assert send('alpha',proto,host,port,v6),('application Allow did not deliver',proto,host,port)
    left=[(v['flow']['protocol'],v['flow']['remote'],v['state'],v.get('reason','')[:80]) for v in events('alpha','awaiting-decision')]
    assert not left,('prompts remained for an allowed application',left)
    log('PASS application Out Allow: TCP/UDP IPv4/6 to 2 destinations x 2 ports delivered, no prompts; scoped rule untouched')
    # 4. Another executable stays independently controlled; In stays separate.
    assert not send('other','tcp','10.79.0.2',43000),'other executable inherited the application Allow'
    wait(lambda:events('other','awaiting-decision') or events('other','blocked'))
    port=infos['alpha']['ports']['udp4'];before=ask(children['alpha'],'counts')['counts'].get('udp4',0)
    remote('udp',port=port,v6=False);time.sleep(.6)
    assert ask(children['alpha'],'counts')['counts'].get('udp4',0)==before,'Out Allow leaked into In'
    log('PASS other executable prompts/blocked; incoming to alpha not covered by Out Allow')
    # 5. A waiting request settles when the covering application policy is saved.
    ask(children['other'],'send',protocol='tcp',v6=False,host='10.79.0.3',port=43000)
    wait(lambda:events('other','awaiting-decision'))
    before=len(peer_lines());save('other',draft('outgoing','allow'))
    wait(lambda:len(peer_lines())>before,8)
    assert not events('other','awaiting-decision'),'obsolete prompt remained after application Allow'
    settled=[v for v in events('other') if v['state']=='allowed']
    assert settled and any('re-evaluated after policy change' in v.get('reason','') for v in settled),settled
    log('PASS waiting request re-evaluated and delivered after application Allow; no obsolete prompt')
    # 6. Explicit overriding rule: scoped Deny wins at equal weight (NetLimiter: Deny before Allow).
    _,deny=save('alpha',draft('outgoing','block',app_policy=False,protocol='tcp',remote_address='10.79.0.3',remote_port=44000))
    assert not send('alpha','tcp','10.79.0.3',44000) and send('alpha','tcp','10.79.0.2',44000),'override'
    view=api('policy-view',generation=gen())['policy_view']
    a=[x for x in view['applications'] if x['identity']['key']==app['filter']['application']][0]['outgoing']
    assert a['application_rule']['id']==app['id'] and a['scoped_rules']==2 and a['configured']=='mixed',a
    out['policy_view_outgoing']=a
    # Scoped rules stay independently editable: disable the Deny and the destination delivers.
    r=api('rule-save',generation=gen(),id=deny['id'],expected_version=deny['version'],rule=dict(deny,disabled=True));assert not r.get('error'),r
    assert send('alpha','tcp','10.79.0.3',44000),'disabled scoped Deny still applied'
    log('PASS scoped Deny override (equal weight Deny-first), application/scoped separation in policy view, scoped rule edit')
    # 7. Explicit zone restriction: Local-only application Allow (10.79/24 local, fd79::/64 internet).
    api('rule-delete',generation=gen(),id=app['id'],expected_version=app['version'])
    zr=api()['network_zones']['revision']
    _,zapp=save('alpha',draft('outgoing','allow',network_zone='local',zone_revision=zr))
    assert zapp['filter']['network_zone']=='local'
    assert send('alpha','tcp','10.79.0.2',43000) and not send('alpha','tcp','fd79::2',43000,True),'zone restriction'
    log('PASS explicit Local zone application Allow covers local peer only')
    api('rule-delete',generation=gen(),id=zapp['id'],expected_version=zapp['version'])
    # 8. Application Deny (set, then update in place) with receiver counts.
    pv,app=save('alpha',draft('outgoing','allow'))
    pv,deny_app=save('alpha',draft('outgoing','block'))
    assert pv['replaces']['id']==app['id'] and deny_app['id']==app['id'] and deny_app['version']==app['version']+1,pv
    before=len(peer_lines())
    for proto,host,port,v6 in [('tcp','10.79.0.2',43000,False),('udp','10.79.0.3',44001,False),('tcp','fd79::3',44000,True)]:
        ask(children['alpha'],'send',protocol=proto,v6=v6,host=host,port=port)
    ask(children['alpha'],'settle');time.sleep(.8)
    # The scoped UDP Allow (weight 3) and application Deny (weight 3): Deny first.
    assert len(peer_lines())==before,'application Deny delivered'
    assert not send('alpha','udp','10.79.0.2',43001),'equal-weight scoped Allow beat application Deny'
    log('PASS application Deny updated in place; 0 deliveries across destinations incl. scoped-Allow destination (Deny first)')
    # 9. Restart persistence.
    rules=sorted((r['id'],r['version'],json.dumps(r['filter'],sort_keys=True)) for r in api()['rules'])
    g['stop']();g['start']()
    after=sorted((r['id'],r['version'],json.dumps(r['filter'],sort_keys=True)) for r in api()['rules'])
    assert rules==after,'rules changed across restart'
    assert not send('alpha','tcp','10.79.0.2',43000),'application Deny not persistent'
    log('PASS rules/versions/scopes identical after daemon restart; application Deny still enforced')
    (RUN/'app-policy-result.json').write_text(json.dumps(dict(passed=True,**out),indent=2))
