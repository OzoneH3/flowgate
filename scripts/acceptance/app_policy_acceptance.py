"""NetLimiter-style application Allow/Deny acceptance with real private receivers.

Driven through the same primary API the Electron setter uses. Private namespaces
only (scripts/lab.sh); never touches host policy.
"""
import datetime,json,time

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
    def logged(endpoint, action, rule, since):
        return next((row for row in api('decision-log',decision_query={'limit':80,'since':since})['decision_log']['records']
            if row['kind']=='final' and row['flow']['remote']==endpoint
            and row['decision']['action']==action and row['decision'].get('rule',{}).get('id')==rule),None)
    # A machine Local Deny has lower target weight than this application Allow.
    zr=api()['network_zones']['revision']
    zone_target=dict(zone='local',scope='machine')
    zone_draft=dict(direction='outgoing',protocol='*',action='block',remote_address='*',
                    local_port=0,remote_port=0,disabled=False,expires='0001-01-01T00:00:00Z')
    pv=api('zone-rule-preview',generation=gen(),zone_revision=zr,zone_target=zone_target,observed_draft=zone_draft)
    assert not pv.get('error'),pv
    sv=api('zone-rule-save',generation=gen(),zone_revision=zr,zone_target=zone_target,
           observed_draft=zone_draft,preview_token=pv['zone_preview']['token'])
    assert not sv.get('error'),sv
    broad=sv['saved_rule']
    assert broad['priority']==app['priority']
    since=datetime.datetime.now(datetime.timezone.utc).isoformat()
    assert send('alpha','tcp','10.79.0.2',43000)
    wait(lambda:logged('10.79.0.2:43000','allow',app['id'],since))
    g['delete'](broad)
    log('PASS equal-priority application Allow defeats all-program Local Block (receiver delivered)')
    # Same program, priorities and service port. Change only the peer zone or
    # whether the connection was admitted before the Local Deny.
    zr=api()['network_zones']['revision']
    same_service=('tcp','10.79.0.2',43000)
    before=len(peer_lines())
    ask(children['alpha'],'send',protocol='tcp',host=same_service[1],port=same_service[2],
        repeat=2,interval_ms=3000)
    wait(lambda:len(peer_lines())==before+1)
    _,local_deny=save('alpha',draft('outgoing','block',network_zone='local',zone_revision=zr))
    assert local_deny['priority']==app['priority']
    wait(lambda:len(peer_lines())==before+2,5)
    since=datetime.datetime.now(datetime.timezone.utc).isoformat()
    assert not send('alpha',*same_service)
    wait(lambda:logged('10.79.0.2:43000','block',local_deny['id'],since))
    assert send('alpha','tcp','fd79::2',43000,True)
    wait(lambda:logged('[fd79::2]:43000','allow',app['id'],since))
    log('PASS Local vs All networks: existing TCP second write delivered; fresh Local Deny selected/zero delivery; fresh non-Local Allow selected/delivered')
    # Toggle and expire the winning Local override on fresh attempts in each direction.
    # Before expiry, use UDP to keep the receiver checks independent of TCP retry timing.
    def edit_override(rule, **changes):
        state=api()
        result=api('rule-save',generation=state['generation'],zone_revision=state['network_zones']['revision'],
                   id=rule['id'],expected_version=rule['version'],rule=dict(rule,**changes))
        assert not result.get('error'),result.get('error')
        return result['saved_rule']
    for direction in ('outgoing','incoming'):
        if direction=='incoming':
            _,base_in=save('alpha',draft(direction,'allow'))
            _,override=save('alpha',draft(direction,'block',network_zone='local',zone_revision=zr))
            def probe(allowed):
                g['incoming']('alpha','udp',False,allowed)
        else:
            override=local_deny
            def probe(allowed):
                assert send('alpha','udp','10.79.0.3',43001)==allowed
        probe(False)
        override=edit_override(override,disabled=True)
        probe(True)
        deadline=datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(seconds=14)
        override=edit_override(override,disabled=False,expires=deadline.isoformat())
        probe(False)
        time.sleep(max(0,(deadline-datetime.datetime.now(datetime.timezone.utc)).total_seconds())+.15)
        probe(True)
        g['delete'](override)
        if direction=='incoming':g['delete'](base_in)
        log('PASS '+direction+' fresh receiver: winning Local Block 0; disabled Block falls back to Allow; re-enabled Block 0; expired Block falls back to Allow')
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
