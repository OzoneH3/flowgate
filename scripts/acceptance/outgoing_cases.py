"""Focused receiver assertions, executed only by host-lab inside namespaces."""
import json,subprocess,time
from pathlib import Path

def exercise(g):
    root,run=g['ROOT'],g['RUN'];api,start,stop,wait=g['api'],g['start'],g['stop_backend'],g['wait'];children=g['clients']
    def count():return len((run/'peer-received.log').read_text().splitlines()) if (run/'peer-received.log').exists() else 0
    def launch(proto,app='alpha',port=None):
        pnum=port or (43000 if proto.startswith('tcp') else 43001)
        with (run/(app+'-'+proto+'.log')).open('w') as f:p=subprocess.Popen([str(root/'.workspace/clients'/app),proto,'fd79::2' if '6'in proto else '10.79.0.2',str(pnum),'fd79::1' if '6'in proto else '10.79.0.1'],stdout=f,stderr=f)
        children.append(p);return p
    def pending(proto):return next((e for e in api().get('events',[]) if e['state']=='awaiting-decision' and e['flow']['direction']=='outgoing' and e['flow']['protocol']==proto),None)
    def answer(e,action,scope='once'):
        r=api('decide',id=e['id'],action=action,scope=scope);assert 'error'not in r,r;return r
    assert api()['enforcement']['profile']=='both'
    # Existing v4/v6 TCP connections were opened before activation by host-lab.
    for v6,p in [(False,44000),(True,44100)]:g['remote']('again',port=p,v6=v6);wait(lambda:g['counts'][p]==2)
    for p,log in g['preexisting']:p.stdin.write(b'+');p.stdin.flush();wait(lambda:'REPLY2'in log.read_text())
    print('PASS both profile preserves startup incoming/outgoing IPv4/IPv6 TCP',flush=True)
    for proto in ['tcp4','tcp6','udp4','udp6']:
        for action in ['allow','block']:
            before=count();p=launch(proto);e=wait(lambda:pending(proto[:3]));assert count()==before
            answer(e,action)
            if action=='allow':wait(lambda:count()==before+1);wait(lambda:'REPLY' in (run/('alpha-'+proto+'.log')).read_text());assert not pending(proto[:3])
            else:time.sleep(.15);assert count()==before
            if p.poll()is None:p.terminate();p.wait(3)
            print('PASS outgoing',proto,action,'at actual peer receiver; reply not prompted',flush=True)
    # Remembered outgoing scope: destination/service, unrestricted source port.
    before=count();p=launch('udp4');e=wait(lambda:pending('udp'));r=answer(e,'allow','persistent');wait(lambda:count()==before+1)
    p.terminate();p.wait();rule=next(r for r in api()['rules'] if r['filter']['direction']=='outgoing');assert rule['filter'].get('local_port',0)==0 and rule['filter']['remote_port']==43001
    p=launch('udp4');wait(lambda:count()==before+2);p.terminate();p.wait()
    p=launch('udp4','beta');e=wait(lambda:pending('udp'));assert count()==before+2;answer(e,'block');p.terminate();p.wait()
    p=launch('udp4',port=43002);e=wait(lambda:pending('udp'));assert e['flow']['remote'].endswith(':43002');answer(e,'block');p.terminate();p.wait()
    print('PASS remembered outgoing new source port, different executable and destination isolation',flush=True)
    # Actual optimistic editor: preview and save, failed/stale edits cannot replace policy.
    def edit(candidate,version,commit=True):return api('rule-save' if commit else 'rule-preview',id=rule['id'],generation=api()['generation'],expected_version=version,rule=candidate)
    changed=dict(rule,action='block');assert 'scope_preview'in edit(changed,rule['version'],False)
    saved=edit(changed,rule['version']);assert 'error'not in saved,saved
    assert 'error'in edit(dict(rule,action='allow'),rule['version'])
    bad=dict(saved['saved_rule']);bad['filter']=dict(bad['filter'],uid=1);assert 'error'in edit(bad,bad['version'])
    before=count();p=launch('udp4');time.sleep(.3);assert count()==before;assert not pending('udp');p.terminate();p.wait()
    stop();start();assert api()['rules'][0]['action']=='block' and api()['rules'][0]['filter']['direction']=='outgoing'
    before=count();p=launch('udp4');time.sleep(.3);assert count()==before;p.terminate();p.wait()
    print('PASS committed edit to Block, stale/invalid edits rejected, direction and edited action survive restart',flush=True)
    # Incoming approval's reply must be exempt from output questions.
    for v6,port in [(False,44001),(True,44101)]:
        g['remote']('udp',port=port,v6=v6,wait_reply=True)
        e=wait(lambda:next((e for e in api().get('events',[]) if e['state']=='awaiting-decision' and e['flow']['direction']=='incoming' and e['flow']['local'].endswith(':'+str(port))),None))
        answer(e,'allow');wait(lambda:g['counts'][port]==1);assert g['remote']('udp-reply',port=port,v6=v6)['reply']=='reply';assert not pending('udp')
    print('PASS incoming control retained in both profile',flush=True)
    # Consumer death fails closed for new outbound flows; deliberate recovery only.
    g['backend'].kill();g['backend'].wait();before=count();p=launch('tcp4');time.sleep(.3);assert count()==before;p.terminate();p.wait();g['cmd'](g['BIN'],'host-recover','--state',str(g['STATE']))
    print('PASS both-profile daemon death blocks new outgoing traffic',flush=True)
