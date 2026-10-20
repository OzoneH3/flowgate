"""Disposable TCP retry/Remember regression, imported only by the private lab.
Actual socket identities/API/receiver results. Never the host endpoint.
"""
import json,time

def check(g):
 api,ask,children,wait,RUN,log=[g[k] for k in ('api','ask','children','wait','RUN','log')]
 generation=g['generation'];native=g['NATIVE'];initial=api()
 assert not initial.get('rules'),initial
 fields=dict(address=False,port=False,protocol=False,process=False)
 def request(op,**kw):return api(op,generation=generation,**kw)
 def peer_count():
  p=RUN/'peer-received.log';return len(p.read_text().splitlines())if p.exists()else 0
 def pending(name):
  pid=g['infos'][name]['pid']
  return next((e for e in api().get('events',[]) if e['state']=='awaiting-decision'and any(p['pid']==pid for p in e['attribution'].get('owners',[]))),None)
 def send(name,ms):ask(children[name],'send',protocol='tcp',timeout_ms=ms)
 def preview(e):return request('decision-preview',id=e['id'],action='allow',scope='persistent',network_zone='any',zone_revision=api()['network_zones']['revision'],remember=fields)
 def save_json(name,v):(RUN/name).write_text(json.dumps(v,indent=2)+'\n')
 before=peer_count();send('alpha',1500);old=wait(lambda:pending('alpha'));save_json('original-pending.json',old)
 assert old['flow']['network_scope']['state']=='unavailable',old['flow']
 # Join the actual connect job: Activity can lag behind creation, so an
 # initially absent sample is not evidence of closure. No timing sleep.
 ask(children['alpha'],'settle')
 # The native program stays alive, but its timed connect closes this exact socket.
 wait(lambda:not any(r['socket']['local']==old['flow']['local']and r['socket']['remote']==old['flow']['remote'] for r in api()['activity']['rows']),seconds=8)
 refused=preview(old);save_json('closed-preview.json',refused)
 assert refused.get('error_code')=='connection_ended',refused
 ended=next(e for e in api()['events']if e['id']==old['id']);save_json('ended.json',ended)
 assert ended['state']=='expired'and ended['revalidation']['processes'][0]['state']=='same',ended
 assert any(c['field']=='socket_inode_cookie'for c in ended['revalidation']['changes']),ended
 assert peer_count()==before and not api().get('rules')
 assert request('decide',id=old['id'],action='allow',scope='once').get('error'), 'dead request approved'
 # New independently validated application identity: existing observed preview,
 # explicit all-instance application scope. No dead Decide token is re-used.
 draft=dict(target_scope='application',application_policy=True,direction='outgoing',protocol='*',action='allow',remote_address='*',local_port=0,remote_port=0,disabled=False,expires='0001-01-01T00:00:00Z')
 pv=request('observed-rule-preview',observed_target=g['target']('alpha'),observed_draft=draft);assert not pv.get('error'),pv
 saved=request('observed-rule-save',preview_token=pv['observed_preview']['token'],observed_draft=draft);assert not saved.get('error'),saved
 rule=saved['saved_rule'];save_json('future-application-save.json',saved)
 assert not rule['filter'].get('process')and not rule['filter'].get('network_zone')
 assert peer_count()==before, 'future rule released dead connection data'
 send('alpha',10000);wait(lambda:peer_count()==before+1)
 assert not pending('alpha'),'future retry not admitted'
 # Different executable, same destination/service never inherits the rule.
 send('other',1500);other=wait(lambda:pending('other'))
 assert other['attribution']['application']['key']!=old['attribution']['application']['key']
 denied=request('decide',id=other['id'],action='block',scope='once');assert not denied.get('error'),denied
 time.sleep(.2);assert peer_count()==before+1
 g['delete'](rule)
 log('PASS real TCP socket closure / unchanged native process; dead preview finalized, no dead packet delivery; fresh application rule saves in unavailable zone; later retry delivered, different executable did not inherit')
 # Genuine exec during review: PID/start persists but the executable changes.
 send('beta',10000);beta=wait(lambda:pending('beta'));save_json('before-exec.json',beta)
 children['beta'].stdin.write('{"op":"exec"}\n');children['beta'].stdin.flush()
 wait(lambda:not any(r['socket']['local']==beta['flow']['local']and r['socket']['remote']==beta['flow']['remote']for r in api()['activity']['rows']))
 exec_result=preview(beta);save_json('exec-preview.json',exec_result)
 assert exec_result.get('error'),exec_result
 beta_end=next(e for e in api()['events']if e['id']==beta['id']);save_json('exec-ended.json',beta_end)
 checks=beta_end['revalidation']['processes'];assert checks[0]['state']=='changed',checks
 assert any(c['field'].endswith('.executable_revision')for c in checks[0]['changes']),checks
 assert peer_count()==before+1 and not api().get('rules')
 log('PASS real exec preserves PID/start but records executable revision change; no rule saved and no delivery')
 # A still-live connection can Remember application-only Any network normally.
 send('alpha',10000);fresh=wait(lambda:pending('alpha'));p=preview(fresh);assert not p.get('error'),p
 reviewed=p['decision_preview'];ack=request('decide',id=fresh['id'],action='allow',scope='persistent',network_zone='any',zone_revision=reviewed['zone_revision'],preview_token=reviewed['token'],remember=fields)
 assert not ack.get('error'),ack;save_json('valid-remember-ack.json',ack)
 assert not ack['saved_rule']['filter'].get('process')
 wait(lambda:peer_count()==before+2)
 g['delete'](ack['saved_rule']);assert not api().get('rules')
 log('PASS real valid application-only Remember/Any zone Preview/Commit and receiver delivery; exact conditional cleanup rules0')
 (RUN/'result.json').write_text(json.dumps({'passed':True,'generation':generation,'native':native,'before':before,'after':peer_count(),'rules':0,'host_actions':False},indent=2)+'\n')
