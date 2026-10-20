"""Future application rule from an ended request, imported only by the private lab.
Real disposable launches, kernel interception, API and receiver. Never the host.
"""
import json,os,shutil,subprocess,time

def check(g):
 api,ask,wait,RUN,log,NATIVE=[g[k] for k in ('api','ask','wait','RUN','log','NATIVE')]
 generation=g['generation'];assert not api().get('rules')
 assert 'request-application-rule-v1' in api()['capabilities']
 APP=str(RUN/'disposable-app');shutil.copy2(NATIVE,APP)  # the application under test
 OTHER=str(RUN/'native-other')                          # a different executable
 launched=[];ports=iter(range(45100,45400,10))
 def save_json(name,v):(RUN/name).write_text(json.dumps(v,indent=2)+'\n')
 def launch(exe):
  c=subprocess.Popen([exe,str(next(ports))],env=dict(os.environ,FLOWGATE_FIXTURE_TIMEOUT_SECONDS='10'),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=(RUN/'launch.log').open('a'),text=True)
  info=json.loads(c.stdout.readline());launched.append(c);return c,info
 def quit(c):
  if c.poll() is None:c.terminate();c.wait(5)
 def peer_count():
  p=RUN/'peer-received.log';return len(p.read_text().splitlines())if p.exists()else 0
 def events_for(pid):return [e for e in api().get('events',[]) if any(o['pid']==pid for o in e['attribution'].get('owners',[]))]
 def pending(pid):return next((e for e in events_for(pid) if e['state']=='awaiting-decision'),None)
 fields=dict(address=False,port=False,protocol=False,process=False)
 rev=lambda:api()['network_zones']['revision']
 def rr(op,e,action,**kw):
  q=dict(generation=generation,id=e['id'],action=action,scope='persistent',network_zone='any',zone_revision=rev(),remember=kw.pop('remember',fields));q.update(kw)
  return api(op,**q)
 def prompt_then_exit(exe,tag):
  c,info=launch(exe);ask(c,'send',protocol='tcp',timeout_ms=8000)
  e=wait(lambda:pending(info['pid']));save_json(tag+'-pending.json',e)
  quit(c)  # the requester exits before any decision
  wait(lambda:not os.path.exists('/proc/%d'%info['pid']))
  return e,info
 def save_from(e,action,tag):
  p=rr('request-rule-preview',e,action);assert not p.get('error'),p;save_json(tag+'-preview.json',p)
  s=rr('request-rule-save',e,action,preview_token=p['request_rule_preview']['token']);assert not s.get('error'),s;save_json(tag+'-save.json',s)
  return p['request_rule_preview'],s
 # 1-3: prompt, requester exits, save an application-wide Allow from the retained request.
 before=peer_count()
 old,old_info=prompt_then_exit(APP,'allow')
 refusal=rr('request-rule-preview',old,'allow',remember=dict(fields,process=True));save_json('process-scope-refusal.json',refusal)
 assert refusal.get('error_code')=='process_scope_unavailable' and 'ended' in refusal['error'],refusal
 preview,saved=save_from(old,'allow','allow')
 rule=saved['saved_rule'];f=rule['filter']
 assert f['application']==old['attribution']['application']['key'] and f['protocol']=='*' and f['remote_address'] in ('*','') and not f.get('local_port') and not f.get('remote_port') and not f.get('network_zone') and not f.get('process'),rule
 assert 'not allowed' in preview['scope_preview'],preview
 ended=next(e for e in api()['events'] if e['id']==old['id']);save_json('allow-ended.json',ended)
 assert ended['state']=='expired' and ended['request_rule']['process_state']=='ended',ended
 assert api('decide',generation=generation,id=old['id'],action='allow',scope='once').get('error'),'ended request approved'
 # 8: repeated click / lost acknowledgement (same token) and a fresh review of the same scope.
 again=rr('request-rule-save',old,'allow',preview_token=preview['token']);assert again.get('replayed') and again['saved_rule']['id']==rule['id'],again
 p2=rr('request-rule-preview',old,'allow');assert p2['request_rule_preview']['replaces']['id']==rule['id'],p2
 s2=rr('request-rule-save',old,'allow',preview_token=p2['request_rule_preview']['token']);assert not s2.get('error'),s2
 rule=s2['saved_rule'];assert len(api()['rules'])==1,api()['rules']
 assert peer_count()==before,'ended request delivered'
 log('PASS prompt, requester exit, process scope refused with reason, application-wide Allow saved from retained request; ended request stays ended/undeliverable; replayed token and repeat review keep exactly one rule')
 # 4-5: relaunch the same application: new PID and source port, delivered without prompt.
 c,info=launch(APP);assert info['pid']!=old_info['pid']
 ask(c,'send',protocol='tcp',timeout_ms=8000);wait(lambda:peer_count()==before+1)
 rows=events_for(info['pid']);save_json('relaunch-events.json',rows)
 assert all(e['state']!='awaiting-decision' for e in rows) and any(e['state']=='allowed' and e['rule']==rule['id'] for e in rows),rows
 new=next(e for e in rows if e['rule']==rule['id'])
 assert new['flow']['local']!=old['flow']['local'],(new['flow'],old['flow'])
 quit(c)
 log('PASS relaunch PID %d -> %d, source %s -> %s delivered by rule %s without prompt'%(old_info['pid'],info['pid'],old['flow']['local'],new['flow']['local'],rule['id']))
 # 7: a different executable does not inherit it.
 c,info=launch(OTHER);ask(c,'send',protocol='tcp',timeout_ms=8000);o=wait(lambda:pending(info['pid']))
 assert o['attribution']['application']['key']!=old['attribution']['application']['key']
 assert not api('decide',generation=generation,id=o['id'],action='block',scope='once').get('error')
 time.sleep(.3);assert peer_count()==before+1;quit(c)
 log('PASS different executable prompted (not covered by the application rule) and was denied once')
 # Same path, different file: the retained identity is not transferred to it.
 g['delete'](rule);assert not api().get('rules')
 swap,_=prompt_then_exit(APP,'swap')
 tmp=APP+'.new';shutil.copy2(NATIVE,tmp)
 with open(tmp,'ab') as fh:fh.write(b'\0')
 os.replace(tmp,APP)
 refused=rr('request-rule-preview',swap,'allow');save_json('replaced-executable-refusal.json',refused)
 assert refused.get('error_code')=='executable_changed' and ('different file' in refused['error'] or 'modified' in refused['error']),refused
 assert not api().get('rules')
 log('PASS executable replaced at the same path: exact refusal, no rule ('+refused['error']+')')
 # 6: Deny for subsequent launches.
 base=peer_count()
 deny_req,_=prompt_then_exit(APP,'deny');_,ds=save_from(deny_req,'block','deny');deny=ds['saved_rule']
 c,info=launch(APP);ask(c,'send',protocol='tcp',timeout_ms=3000)
 b=wait(lambda:next((e for e in events_for(info['pid']) if e['state']=='blocked'),None));save_json('deny-relaunch.json',b)
 assert b['rule']==deny['id'] and not pending(info['pid']);time.sleep(.3);assert peer_count()==base;quit(c)
 g['delete'](deny)
 log('PASS Deny saved from ended request blocks the next launch without prompt (rule %s)'%deny['id'])
 # 6: Ask for subsequent launches.
 ask_req,_=prompt_then_exit(APP,'ask');_,as_=save_from(ask_req,'ask','ask');ask_rule=as_['saved_rule']
 c,info=launch(APP);ask(c,'send',protocol='tcp',timeout_ms=8000)
 q=wait(lambda:pending(info['pid']));save_json('ask-relaunch.json',q)
 assert q.get('ask_rule',{}).get('id')==ask_rule['id'],q
 assert not api('decide',generation=generation,id=q['id'],action='block',scope='once').get('error')
 time.sleep(.3);assert peer_count()==base;quit(c)
 g['delete'](ask_rule);assert not api().get('rules')
 log('PASS Ask saved from ended request prompts the next launch via that stored rule (%s)'%ask_rule['id'])
 for c in launched:quit(c)
 (RUN/'result.json').write_text(json.dumps({'passed':True,'generation':generation,'native':NATIVE,'deliveries':peer_count()-before,'rules':0,'host_actions':False},indent=2)+'\n')
