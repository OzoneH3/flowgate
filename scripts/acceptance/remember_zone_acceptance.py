"""Focused same-peer zone Remember receiver check; private harness only."""
import json,time,socket,shutil,subprocess

def check(g):
 api,remote,infos,received=g['api'],g['remote'],g['infos'],g['received']
 wait,log,stop,start=g['wait'],g['log'],g['stop'],g['start']
 children,ask,RUN=g['children'],g['ask'],g['RUN']
 proofs=[]
 def pending(port):return next((e for e in api().get('events',[]) if e['state']=='awaiting-decision' and e['flow']['local'].endswith(':'+str(port))),None)
 def send(name):return remote('udp',port=infos[name]['ports']['udp4'])
 def preview(e,action,zone):
  r=api('decision-preview',generation=api()['generation'],id=e['id'],action=action,scope='application',network_zone=zone,zone_revision=api()['network_zones']['revision']);assert not r.get('error'),r;return r['decision_preview']
 def decide(p,drop_ack=False):
  fields=dict(generation=p['generation'],id=p['event_id'],action=p['action'],scope=p['scope'],network_zone=p['network_zone'],zone_revision=p['zone_revision'],preview_token=p['token'])
  if drop_ack:
   with socket.socket(socket.AF_UNIX)as s:s.connect(g['API']);s.sendall((json.dumps(dict(version=1,operation='decide',**fields))+'\n').encode());s.shutdown(socket.SHUT_WR)
   r=wait(lambda:(lambda r:r if r.get('decision_receipt',{}).get('state')=='committed'else None)(api('decision-status',generation=p['generation'],preview_token=p['token'])))
   assert r['decision_receipt']['saved_rule']==p['rule'],r
   replay=api('decide',**fields);assert replay.get('replayed')and replay['saved_rule']==p['rule'],replay
  else:
   r=api('decide',**fields);assert not r.get('error')and r['saved_rule']==p['rule'],r
  return r
 def count(name):return received(name,'udp4')
 def fresh(name):
  before=count(name);send(name);return before,wait(lambda:pending(infos[name]['ports']['udp4']))
 # Fixed application, protocol, peer and service across daemon restarts. ONLY root
 # configured zone membership changes, with an actual new generation/revision.
 before,e=fresh('alpha');p=preview(e,'allow','local');decide(p,True);wait(lambda:count('alpha')==before+1)
 before=count('alpha');send('alpha');wait(lambda:count('alpha')==before+1)
 localrule=p['rule'];proofs.append({'case':'Local remembered Allow/subsequent same peer','rule':localrule,'receiver':count('alpha')})
 stop();start(True)
 before,e=fresh('alpha');assert e['flow']['network_scope']['zone']=='internet';time.sleep(.2);assert count('alpha')==before
 old=api('decide',generation=p['generation'],id=p['event_id'],action='allow',scope='application',network_zone='local',zone_revision=p['zone_revision'],preview_token=p['token']);assert old.get('error_code')=='generation_conflict',old
 wrong=api('decision-preview',generation=api()['generation'],id=e['id'],action='block',scope='application',network_zone='local',zone_revision=api()['network_zones']['revision']);assert wrong.get('error_code')=='zone_mismatch',wrong
 p=preview(e,'block','internet');decide(p);time.sleep(.3);assert count('alpha')==before
 send('alpha');time.sleep(.3);assert count('alpha')==before
 internetrule=p['rule'];proofs.append({'case':'Same peer/identity/protocol/service now Internet skips LocalAllow; InternetDeny receiver0','rule':internetrule})
 # Same exact fields apart from explicit network_zone/action/ID/timestamps.
 assert {k:v for k,v in localrule['filter'].items()if k!='network_zone'}=={k:v for k,v in internetrule['filter'].items()if k!='network_zone'}
 # Any network uses a different service to avoid duplicate-scope ambiguity.
 before,e=fresh('beta');p=preview(e,'allow','any');decide(p);wait(lambda:count('beta')==before+1);anyrule=p['rule'];assert anyrule['schema']==2 and 'network_zone'not in anyrule['filter']
 stop();start(False)
 before=count('alpha');send('alpha');wait(lambda:count('alpha')==before+1) # LocalAllow unaffected by InternetDeny
 before=count('beta');send('beta');wait(lambda:count('beta')==before+1) # Any survives same-peer zone change
 proofs.append({'case':'Restored Local membership uses LocalAllow not InternetDeny; Any beta still delivers','rule':anyrule})
 # Replace alpha with a distinct executable at the SAME service/peer/protocol;
 # the saved application permission must not be inherited just by reusing its port.
 children['alpha'].terminate();children['alpha'].wait(5)
 other=RUN/'different-native';shutil.copyfile(g['NATIVE'],other);other.chmod(0o700)
 child=subprocess.Popen([str(other),'45000'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
 children['gamma']=child;infos['gamma']=json.loads(child.stdout.readline())
 before,e=fresh('gamma');assert e['attribution']['application']['key']!=localrule['filter']['application'];time.sleep(.2);assert count('gamma')==before
 out=api('decide',id=e['id'],action='block',scope='once');assert not out.get('error'),out
 time.sleep(.2);assert count('gamma')==before
 proofs.append({'case':'Different executable at identical peer/protocol/service does not inherit permission; independent prompt/Deny receiver0'})
 for r in api().get('rules',[]):
  out=api('rule-delete',generation=api()['generation'],id=r['id'],expected_version=r['version']);assert not out.get('error'),out
 assert not api().get('rules')
 (RUN/'remember-zone-evidence.json').write_text(json.dumps({'proofs':proofs,'rules':0,'note':'Only explicit zone config changes on same peer; fresh generation each restart, private addresses are configured policy labels'},indent=2))
 log('PASS same application+peer+protocol+service across Local/Internet config revisions: LocalAllow delivery/subsequent; nonmatch prompts; InternetDeny0; LocalAllow restored; Any delivers across zones; lostACK receipt+idempotent replay; stale generation rejected; rules0')
