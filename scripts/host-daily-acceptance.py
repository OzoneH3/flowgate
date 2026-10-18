#!/usr/bin/env python3
"""One authorized live-host acceptance. Dedicated test peers/executables only.
No broad policy rules. Deletes only acknowledged test rule IDs and own resources.
Failure restores monitoring through the installer; never reports ACK as delivery.
"""
import argparse,json,os,pathlib,signal,socket,struct,subprocess,time,uuid
p=argparse.ArgumentParser();p.add_argument('--release',required=True);p.add_argument('--evidence',required=True);p.add_argument('--isolated',action='store_true',help='test harness only; kernel collectors remain separately accepted');a=p.parse_args()
if a.isolated:assert os.environ.get('FLOWGATE_PARENT_NETNS')!=os.readlink('/proc/self/ns/net') and pathlib.Path('/proc/self/uid_map').read_text().split()[-1]=='1'
test_uid=0 if a.isolated else 1000
user_options={}if a.isolated else dict(user=1000,group=1000,extra_groups=[])
assert os.geteuid()==0
release=pathlib.Path(a.release).resolve();evidence=pathlib.Path(a.evidence);evidence.mkdir(mode=0o700)
children={};infos={};peer=None;owned={};cases=[]
def cmd(*args):return subprocess.check_output(args,text=True,stderr=subprocess.STDOUT)
def wait(fn,seconds=20):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  v=fn()
  if v:return v
  time.sleep(.08)
 raise AssertionError('timeout '+str(fn))
def api(op='list',**q):
 with socket.socket(socket.AF_UNIX)as s:
  s.settimeout(10);s.connect('/run/flowgate-api/daemon.sock');s.sendall((json.dumps(dict(version=1,operation=op,**q))+'\n').encode());r=json.loads(s.makefile('rb').readline());assert not r.get('error'),r;return r
def ask(child,**q):
 child.stdin.write(json.dumps(q)+'\n');child.stdin.flush();line=child.stdout.readline();assert line,child.poll();return json.loads(line)
def counts(name,key):return ask(children[name],op='counts')['counts'].get(key,0)
def peer_counts(key):return ask(peer,op='counts')['counts'].get(key,0)
def passed(label):
 label=label.replace('Real host','Isolated receiver')if a.isolated else label
 cases.append(label);print('PASS',label,flush=True);(evidence/'result.json').write_text(json.dumps({'passed':False,'cases':cases},indent=2))
def pending(name,key,direction,ids):
 pid=infos[name]['pid'];port=infos[name]['ports'][key]if direction=='incoming'else 24688+(key[:3]=='udp')
 def find():
  r=api();return next((e for e in r.get('events',[])if e['id']not in ids and e['state']=='awaiting-decision'and e['flow']['direction']==direction and e['flow']['protocol']==key[:3]and e['flow']['local'if direction=='incoming'else'remote'].endswith(':'+str(port))and any(o['pid']==pid for o in e['attribution'].get('owners',[]))),None)
 return wait(find)
def trigger(name,key,direction):
 if direction=='incoming':return ask(peer,op='send',protocol=key[:3],v6=key.endswith('6'),port=infos[name]['ports'][key])
 return ask(children[name],op='send',protocol=key[:3],v6=key.endswith('6'))
def transfer(name,key,direction,action,remember=None):
 before=counts(name,key)if direction=='incoming'else peer_counts(key);ids={e['id']for e in api().get('events',[])};trigger(name,key,direction);e=pending(name,key,direction,ids)
 scope='persistent'if remember else'once';fields=dict(generation=api()['generation'],id=e['id'],action=action,scope=scope)
 if remember:
  r=api();pv=api('decision-preview',**fields,network_zone=remember,zone_revision=r['network_zones']['revision'])['decision_preview'];fields.update(preview_token=pv['token'],network_zone=remember,zone_revision=r['network_zones']['revision'])
 r=api('decide',**fields)
 if remember:
  saved=r['saved_rule'];owned[saved['id']]=saved;assert saved['filter']['network_zone']==remember
 record_path=evidence/(direction+'-'+key+'-'+action+'.json')
 record_path.write_text(json.dumps({'event':e,'decision':r,'receiver_before':before},indent=2))
 try:
  if action=='allow':wait(lambda:(counts(name,key)if direction=='incoming'else peer_counts(key))==before+1)
  else:time.sleep(.6);assert(counts(name,key)if direction=='incoming'else peer_counts(key))==before
 except Exception:
  (evidence/'failure-runtime.json').write_text(json.dumps(api(),indent=2))
  (evidence/'failure-decision-log.json').write_text(json.dumps(api('decision-log',decision_query={'limit':100}),indent=2))
  try:(evidence/'failure-fresh-attribution.json').write_text(cmd(str(release/'flowgate'),'attribute','--protocol',e['flow']['protocol'],'--direction',direction,'--local',e['flow']['local'],'--remote',e['flow']['remote']))
  except Exception:pass
  raise
 (evidence/(direction+'-'+key+'-'+action+'.json')).write_text(json.dumps({'event':e,'decision':r,'receiver_before':before,'receiver_after':counts(name,key)if direction=='incoming'else peer_counts(key)},indent=2))
 return e

def target(name):
 def find():
  a=api()['activity']
  for row in a['rows']:
   if len(row['owners'])==1 and a['processes'][row['owners'][0]]['pid']==infos[name]['pid']:return {'row_id':row['id'],'process_id':row['owners'][0]}
 return wait(find)
def create(scope,action):
 r=api();d=dict(target_scope=scope,direction='incoming',protocol='udp',action=action,remote_address='fd79:6667::2',local_port=0,remote_port=0,disabled=False,expires='0001-01-01T00:00:00Z')
 pv=api('observed-rule-preview',generation=r['generation'],observed_target=target('alpha'),observed_draft=d)['observed_preview']
 saved=api('observed-rule-save',generation=r['generation'],preview_token=pv['token'],observed_draft=d)['saved_rule'];owned[saved['id']]=saved;return saved

def rule_delivery(name,key,expected):
 before=counts(name,key);trigger(name,key,'incoming')
 if expected:wait(lambda:counts(name,key)==before+1)
 else:time.sleep(.7);assert counts(name,key)==before

def restart():
 g=api()['generation'];cmd('systemctl','reset-failed','flowgate.service');cmd('systemctl','restart','flowgate.service');r=wait(lambda:(lambda r:r if r['generation']!=g and r['protection']['state']=='active'else None)(api()));assert r['protection']['desired_mode']=='both';return r

def write_zones(z):
 path=pathlib.Path('/etc/flowgate/zones.json');tmp=path.with_suffix('.acceptance-new');tmp.write_text(json.dumps(z));tmp.chmod(0o600);os.replace(tmp,path)
def foreign():
 r=json.loads(cmd('nft','-j','list','ruleset'))
 def clean(o):
  if isinstance(o,dict):return{k:clean(v)for k,v in o.items()if k not in ['handle','counter','metainfo']}
  if isinstance(o,list):return[clean(v)for v in o]
  return o
 r['nftables']=[o for o in r['nftables']if not any(isinstance(v,dict)and(v.get('table')in ['flowgate_host','flowgate_guard']or v.get('name')in ['flowgate_host','flowgate_guard'])for v in o.values())]
 return clean(r)

baseline=api();baseline_ids={r['id']for r in baseline.get('rules',[])};oldzones=json.loads(pathlib.Path('/etc/flowgate/zones.json').read_text());before_foreign=foreign();before_ts=json.loads(cmd('tailscale','status','--json'))['BackendState'];assert before_ts=='Running'
# Explicit fixture zones only; private IPv6 represents configured Internet policy,
# not public connectivity. Original zone configuration is restored afterwards.
testzones={'local':list(dict.fromkeys(oldzones['local']+['192.0.2.0/30'])),'internet':list(dict.fromkeys(oldzones['internet']+['fd79:6667::/64']))}
try:
 write_zones(testzones);cmd('systemctl','reset-failed','flowgate.service');cmd('systemctl','restart','flowgate.service');initial=api();assert initial['protection']['state']=='stopped'
 peer=subprocess.Popen([str(release/'flowgate'),'host-test-peer'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=(evidence/'peer.log').open('w'),text=True)
 assert json.loads(peer.stdout.readline())['ready']
 for name,base,exe in [('alpha',24680,'native'),('beta',24690,'native'),('other',24700,'native-other')]:
  env=dict(os.environ,FLOWGATE_FIXTURE_TIMEOUT_SECONDS='30',FLOWGATE_FIXTURE_PEER4='192.0.2.2',FLOWGATE_FIXTURE_PEER6='fd79:6667::2',FLOWGATE_FIXTURE_PEER_PORT='24688')
  child=subprocess.Popen([str(release/exe),str(base),'192.0.2.1','fd79:6667::1'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=(evidence/(name+'.log')).open('w'),text=True,env=env,**user_options);children[name]=child;infos[name]=json.loads(child.stdout.readline())
 target('alpha');r=api();api('protection-readiness',generation=r['generation'],profile='both');wait(lambda:api()['protection']['readiness']['state']!='checking');assert api()['protection']['readiness']['state']=='ready'
 r=api();api('protection-start',generation=r['generation'],protection_id=r['protection']['id'],request_id=uuid.uuid4().hex,profile='both');wait(lambda:api()['protection']['state']=='active')
 for direction in ['incoming','outgoing']:
  for key in ['tcp4','tcp6','udp4','udp6']:
   transfer('alpha',key,direction,'allow');transfer('alpha',key,direction,'block')
  passed('Real host '+direction+' TCP4/6 and UDP4/6 Allow receiver+1 / Deny receiver0')
 transfer('alpha','udp4','incoming','allow','local');rule_delivery('alpha','udp4',True)
 passed('Named Local remembered rule stored and subsequent host delivery')
 # Process override and sibling fallback; then actual restart invalidates process.
 app=create('application','block');proc=create('process','allow');rule_delivery('alpha','udp6',True);rule_delivery('beta','udp6',False)
 r=restart();assert r['rule_states'][proc['id']]['state']=='inactive';rule_delivery('alpha','udp6',False)
 passed('Process override/sibling fallback; service restart restores both and application policy, process target inactive')
 for saved in [proc,app]:api('rule-delete',generation=api()['generation'],id=saved['id'],expected_version=saved['version']);owned.pop(saved['id'])
 # Exact same peer/app/protocol/service, only privileged classification changes.
 flipped={'local':[x for x in testzones['local']if x!='192.0.2.0/30'],'internet':list(dict.fromkeys(testzones['internet']+['192.0.2.0/30']))};write_zones(flipped);restart();transfer('alpha','udp4','incoming','block')
 passed('Same host peer/application/service reclassified Internet does not inherit Local remembered Allow')
 write_zones(testzones);restart();rule_delivery('alpha','udp4',True)
 # Different executable replaces only the test receiver at the identical endpoint.
 children['alpha'].terminate();children['alpha'].wait(5)
 child=subprocess.Popen([str(release/'native-other'),'24680','192.0.2.1','fd79:6667::1'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=(evidence/'replacement.log').open('w'),text=True,env=env,**user_options);children['alpha']=child;infos['alpha']=json.loads(child.stdout.readline())
 transfer('alpha','udp4','incoming','block');passed('Different executable remains independently prompted/denied')
 # No Electron process participates in these writes: continuous policy remains active.
 assert api()['protection']['state']=='active';passed('Continuous control without Electron; no GUI-owned firewall lifecycle')
finally:
 # Delete only ACKed exact ID/version records; preserve every pre-existing rule.
 for saved in list(owned.values()):
  try:api('rule-delete',generation=api()['generation'],id=saved['id'],expected_version=saved['version']);owned.pop(saved['id'])
  except Exception:pass
 for child in children.values():
  if child.poll()is None:child.terminate()
  child.wait(5)
 if peer and peer.poll()is None:
  try:ask(peer,op='quit');peer.wait(6)
  except Exception:peer.terminate();peer.wait(6)
 write_zones(oldzones)
 (evidence/'remaining-test-rules.json').write_text(json.dumps(owned,indent=2))
 # Final restart restores original config and desired mode, no disposable resources.
 if not owned:
  cmd('systemctl','reset-failed','flowgate.service');cmd('systemctl','restart','flowgate.service')
assert not owned,'Unconfirmed test rule cleanup; inspect exact IDs in saved evidence'
r=wait(lambda:(lambda r:r if r['protection']['state']=='active'and (a.isolated or (r['traffic_monitor']['state']=='active'and r.get('activity',{}).get('tcp_initiation',{}).get('state')=='active'))else None)(api()))
assert{rule['id']for rule in r.get('rules',[])}==baseline_ids
assert foreign()==before_foreign,'Foreign firewall semantics changed'
assert json.loads(cmd('tailscale','status','--json'))['BackendState']==before_ts
assert r['protection']['profile']=='both'
# Event source may be partial by design but must be active on this accepted host.
if not a.isolated:assert r['activity']['tcp_initiation']['state']=='active',r['activity'].get('tcp_initiation')
passed('Final both active; original zones/policies/foreign firewall retained'+('; isolated adapter, collectors NOT part of this check'if a.isolated else'; UDP/shared direction active and Tailscale retained'))
(evidence/'runtime-final.json').write_text(json.dumps(r,indent=2));(evidence/'result.json').write_text(json.dumps({'passed':True,'cases':cases,'generation':r['generation']},indent=2))
