#!/usr/bin/env python3
"""Private native process-rule receiver suite or exclusively delegated UI fixture.
Run through scripts/lab.sh. Never opens host endpoints or deployed executable.
"""
import argparse,json,os,pathlib,socket,subprocess,time,sys,shutil
ROOT=pathlib.Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser();p.add_argument('--binary',required=True);p.add_argument('--native',required=True);p.add_argument('--run',required=True);p.add_argument('--hold',action='store_true');p.add_argument('--any-protocol',action='store_true');p.add_argument('--zones',action='store_true');p.add_argument('--automatic-zones',action='store_true');p.add_argument('--legacy-zone-fixture',action='store_true');p.add_argument('--zones-unknown',action='store_true');p.add_argument('--remember-zones',action='store_true');p.add_argument('--hold-enforcement',action='store_true',help='with --hold, bounded private incoming+outgoing interception for prompt acceptance');p.add_argument('--continuous',action='store_true',help='held daily lifecycle candidate; monitoring initially, UI owns Start/Stop');p.add_argument('--other',action='store_true',help='held third executable identity');p.add_argument('--app-policy',action='store_true',help='NetLimiter application Allow/Deny receiver acceptance');p.add_argument('--remember-ended',action='store_true',help='real outgoing retry/socket-close Remember regression');p.add_argument('--request-rule',action='store_true',help='future application rule from an ended request after requester exit');p.add_argument('--ask',action='store_true',help='stored Ask receiver acceptance');p.add_argument('--for-a-while',action='store_true',help='For a while process lease receiver acceptance');p.add_argument('--provenance',action='store_true',help='SIMULATED umu/Proton launch provenance, grouping and permission-target acceptance');p.add_argument('--queue-reconcile',action='store_true',help='queue reconciliation, Once retransmission, ended-request For a while and durations receiver acceptance');p.add_argument('--sandbox-identity',action='store_true',help='rule from an ENDED request of a sandboxed (private mount namespace) process; relaunch in a new namespace');p.add_argument('--local-pair',action='store_true',help='same-host connection pairs: exact reversed tuple, decide-pair, receiver delivery (both directions intercepted)');a=p.parse_args()
if a.continuous and not a.hold:p.error('--continuous requires --hold')
if a.hold_enforcement and not a.hold:p.error('--hold-enforcement requires --hold')
if a.zones_unknown or a.remember_zones or a.app_policy or a.ask:a.zones=True
if a.app_policy or a.ask or a.remember_ended or a.request_rule or a.for_a_while or a.queue_reconcile:a.other=True
assert os.environ['FLOWGATE_PARENT_NETNS']!=os.readlink('/proc/self/ns/net')
RUN=pathlib.Path(a.run).resolve();assert RUN.is_relative_to(ROOT/'.workspace');RUN.mkdir(mode=0o700,parents=True)
for d in ['api','data','state']:(RUN/d).mkdir(mode=0o711 if d=='api' and a.continuous else 0o700)
BIN=str(pathlib.Path(a.binary).resolve());assert BIN!=str(ROOT/'.workspace/flowgate');NATIVE=str(pathlib.Path(a.native).resolve());API=str(RUN/'api/control.sock')
backend=peer=None;children={};infos={}
def cmd(*args):return subprocess.check_output(args,text=True,stderr=subprocess.STDOUT)
def wait(fn,seconds=12):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  v=fn()
  if v:return v
  time.sleep(.05)
 raise AssertionError('timeout')
def api(op='list',readonly=False,**fields):
 with socket.socket(socket.AF_UNIX)as s:
  s.settimeout(10);s.connect(API+('.monitor'if readonly else ''));s.sendall((json.dumps(dict(version=1,operation=op,**fields))+'\n').encode());b=b''
  while b'\n'not in b:
   x=s.recv(65536)
   if not x:raise RuntimeError('lost ACK')
   b+=x
  return json.loads(b)
def ask(child,op,**kw):
 child.stdin.write(json.dumps(dict(op=op,**kw))+'\n');child.stdin.flush();return json.loads(child.stdout.readline())
def remote(op,**kw):
 r=ask(peer,op,**kw);assert 'error'not in r,r;return r
def log(s):
 print(s,flush=True)
 with (RUN/'verification.log').open('a')as f:f.write(s+'\n')
def activity():return api()['activity']
def target(name):
 def find():
  s=activity()
  for row in sorted(s.get('rows') or [], key=lambda r:0 if r['socket']['protocol']=='tcp'and r['socket']['state']==10 else 1):
   for oid in row['owners']:
    if s['processes'][oid]['pid']==infos[name]['pid']and len(row['owners'])==1 and row['ownership_category']=='visible-holder':return dict(row_id=row['id'],process_id=oid)
 return wait(find)
def create(name,scope,direction,protocol,action):
 draft=dict(target_scope=scope,direction=direction,protocol=protocol,action=action,remote_address='*',local_port=0,remote_port=0,disabled=False,expires='0001-01-01T00:00:00Z')
 pv=api('observed-rule-preview',generation=api()['generation'],observed_target=target(name),observed_draft=draft);assert not pv.get('error'),pv
 sv=api('observed-rule-save',generation=api()['generation'],preview_token=pv['observed_preview']['token'],observed_draft=draft);assert not sv.get('error'),sv
 (RUN/'example-preview.json').write_text(json.dumps(pv,indent=2));return sv['saved_rule']
def edit(r,**changes):
 candidate=dict(r,**changes);out=api('rule-save',generation=api()['generation'],id=r['id'],expected_version=r['version'],rule=candidate);assert not out.get('error'),out;return out['saved_rule']
def delete(r):
 out=api('rule-delete',generation=api()['generation'],id=r['id'],expected_version=r['version']);assert not out.get('error'),out
def received(name,key):return ask(children[name],'counts')['counts'].get(key,0)
def incoming(name,proto,v6,allowed):
 key=proto+('6'if v6 else'4');port=infos[name]['ports'][key];before=received(name,key)
 remote(proto,port=port,v6=v6)
 if allowed:wait(lambda:received(name,key)==before+1)
 else:
  time.sleep(.4);assert received(name,key)==before,(name,key,'unexpected delivery')
  wait(lambda:any(v['flow']['local'].endswith(':'+str(port))and v['state']=='blocked'for v in api().get('events',[])))
 if proto=='tcp':remote('close',port=port,v6=v6)
def outgoing(name,proto,v6,allowed):
 f=RUN/'peer-received.log';before=len(f.read_text().splitlines())if f.exists()else 0
 ask(children[name],'send',protocol=proto,v6=v6);ask(children[name],'settle')
 if allowed:wait(lambda:f.exists()and len(f.read_text().splitlines())==before+1)
 else:
  time.sleep(.4);assert(len(f.read_text().splitlines())if f.exists()else 0)==before
  pid=infos[name]['pid'];wait(lambda:any(v['flow']['direction']=='outgoing'and v['flow']['protocol']==proto and v['state']=='blocked'and any(o['pid']==pid for o in v['attribution']['owners'])for v in api().get('events',[])))
def start(zone_flip=False):
 global backend
 with (RUN/'daemon.log').open('a')as f:
  args=[BIN,'serve','--socket',API,'--database',str(RUN/'data/rules.db'),'--uid','0','--administrator']if a.hold and not a.hold_enforcement else[BIN,'host-start','--state',str(RUN/'state'),'--socket',API,'--database',str(RUN/'data/rules.db'),'--uid','0','--administrator','--profile','both','--duration','300s','--timeout','60s'if a.hold_enforcement else'20s'if a.app_policy or a.ask or a.remember_ended or a.request_rule or a.sandbox_identity or a.for_a_while or a.provenance or a.queue_reconcile or a.local_pair else'4s']
  if a.continuous:args=[BIN,'serve','--socket',API,'--database',str(RUN/'data/rules.db'),'--uid','0','--administrator','--allow-protection','--protection-state',str(RUN/'data/desired.json'),'--allow-evaluation','--evaluation-state',str(RUN/'state'),'--decision-timeout','12s']
  if a.zones:args+=['--zone-local','fd79::/64'if zone_flip else'10.79.0.0/24','--zone-internet','10.79.0.0/24'if zone_flip else'fd79::/64']
  backend=subprocess.Popen(args,stdout=f,stderr=f)
 def ready():
  if backend.poll()is not None:raise RuntimeError((RUN/'daemon.log').read_text())
  try:return api()
  except(OSError,ValueError):return None
 return wait(ready)
def stop():
 if backend and backend.poll()is None:
  if a.continuous:
   s=api();r=api('protection-stop',generation=s['generation'],protection_id=s['protection']['id']) if s['protection']['state']!='stopped'else {};assert not r.get('error'),r
   wait(lambda:api()['protection']['state']=='stopped');backend.terminate()
  elif a.hold and not a.hold_enforcement:backend.terminate()
  else:cmd(BIN,'host-stop','--state',str(RUN/'state'))
  backend.wait(20)
try:
 peer=subprocess.Popen(['unshare','--net','python3',str(ROOT/'scripts/acceptance/host-peer.py'),str(RUN)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
 wait(lambda:os.readlink(f'/proc/{peer.pid}/ns/net')!=os.readlink('/proc/self/ns/net'))
 cmd('ip','link','add','fghost','type','veth','peer','name','fgpeer');cmd('ip','link','set','fgpeer','netns',str(peer.pid));cmd('ip','link','set','fghost','up');cmd('ip','addr','add','10.79.0.1/24','dev','fghost');cmd('ip','-6','addr','add','fd79::1/64','dev','fghost','nodad');remote('setup')
 cmd('nft','add','table','inet','unrelated_fixture');cmd('nft','add','chain','inet','unrelated_fixture','track','{ type filter hook input priority 0; policy accept; }');cmd('nft','add','rule','inet','unrelated_fixture','track','ct','state','established','counter')
 for name,port in [('alpha',45000),('beta',45010)]+([('other',45020)]if a.other else []):
  executable=NATIVE
  if name=='other':executable=str(RUN/'native-other');shutil.copy2(NATIVE,executable)
  children[name]=subprocess.Popen([executable,str(port)],env=dict(os.environ,FLOWGATE_FIXTURE_TIMEOUT_SECONDS='60'if a.hold_enforcement or a.continuous else'10'if a.app_policy or a.ask or a.for_a_while or a.queue_reconcile else'2'),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=(RUN/(name+'.log')).open('w'),text=True);infos[name]=json.loads(children[name].stdout.readline())
 if a.legacy_zone_fixture:
  assert a.hold, 'legacy fixture is monitor-only'
  import sqlite3,datetime
  r=dict(schema=4,id='user:synthetic-legacy-zone',version=1,priority=0,action='block',disabled=True,created=datetime.datetime.now(datetime.timezone.utc).isoformat(),expires='0001-01-01T00:00:00Z',filter=dict(all_programs=True,uid=0,network_zone='local',direction='outgoing',protocol='*'))
  db=sqlite3.connect(RUN/'data/rules.db');db.execute('CREATE TABLE rules(id TEXT PRIMARY KEY, document TEXT NOT NULL CHECK(length(document)<=16384))');db.execute('PRAGMA user_version=1');db.execute('INSERT INTO rules VALUES(?,?)',(r['id'],json.dumps(r)));db.commit();db.close();os.chmod(RUN/'data/rules.db',0o600)
 initial=start();generation=initial['generation'];assert 'process-instance-rules-v1'in initial['capabilities']
 ta,tb=target('alpha'),target('beta')
 if a.hold:
  (RUN/'ready.json').write_text(json.dumps(dict(socket=API,monitor_socket=API+'.monitor',generation=generation,alpha=infos['alpha'],beta=infos['beta'],alpha_target=ta,beta_target=tb,other=infos.get('other'),other_target=target('other')if a.other else None,command=str(RUN/'command'),profile='continuous'if a.continuous else'both'if a.hold_enforcement else'monitor',prompt_timeout_seconds=12 if a.continuous else 60 if a.hold_enforcement else None,enforcement=initial.get('enforcement'))))
  log('READY; UI exclusively owns API. command file JSON: {op:incoming|outgoing,protocol:tcp|udp,v6:false,name:alpha|beta}, {op:counts|peer-counts|exit|exec,name:alpha|beta}, or {op:quit}. Reply command-result.json')
  while True:
   path=RUN/'command'
   if not path.exists():time.sleep(.1);continue
   q=json.loads(path.read_text());path.unlink();op=q['op'];name=q.get('name','alpha')
   if op=='quit':break
   if op=='batch':
    results=[]
    for item in q['items']:
     n=item.get('name','alpha');proto=item.get('protocol','udp');v6=item.get('v6',False)
     if item['op']=='incoming':r=remote(proto,port=infos[n]['ports'][proto+('6'if v6 else'4')],v6=v6)
     elif item['op']=='outgoing':r=ask(children[n],'send',protocol=proto,v6=v6,**{k:item[k] for k in('host','port','timeout_ms') if k in item})
     else:raise ValueError('batch accepts incoming/outgoing only')
     results.append(r)
    result={'started':results}
   elif op=='exit':children[name].terminate();children[name].wait(5);result={'exited':name}
   elif op=='exec':children[name].stdin.write('{"op":"exec"}\n');children[name].stdin.flush();result={'exec':name}
   elif op=='launch':
    # Relaunch the same executable as a new process (new PID/ports) for UI journeys.
    if children[name].poll() is None:children[name].terminate();children[name].wait(5)
    executable=str(RUN/'native-other')if name=='other'else NATIVE;port=45100+10*len(infos.setdefault('_launches',[]))
    children[name]=subprocess.Popen([executable,str(port)],env=dict(os.environ,FLOWGATE_FIXTURE_TIMEOUT_SECONDS='60'),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=(RUN/(name+'.log')).open('a'),text=True)
    infos[name]=json.loads(children[name].stdout.readline());infos['_launches'].append(infos[name]['pid']);result={'launched':name,'info':infos[name]}
   elif op=='incoming':
    proto=q.get('protocol','udp');v6=q.get('v6',False);port=infos[name]['ports'][proto+('6'if v6 else'4')];result=remote(proto,port=port,v6=v6)
   elif op=='outgoing':result=ask(children[name],'send',protocol=q.get('protocol','udp'),v6=q.get('v6',False),**{k:q[k] for k in('host','port','timeout_ms') if k in q})
   elif op=='peer-counts':
    f=RUN/'peer-received.log';result={'lines':f.read_text().splitlines()if f.exists()else[]}
   else:result=ask(children[name],op)
   (RUN/'command-result.json').write_text(json.dumps(result))
 elif a.automatic_zones:
  from automatic_zones_acceptance import check
  check(globals())
  stop();assert 'flowgate_host'not in cmd('nft','list','tables')and'unrelated_fixture'in cmd('nft','list','tables')
  log('PASS owned-only cleanup; unrelated nft table preserved; no host changes')
 elif a.sandbox_identity:
  from sandbox_identity_acceptance import check
  check(globals())
  stop();assert 'flowgate_host'not in cmd('nft','list','tables')and'unrelated_fixture'in cmd('nft','list','tables')
  log('PASS owned-only cleanup; unrelated nft table preserved; no host changes')
 elif a.local_pair:
  from local_pair_acceptance import check
  check(globals())
  stop();assert 'flowgate_host'not in cmd('nft','list','tables')and'unrelated_fixture'in cmd('nft','list','tables')
  log('PASS owned-only cleanup; unrelated nft table preserved; no host changes')
 elif a.queue_reconcile:
  from queue_reconcile_acceptance import check
  check(globals())
  stop();assert 'flowgate_host'not in cmd('nft','list','tables')and'unrelated_fixture'in cmd('nft','list','tables')
  log('PASS owned-only cleanup; unrelated nft table preserved; no host changes')
 elif a.provenance:
  from provenance_acceptance import check
  check(globals())
  stop();assert 'flowgate_host'not in cmd('nft','list','tables')and'unrelated_fixture'in cmd('nft','list','tables')
  log('PASS owned-only cleanup; unrelated nft table preserved; no host changes')
 elif a.for_a_while:
  from for_a_while_acceptance import check
  check(globals())
  stop();assert 'flowgate_host'not in cmd('nft','list','tables')and'unrelated_fixture'in cmd('nft','list','tables')
  log('PASS owned-only cleanup; unrelated nft table preserved; no host changes')
 elif a.request_rule:
  from request_rule_acceptance import check
  check(globals())
  stop();assert 'flowgate_host'not in cmd('nft','list','tables')and'unrelated_fixture'in cmd('nft','list','tables')
  log('PASS owned-only cleanup; unrelated nft table preserved; no host changes')
 elif a.remember_ended:
  from remember_ended_acceptance import check
  check(globals())
  stop();assert 'flowgate_host'not in cmd('nft','list','tables')and'unrelated_fixture'in cmd('nft','list','tables')
  log('PASS owned-only cleanup; unrelated nft table preserved; no host changes')
 elif a.ask:
  from ask_acceptance import check
  check(globals())
  stop();assert 'flowgate_host'not in cmd('nft','list','tables')and'unrelated_fixture'in cmd('nft','list','tables')
  log('PASS owned-only cleanup; unrelated nft table preserved; no host changes')
 elif a.app_policy:
  from app_policy_acceptance import check
  check(globals())
  stop();assert 'flowgate_host'not in cmd('nft','list','tables')and'unrelated_fixture'in cmd('nft','list','tables')
  log('PASS owned-only cleanup; unrelated nft table preserved; no host changes')
 elif a.remember_zones:
  from remember_zone_acceptance import check
  check(globals())
 elif a.zones:
  from zone_policy_acceptance import check,check_unknown
  (check_unknown if a.zones_unknown else check)(globals())
 elif a.any_protocol:
  assert 'observed-rule-any-protocol-v1' in initial['capabilities']
  for direction in ['incoming','outgoing']:
   app=create('alpha','application',direction,'*','block');pa=create('alpha','process',direction,'*','allow')
   send=incoming if direction=='incoming'else outgoing
   for proto in ['tcp','udp']:
    for v6 in [False,True]:send('alpha',proto,v6,True);send('beta',proto,v6,False)
   view=api('policy-view',generation=generation)['policy_view']
   assert any(x[direction]['configured']=='uniform'for x in view['applications'])
   app=edit(app,action='allow');pa=edit(pa,action='block')
   for proto in ['tcp','udp']:send('alpha',proto,False,False);send('beta',proto,False,True)
   delete(pa);delete(app)
   log('PASS wildcard '+direction+' one rule covers TCP+UDP IPv4/6, process override/sibling fallback, Allow/Block receiver results and uniform summary')
  records=wait(lambda:(lambda r:r if any(x.get('decision',{}).get('rule',{}).get('filter',{}).get('protocol')=='*'for x in r['decision_log']['records'])else None)(api('decision-log',decision_query={'limit':100})))
  (RUN/'wildcard-decision.json').write_text(json.dumps(next(x for x in records['decision_log']['records']if x.get('decision',{}).get('rule',{}).get('filter',{}).get('protocol')=='*'),indent=2))
  stop();assert 'flowgate_host'not in cmd('nft','list','tables')and'unrelated_fixture'in cmd('nft','list','tables')
  log('PASS immutable wildcard Decision Log snapshot; owned-only cleanup; no host changes')
 else:
  # Each protocol/direction has an application fallback plus one exclusive instance override.
  for direction in ['incoming','outgoing']:
   for proto in ['udp','tcp']:
    app=create('alpha','application',direction,proto,'block');pa=create('alpha','process',direction,proto,'allow')
    send=incoming if direction=='incoming'else outgoing
    for v6 in [False,True]:
     send('alpha',proto,v6,True);send('beta',proto,v6,False)
    app=edit(app,action='allow');pa=edit(pa,action='block')
    # Separate attempts/ports and tokens; admitted TCP sockets intentionally retain admission.
    for v6 in [False,True]:
     send('alpha',proto,v6,False);send('beta',proto,v6,True)
    pa=edit(pa,disabled=True);send('alpha',proto,False,True)
    pa=edit(pa,disabled=False);send('alpha',proto,False,False)
    delete(pa);send('alpha',proto,False,True)
    assert any(r['id']==app['id']for r in api()['rules']);delete(app)
    log('PASS '+direction+' '+proto+' IPv4/6 process Allow/Block, sibling isolation, application fallback, override, disable/enable/delete')
  # Actual process exit and different-executable exec retire pins and never affect sibling rule.
  pa=create('alpha','process','incoming','udp','allow');pb=create('beta','process','incoming','udp','block')
  children['alpha'].terminate();children['alpha'].wait(5)
  wait(lambda:api()['rule_states'][pa['id']]['state']=='inactive')
  assert api()['rule_states'][pb['id']]['state']=='active'
  children['beta'].stdin.write('{"op":"exec"}\n');children['beta'].stdin.flush()
  wait(lambda:api()['rule_states'][pb['id']]['state']=='inactive')
  view=api('policy-view',generation=generation);assert all(x['state']=='inactive'for x in view['policy_view']['processes']if x['target']['instance_id'])
  records=wait(lambda:(lambda r:r if any(x.get('decision',{}).get('rule',{}).get('target_scope')=='process'for x in r['decision_log']['records'])else None)(api('decision-log',decision_query={'limit':100})))
  (RUN/'decision-example.json').write_text(json.dumps(next(x for x in records['decision_log']['records']if x.get('decision',{}).get('rule',{}).get('target_scope')=='process'),indent=2))
  before=api()['rules'];stop();start();assert api()['generation']!=generation and api()['rules']==before and all(v['state']=='inactive'for v in api()['rule_states'].values())
  log('PASS actual exit/exec invalidation, sibling independence, Decision Log immutable process snapshot, restart persistence inactive; no PID reuse claim')
except Exception:
 if (RUN/'daemon.log').exists():print((RUN/'daemon.log').read_text()[-8000:],file=sys.stderr)
 raise
finally:
 stop()
 for child in children.values():
  if child.poll()is None:child.terminate()
  child.wait(5)
 if peer and peer.poll()is None:peer.terminate();peer.wait(5)
 log('CLEANED fixture daemon/instances/peer; namespace resources discarded, host untouched')
