#!/usr/bin/env python3
"""Private native process-rule receiver suite or exclusively delegated UI fixture.
Run through scripts/lab.sh. Never opens host endpoints or deployed executable.
"""
import argparse,json,os,pathlib,socket,subprocess,time,sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('--binary',required=True);p.add_argument('--native',required=True);p.add_argument('--run',required=True);p.add_argument('--hold',action='store_true');p.add_argument('--any-protocol',action='store_true');p.add_argument('--zones',action='store_true');a=p.parse_args()
assert os.environ['FLOWGATE_PARENT_NETNS']!=os.readlink('/proc/self/ns/net')
RUN=pathlib.Path(a.run).resolve();assert RUN.is_relative_to(ROOT/'.workspace');RUN.mkdir(mode=0o700,parents=True)
for d in ['api','data','state']:(RUN/d).mkdir(mode=0o700)
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
  for row in sorted(s['rows'], key=lambda r:0 if r['socket']['protocol']=='tcp'and r['socket']['state']==10 else 1):
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
def start():
 global backend
 with (RUN/'daemon.log').open('a')as f:
  args=[BIN,'serve','--socket',API,'--database',str(RUN/'data/rules.db'),'--uid','0','--administrator']if a.hold else[BIN,'host-start','--state',str(RUN/'state'),'--socket',API,'--database',str(RUN/'data/rules.db'),'--uid','0','--administrator','--profile','both','--duration','300s','--timeout','4s']
  if a.zones:args+=['--zone-local','10.79.0.0/24','--zone-internet','fd79::/64']
  backend=subprocess.Popen(args,stdout=f,stderr=f)
 def ready():
  if backend.poll()is not None:raise RuntimeError((RUN/'daemon.log').read_text())
  try:return api()
  except(OSError,ValueError):return None
 return wait(ready)
def stop():
 if backend and backend.poll()is None:
  if a.hold:backend.terminate()
  else:cmd(BIN,'host-stop','--state',str(RUN/'state'))
  backend.wait(20)
try:
 peer=subprocess.Popen(['unshare','--net','python3',str(ROOT/'scripts/host-peer.py'),str(RUN)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
 wait(lambda:os.readlink(f'/proc/{peer.pid}/ns/net')!=os.readlink('/proc/self/ns/net'))
 cmd('ip','link','add','fghost','type','veth','peer','name','fgpeer');cmd('ip','link','set','fgpeer','netns',str(peer.pid));cmd('ip','link','set','fghost','up');cmd('ip','addr','add','10.79.0.1/24','dev','fghost');cmd('ip','-6','addr','add','fd79::1/64','dev','fghost','nodad');remote('setup')
 cmd('nft','add','table','inet','unrelated_fixture');cmd('nft','add','chain','inet','unrelated_fixture','track','{ type filter hook input priority 0; policy accept; }');cmd('nft','add','rule','inet','unrelated_fixture','track','ct','state','established','counter')
 for name,port in [('alpha',45000),('beta',45010)]:
  children[name]=subprocess.Popen([NATIVE,str(port)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=(RUN/(name+'.log')).open('w'),text=True);infos[name]=json.loads(children[name].stdout.readline())
 initial=start();generation=initial['generation'];assert 'process-instance-rules-v1'in initial['capabilities']
 ta,tb=target('alpha'),target('beta')
 if a.hold:
  (RUN/'ready.json').write_text(json.dumps(dict(socket=API,monitor_socket=API+'.monitor',generation=generation,alpha=infos['alpha'],beta=infos['beta'],alpha_target=ta,beta_target=tb,command=str(RUN/'command'))))
  log('READY; UI exclusively owns API. command file JSON: {op:exit|exec|counts,name:alpha|beta}, or {op:quit}. Reply command-result.json')
  while True:
   path=RUN/'command'
   if not path.exists():time.sleep(.1);continue
   q=json.loads(path.read_text());path.unlink();op=q['op'];name=q.get('name','alpha')
   if op=='quit':break
   if op=='exit':children[name].terminate();children[name].wait(5);result={'exited':name}
   elif op=='exec':children[name].stdin.write('{"op":"exec"}\n');children[name].stdin.flush();result={'exec':name}
   else:result=ask(children[name],op)
   (RUN/'command-result.json').write_text(json.dumps(result))
 elif a.zones:
  from zone_policy_acceptance import check
  check(globals())
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
