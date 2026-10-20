#!/usr/bin/env python3
"""Real Winsock sender + receiver proof in private namespaces and copied prefixes.
Uses the production on-demand observer manager; never touches a game prefix.
"""
import argparse,json,os,pathlib,socket,subprocess,threading,time,signal
ROOT=pathlib.Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser();p.add_argument('--binary',required=True);p.add_argument('--run',required=True);p.add_argument('--runtime-bin',required=True);p.add_argument('--prefix-source',required=True);p.add_argument('--mount-namespaces',action='store_true');p.add_argument('--helper-alias',action='store_true');p.add_argument('--sync',action='store_true');p.add_argument('--private-runtime',action='store_true');a=p.parse_args()
if a.helper_alias:a.mount_namespaces=True
assert os.environ['FLOWGATE_PARENT_NETNS']!=os.readlink('/proc/self/ns/net')
RUN=pathlib.Path(a.run).resolve();assert RUN.is_relative_to(ROOT/'.workspace');RUN.mkdir(mode=0o700,parents=True)
source=pathlib.Path(a.prefix_source).resolve();assert source.is_relative_to(ROOT/'.workspace')
for d in ['tmp','scratch','runtime','hidden-scratch','private-runtime']:(RUN/d).mkdir(mode=0o700)
prefixes=[RUN/'prefix-a',RUN/'prefix-b']
for f in prefixes:subprocess.run(['cp','-a','--reflink=auto',str(source),str(f)],check=True)
rt=pathlib.Path(a.runtime_bin).resolve();runner=str(rt/'wine');API=str(RUN/'control.sock');children=[];receivers=[];evidence=[]
baseenv=dict(os.environ,TMPDIR=str(RUN/'tmp'),WINEDEBUG='-all',WINESERVER=str(rt/'wineserver'),DISPLAY='',WAYLAND_DISPLAY='',XDG_CACHE_HOME=str(RUN/'scratch'),XDG_CONFIG_HOME=str(RUN/'scratch'),XDG_DATA_HOME=str(RUN/'scratch'),WINEDLLOVERRIDES='mscoree,mshtml=')
for k in ['FLOWGATE_WINE_TABLE_RUNNER','FLOWGATE_WINE_TABLE_HELPER','FLOWGATE_WINE_BROKER']:baseenv.pop(k,None)
if a.sync:baseenv.update(WINEESYNC='1',WINEFSYNC='1')
anchors=[]
if a.helper_alias:
 (RUN/'observer-alias.exe').write_bytes(b'placeholder')
 (RUN/'decoy.exe').write_bytes(b'not the observer')
 baseenv['XDG_RUNTIME_DIR']=str(RUN/'runtime')
if a.mount_namespaces:
 for prefix in prefixes:
  anchorargs=['sleep','180']
  if a.helper_alias:anchorargs=['sh','-c','mount --bind "$1" "$2"; mount --bind "$3" "$1"; mount --bind "$4" "$5"; mount --bind "$6" "$7"; exec sleep 180','sh',str(ROOT/'.workspace/windows/table-probe.exe'),str(RUN/'observer-alias.exe'),str(RUN/'decoy.exe'),str(RUN/'hidden-scratch'),str(RUN/'scratch'),str(RUN/('private-runtime' if a.private_runtime else 'runtime')),str(RUN/'runtime')]
  anchor=subprocess.Popen(['unshare','--mount','--propagation','private']+anchorargs);anchors.append(anchor);children.append(anchor)
  until=time.monotonic()+3
  while os.readlink('/proc/'+str(anchor.pid)+'/ns/mnt')==os.readlink('/proc/self/ns/mnt'):
   assert time.monotonic()<until and anchor.poll()is None
   time.sleep(.02)
def log(s):print(s,flush=True)
def call(op='list',**q):
 with socket.socket(socket.AF_UNIX)as s:
  s.settimeout(20);s.connect(API);s.sendall((json.dumps(dict(version=1,operation=op,**q))+'\n').encode());return json.loads(s.makefile('rb').readline())
def wait(fn,n=15):
 end=time.monotonic()+n
 while time.monotonic()<end:
  x=fn()
  if x:return x
  time.sleep(.04)
 raise AssertionError('timeout')
def start(name='connect-alpha.exe',prefix=0,duplicate=False,reuse=False,pollfd=False):
 s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('127.0.0.1',0));s.listen();port=s.getsockname()[1];received=[];receivers.append(s)
 def receive():
  try:
   c,_=s.accept();c.settimeout(2);data=c.recv(100);c.close()
   if data:received.append(data.decode())
  except OSError:pass
 threading.Thread(target=receive,daemon=True).start()
 path=RUN/('client-'+str(port)+'.log');f=path.open('w');args=[runner,str(ROOT/'.workspace/windows'/name),str(port)]+(['d']if duplicate else['r']if reuse else['q']if pollfd else[])
 if a.mount_namespaces:args=['/usr/bin/nsenter','--target',str(anchors[prefix].pid),'--mount','--root','--wdns=/','--']+args
 proc=subprocess.Popen(args,env=dict(baseenv,WINEPREFIX=str(prefixes[prefix]),FLOWGATE_FIXTURE_RELEASE='Z:'+str(RUN/'reuse-release')),stdout=f,stderr=f);children.append(proc)
 return dict(process=proc,port=port,received=received,path=path,name=name,prefix=prefix)
def event(c):return next((e for e in call().get('events',[])if e['flow']['remote'].endswith(':'+str(c['port']))),None)
def pending(c):
 e=wait(lambda:event(c));assert e['state']=='awaiting-decision',e
 assert e['attribution']['status']=='corroborated-runtime-table',e
 assert e['attribution']['runtime_table']['windows_handle_holders'][0]['state']==3,e
 assert not c['received'];evidence.append(e);return e
def once(c,action):
 e=pending(c);r=call('decide',generation=call()['generation'],id=e['id'],action=action,scope='once');assert not r.get('error'),r
 if action=='allow':wait(lambda:c['received'])
 else:time.sleep(.25);assert not c['received']
 return e
try:
 f=(RUN/'daemon.log').open('w');daemon=subprocess.Popen([str(pathlib.Path(a.binary).resolve()),'serve-lab','--direction','outgoing','--parent-netns',os.environ['FLOWGATE_PARENT_NETNS'],'--socket',API,'--timeout','30s','--database',str(RUN/'rules.db'),'--observe-prefixes',','.join(map(str,prefixes)),'--runtime-bins',str(rt),'--wine-helper',str(ROOT/'.workspace/windows/table-probe.exe'),'--observer-scratch',str(RUN/'scratch')],env=baseenv,stdout=f,stderr=f);children.append(daemon)
 wait(lambda:pathlib.Path(API).exists())
 c=start();e=once(c,'allow');assert len(e['attribution']['owners'])==1 and e['attribution']['owners'][0]['application']['kind']=='wine-unresolved'
 log('PASS broker-only Linux FD; Windows handle owner+SYN_SENT exact tuple identified before completion; Allow payload reached receiver')
 once(start('connect-beta.exe'),'block');log('PASS independent second executable Deny: receiver empty')
 c=start();e=pending(c);s=call();q=dict(generation=s['generation'],id=e['id'],action='allow',scope='persistent',network_zone='any',zone_revision=s['network_zones']['revision'],remember=dict(address=False,port=False,protocol=False,process=False),duration_seconds=0)
 assert not e['request_rule']['process_lease_available'],e
 pv=call('decision-preview',**q);assert not pv.get('error'),pv
 saved=call('decide',**q,preview_token=pv['decision_preview']['token']);assert not saved.get('error'),saved
 wait(lambda:c['received']);rule=saved['saved_rule'];assert rule['filter']['remote_address']=='*' and not rule['filter'].get('local_port')
 c=start();wait(lambda:c['received']);log('PASS Remember application-only Allow reaches receiver from subsequent Windows instance on a different endpoint')
 once(start('connect-beta.exe'),'block');log('PASS second executable in same prefix does not inherit Remember')
 e=once(start(prefix=1),'block');assert e['attribution']['application']['key']!=rule['filter']['application'];log('PASS same executable in separate prefix has a separate identity and Deny remains empty')
 # Broker's duplicate FD must not revoke an established exact client mapping.
 c=start(prefix=1,pollfd=True);old=pending(c);wait(lambda:'POLLED' in c['path'].read_text())
 raw=subprocess.run([str(pathlib.Path(a.binary).resolve()),'attribute','--protocol','tcp','--direction','outgoing','--local',old['flow']['local'],'--remote',old['flow']['remote']],capture_output=True,text=True);assert raw.returncode==0,raw.stderr
 holders=json.loads(raw.stdout);assert len(holders['owners'])==2,holders
 (RUN/'broker-plus-client.json').write_text(json.dumps(holders,indent=2))
 r=call('decide',generation=call()['generation'],id=old['id'],action='allow',scope='once');assert not r.get('error'),r;wait(lambda:c['received']);log('PASS broker plus exact client hold the same FD; established Windows association survives transfer and Allow reaches receiver')
 # Client exit: the original held cookie cannot be approved after process loss.
 c=start('connect-beta.exe',prefix=1);old=pending(c)
 owners=old['attribution']['runtime_table']['windows_handle_holders'];winimage=owners[0]['image'].replace('\\','/')
 ids=[]
 for pr in pathlib.Path('/proc').iterdir():
  if not pr.name.isdigit():continue
  try:
   cmd=(pr/'cmdline').read_bytes();maps=(pr/'maps').read_text()
   if str(ROOT/'.workspace/windows/connect-beta.exe')in maps and str(c['port']).encode()in cmd:ids.append(int(pr.name))
  except(OSError,UnicodeError):pass
 assert len(ids)==1,ids;os.kill(ids[0],signal.SIGKILL)
 r=call('decide',generation=call()['generation'],id=old['id'],action='allow',scope='once');assert r.get('error')and not c['received'];log('PASS client exit invalidates held approval')
 # Genuine Windows inheritance before connect is visible in the handle census,
 # even when the second process never materializes a Unix socket FD.
 c=start(duplicate=True,prefix=1);shared=wait(lambda:event(c));assert shared['state']=='blocked'and shared['attribution']['status']=='multiple-candidates',shared
 assert len(shared['attribution']['runtime_table']['windows_handle_holders'])==2 and not c['received'];evidence.append(shared);log('PASS dormant inherited Windows handle in distinct executable: genuine ambiguity blocked, receiver empty')
 # Reuse the exact numeric Windows handle and TCP tuple; cookie must change.
 c=start('connect-beta.exe',prefix=1,reuse=True);old=pending(c)
 (RUN/'reuse-release').touch();wait(lambda:'REUSED' in c['path'].read_text())
 def replacement():
  rows=[e for e in call().get('events',[])if e['flow']['remote'].endswith(':'+str(c['port']))and e['id']!=old['id']and e['state']=='awaiting-decision']
  return rows[0]if rows else None
 new=wait(replacement);assert new['attribution']['runtime_table']['socket_cookie']!=old['attribution']['runtime_table']['socket_cookie']
 r=call('decide',generation=call()['generation'],id=old['id'],action='allow',scope='once');assert r.get('error')and not c['received']
 r=call('decide',generation=call()['generation'],id=new['id'],action='allow',scope='once');assert not r.get('error'),r;wait(lambda:c['received']);evidence.extend([old,new]);log('PASS numeric Windows handle and exact TCP tuple reused: new cookie fences stale approval; fresh Allow reaches receiver')
 # Broker lifetime loss invalidates table evidence and cannot reuse its session.
 c=start('connect-beta.exe',prefix=1);old=pending(c);os.kill(old['attribution']['runtime_table']['broker_pid'],signal.SIGKILL)
 r=call('decide',generation=call()['generation'],id=old['id'],action='allow',scope='once');assert r.get('error')and not c['received'];log('PASS broker exit invalidates held approval')
 r=call('rule-delete',generation=call()['generation'],id=rule['id'],expected_version=rule['version']);assert not r.get('error'),r;assert not call().get('rules')
 (RUN/'result.json').write_text(json.dumps(dict(passed=True,runtime=str(rt),mount_namespaces=a.mount_namespaces,helper_alias=a.helper_alias,sync=a.sync,events=evidence,final_rules=0),indent=2));log('PASS final rules0; copied prefixes and private namespaces only')
finally:
 for p in children:
  if p.poll()is None:p.terminate()
 for p in children:
  try:p.wait(3)
  except subprocess.TimeoutExpired:p.kill()
 for s in receivers:s.close()
 log('CLEANED fixture processes; private namespace teardown owns runtime descendants')
