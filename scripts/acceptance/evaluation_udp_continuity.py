"""Focused kernel continuity check, called only by the isolated UDP harness."""
import json,os,socket,subprocess,threading,time,uuid

def route_snapshot():
 # Preserve every route field; canonicalize only JSON representation/order.
 return [sorted(json.loads(subprocess.check_output(['ip',family,'-j','route','show','table','all'],text=True)),key=lambda r:json.dumps(r,sort_keys=True))for family in ['-4','-6']]

def settle_ipv6(wait):
 # Bringing the veth up starts kernel link-local DAD asynchronously. Its local
 # route appears only on completion; that setup is not an evaluation mutation.
 def ready():
  links=json.loads(subprocess.check_output(['ip','-6','-j','addr','show'],text=True))
  info=[a for link in links for a in link['addr_info']]
  assert not any('dadfailed'in a.get('flags',[])or a.get('dadfailed',False)for a in info),info
  return any(a.get('scope')=='link'for a in info)and not any('tentative'in a.get('flags',[])or a.get('tentative',False)for a in info)
 wait(ready)

def check(g):
 api,wait,run,root=g['api'],g['wait'],g['run'],g['root']
 peer=None;receivers=[];done=threading.Event();worker=None;errors=[];states=[];lock=threading.Lock()
 def cmd(*args):return subprocess.check_output(args,text=True)
 def remote(**q):
  peer.stdin.write(json.dumps(q)+'\n');peer.stdin.flush();v=json.loads(peer.stdout.readline());assert 'error'not in v,v;return v
 def rows():return {r['socket']['cookie']:r for r in api()['activity']['rows']}
 def stable():
  v=api();assert v['generation']==generation and v['traffic_monitor']['generation']==collector
  assert v['traffic_monitor']['state']=='active'and g['native_pid']()==helper
  now=rows()
  for k in cookies:
   assert now[k]['id']==baseline[k]['id'] and now[k]['traffic']['since']==baseline[k]['traffic']['since'],(k,now[k],baseline[k])
   assert now[k]['traffic']['uploaded']>=baseline[k]['traffic']['uploaded']
  return now
 def progress(previous):
  now=stable()
  return now if all(now[k]['traffic']['uploaded']+now[k]['traffic']['downloaded']>previous[k]['traffic']['uploaded']+previous[k]['traffic']['downloaded']for k in cookies)else None
 def normalized_rules():
  v=json.loads(cmd('nft','-j','list','ruleset'))
  def clean(x):
   if isinstance(x,dict):return {k:clean(v)for k,v in x.items()if k not in ('metainfo','handle','packets','bytes')}
   if isinstance(x,list):return [clean(v)for v in x if 'metainfo'not in v]
   return x
  return clean(v)
 try:
  peer=subprocess.Popen(['unshare','--net','python3',str(root/'scripts/acceptance/host-peer.py'),str(run)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
  wait(lambda:os.readlink(f'/proc/{peer.pid}/ns/net')!=os.readlink('/proc/self/ns/net'))
  cmd('ip','link','add','fghost','type','veth','peer','name','fgpeer');cmd('ip','link','set','fgpeer','netns',str(peer.pid));cmd('ip','link','set','fghost','up');cmd('ip','addr','add','10.79.0.1/24','dev','fghost');cmd('ip','-6','addr','add','fd79::1/64','dev','fghost','nodad');remote(op='setup')
  settle_ipv6(wait)
  original=normalized_rules();routes=route_snapshot()
  (run/'routes-before.json').write_text(json.dumps(routes,indent=2))
  counts={44001:0,44003:0}
  def receive(s,port):
   while not done.is_set():
    try:s.recvfrom(4096);counts[port]+=1
    except socket.timeout:continue
    except OSError:return
  for port in counts:
   s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('10.79.0.1',port));s.settimeout(.2);receivers.append(s);threading.Thread(target=receive,args=(s,port),daemon=True).start()
  initial=api();generation=initial['generation'];rules=initial.get('rules',[])
  reply=g['mutate']('traffic-start');assert not reply.get('error'),reply
  def active():
   v=api()['traffic_monitor']
   assert v['state']!='failed',v
   return v if v['state']=='active'else None
  active=wait(active);collector=active['generation'];helper=g['native_pid']()
  held=[]
  for family in ['4','6']:
   f,state=g['fixture'](family);wait(lambda:g['measured'](state));state=g['transfer'](f);g['verify'](state);held.append(f);states.append(state)
  cookies=[k for state in states for k in state['cookies']];baseline=rows();phases={'before':{k:baseline[k]for k in cookies}}
  def traffic():
   try:
    while not done.wait(.35):
     for i,f in enumerate(held):
      v=g['transfer'](f)
      with lock:states[i]=v
   except Exception as e:errors.append(repr(e));done.set()
  worker=threading.Thread(target=traffic,daemon=True);worker.start()
  old=api()['evaluation'];r=api('evaluation-start',generation=generation,evaluation_id=old['id'],request_id=uuid.uuid4().hex,profile='incoming');assert not r.get('error'),r
  def evaluating():
   v=api()['evaluation'];assert v['state']not in ('failed','degraded'),v
   return v if v['state']=='active'else None
  evaluation=wait(evaluating);phases['active']=wait(lambda:progress(baseline))
  decisions=[]
  for port,action in [(44001,'allow'),(44003,'block')]:
   remote(op='udp',port=port)
   def pending():return next((v for v in api().get('events',[])if v['state']=='awaiting-decision'and v['flow']['local'].endswith(':'+str(port))),None)
   event=wait(pending);assert counts[port]==0
   response=api('decide',id=event['id'],action=action,scope='once');assert not response.get('error'),response;decisions.append(event['id'])
   if action=='allow':wait(lambda:counts[port]==1)
   else:time.sleep(.3);assert counts[port]==0
  r=api('evaluation-stop',generation=generation,evaluation_id=evaluation['id']);assert not r.get('error'),r
  wait(lambda:api()['evaluation']['state']=='stopped'and api()['evaluation']['cleanup']=='confirmed')
  phases['stopped']=wait(lambda:progress(phases['active']))
  g['client'].sendall(b'continuity');assert g['accepted'].recv(10)==b'continuity';wait(g['tcp_present'])
  # Match the actual log API; no records are injected and verdict != delivery.
  def recorded():
   page=api('decision-log');assert not page.get('error'),page
   records=page['decision_log']['records']
   return page if all(any(r.get('request_id')==request and r.get('kind')=='final'and r.get('decision',{}).get('action')==action and r.get('evaluation_id')==evaluation['id'] for r in records)for request,action in zip(decisions,['allow','block']))else None
  log=wait(recorded)
  assert api().get('rules',[])==rules and api()['enforcement']['state']=='stopped'
  done.set();worker.join(5);assert not worker.is_alive()and not errors,errors
  for state in states:g['verify'](state)
  final=stable();assert normalized_rules()==original
  assert not log['decision_log']['health']['recording'],log['decision_log']['health']
  after_routes=route_snapshot()
  (run/'routes-after.json').write_text(json.dumps(after_routes,indent=2))
  (run/'continuity.json').write_text(json.dumps(dict(daemon_generation=generation,collector_generation=collector,helper_pid=helper,evaluation=evaluation,receiver_counts=counts,fixture_totals=states,phases={name:{k:dict(id=row['id'],traffic=row['traffic'])for k,row in values.items()if k in cookies}for name,values in phases.items()},final={k:final[k]['traffic']for k in cookies},traffic_monitor=api()['traffic_monitor'],decision_log=log,owned_cleanup=True,routes_unchanged=after_routes==routes),indent=2))
  assert after_routes==routes, f'Routes changed; inspect {run}/routes-{{before,after}}.json and continuity.json'
  g['log']('PASS real BPF UDP4/6 connected/unconnected counters advance before/during/after evaluation; stable cookie IDs, observed-since baselines, helper and collector generation; exact final socket API byte totals')
  g['log']('PASS incoming Allow receiver1 / Block receiver0; TCP exchange and Decision Log available; Stop removes only owned interception, foreign rules/routes unchanged; host untouched')
  g['log']('EVIDENCE '+str(run))
 finally:
  done.set()
  if worker:worker.join(5)
  for s in receivers:s.close()
  if peer and peer.poll()is None:peer.terminate();peer.wait(4)
