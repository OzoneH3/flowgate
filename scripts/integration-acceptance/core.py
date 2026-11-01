# Executed only inside common.run() in a disconnected disposable guest.
from measure import *
mode=os.environ['ACCEPTANCE_MODE']
core=json.loads((P/'spec/matrix-v2.json').read_text())['core']
assert len(core)==144

def cpu(pid):
 v=pathlib.Path('/proc/'+str(pid)+'/stat').read_text().rsplit(')',1)[1].split()
 return (int(v[11])+int(v[12]))/os.sysconf('SC_CLK_TCK')
def gate():return api().get('socket_authorization') or {}
def fast():return gate().get('fast_packets',0)
def stopchild(p):
 if p.poll() is None:p.terminate();p.wait(10)
def tc(dev=DEV):return json.loads(cmd('tc','-s','-j','class','show','dev',dev))
def qd(dev=DEV):return json.loads(cmd('tc','-s','-j','qdisc','show','dev',dev))
def telemetry():
 s=api();sh=status();ifb=((sh.get('kernel') or {}).get('download') or {}).get('interface')
 return {'gate':s.get('socket_authorization'),'queue':s.get('queue_health'),'shaper':sh,'tc':tc(),'qdisc':qd(),'dl_tc':tc(ifb) if ifb else [],'dl_qdisc':qd(ifb) if ifb else []}
def leaf(rows):
 xs=htb_leaf(rows)
 if len(xs)>1:raise MeasurementInconclusive('ambiguous application leaf: '+json.dumps(xs))
 return xs[0] if xs else {}
def pending_qdisc(qs,h):return sum(q.get('backlog',q.get('stats',{}).get('backlog',0)) for q in qs if q.get('parent')==h)
def map_expected_tuple(actual,expected):
 return int(actual.get('ceil',0))*8==expected['ceil_bps'] and int(actual.get('prio',0))==expected['htb_prio']

def loss(sent,got,before,after,expected_leaf):
 missing=max(0,sent.get('sent',0)-got.get('received',0))
 leaf0=leaf(before['tc']);leaf1=leaf(after['tc'])
 drops=max(0,queue_drop(after['qdisc'],leaf1.get('handle'))-queue_drop(before['qdisc'],leaf0.get('handle'))) if expected_leaf else 0
 # Without matching queue drop evidence never label a loss deliberate throttling.
 shaping=min(missing,drops)
 return {'sent_ok':sent.get('sent',0),'sender_errors':sent.get('errors',0),'received':got.get('received',0),'missing':missing,'shaping_queue_drops':shaping,'startup_admission':None,'attribution_failure':None,'unclassified':missing-shaping,'unexplained':missing-shaping,'queue_before':before['queue'],'queue_after':after['queue'],'classification_limit':'admission/attribution counters retained as evidence; no exact flow attribution inferred'}

if mode=='off':
 tables=json.loads(cmd('nft','-j','list','tables'))
 assert not any(x.get('table',{}).get('name')=='flowgate_host' for x in tables.get('nftables',[])),tables
u=spawn('alpha','game');ui=open_retry(u,'OPEN 4 0 1 1 0 43001','game')
v=spawn('beta','other-app');vi=open_retry(v,'OPEN 4 0 1 1 0 43001','other-app')
sent=ask(u,'SEND initialA 125 8000');ask(v,'SEND initialB 125 8000');time.sleep(.5)
record('startup',mode=mode,sender=sent,receiver=peerop('stats').get('initialA',{}),socket=ui)
if mode=='fast':
 until=time.monotonic()+10
 while fast()==0 and time.monotonic()<until:ask(u,'SEND warmA 10 10000')
 assert fast()>0,gate()
 assert gate().get('window_ms')==0 and gate().get('ownership_renewal_required') is False,gate()

cell_rows=[];previous=None
selected=set(os.environ.get('ACCEPTANCE_CELLS','').split(','))-{''}
for idx,cell in enumerate(c for c in core if c['mode']==mode and (not selected or c['id'] in selected)):
 ps=[];out={'id':cell['id'],'expected':cell,'previous_cell':previous,'status':'Not tested'};t0=time.monotonic();checks={};inconclusive=[]
 try:
  e=cell['expected_v2'];lim=cell['limits'];b=cell['budget'];ul=2_000_000 if lim in ('ul','both') else 0;dl=2_000_000 if lim in ('dl','both') else 0;prio=cell['priority']
  caps=[] if not ul and not dl and prio=='normal' else [cap('A',ul,dl,prio='' if prio=='normal' else prio)]
  before_edit=telemetry();cpu0=cpu(backend.pid);r0=resource.getrusage(resource.RUSAGE_SELF)
  # Continuous probe while Applying; the parent never uses this stdin concurrently.
  done=threading.Event();probe=[];probe_error=[]
  def apply_probe():
   j=0
   try:
    while not done.is_set():
     tag='ap%02d_%02d'%(idx,j);t=time.monotonic();s=ask(u,'SEND '+tag+' 250 5000');probe.append({'tag':tag,'sent':s,'start':t,'end':time.monotonic()});j+=1
   except Exception:probe_error.append(traceback.format_exc())
  worker=threading.Thread(target=apply_probe,daemon=True);worker.start()
  editdone=threading.Event();editerr=[];edits=[]
  def edit_config():
   try:edits.append(configure(caps,ub=16_000_000 if b in ('ul','both') else 0,db=16_000_000 if b in ('dl','both') else 0))
   except Exception:editerr.append(traceback.format_exc())
   finally:editdone.set()
  edit_start=time.monotonic();editor=threading.Thread(target=edit_config,daemon=True);editor.start();samples=[]
  while not editdone.is_set():
   samples.append({'at':time.monotonic(),'classes':tc(),'qdisc':qd()});time.sleep(.1)
  applied=time.monotonic()
  while time.monotonic()<applied+1:
   samples.append({'at':time.monotonic(),'after_applied':True,'classes':tc(),'qdisc':qd()});time.sleep(.1)
  done.set();worker.join(5);editor.join()
  if editerr:raise RuntimeError(editerr[0])
  if worker.is_alive() or probe_error:raise RuntimeError('Applying probe failed '+str(probe_error))
  out['applying']={'request_at':edit_start,'applied_at':applied,'seconds':applied-edit_start,'samples':samples,'probe':probe,'gate_before':before_edit['gate'],'gate_after':gate(),'note':'sampling itself perturbs guest; quiet measurements below exclude this interval'}
  # Complete required per-direction binding, no wait if no class is expected.
  bind_start=time.monotonic()
  if e['bindings']['wait_for_upload_class_binding']:wait(lambda s:any(x['app']==appkey('A') and x.get('upload_class') and x.get('cookie')==ui['sockets'][0]['cookie'] for x in bindings(s)),30)
  out['initial_binding_wait_seconds']=time.monotonic()-bind_start
  # Quiet UDP-only window; tc-after is BEFORE PING or other-app traffic.
  qb=telemetry();hb=fast();tag='q%02d'%idx;sent=ask(u,'SEND '+tag+' 75 8000');time.sleep(.3);got=peerop('stats').get(tag,{})
  qa=telemetry()
  drain_until=time.monotonic()+2
  while pending_qdisc(qa['qdisc'],leaf(qa['tc']).get('handle'))>0 and time.monotonic()<drain_until:
   time.sleep(.05);qa=telemetry()
  if pending_qdisc(qa['qdisc'],leaf(qa['tc']).get('handle'))>0:raise MeasurementInconclusive('quiet leaf backlog did not drain')
  ha=fast();l0=leaf(qb['tc']);l1=leaf(qa['tc']);dlt=snapshot_delta(l0,l1)
  out['quiet']={'sender':sent,'receiver':got,'class_delta':dlt,'before':qb,'after':qa,'fast_delta':ha-hb,'loss':loss(sent,got,qb,qa,e['queues']['app_ul_class'])}
  checks['quiet_unexplained_loss']=out['quiet']['loss']['unexplained']==0
  checks['quiet_sender_completed']=sent['sent']+sent['errors']==75
  if e['queues']['app_ul_class']:
   checks['unique_app_leaf']=bool(l1)
   expected_tuple=e['queues']['app_ul_tuple'];checks['app_ul_tuple']=map_expected_tuple(l1,expected_tuple)
   runtime_tuple=((qa['shaper'].get('kernel') or {}).get('traffic_priority') or {}).get('apps',{}).get(appkey('A'),{}).get('upload')
   checks['runtime_ul_tuple_matches_leaf']=[int(l1.get('rate',0))*8,int(l1.get('ceil',0))*8,int(l1.get('prio',0))]==runtime_tuple
   quiet_drops=max(0,queue_drop(qa['qdisc'],l1.get('handle'))-queue_drop(qb['qdisc'],l0.get('handle')))
   checks['same_udp_class_packets']=dlt['packets']==sent['sent']-quiet_drops
   checks['same_udp_class_bytes']=dlt['bytes']==dlt['packets']*(1200+42)
   checks['same_udp_receiver_equals_charged']=got.get('received',0)==dlt['packets']
  else:
   checks['no_app_ul_class']=not l1
   target='fffe' if b in ('ul','both') else 'fff1'
   placement=delta(klass(qb['tc'],target),klass(qa['tc'],target),'packets')
   checks['default_or_bypass_udp_placement']=placement==sent['sent'] if qb['tc'] else True
   out['quiet']['default_or_bypass_delta']=placement
  post=[x for x in samples if x.get('after_applied')]
  if e['queues']['app_ul_class'] and len(post)>1:
   out['applying']['post_applied_bypass_packets']=delta(klass(post[0]['classes'],'fff1'),klass(post[-1]['classes'],'fff1'),'packets')
   out['applying']['bypass_coverage_note']='Applying/version is not binding coverage. Binding awaited after probe; this value is observational only.'
  if mode=='fast':checks['same_udp_fast_hits']=ha-hb>=dlt['packets'] if e['queues']['app_ul_class'] else ha-hb>=sent['sent']
  # Echo is a separate window so it cannot corrupt same-flow charging equality.
  out['quiet_rtt']=ask(u,'PING rtt%02d 30 8000'%idx);checks['echo_delivery']=out['quiet_rtt']['received']==30
  # Other executable must not charge A's leaf.
  neg0=tc();bs=ask(v,'SEND b%02d 30 8000'%idx);time.sleep(.2);neg1=tc()
  checks['cross_app_no_A_charge']=delta(leaf(neg0),leaf(neg1),'packets')==0
  out['cross_app']={'sender':bs,'before':neg0,'after':neg1}
  # Two upload sockets and one established-TCP download socket of A.
  keys=[];upload_cookies=[]
  for j in range(2):
   p=spawn('alpha','upload-%d-%d'%(idx,j));ps.append(p);i=open_retry(p,'OPEN 4 1 1 1 0 43003','upload');keys.append(flowkey('tcp',i));upload_cookies.append(i['sockets'][0]['cookie'])
  d=spawn('alpha','download-%d'%idx);ps.append(d);di=open_retry(d,'OPEN 4 1 1 1 0 43005','download')
  bind_start=time.monotonic()
  if e['bindings']['wait_for_download_class_binding']:wait(lambda s:any(x['app']==appkey('A') and x.get('download_class') and x.get('cookie')==di['sockets'][0]['cookie'] for x in bindings(s)),30)
  if e['bindings']['wait_for_upload_class_binding']:wait(lambda s:all(any(x['app']==appkey('A') and x.get('upload_class') and x.get('cookie')==cookie for x in bindings(s)) for cookie in upload_cookies),30)
  out['dl_and_bulk_binding_wait_seconds']=time.monotonic()-bind_start
  for p in ps[:2]:write(p,'BULK load 1000000 65536 0')
  ask(d,'DRAIN 2000');windows=[]
  for win in range(2):
   ss0=time.monotonic();first=peerop('bulk');ss1=time.monotonic();tb=time.monotonic();w0=telemetry();recvq=ask(d,'RECVQ')['recvq_bytes'];tag='bulk%02d_%d'%(idx,win)
   begin=time.monotonic();write(u,'SEND '+tag+' 375 8000');dr=ask(d,'DRAIN 3000');us=line(u,10);ss2=time.monotonic();last=peerop('bulk');ss3=time.monotonic();w1=telemetry();te=time.monotonic();ug=peerop('stats').get(tag,{})
   tcpbytes=sum(last.get(k,{}).get('bytes',0)-first.get(k,{}).get('bytes',0) for k in keys);payload=tcpbytes+ug.get('bytes',0);elapsed=ss3-ss0
   a0=leaf(w0['tc']);a1=leaf(w1['tc']);dl0=leaf(w0['dl_tc']);dl1=leaf(w1['dl_tc'])
   checks_win={};bound_inputs={}
   # Bounding timestamps encompass the entire counter acquisition, no arbitrary multiplier.
   for direction,rate,rows0,rows1,qs,app0,app1,recv,payloadbytes in [('ul',ul,w0['tc'],w1['tc'],w0['qdisc'],a0,a1,sum(first.get(k,{}).get('recvq_bytes',0) for k in keys),payload),('dl',dl,w0['dl_tc'],w1['dl_tc'],w0['dl_qdisc'],dl0,dl1,recvq,dr['bytes'])]:
    if rate:
     backlog=pending_qdisc(qs,app0.get('handle'));burst=app0.get('burst',0);cburst=app0.get('cburst',0);upper=payload_bound(rate,elapsed,burst,backlog,65536,recv);charged=charged_bound(rate,te-tb,burst,cburst)
     valid_payload=payloadbytes<=delta(app0,app1,'bytes')+backlog+recv
     if not valid_payload:inconclusive.append(direction+' payload exceeds charged+backlog+RecvQ: sampling mismatch')
     checks_win[direction+'_payload_cap']=(payloadbytes<=upper) if valid_payload else None;checks_win[direction+'_charged_cap']=delta(app0,app1,'bytes')<=charged
     bound_inputs[direction]={'rate_bps':rate,'T_max':elapsed,'rpc0':ss1-ss0,'rpc1':ss3-ss2,'burst':burst,'cburst':cburst,'backlog0':backlog,'recvq0':recv,'max_skb':65536,'payload_bytes':payloadbytes,'payload_bound_bytes':upper,'charged_bytes':delta(app0,app1,'bytes'),'charged_interval':te-tb,'charged_bound_bytes':charged}
   for direction,active,rs0,rs1 in [('ul',b in ('ul','both'),w0['tc'],w1['tc']),('dl',b in ('dl','both'),w0['dl_tc'],w1['dl_tc'])]:
    if active:
     c0=klass(rs0,'fff0');c1=klass(rs1,'fff0');bound=charged_bound(16_000_000,te-tb,c0.get('burst',0),c0.get('cburst',0));checks_win[direction+'_budget_charge']=delta(c0,c1,'bytes')<=bound
   taxonomy=loss(us,ug,w0,w1,e['queues']['app_ul_class'])
   if taxonomy['missing']:
    taxonomy['shaping_drop_possible_upper_bound']=taxonomy['shaping_queue_drops'];taxonomy['shaping_queue_drops']=None;taxonomy['unclassified']=taxonomy['missing']
    inconclusive.append('mixed TCP/UDP leaf drops cannot attribute exact UDP loss; raw class/qdisc/queue deltas retained')
   windows.append({'window':win,'seconds':elapsed,'tcp_ul_payload_bytes':tcpbytes,'combined_ul_payload_mbps':payload*8/elapsed/1e6,'tcp_dl_payload_mbps':dr['bytes']*8e3/dr['elapsed_ns'],'udp_receiver':ug,'udp_sender':us,'download_receiver':dr,'bounds':bound_inputs,'checks':checks_win,'loss':taxonomy,'before':w0,'after':w1})
   checks.update({str(win)+'_'+k:v for k,v in checks_win.items()})
  out['windows']=windows;out['deny']=deny_check('cell%02d'%idx)
  g1=gate();checks['fast_continuity']=fast()>ha if mode=='fast' else not bool(g1.get('route_bound'))
  if mode=='fast':
   checks['shaping_edit_no_grant_close']=(out['applying']['gate_after'] or {}).get('closed_connections')==(before_edit['gate'] or {}).get('closed_connections')
  r1=resource.getrusage(resource.RUSAGE_SELF);out['daemon_cpu_seconds']=cpu(backend.pid)-cpu0;out['driver_cpu_seconds']=r1.ru_utime+r1.ru_stime-r0.ru_utime-r0.ru_stime
  out['inconclusive_reasons']=inconclusive;out['checks']=checks;out['status']='Fail' if not all(v for v in checks.values() if v is not None) else 'Inconclusive' if inconclusive else 'Pass'
 except MeasurementInconclusive:out['status']='Inconclusive';out['error']=traceback.format_exc()
 except Exception:out['status']='Fail';out['error']=traceback.format_exc()
 finally:
  for p in ps:stopchild(p)
  out['elapsed_seconds']=time.monotonic()-t0;cell_rows.append(out);(R/'core-results.json').write_text(json.dumps(cell_rows,indent=2));print('CELL '+out['id']+' '+out['status']+' '+json.dumps({'error':out.get('error'),'failed':[k for k,v in out.get('checks',{}).items() if not v]}),flush=True);previous=cell['id']
stopchild(u);stopchild(v)
results['core']={x['id']:x['status']=='Pass' for x in cell_rows}
