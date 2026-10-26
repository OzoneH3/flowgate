# Disposable VM only: segmentation-enabled shaping on a netdevsim NIC pair (TSO/GSO on),
# actual serve API, unchanged firewall ownership rules. Never run in the host namespace.
import os,sys,json,socket,subprocess,time,pathlib,sqlite3,select,traceback
P=pathlib.Path('/work/m1');R=pathlib.Path('/work/.workspace/m1');R.mkdir(mode=0o700,exist_ok=True);API=R/'session'/'api.sock';children=[];records=[];backend=None
assert os.environ.get('FLOWGATE_PARENT_NETNS') and os.environ['FLOWGATE_PARENT_NETNS']!=os.readlink('/proc/self/ns/net')
DEV='fghost'
def cmd(*a):return subprocess.check_output([str(x) for x in a],text=True,timeout=20)
def launch(args,name):
 p=subprocess.Popen([str(x) for x in args],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=(R/(name+'.err')).open('w'),text=True,bufsize=1);children.append(p);return p
def line(p,timeout=25):
 if not select.select([p.stdout],[],[],timeout)[0]:raise RuntimeError('fixture timeout '+str(p.pid))
 s=p.stdout.readline()
 if not s:raise RuntimeError('fixture exited '+str(p.pid))
 return json.loads(s)
def write(p,s):p.stdin.write(s+'\n');p.stdin.flush()
def ask(p,s):write(p,s);return line(p)
def peerop(op):return ask(peer,json.dumps({'op':op}))
def request(op='list',ro=False,lost=False,**kw):
 with socket.socket(socket.AF_UNIX) as s:
  s.settimeout(4);s.connect(str(API)+('.monitor' if ro else ''));s.sendall((json.dumps(dict(version=1,operation=op,**kw))+'\n').encode())
  if lost:return
  return json.loads(s.makefile('rb').readline())
def api(op='list',**kw):
 d=request(op,**kw);assert not d.get('error'),d;return d
GEN=''
def status():return api('upload-status',generation=GEN)['upload_shaping']
def wait(pred,timeout=35):
 until=time.monotonic()+timeout
 while time.monotonic()<until:
  s=status()
  if s['status']=='Unsupported':raise RuntimeError('shaping fault '+json.dumps(s))
  if pred(s):return s
  time.sleep(.3)
 raise RuntimeError('wait timeout '+json.dumps(s))
def configure(caps=None,enabled=True,**kw):
 before=status();r=api('upload-configure',generation=GEN,expected_version=before['version'],upload_config={'enabled':enabled,'caps':caps or []},**kw)['upload_shaping'];assert r['version']==before['version']+1
 return wait(lambda s:s['applied_version']==r['version'])
def cap(name,rate):return {'uid':0,'application':procs[name]['application']['key'],'bits_per_second':rate}
def childpids():
 pids=set()
 for task in pathlib.Path(f'/proc/{backend.pid}/task').glob('*'):
  try:pids.update((task/'children').read_text().split())
  except FileNotFoundError:pass
 result=[]
 for pid in pids:
  try:
   if b'controller.py' in pathlib.Path('/proc/'+pid+'/cmdline').read_bytes():result.append(pid)
  except FileNotFoundError:pass
 return result
def start(name):
 global backend,GEN
 args=[P/'flowgate','serve','--socket',API,'--database',R/'rules.db','--uid','0','--administrator','--allow-protection','--protection-state',R/'protection.json','--evaluation-state',R/'session'/'evaluation','--decision-timeout','2s','--experimental-upload-interface',DEV,'--experimental-upload-helpers',P,'--experimental-upload-state',R/'controller','--experimental-upload-parent-netns',os.environ['FLOWGATE_PARENT_NETNS']]
 backend=launch(args,name)
 for _ in range(200):
  try:
   s=api()
   if s.get('protection',{}).get('state')=='active':GEN=s['generation'];return s
  except (FileNotFoundError,ConnectionRefusedError,AssertionError):pass
  if backend.poll() is not None:raise RuntimeError('daemon exited '+str(backend.returncode))
  time.sleep(.1)
 raise RuntimeError('not ready')
def record(kind,**kw):records.append(dict(kind=kind,**kw));(R/'records.json').write_text(json.dumps(records,indent=2));print(kind,flush=True)
def qdiscs():return json.loads(cmd('tc','-j','qdisc','show','dev',DEV))
def classes_stats():return json.loads(cmd('tc','-s','-j','class','show','dev',DEV))
def qdisc_stats():return json.loads(cmd('tc','-s','-j','qdisc','show','dev',DEV))
def class_bytes(stats,classid):
 for c in stats:
  if c.get('handle')==classid:return c.get('stats',{}).get('bytes',c.get('bytes',0))
 return None
def leaf_stats(stats,minor):
 for q in stats:
  if q.get('kind')=='fq_codel' and q.get('handle')==f'{minor:x}:':return q
 return None
def flowkey(proto,info):
 s=info['sockets'][0];ip='10.79.0.1' if info['family']==4 else 'fd79::1'
 return f"{proto}:{ip}:{s['port']}"
def counters():
 k=status()['kernel'];return k['counters'],k.get('segmentation')
def sample(app_minor):
 cs=classes_stats();qs=qdisc_stats();c,seg=counters();rx=peerop('bulk')
 return {'t':time.monotonic(),'class_bytes':class_bytes(cs,f'{journal_major:x}:{app_minor:x}') if app_minor else None,'leaf':leaf_stats(qs,app_minor) if app_minor else None,'classifier':c,'segmentation':seg,'rx':rx}
def rate_of(a,b,key):
 return (b[key]-a[key])/(b['t']-a['t']) if b['t']>a['t'] else None
def measure(label,sender,bulk,rate,app_minor,rxkey,seconds):
 """Sustained interval: per-second samples of HTB class bytes, classifier/GSO counters, leaf queue stats and receiver bytes."""
 pre=sample(app_minor);write(sender,bulk);samples=[pre];t_end=time.monotonic()+seconds
 while time.monotonic()<t_end:
  time.sleep(1.0);samples.append(sample(app_minor))
 result=line(sender,timeout=30);time.sleep(.5);post=sample(app_minor)
 def rxb(s):return s['rx'].get(rxkey,{}).get('bytes',0)
 steady=[s for s in samples[1:]]  # exclude pre; first interval includes the token burst
 cls=[(steady[i]['class_bytes']-steady[i-1]['class_bytes'])/(steady[i]['t']-steady[i-1]['t']) for i in range(2,len(steady)) if steady[i]['class_bytes'] is not None and steady[i-1]['class_bytes'] is not None]
 rxs=[(rxb(steady[i])-rxb(steady[i-1]))/(steady[i]['t']-steady[i-1]['t']) for i in range(2,len(steady))]
 total_t=post['t']-pre['t']
 out={'label':label,'rate_bps':rate,'seconds':seconds,'sender':result,
  'class_total_bytes':(post['class_bytes']-pre['class_bytes']) if app_minor else None,
  'classifier_total_bytes':post['classifier'][1]['bytes']-pre['classifier'][1]['bytes'],
  'classifier_total_packets':post['classifier'][1]['packets']-pre['classifier'][1]['packets'],
  'receiver_total_bytes':rxb(post)-rxb(pre),'interval_s':total_t,
  'steady_class_bps':sorted(cls)[len(cls)//2]*8 if cls else None,'steady_class_bps_series':[round(x*8) for x in cls],
  'steady_receiver_bps_series':[round(x*8) for x in rxs],
  'gso_superpackets_classified':post['classifier'][2]['packets']-pre['classifier'][2]['packets'],
  'gso_superpacket_bytes_classified':post['classifier'][2]['bytes']-pre['classifier'][2]['bytes'],
  'gso_segments_classified':post['classifier'][4]['packets']-pre['classifier'][4]['packets'],
  'gso_superpackets_unbound':post['classifier'][3]['packets']-pre['classifier'][3]['packets'],
  'leaf_before':pre['leaf'],'leaf_after':post['leaf'],
  'leaf_peak_memory_used':max([s['leaf'].get('memory_used',0) for s in samples+[post] if s['leaf']] or [0]),
  'leaf_peak_backlog':max([s['leaf'].get('backlog',0) for s in samples+[post] if s['leaf']] or [0]),
  'leaf_peak_qlen':max([s['leaf'].get('qlen',0) for s in samples+[post] if s['leaf']] or [0]),
  'leaf_drops':(post['leaf'].get('drops',0)-pre['leaf'].get('drops',0)) if pre['leaf'] and post['leaf'] else None,
  'samples':samples+[post]}
 if rate and app_minor:
  expected=rate/8*total_t
  out['class_accuracy']=out['class_total_bytes']/expected
  out['steady_accuracy']=out['steady_class_bps']/rate if out['steady_class_bps'] else None
  out['allowance_bytes']=65536
 return out
def wrapper_interrupt(match):
 w=R/'interrupt.py'
 w.write_text("import sys,os,types\nsys.path.insert(0,'/work/m1')\nimport controller\nclass Interrupted(controller.Controller):\n def call(self,*args):\n  out=super().call(*args)\n  if args[:%d]==%r: os._exit(77)\n  return out\nInterrupted(types.SimpleNamespace(interface=%r,helpers='/work/m1',state='/work/.workspace/m1/controller',lab_parent_netns=os.environ['FLOWGATE_PARENT_NETNS'],cleanup_only=False))\n"%(len(match),match,DEV))
 r=subprocess.run(['python3','-I',str(w)],capture_output=True,text=True,timeout=30)
 assert r.returncode==77,(r.returncode,r.stdout,r.stderr)
journal_major=None
gates={}
def cpu_ticks():
 out={}
 procs_=[('peer',peer.pid)]+[('sender_'+n,p.pid) for n,p in senders.items()]
 if backend is not None:procs_+=[('daemon',backend.pid)]+[('controller_'+c,int(c)) for c in childpids()]
 for name,pid in procs_:
  try:
   st=pathlib.Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split();out[name]=int(st[11])+int(st[12])
  except (FileNotFoundError,IndexError):pass
 total=pathlib.Path('/proc/stat').read_text().splitlines()[0].split()[1:];out['_all']=sum(int(x) for x in total);out['_idle']=int(total[3])
 return out
def cpu_delta(a,b):return {k:b.get(k,0)-a.get(k,0) for k in set(a)|set(b)}
def efficiency(rx,cpu):
 # payload bytes per CPU tick spent by the bulk sender and the receiver: datapath cost independent of CPU share
 ticks=cpu.get('sender_B',0)+cpu.get('peer',0);return rx['bytes']/ticks if ticks else None
try:
 peer=launch(['unshare','--net','python3',P/'peer.py'],'peer')
 for _ in range(100):
  if os.readlink(f'/proc/{peer.pid}/ns/net')!=os.readlink('/proc/self/ns/net'):break
  time.sleep(.02)
 cmd('ip','link','set','nsim0','name',DEV);cmd('ip','link','set','nsim1','name','fgpeer')
 # Offloads are left exactly as the device reports them: nothing is switched on or off.
 cmd('ip','link','set','fgpeer','netns',peer.pid)
 for a in [('link','set','dev',DEV,'addrgenmode','none'),('link','set',DEV,'up'),('addr','add','10.79.0.1/24','dev',DEV),('-6','addr','add','fd79::1/64','dev',DEV,'nodad')]:cmd('ip',*a)
 peerop('setup')
 original=qdiscs()
 link=json.loads(cmd('ip','-d','-j','link','show','dev',DEV))[0]
 record('nic-capabilities',device=DEV,default_sysctl_exists=pathlib.Path('/proc/sys/net/core/default_qdisc').exists(),link=link,offloads=cmd('ethtool','-k',DEV),qdiscs=original,
  virtio_hub_offloads=cmd('ethtool','-k','eth0'),virtio_hub_link=json.loads(cmd('ip','-d','-j','link','show','dev','eth0'))[0])
 feats={l.split(':')[0].strip():l.split(':',1)[1].strip().split()[0] for l in cmd('ethtool','-k',DEV).splitlines() if ':' in l and not l.startswith('Features')}
 assert feats['tcp-segmentation-offload']=='on' and feats['generic-segmentation-offload']=='on' and feats['scatter-gather']=='on',feats
 assert original[0]['kind']=='fq_codel' and original[0]['handle']=='0:',original
 senders={};procs={}
 for n,exe in [('A','alpha'),('A2','alpha'),('B','beta'),('D','denied')]:
  p=launch([P/exe],n);line(p);senders[n]=p;procs[n]=json.loads(cmd(P/'inspect','inspect',p.pid))
 db=sqlite3.connect(R/'rules.db');db.execute('create table rules(id text primary key,document text not null)');db.execute('pragma user_version=1')
 for n in ['A','B','D']:
  a=procs[n]['application'];rule={'schema':2,'id':'m0-'+n,'version':1,'created':'2026-01-01T00:00:00Z','action':'block' if n=='D' else 'allow','priority':0,'executable':a['executable'],'filter':{'application':a['key'],'revision':a['revision'],'uid':0,'direction':'outgoing','protocol':'*'}};db.execute('insert into rules values(?,?)',(rule['id'],json.dumps(rule)))
 db.commit();db.close();os.chmod(R/'rules.db',0o600)
 (R/'protection.json').write_text('{"schema":1,"mode":"both"}');os.chmod(R/'protection.json',0o600)
 (R/'session').mkdir(mode=0o711)
 # Baseline: unbound bulk through the untouched kernel default root, before any takeover.
 binfo=ask(senders['B'],'OPEN 4 1 1 1 0 43003');bkey=flowkey('tcp',binfo)
 c0=cpu_ticks();bres=ask(senders['B'],'BULK base 4000 65536 0',);time.sleep(.5);c1=cpu_ticks();brx=peerop('bulk')[bkey]
 baseline_bps=brx['bytes']*8/((brx['last']-brx['first'])/1e9);baseline_cpu=cpu_delta(c0,c1);baseline_eff=efficiency(brx,baseline_cpu)
 record('baseline-default-root',sender=bres,receiver=brx,baseline_bps=baseline_bps,cpu_ticks_delta=baseline_cpu,bytes_per_cpu_tick=baseline_eff,clk_tck=os.sysconf('SC_CLK_TCK'))
 ask(senders['B'],'CLOSE')
 start('serve');assert status()['status']=='Disabled';time.sleep(1)
 assert not childpids(),childpids();assert qdiscs()==original
 record('disabled-no-helper-no-tc',status=status())
 # Daemon running, shaping disabled: the firewall's own CPU share on this single vCPU, no shaper objects.
 binfo=ask(senders['B'],'OPEN 4 1 1 1 0 43003');bkey=flowkey('tcp',binfo)
 c0=cpu_ticks();bres=ask(senders['B'],'BULK daemononly 4000 65536 0');time.sleep(.5);c1=cpu_ticks();brx=peerop('bulk')[bkey]
 daemon_only_bps=brx['bytes']*8/((brx['last']-brx['first'])/1e9);dcpu=cpu_delta(c0,c1)
 record('default-traffic-daemon-only',baseline_bps=baseline_bps,daemon_only_bps=daemon_only_bps,ratio=daemon_only_bps/baseline_bps,cpu_ticks_delta=dcpu,bytes_per_cpu_tick=efficiency(brx,dcpu),sender=bres,receiver=brx)
 ask(senders['B'],'CLOSE')
 ainfo=ask(senders['A'],'OPEN 4 1 1 1 0 43003');akey=flowkey('tcp',ainfo)
 s=configure([cap('A',8000000)]);s=wait(lambda s:len(s.get('kernel',{}).get('bindings',[]))==1)
 journal=json.loads((R/'controller'/'owner.json').read_text());journal_major=journal['major']
 compat=s['kernel']['compatibility'];assert compat['supported'] and compat['segmentation']['profile']=='segmentation-capable',compat
 assert compat['segmentation']['gso_max_size']==link['gso_max_size']
 record('takeover-segmentation-capable',status=s,compatibility=compat,qdiscs=qdiscs(),classes=json.loads(cmd('tc','-j','class','show','dev',DEV)))
 def minor_of(name):return status()['kernel']['apps']['0:'+procs[name]['application']['key']]['minor']
 # Sustained cap accuracy with TCP superpackets at three rates.
 results={}
 for rate in (8000000,2000000,32000000):
  configure([cap('A',rate)]);wait(lambda s:len(s['kernel']['bindings'])==1);m=minor_of('A')
  r=measure(f'tcp{rate//1000000}M',senders['A'],f'BULK tcp{rate//1000000} 6000 65536 0',rate,m,akey,6);results[r['label']]=r
  assert r['gso_superpackets_classified']>0 and r['gso_segments_classified']>r['gso_superpackets_classified'],r
  assert r['leaf_after']['maxpacket']>2*1514,r['leaf_after']
  assert 0.85<=r['class_accuracy']<=1.12,(r['label'],r['class_accuracy'])
  assert r['steady_accuracy'] is None or 0.85<=r['steady_accuracy']<=1.10,(r['label'],r['steady_accuracy'])
  # tc JSON on this iproute2 exposes backlog/qlen/drops but no memory_used; backlog is the sampled occupancy.
  assert r['leaf_after']['options']['memory_limit']>=3*65536 and r['leaf_peak_backlog']<=r['leaf_after']['options']['memory_limit'],r['leaf_after']
  record('cap-accuracy',**{k:v for k,v in r.items() if k!='samples'},samples=r['samples'])
 # Explicit UDP_SEGMENT superpackets (64000-byte datagrams, 1400-byte segments) at 8 Mbit/s.
 old={b['cookie'] for b in status()['kernel']['bindings']}
 ask(senders['A'],'CLOSE');uinfo=ask(senders['A'],'OPEN 4 0 1 1 0 43004');ukey=flowkey('udp',uinfo)
 # A connected UDP socket is discovered by the census without traffic; the closed TCP binding is unbound at the next census.
 configure([cap('A',8000000)]);wait(lambda s:len(s['kernel']['bindings'])==1 and s['kernel']['bindings'][0]['cookie'] not in old,timeout=45);m=minor_of('A')
 # FINDING, not a cap-accuracy phase: FlowGate queues every UDP packet to userspace
 # (NFQUEUE without NFQA_CFG_F_GSO), so the kernel segments UDP_SEGMENT superpackets
 # BEFORE the queue and the egress hook only ever sees ordinary segments; the
 # 128-entry queue also bounds the deliverable UDP rate under the single-vCPU guest.
 r=measure('udpseg8M',senders['A'],'BULK udpseg 4000 64000 1400',8000000,m,ukey,4);results['udpseg8M']=r
 assert r['sender']['gso']==1400 and r['sender']['messages']>0 and r['sender']['errors']==0,r['sender']
 assert r['classifier_total_packets']>0 and r['receiver_total_bytes']>0,r
 segment_avg=r['receiver_total_bytes']/max(1,r['classifier_total_packets'])
 record('udp-segment-finding',superpackets_at_hook=r['gso_superpackets_classified'],segments_at_hook=r['classifier_total_packets'],
  classifier_bytes=r['classifier_total_bytes'],class_dequeued_bytes=r['class_total_bytes'],receiver_bytes=r['receiver_total_bytes'],
  sender=r['sender'],interval_s=r['interval_s'],avg_bytes_per_hook_packet=segment_avg,leaf_maxpacket_after=r['leaf_after']['maxpacket'],
  steady_class_bps_series=r['steady_class_bps_series'],steady_receiver_bps_series=r['steady_receiver_bps_series'],
  queue_flags='nfqueue Conntrack only; no GSO passthrough (internal/queue/queue.go)',samples=r['samples'])
 # Independent low-rate application stays responsive while the bulk application is saturating its cap.
 ask(senders['A'],'CLOSE');ainfo=ask(senders['A'],'OPEN 4 1 1 1 0 43003');akey=flowkey('tcp',ainfo)
 ask(senders['B'],'OPEN 4 1 1 1 0');configure([cap('A',8000000),cap('B',1000000)]);wait(lambda s:len(s['kernel']['bindings'])==2 and len(s['kernel']['apps'])==2,timeout=45)
 write(senders['A'],'BULK bulklow 5000 65536 0');time.sleep(.8);bsend=ask(senders['B'],'SEND lowrate 100 20000');ares=line(senders['A'],timeout=30);time.sleep(.5)
 st=peerop('stats')['lowrate'];brx=peerop('bulk')[akey]
 assert st['received']==100,st;assert st['p95_ms']<300,st
 record('low-rate-responsive',low=st,bulk_sender=ares,bulk_receiver=brx,status=status())
 # Unbound default traffic through our HTB default class versus the pre-takeover baseline.
 # The guest has ONE TCG vCPU: uncapped throughput is CPU-bound, so per-process CPU is
 # recorded to separate scheduler cost from competing userspace (senders, controller).
 configure([cap('A',8000000)]);wait(lambda s:len(s['kernel']['bindings'])==1)
 # (a) capped application idle: measures the HTB/clsact path plus controller housekeeping only.
 binfo=ask(senders['B'],'OPEN 4 1 1 1 0 43003');bkey=flowkey('tcp',binfo)
 c0=cpu_ticks();bres=ask(senders['B'],'BULK deflt 4000 65536 0');time.sleep(.5);c1=cpu_ticks()
 brx=peerop('bulk')[bkey];default_bps=brx['bytes']*8/((brx['last']-brx['first'])/1e9);c,seg=counters();ecpu=cpu_delta(c0,c1);eff=efficiency(brx,ecpu)
 ratio=default_bps/baseline_bps;eff_ratio=eff/baseline_eff if eff and baseline_eff else None
 record('default-traffic-no-regression',baseline_bps=baseline_bps,default_bps=default_bps,ratio=ratio,bytes_per_cpu_tick=eff,baseline_bytes_per_cpu_tick=baseline_eff,datapath_efficiency_ratio=eff_ratio,sender=bres,receiver=brx,unbound_superpackets=seg,default_leaf=leaf_stats(qdisc_stats(),0xfffe),cpu_ticks_delta=ecpu,clk_tck=os.sysconf('SC_CLK_TCK'))
 ask(senders['B'],'CLOSE')
 # (b) with the capped application transmitting concurrently (informational: shares the single vCPU).
 binfo=ask(senders['B'],'OPEN 4 1 1 1 0 43003');bkey=flowkey('tcp',binfo)
 c0=cpu_ticks();write(senders['A'],'BULK bulkbg 5000 65536 0');time.sleep(.5);bres2=ask(senders['B'],'BULK deflt2 4000 65536 0');ares=line(senders['A'],timeout=30);time.sleep(.5);c1=cpu_ticks()
 brx2=peerop('bulk')[bkey];concurrent_bps=brx2['bytes']*8/((brx2['last']-brx2['first'])/1e9)
 record('default-traffic-with-concurrent-cap',baseline_bps=baseline_bps,default_bps=concurrent_bps,ratio=concurrent_bps/baseline_bps,sender=bres2,capped_sender=ares,receiver=brx2,cpu_ticks_delta=cpu_delta(c0,c1),clk_tck=os.sysconf('SC_CLK_TCK'))
 ask(senders['B'],'CLOSE')
 # Gate: raw throughput of unbound traffic with shaping enabled versus the matched control
 # (daemon running, shaping disabled, identical workload). Non-fatal so the remaining phases
 # still execute; the verdict is recorded and must be reported as-is. CPU figures are diagnostics.
 gate_ratio=default_bps/daemon_only_bps
 gates['default-traffic']={'verdict':'PASS' if gate_ratio>=0.9 else 'FAILED','ratio_vs_matched_control':gate_ratio,'ratio_vs_pre_daemon_baseline':ratio,'enabled_bps':default_bps,'matched_control_bps':daemon_only_bps,'baseline_bps':baseline_bps}
 record('gate-default-traffic',**gates['default-traffic'])
 # Live cap change and removal during a transfer; receiver rate follows each step.
 m=minor_of('A');pre=sample(m);write(senders['A'],'BULK live 8000 65536 0');series=[pre]
 for i in range(8):
  time.sleep(1.0)
  if i==2:configure([cap('A',32000000)])
  if i==5:configure([])
  series.append(sample(m))
 ares=line(senders['A'],timeout=30)
 def rxbytes(s):return s['rx'].get(akey,{}).get('bytes',0)
 rx=[round((rxbytes(series[i])-rxbytes(series[i-1]))*8/(series[i]['t']-series[i-1]['t'])) for i in range(1,len(series))]
 # Sampling on the TCG guest takes longer than 1 s per round, so the 8 s transfer can end before the
 # last samples: judge the post-removal step by the best post-removal second, not a fixed index.
 assert 0.8*8e6<=rx[1]<=1.25*8e6,rx;assert 0.8*32e6<=rx[4]<=1.3*32e6,rx;assert max(rx[5:])>1.3*rx[4],rx
 record('live-change-and-removal',receiver_bps_series=rx,sender=ares,status=status())
 # Firewall Deny is independent of shaping: a capped denied application delivers nothing.
 configure([cap('A',8000000),cap('D',8000000)]);dinfo=ask(senders['D'],'OPEN 4 0 1 1 0 43004');dkey=flowkey('udp',dinfo)
 dres=ask(senders['D'],'BULK denied 1000 1400 0');time.sleep(.5)
 assert dkey not in peerop('bulk'),peerop('bulk')
 record('firewall-deny-independent',sender=dres,status=status())
 configure([],False);assert qdiscs()==original and not childpids()
 record('clean-disable-restored',qdiscs=qdiscs())
 binfo=ask(senders['B'],'OPEN 4 1 1 1 0 43003');bkey=flowkey('tcp',binfo)
 c0=cpu_ticks();bres=ask(senders['B'],'BULK daemononly2 4000 65536 0');time.sleep(.5);c1=cpu_ticks();brx=peerop('bulk')[bkey]
 control2_bps=brx['bytes']*8/((brx['last']-brx['first'])/1e9)
 record('default-traffic-daemon-only-after',daemon_only_after_bps=control2_bps,daemon_only_before_bps=daemon_only_bps,enabled_bps=default_bps,ratio_enabled_vs_after=default_bps/control2_bps,cpu_ticks_delta=cpu_delta(c0,c1),sender=bres,receiver=brx)
 gates['default-traffic']['matched_control_after_bps']=control2_bps;gates['default-traffic']['ratio_vs_matched_control_after']=default_bps/control2_bps
 ask(senders['B'],'CLOSE')
 # Recovery branch 1: crash exactly after the default class add, before its journal save.
 wrapper_interrupt(('tc','class','add'))
 journal=json.loads((R/'controller'/'owner.json').read_text())
 assert journal['pending_setup'] and journal['setup_step'][0:2]==['class','add'],journal
 assert any(c.get('handle')==f"{journal['major']:x}:fffe" for c in json.loads(cmd('tc','-j','class','show','dev',DEV)))
 backend.terminate();backend.wait(25);start('class-interrupted-restart')
 assert status()['status']=='Unsupported'
 configure([],False)
 assert qdiscs()==original and not (R/'controller'/'owner.json').exists() and not childpids()
 record('interrupted-class-add-restored',journal=journal,qdiscs=qdiscs(),status=status())
 # Recovery branch 2: previous-boot journal whose recorded original differs from the restored default (MTU 1400 quantum).
 stale=dict(journal,boot_id='previous-test-boot',netns='net:[1]',ifindex=99999,pending_setup=False,setup_step=None)
 stale['original']=json.loads(json.dumps(original));stale['original'][0]['options']['quantum']=1414
 (R/'controller'/'owner.json').write_text(json.dumps(stale));os.chmod(R/'controller'/'owner.json',0o600)
 backend.terminate();backend.wait(25);start('stale-boot-changed-default-restart')
 assert status()['status']=='Unsupported' and not childpids()
 configure([],False)
 assert not (R/'controller'/'owner.json').exists() and qdiscs()==original
 record('previous-boot-changed-default-forgotten',status=status(),qdiscs=qdiscs())
 configure([cap('A',8000000)]);wait(lambda s:len(s['kernel']['bindings'])==1);configure([],False)
 assert qdiscs()==original and api()['protection']['state']=='active' and not childpids()
 record('final-cleanup-firewall-active',rules=len(api()['rules']),qdiscs=qdiscs())
 verdict='SEGMENTATION_PASS' if all(g['verdict']=='PASS' for g in gates.values()) else 'SEGMENTATION_PARTIAL_GATE_FAILED'
 record('gates',gates=gates,verdict=verdict)
 (R/'success.json').write_text(json.dumps({'result':verdict,'gates':gates}));print('INTEGRATION_PROOF_COMPLETE',flush=True)
except BaseException:
 (R/'failure.txt').write_text(traceback.format_exc());print(traceback.format_exc(),flush=True);raise
finally:
 if backend and backend.poll() is None:
  backend.terminate()
  try:backend.wait(25)
  except subprocess.TimeoutExpired:backend.kill()
 for p in reversed(children):
  if p.poll() is None:p.terminate()
