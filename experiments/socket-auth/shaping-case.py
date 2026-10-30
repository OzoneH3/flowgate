# Executed in the disposable guest's common harness only.
def daemon_cpu():
 row=pathlib.Path('/proc/'+str(backend.pid)+'/stat').read_text().rsplit(')',1)[1].split()
 return (int(row[11])+int(row[12]))/os.sysconf('SC_CLK_TCK')
cpu_start=daemon_cpu();elapsed_start=time.monotonic()
gated = os.environ.get('FLOWGATE_COEXIST_GATE') == '1'
def gate(): return api().get('socket_authorization') or {}
def fast(): return gate().get('fast_packets', 0)
def health():
 pin=json.loads((R/'controller'/'owner.json').read_text())['pin']
 return json.loads(cmd(P/'kernel','health',pin))
def classes(): return json.loads(cmd('tc','-s','-j','class','show','dev',DEV))
def waitfast(before):
 if not gated: return
 until=time.monotonic()+10
 while time.monotonic()<until:
  if fast()>before: return
  time.sleep(.1)
 raise AssertionError(('no production fast hits',gate()))
def newudp(name,port):
 p=spawn('alpha' if name=='A' else 'beta','udp-'+name+'-'+str(port))
 info=open_retry(p,'OPEN 4 0 1 1 0 '+str(port),'udp-'+name)
 return p,info

a,ai=newudp('A',43001)
configure([cap('A',2_000_000,2_000_000)])
# Real StartSession + UploadShaping acceptance, not merely a model check.
if gated:
 assert gate().get('route_bound'), gate()
 assert not gate().get('failure'),gate()
for i in range(5): ask(a,'SEND warm 40 5000')
wait(lambda s:any(b['app']==appkey('A') for b in bindings(s)))
hits=fast();ask(a,'SEND warmed 100 5000');waitfast(hits)
# Below-cap delay/loss reported separately from deliberate saturation.
for i in range(3):
 tag='paced'+str(i);hits=fast();sent=ask(a,'SEND '+tag+' 200 10000');time.sleep(.5)
 got=peerop('stats').get(tag,{})
 record('paced-udp',gated=gated,offered=200,sender=sent,receiver=got,missing=200-got.get('received',0),gate=gate())
 assert got.get('received')==200,(sent,got)
 waitfast(hits)
a.terminate();a.wait(10)
wait(lambda s:not bindings(s),30)

# Same socket throughout cap edit: no new socket or queued Offer required.
a,ai=newudp('A',43004);key=flowkey('udp',ai)
ask(a,'BULK warm 1000 1200 0')
wait(lambda s:any(b['app']==appkey('A') for b in bindings(s)))
def ulwindow(label,seconds=5):
 first=peerop('bulk').get(key,{}).get('bytes',0);start=time.monotonic()
 time.sleep(seconds)
 last=peerop('bulk').get(key,{}).get('bytes',0)
 return {'label':label,'mbps':(last-first)*8/(time.monotonic()-start)/1e6}
hits=fast();write(a,'BULK caplive 25000 1200 0');time.sleep(2);waitfast(hits)
first=ulwindow('2mbps');before=health();before_gate=gate();begin=time.monotonic()
configure([cap('A',1_000_000,2_000_000,prio='high')])
applied=time.monotonic()-begin;after=health();time.sleep(2);second=ulwindow('1mbps')
record('live-cap-edit',sample_count=1,observed_apply_seconds=applied,first=first,second=second,before=before,after=after,classes=classes(),gate_before=before_gate,gate_after=gate())
assert .9<=first['mbps']<=2.3 and .45<=second['mbps']<=1.2,(first,second)
assert second['mbps']<first['mbps']*.8,(first,second)
line(a,30);a.terminate();a.wait(10);wait(lambda s:not bindings(s),30)

# Existing DL support is established native TCP only. Keep a simultaneous
# accelerated UDP stream active while testing that unchanged TCP download path.
u,ui=newudp('A',43001)
ask(u,'SEND dlwarm 100 5000')
d=spawn('alpha','download-tcp')
open_retry(d,'OPEN 4 1 1 1 0 43005','download-tcp')
wait(lambda s:any(b['app']==appkey('A') and b.get('download_class') for b in bindings(s)),30)
hits=fast();write(u,'SEND dlside 1200 10000')
ask(d,'DRAIN 3000');got=ask(d,'DRAIN 6000');rate=got['bytes']*8e3/got['elapsed_ns']
waitfast(hits)
record('download-tcp-with-udp',mbps=rate,receiver=got,snapshot=status(),health=health(),gate=gate(),scope='TCP DL only; UDP DL remains explicitly uncovered by retained shaper')
assert .9<=rate<=2.3,rate
line(u,20);u.terminate();u.wait(10);d.terminate();d.wait(10);wait(lambda s:not bindings(s),30)

# Two native TCP executables compete under the minimum supported 16M budget;
# accelerated UDP remains active. This preserves existing priority coverage.
def priority_window(high):
 configure([cap('A',prio='high' if high=='A' else 'low'),cap('B',prio='high' if high=='B' else 'low')],ub=16_000_000)
 ps={};ks={}
 for n in ('A','B'):
  ps[n]=spawn('alpha' if n=='A' else 'beta','priority-'+n)
  info=open_retry(ps[n],'OPEN 4 1 1 1 0 43003','priority-'+n);ks[n]=flowkey('tcp',info)
  ask(ps[n],'BULK warm 500 65536 0')
 wait(lambda s:all(any(b['app']==appkey(n) for b in bindings(s)) for n in ('A','B')),40)
 u,ui=newudp('A',43001);ask(u,'SEND priowarm 60 5000');hits=fast();write(u,'SEND prioside 1400 10000')
 for p in ps.values():write(p,'BULK prio 12000 65536 0')
 time.sleep(3);before=peerop('bulk');begin=time.monotonic();time.sleep(5);after=peerop('bulk');elapsed=time.monotonic()-begin
 rates={n:(after.get(ks[n],{}).get('bytes',0)-before.get(ks[n],{}).get('bytes',0))*8/elapsed/1e6 for n in ps}
 record('priority-tcp-with-udp',scope='TCP competing flows plus simultaneous accelerated UDP; kernel bindings captured',high=high,rates=rates,health=health(),gate=gate())
 waitfast(hits)
 for p in ps.values():line(p,20);p.terminate();p.wait(10)
 line(u,20);u.terminate();u.wait(10)
 wait(lambda s:not bindings(s),30)
 return rates
p1=priority_window('A');p2=priority_window('B')
assert p1['A']>p1['B']*1.5 and p2['B']>p2['A']*1.5,(p1,p2)
record('negative-app',received=deny_check('coexist'))
# Preserve source accounting evidence separately; never add BPF hits to usage.
record('cpu',daemon_cpu_seconds=daemon_cpu()-cpu_start,elapsed_seconds=time.monotonic()-elapsed_start,scope='entire coexistence fixture; not gaming CPU or latency')
record('accounting-snapshot',api=api(),bpf_authorization_diagnostics_only=gate())
results['coexistence']={'paced_delivery':True,'live_cap':True,'existing_tcp_download':True,'priority':True,'separate_deny':True}
