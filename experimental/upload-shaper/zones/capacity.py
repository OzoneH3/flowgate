# Additional checkpoint only: run1 already measured caps + same-app priority.
B=40_000_000
population=[]
for n in ('A','B','C','E'):
 population.extend([cap(n,prio='normal',scope='local'),cap(n,prio='normal',scope='internet')])
configure(population,ub=B,db=B)
holders=[]
for n in ('A','B','C','E'):
 for z,fam in ZONES.items():
  h=spawn(EXE[n],'population-'+n+'-'+z);open_retry(h,f'OPEN {fam} 1 1 1 0 43003',n+'-'+z);holders.append(h)
def instantiated(s):
 apps=((s.get('kernel') or {}).get('traffic_priority') or {}).get('apps') or {}
 return sum(1 for v in apps.values() if v.get('upload') and v.get('download'))
wait(lambda s:instantiated(s)==4 and len(bindings(s))==8,60)
samples=[];stop_sample=threading.Event()
def sample():
 pin=json.loads((R/'controller'/'owner.json').read_text())['pin']
 while not stop_sample.is_set():
  try:
   health=json.loads(cmd(P/'kernel','health',pin));now=time.monotonic_ns();remaining=[(row['until']-now)//1000000 for row in health['bindings']]
   samples.append({'config_ms':(health['config_until']-now)//1000000,'min_binding_ms':min(remaining,default=-1),'bindings':len(remaining)})
  except Exception as e:samples.append({'error':str(e)})
  time.sleep(.25)
before=status();thread=threading.Thread(target=sample,daemon=True);thread.start();time.sleep(.5)
edited=[]
for n in ('A','B','C','E'):edited.extend([cap(n,prio='high',scope='local'),cap(n,prio='low',scope='internet')])
t=time.monotonic();after=configure(edited,ub=32_000_000,db=36_000_000);elapsed=time.monotonic()-t
wait(lambda s:instantiated(s)==4 and len(bindings(s))==8,60);time.sleep(1);stop_sample.set();thread.join()
k=after.get('kernel') or {}
results['capacity-leases']={'four_zoned_apps':instantiated(after)==4,'eight_bindings':len(bindings(after))==8,'sampled_live':bool(samples) and all(not x.get('error') and x['config_ms']>0 and x['min_binding_ms']>0 and x['bindings']==8 for x in samples),'completion_gap_under_lease':(k.get('max_completion_gap_ms') or 0)<5000}
record('capacity-leases',apply_seconds=elapsed,checks=results['capacity-leases'],samples=samples,before=before,after=after,classes=json.loads(cmd('tc','-s','-j','class','show','dev',DEV)),kernel={key:k.get(key) for key in ('max_maintenance_pass_ms','max_completion_gap_ms','max_renewal_span_ms')})
for h in holders:h.terminate();h.wait()
wait(lambda s:not bindings(s),60)
# Cross-app zone priorities are observed, not asserted to give strict global
# ordering: parent All-network allocations remain a separate hierarchy level.
configure([cap('A',prio='high',scope='local'),cap('B',prio='low',scope='internet')],ub=B,db=B)
ups={};downs={};keys={};active=[]
for n,z,fam in [('A','local',4),('B','internet',6)]:
 u=spawn(EXE[n],'cross-ul-'+n);info=open_retry(u,f'OPEN {fam} 1 1 1 0 43003',n);ups[n]=u;keys[n]=flowkey('tcp',info);active.append(u)
 d=spawn(EXE[n],'cross-dl-'+n);open_retry(d,f'OPEN {fam} 1 1 1 0 43005',n);downs[n]=d;active.append(d)
wait(lambda s:len(bindings(s))==4,60)
for u in ups.values():write(u,'BULK cross 60000 65536 0')
def crosswindow():
 for d in downs.values():write(d,'DRAIN 3000')
 for d in downs.values():line(d)
 a=peerop('bulk');t=time.monotonic()
 for d in downs.values():write(d,'DRAIN 8000')
 got={n:line(d,25) for n,d in downs.items()};b=peerop('bulk');elapsed=time.monotonic()-t;out={}
 for n in ups:
  out['ul:'+n]=round((b.get(keys[n],{}).get('bytes',0)-a.get(keys[n],{}).get('bytes',0))*8/elapsed/1e6,3)
  out['dl:'+n]=round(got[n]['bytes']*8e3/got[n]['elapsed_ns'],3)
 return out
first=crosswindow();configure([cap('A',prio='low',scope='local'),cap('B',prio='high',scope='internet')],ub=B,db=B);second=crosswindow()
checks={d:28<=first[d+':A']+first[d+':B']<=44 and 28<=second[d+':A']+second[d+':B']<=44 for d in ('ul','dl')};results['cross-app-budget']=checks
record('cross-app-priority-observation',first=first,after_swap=second,checks=checks,contract='best effort leaf borrowing within unchanged parent allocations; no strict global ordering claim',snapshot=status(),deny=deny_check('cross'))
for h in active:h.terminate();h.wait()
wait(lambda s:not bindings(s),60)
