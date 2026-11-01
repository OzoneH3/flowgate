# All + specific scope conjunction and scope deletion, measured with real TCP.
from measure import *
def scope_tc():
 t=time.monotonic();s=status();dev=((s.get('kernel') or {}).get('download') or {}).get('interface')
 return {'begin':t,'status':s,'ul':json.loads(cmd('tc','-s','-j','class','show','dev',DEV)),'dl':json.loads(cmd('tc','-s','-j','class','show','dev',dev)) if dev else [],'end':time.monotonic()}
configure([cap('A',8_000_000,8_000_000),cap('A',4_000_000,4_000_000,scope='local'),cap('A',6_000_000,6_000_000,scope='internet')])
# Same accelerated UDP cookie under the Local child, including scope edits.
qu=spawn('alpha','scope-udp');qi=open_retry(qu,'OPEN 4 0 1 1 0 43001','scope-udp');ask(qu,'SEND scopeWarm 125 8000')
for label,caps,ub,expected_prio in [
 ('overlap',[cap('A',8_000_000,8_000_000),cap('A',4_000_000,4_000_000,scope='local'),cap('A',6_000_000,6_000_000,scope='internet')],0,0),
 ('delete-local',[cap('A',8_000_000,8_000_000),cap('A',6_000_000,6_000_000,scope='internet')],0,0),
 ('explicit-normal',[cap('A',8_000_000,8_000_000,prio='high'),cap('A',4_000_000,4_000_000,prio='normal',scope='local'),cap('A',6_000_000,6_000_000,scope='internet')],16_000_000,1)]:
 configure(caps,ub=ub)
 wait(lambda x:any(b.get('cookie')==qi['sockets'][0]['cookie'] and b.get('upload_class') and b.get('zone')=='local' for b in bindings(x)),30)
 a=scope_tc();minor=a['status']['kernel']['apps'][appkey('A')]['zone_minors']['local'];c0=klass(a['ul'],format(minor,'x'));hits=fast();tag='scopeU'+label[:6]
 sent=ask(qu,'SEND '+tag+' 75 8000');time.sleep(.3);b=scope_tc();c1=klass(b['ul'],format(minor,'x'));rx=peerop('stats').get(tag,{})
 internet_minor=b['status']['kernel']['apps'][appkey('A')]['zone_minors']['internet'];internet_class=klass(b['ul'],format(internet_minor,'x'))
 expected_ceil=8_000_000 if label=='delete-local' else 4_000_000
 checks={'local_expected_ceil':c1.get('ceil',0)*8==expected_ceil,'internet_inherits_High':internet_class.get('prio',0)==0 if label=='explicit-normal' else True,'same_local_child_packets':delta(c0,c1,'packets')==sent['sent'],'same_local_child_bytes':delta(c0,c1,'bytes')==sent['sent']*1242,'receiver_delivery':rx.get('received')==sent['sent'],'child_priority':c1.get('prio',0)==expected_prio,'fast_continuity':fast()-hits>=sent['sent'] if mode=='fast' else True}
 results['scope-UDP-'+label]=checks;record('scope-UDP',label=label,checks=checks,sender=sent,receiver=rx,before=a,after=b,fast_delta=fast()-hits,cookie=qi['sockets'][0]['cookie'],local_minor=minor)
stopchild(qu)
configure([cap('A',8_000_000,8_000_000),cap('A',4_000_000,4_000_000,scope='local'),cap('A',6_000_000,6_000_000,scope='internet')])
active=[];ups={};downs={};ks={};all_ul=[];all_dl=[]
for zone,fam in ZONES.items():
 ups[zone]=[];ks[zone]=[]
 for j in range(2):
  p=spawn('alpha','scope-'+zone+'-ul'+str(j));active.append(p);ups[zone].append(p);i=open_retry(p,f'OPEN {fam} 1 1 1 0 43003','scope-ul');ks[zone].append(flowkey('tcp',i));all_ul.append(i['sockets'][0]['cookie'])
 p=spawn('alpha','scope-'+zone+'-dl');active.append(p);downs[zone]=p;i=open_retry(p,f'OPEN {fam} 1 2 1 0 43005','scope-dl');all_dl.extend(x['cookie'] for x in i['sockets'])
wait(lambda s:all(any(x.get('cookie')==c and x.get('upload_class') for x in bindings(s)) for c in all_ul) and all(any(x.get('cookie')==c and x.get('download_class') for x in bindings(s)) for c in all_dl),60)
for ps in ups.values():
 for p in ps:write(p,'BULK scope 120000 65536 0')
for phase in ('overlap','local-deleted'):
 if phase=='local-deleted':configure([cap('A',8_000_000,8_000_000),cap('A',6_000_000,6_000_000,scope='internet')])
 for p in downs.values():write(p,'DRAIN 2000')
 for p in downs.values():line(p,10)
 for win in range(2):
  a=scope_tc();first=peerop('bulk');recvq={z:ask(p,'RECVQ')['recvq_bytes'] for z,p in downs.items()};begin=time.monotonic()
  for p in downs.values():write(p,'DRAIN 3000')
  got={z:line(p,15) for z,p in downs.items()};last=peerop('bulk');b=scope_tc();seconds=b['end']-a['begin']
  app=(a['status'].get('kernel') or {}).get('apps',{}).get(appkey('A'),{});parent=app['minor'];zone_minors=app.get('zone_minors',{})
  checks={};observed={};inconclusive=[]
  for direction in ('ul','dl'):
   for name,minor,caprate in [('combined',parent,8_000_000),('local',zone_minors['local'],4_000_000 if phase=='overlap' else 8_000_000),('internet',zone_minors['internet'],6_000_000)]:
    c0=klass(a[direction],format(minor,'x'));c1=klass(b[direction],format(minor,'x'));charged=delta(c0,c1,'bytes');actual_ceil=c0.get('ceil',0)*8;checks[direction+'-'+name+'-expected-ceil']=actual_ceil==caprate;bound=charged_bound(actual_ceil,seconds,c0.get('burst',0),c0.get('cburst',0))
    checks[direction+'-'+name+'-charged-ceiling']=charged<=bound
    if name=='combined':
     payload=sum(sum(last.get(k,{}).get('bytes',0)-first.get(k,{}).get('bytes',0) for k in ks[z]) for z in ZONES) if direction=='ul' else sum(g['bytes'] for g in got.values())
    else:payload=sum(last.get(k,{}).get('bytes',0)-first.get(k,{}).get('bytes',0) for k in ks[name]) if direction=='ul' else got[name]['bytes']
    observed[direction+'-'+name]={'class':c0.get('handle'),'charged_bytes':charged,'charged_bound':bound,'receiver_payload_bytes':payload,'payload_mbps':payload*8/seconds/1e6,'T_max':seconds,'burst':c0.get('burst'),'cburst':c0.get('cburst')}
  # Record exact class/receiver coverage; no arbitrary percentage rate band.
  results['scope-'+phase+'-'+str(win)]=checks
  record('scope-window',phase=phase,window=win,checks=checks,observed=observed,before=a,after=b,receiver=got,recvq=recvq,peer_before=first,peer_after=last,synthetic_scope_families=ZONES)
for p in active:stopchild(p)
wait(lambda s:not bindings(s),60)
