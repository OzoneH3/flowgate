# Actual syscall-return accounting under intentional Deny, qdisc drops, restart.
from measure import *
def until(fn,seconds=60):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  v=fn()
  if v:return v
  time.sleep(.1)
 raise AssertionError('usage semantics timeout')
def sample(cookie):
 s=api();return {'row':next((r for r in s['activity']['rows'] if r['socket']['cookie']==cookie),None),'usage':api('observed-usage')['observed_usage'],'monitor':s['traffic_monitor'],'gate':s.get('socket_authorization')}
def measured(cookie):
 s=sample(cookie);return s if s['row'] and s['row'].get('traffic',{}).get('available') else None
def settled(cookie):
 previous=sample(cookie);stable=0
 for _ in range(120):
  time.sleep(.2);current=sample(cookie)
  if current['usage']['sequence']!=previous['usage']['sequence']:
   stable=stable+1 if total(current)==total(previous) else 0
   previous=current
   if stable>=2:return current
 raise AssertionError('ledger did not settle over distinct observation cycles')
def total(s):return sum(int(e['uploaded']) for e in s['usage']['entries']+s['usage'].get('unattributed',[]) if e['source']=='udp-api-reported')
configure([],enabled=False);s=api();api('traffic-start',generation=GEN,collector_generation=s['traffic_monitor'].get('generation',''));until(lambda:api()['traffic_monitor']['state']=='active')
for label,exe in [('allowed','alpha'),('denied','denied')]:
 p=spawn(exe,'usage-'+label);i=open_retry(p,'OPEN 4 0 1 1 0 43001','usage-'+label);cookie=i['sockets'][0]['cookie'];until(lambda:measured(cookie));time.sleep(2)
 before=sample(cookie);sent=ask(p,'SEND s'+label+' 125 8000');time.sleep(2);after=settled(cookie);rx=peerop('stats').get('s'+label,{})
 expected=sent['successful_return_bytes'];actual=after['row']['traffic']['uploaded']-before['row']['traffic']['uploaded']
 checks={'nonvacuous':sent['sent']+sent['errors']==125,'counter_matches_successful_returns':actual==expected,'usage_conserved':total(after)-total(before)==expected,'firewall_outcome':rx.get('received',0)==(125 if label=='allowed' or os.environ['ACCEPTANCE_MODE']=='off' else 0)}
 results['usage-syscall-'+label]=checks;record('usage-syscall',label=label,syscalls=sent,receiver=rx,before=before,after=after,expected=expected,actual_socket_bytes=actual,checks=checks)
 if label=='allowed':u=p;ucookie=cookie
 else:p.terminate();p.wait(10)
# One registered socket remains authorized while its leaf deliberately throttles.
configure([cap('A',ul=2_000_000)]);until(lambda:any(b.get('cookie')==ucookie and b.get('upload_class') for b in bindings()))
time.sleep(2);before=sample(ucookie);q0=json.loads(cmd('tc','-s','-j','qdisc','show','dev',DEV));sent=ask(u,'SEND semanticscap 3000 0');time.sleep(4)
until(lambda:all(q.get('backlog',q.get('stats',{}).get('backlog',0))==0 for q in json.loads(cmd('tc','-s','-j','qdisc','show','dev',DEV))))
after=settled(ucookie);q1=json.loads(cmd('tc','-s','-j','qdisc','show','dev',DEV));rx=peerop('stats').get('semanticscap',{})
expected=sent['successful_return_bytes'];actual=after['row']['traffic']['uploaded']-before['row']['traffic']['uploaded'];drops=sum(int(x.get('drops',0)) for x in q1)-sum(int(x.get('drops',0)) for x in q0)
checks={'socket_counts_success_not_delivery':actual==expected,'usage_conserved':total(after)-total(before)==expected,'qdisc_drop_case_exercised':0<rx.get('received',0)<sent['sent'] and drops>=sent['sent']-rx.get('received',0)}
results['usage-qdisc-drops']=checks;record('usage-qdisc-drops',syscalls=sent,receiver=rx,qdisc_drop_delta=drops,before=before,after=after,expected=expected,actual_socket_bytes=actual,checks=checks)
configure([],enabled=False)
# A new collector generation never replays the old socket lifetime.
before_stop=sample(ucookie);total_before_stop=total(before_stop);gaps_before_stop=int(before_stop['usage']['gaps']);s=api();old=s['traffic_monitor']['generation'];api('traffic-stop',generation=GEN,collector_generation=old);s=api();api('traffic-start',generation=GEN,collector_generation=s['traffic_monitor']['generation']);until(lambda:api()['traffic_monitor']['state']=='active');until(lambda:measured(ucookie));time.sleep(2);before=sample(ucookie)
sent=ask(u,'SEND semanticsrestart 125 8000');time.sleep(2);after=settled(ucookie)
checks={'generation_changed':after['monitor']['generation']!=old,'no_lifetime_replay':total(after)-total(before)==sent['successful_return_bytes'],'restart_conservation':total(after)-total_before_stop==sent['successful_return_bytes'],'generation_gap_explicit':int(after['usage']['gaps'])>gaps_before_stop,'socket_delta_exact':after['row']['traffic']['uploaded']-before['row']['traffic']['uploaded']==sent['successful_return_bytes']}
results['usage-generation']=checks;record('usage-generation',before_stop=before_stop,before=before,after=after,syscalls=sent,checks=checks)
u.terminate();u.wait(10);s=api();api('traffic-stop',generation=GEN,collector_generation=s['traffic_monitor']['generation'])
