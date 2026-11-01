# Real-collector regression: unrelated misses and final-close tail conservation.
# Permission/enforcement remain the original production session.
configure([],enabled=False)
def until(fn,seconds=15):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  value=fn()
  if value:return value
  time.sleep(.1)
 raise AssertionError('edge sample timeout')
def sample(cookie):
 s=api();r=next((r for r in s.get('activity',{}).get('rows',[]) if r['socket']['cookie']==cookie),None)
 return {'row':r,'monitor':s.get('traffic_monitor'),'usage':api('observed-usage')['observed_usage']}
def measured(cookie):
 s=sample(cookie);return s if s['row'] and s['row'].get('traffic',{}).get('available') else None
def app_bytes(s):return sum(int(e['uploaded']) for e in s['usage']['entries'] if e['source']=='udp-api-reported' and e['application']['key']==procs['A']['application']['key'] and e['uid']==0)
def all_bytes(s):return sum(int(e['uploaded']) for e in s['usage']['entries'] if e['source']=='udp-api-reported')+sum(int(e['uploaded']) for e in s['usage'].get('unattributed',[]) if e['source']=='udp-api-reported')
s=api();api('traffic-start',generation=GEN,collector_generation=s['traffic_monitor'].get('generation',''))
until(lambda:api()['traffic_monitor']['state']=='active')
p=spawn('alpha','accounting-established');info=open_retry(p,'OPEN 4 0 1 1 0 43001','edge-open');cookie=info['sockets'][0]['cookie'];until(lambda:measured(cookie));time.sleep(2)
# Warm grant and both accounting baselines before the measured window.
ask(p,'SEND edgewarm 50 8000');time.sleep(2);before=measured(cookie)
other=spawn('beta','accounting-unregistered');spam=[]
def churn():
 for j in range(12):
  o=ask(other,'OPEN 4 0 1 1 0 43001');r=ask(other,f'SEND unreg{j} 4 0');spam.append({'open':o,'send':r})
t=threading.Thread(target=churn);t.start();sent=ask(p,'SEND edgeknown 250 8000');t.join();time.sleep(3);after=measured(cookie)
expected=sent['sent']*1200;actual=app_bytes(after)-app_bytes(before)
results['unrelated-misses']={'misses_reproduced':after['monitor']['missed_operations']>before['monitor']['missed_operations'],'known_socket_bytes_exact':after['row']['traffic']['uploaded']-before['row']['traffic']['uploaded']==expected,'known_application_bytes_exact':actual==expected}
record('accounting-unrelated-misses',before=before,after=after,known_sender=sent,unregistered_senders=spam,expected=expected,actual_ledger=actual,checks=results['unrelated-misses'])
# No unrelated writes during final-close measurement. This is a new clean
# registered socket, then immediate close before the next one-second sample.
other.terminate();other.wait(10);time.sleep(2)
before=measured(cookie);sent=ask(p,'SEND edgetail 20 0');p.terminate();p.wait(10);time.sleep(3);after=sample(cookie)
# Tail must be conserved, but fresh ownership at close is absent, so assignment
# to this app is not required. Never add authorization hit counts to usage.
expected=sent['sent']*1200;actual=all_bytes(after)-all_bytes(before)
results['close-tail']={'closed_row_absent':after['row'] is None,'conserved_tail_bytes':actual==expected}
results['close-tail']['no_unregistered_operations_in_tail_window']=after['monitor']['missed_operations']==before['monitor']['missed_operations']
record_history=api('usage-history',generation=GEN,history_query={'range':'1h','source':'udp-api-reported'})
record('accounting-close-tail',before=before,after=after,sender=sent,history=record_history,expected=expected,actual_conserved=actual,checks=results['close-tail'])
s=api();api('traffic-stop',generation=GEN,collector_generation=s['traffic_monitor']['generation'])
