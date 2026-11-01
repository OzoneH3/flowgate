# Real UDP collector + production daemon; separate syscall/socket/ledger/delivery evidence.
# Executed only by accounting-stage.py inside the disconnected guest.
mode=os.environ['ACCEPTANCE_MODE']
def until(fn,seconds=15):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  value=fn()
  if value:return value
  time.sleep(.2)
 raise AssertionError('accounting sample timeout')
def socket_sample(cookie):
 state=api();row=next((r for r in state.get('activity',{}).get('rows',[]) if r['socket']['cookie']==cookie),None)
 return {'row':row,'monitor':state.get('traffic_monitor'),'usage':api('observed-usage').get('observed_usage'),'history':api('usage-history',generation=GEN,history_query={'range':'1h','source':'udp-api-reported'}).get('usage_history')}
def measured(cookie):
 sample=socket_sample(cookie)
 return sample if sample['row'] and sample['row'].get('traffic',{}).get('available') else None
configure([],enabled=False)
initial=api();start=api('traffic-start',generation=GEN,collector_generation=initial['traffic_monitor'].get('generation',''))
record('accounting-start',response=start)
until(lambda:api()['traffic_monitor']['state']=='active')
h=api('usage-history',generation=GEN,history_query={'range':'1h','source':'udp-api-reported'})['usage_history']
api('usage-history-configure',generation=GEN,history_options={'enabled':True,'retention_days':7,'expected_revision':h['settings']['revision']})
time.sleep(31)  # first real periodic checkpoint establishes history baseline
for fam in (4,6):
 p=spawn('alpha',f'accounting-{fam}');info=open_retry(p,f'OPEN {fam} 0 1 1 0 43001','accounting-open');cookie=info['sockets'][0]['cookie']
 before=until(lambda:measured(cookie));time.sleep(2);before=measured(cookie)
 # SEND records syscall results, receiver reports actual delivery independently.
 fast_before=(api().get('socket_authorization') or {}).get('fast_packets',0)
 tag='acct'+str(fam);sent=ask(p,f'SEND {tag} 125 8000');time.sleep(2)
 echo=ask(p,f'PING rttacct{fam} 125 8000 1200');time.sleep(2)
 after=until(lambda:measured(cookie));rx=peerop('stats').get(tag,{})
 up=after['row']['traffic']['uploaded']-before['row']['traffic']['uploaded']
 expected=(sent['sent']+echo['sent']-echo['send_errors'])*1200
 downloaded=after['row']['traffic']['downloaded']-before['row']['traffic']['downloaded']
 actual=api()['activity']['processes'][after['row']['owners'][0]]
 def ledger_up(sample):return sum(int(e['uploaded']) for e in sample['usage']['entries'] if e['application']['key']==procs['A']['application']['key'] and e['uid']==0 and e['source']=='udp-api-reported')
 checks={'successful_api_upload_bytes':up==expected,'download_api_bytes':downloaded==echo['received']*1200,'exact_application':actual['application']['key']==procs['A']['application']['key'] and actual['uid']==0,'ledger_upload_bytes':ledger_up(after)-ledger_up(before)==expected}
 results['accounting-socket-'+str(fam)]=checks
 record('accounting-transfer',family=fam,cookie=cookie,syscalls=sent,echo=echo,fast_delta=(api().get('socket_authorization') or {}).get('fast_packets',0)-fast_before,receiver=rx,before=before,after=after,expected_uploaded=expected,actual_uploaded=up,checks=checks)
 p.terminate();p.wait(10);time.sleep(2)
 time.sleep(31)
 closed=socket_sample(cookie)
 hu=lambda v:sum(int(e['uploaded']) for e in v['history']['entries'] if e['application']['key']==procs['A']['application']['key'] and e['uid']==0)
 results['accounting-close-'+str(fam)]={'retained_ledger_unchanged':ledger_up(closed)==ledger_up(after),'history_matches_observed_delta':hu(closed)-hu(before)==expected}
 record('accounting-after-close',family=fam,cookie=cookie,sample=closed,checks=results['accounting-close-'+str(fam)])
state=api();stopped=api('traffic-stop',generation=GEN,collector_generation=state['traffic_monitor']['generation']);record('accounting-stopped',response=stopped)
