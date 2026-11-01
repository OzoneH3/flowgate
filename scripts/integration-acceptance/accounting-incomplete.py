# Deterministic TEST-ONLY observer fault: real byte collector and receivers run
# normally; only Activity completeness is changed by the diagnostic Go overlay.
configure([],enabled=False)
def until(fn,seconds=15):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  v=fn()
  if v:return v
  time.sleep(.1)
 raise AssertionError('incomplete observation timeout')
def snapshot(cookie):
 s=api();return {'activity':s['activity'],'usage':api('observed-usage')['observed_usage'],'monitor':s['traffic_monitor'],'row':next((r for r in s['activity'].get('rows',[]) if r['socket']['cookie']==cookie),None)}
def total(s):return sum(int(x['uploaded']) for x in s['usage']['entries'] if x['source']=='udp-api-reported')+sum(int(x['uploaded']) for x in s['usage'].get('unattributed',[]) if x['source']=='udp-api-reported')
def assigned(s):return sum(int(x['uploaded']) for x in s['usage']['entries'] if x['source']=='udp-api-reported')
s=api();api('traffic-start',generation=GEN,collector_generation=s['traffic_monitor'].get('generation',''));until(lambda:api()['traffic_monitor']['state']=='active')
u=spawn('alpha','incomplete-accounting');i=open_retry(u,'OPEN 4 0 1 1 0 43001','incomplete-open');cookie=i['sockets'][0]['cookie']
def measured():
 x=snapshot(cookie);return x if x['row'] and x['row'].get('traffic',{}).get('available') else None
until(measured)
ask(u,'SEND incwarm 50 8000');time.sleep(2)
marker=R/'force-incomplete';marker.write_text('TEST OBSERVER FAULT ONLY')
until(lambda:not api()['activity']['complete']);before=snapshot(cookie)
sent=ask(u,'SEND incwindow 250 8000');time.sleep(3);after=snapshot(cookie);got=peerop('stats').get('incwindow',{})
expected=sent['sent']*1200
checks={'fault_observed':not before['activity']['complete'] and not after['activity']['complete'],'socket_api_bytes':after['row']['traffic']['uploaded']-before['row']['traffic']['uploaded']==expected,'all_usage_conserved':total(after)-total(before)==expected,'no_unverified_owner_assignment':assigned(after)==assigned(before),'no_receiver_loss':got.get('received')==sent['sent']}
results['incomplete-registered-usage']=checks;record('incomplete-registered-usage',before=before,after=after,sender=sent,receiver=got,expected=expected,actual_conserved=total(after)-total(before),checks=checks)
marker.unlink();u.terminate();u.wait(10)
s=api();api('traffic-stop',generation=GEN,collector_generation=s['traffic_monitor']['generation'])
