# Real production daemon policy edits, receiver-backed. No shaping confounder.
if mode=='off':
 record('policy-protection-off',result='Not tested',reason='policy revocation/Ask protection is intentionally off; off Deny delivery covered by core')
else:
 import datetime
 configure([],enabled=False)
 a=spawn('alpha','policy-A');open_retry(a,'OPEN 4 0 1 1 0 43001','policy-A')
 c=spawn('gamma','policy-C');open_retry(c,'OPEN 4 0 1 1 0 43001','policy-C')
 ask(a,'SEND policyAwarm 125 8000');ask(c,'SEND policyCwarm 125 8000')
 saved=next(r for r in api()['rules'] if r['id']=='zone-C')
 def edit_C(action,expires=None):
  current=next(r for r in api()['rules'] if r['id']==saved['id']);r=dict(current,action=action)
  r['filter']=dict(current['filter'],remote_address=current['filter'].get('remote_address') or '*')
  if expires is not None:r['expires']=expires
  start=time.monotonic();ack=api('rule-save',generation=GEN,id=r['id'],expected_version=current['version'],rule=r)
  record('policy-edit-ack',action=action,elapsed=time.monotonic()-start,ack=ack)
  return ack
 # Unrelated A continues across C's live Deny edit.
 before=gate();edit_C('block')
 immediate=ask(c,'SEND policyCnow 8 10000');time.sleep(.1);immediate_rx=peerop('stats').get('policyCnow',{}).get('received',0)
 results['policy-Deny-immediate']={'receiver_zero_after_ACK':immediate_rx==0,'nonvacuous':immediate['sent']+immediate['errors']==8}
 record('policy-Deny-immediate',sender=immediate,received=immediate_rx)
 time.sleep(.3)
 write(a,'SEND policyAdeny 375 8000');cs=ask(c,'SEND policyCdeny 125 8000');ar=line(a,10);time.sleep(.3)
 rx=peerop('stats');checks={'edited_deny_receiver':rx.get('policyCdeny',{}).get('received',0)==0,'deny_sender_nonvacuous':cs['sent']+cs['errors']==125,'unrelated_A_delivery':rx.get('policyAdeny',{}).get('received')==375,'fast_continuity':fast()>before.get('fast_packets',0) if mode=='fast' else True}
 results['policy-Deny-unrelated']=checks;record('policy-deny',checks=checks,receiver=rx.get('policyAdeny'),denied_receiver=rx.get('policyCdeny'),before=before,after=gate())
 edit_C('allow');ask(c,'SEND policyRestore 125 8000');time.sleep(.3);rx=peerop('stats').get('policyRestore',{})
 results['policy-restore']={'delivery':rx.get('received',0)>0};record('policy-restore',receiver=rx,gate=gate())
 # Ask must hold/block before a deliberate decision; no lifetime Allow seeded.
 edit_C('ask');sent=ask(c,'SEND policyAsk 8 10000');time.sleep(.15);held=peerop('stats').get('policyAsk',{}).get('received',0)
 state=api();events=state.get('events',[])
 pending=[];until=time.monotonic()+1
 while not pending and time.monotonic()<until:
  state=api();events=state.get('events',[])
  pending=[ev for ev in events if ev.get('attribution',{}).get('application',{}).get('key')==procs['C']['application']['key'] and ev.get('state')=='awaiting-decision']
  if not pending:time.sleep(.05)
 # Event schemas are retained; inability to locate the event is Not tested, not a pass.
 record('policy-ask',sender=sent,received_before_decision=held,events=events,gate=gate())
 results['policy-Ask-holds']={'no_delivery_before_decision':held==0,'nonvacuous':sent['sent']+sent['errors']==8}
 if pending:
  d=api('decide',generation=GEN,id=pending[-1]['id'],action='allow',scope='once');time.sleep(.3);got=peerop('stats').get('policyAsk',{}).get('received',0)
  record('policy-Ask-once',ack=d,received_after_decision=got,gate=gate());results['policy-Ask-once']={'receiver_delivery':got>0}
 else:record('policy-Ask-once',result='Not tested',reason='no matching actionable event in retained API snapshot')
 # Temporary explicit Allow has only its real rule horizon, then must stop.
 expiry=(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(seconds=4)).isoformat().replace('+00:00','Z')
 edit_C('allow',expiry);live=ask(c,'SEND tempLive 125 8000');time.sleep(4);expired=ask(c,'SEND tempExpired 30 10000');time.sleep(.3);rx=peerop('stats')
 checks={'live_delivery':rx.get('tempLive',{}).get('received',0)>0,'expired_no_delivery':rx.get('tempExpired',{}).get('received',0)==0,'expired_sender_nonvacuous':expired['sent']+expired['errors']==30}
 results['policy-temporary-expiry']=checks;record('policy-expiry',expires=expiry,checks=checks,live=live,expired=expired,gate=gate(),receiver_live=rx.get('tempLive'),receiver_expired=rx.get('tempExpired'))
 # Restore original semantics; versions intentionally advance in this isolated test.
 edit_C(saved['action'],saved.get('expires','0001-01-01T00:00:00Z'))
 current=next(r for r in api()['rules'] if r['id']==saved['id'])
 assert dict(current['filter'],remote_address='*')==dict(saved['filter'],remote_address='*') and current['action']==saved['action']
 record('policy-restored',original=saved,current=current,intentional_version_change=True)
 initial_rules=api()['rules']
 stopchild(a);stopchild(c)
