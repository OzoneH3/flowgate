# Combined candidate: existing C UDP fast grant/class survives A/B rebinding.
from measure import *
mode=os.environ['ACCEPTANCE_MODE']
def stopchild(p):
 if p.poll() is None:p.terminate();p.wait(10)
def tc():return json.loads(cmd('tc','-s','-j','class','show','dev',DEV))
def c_leaf():
 rows=[r for r in htb_leaf(tc()) if int(r.get('ceil',0))*8==8_000_000]
 assert len(rows)==1,rows
 return rows[0]
C=cap('C',ul=8_000_000,dl=2_000_000)
configure([C],ub=16_000_000,db=16_000_000)
u=spawn('gamma','rebind-unrelated-game');ui=open_retry(u,'OPEN 4 0 1 1 0 43001','rebind-C');cookie=ui['sockets'][0]['cookie'];ask(u,'SEND rebindCwarm 125 8000')
wait(lambda s:any(b.get('cookie')==cookie and b.get('upload_class') and b.get('covered') for b in bindings(s)),60);time.sleep(2)
gate_before=api().get('socket_authorization') or {};c0=c_leaf();version0=status()['version'];binding0=next(b for b in bindings() if b.get('cookie')==cookie);stream=[];stream_end=[];transition_end=[]
def game_stream():
 for j in range(6):stream.append(ask(u,f'SEND rebindC{j} 1250 8000'))
 stream_end.append(time.monotonic())
thread=threading.Thread(target=game_stream);thread.start()
end=time.monotonic()+5
while not peerop('stats').get('rebindC0',{}).get('received'):
 assert time.monotonic()<end,'control stream never started';time.sleep(.05)
first_edit_ns=time.monotonic_ns()
configure([C,cap('A',prio='low'),cap('B',prio='high')],ub=16_000_000,db=16_000_000)
active=[];cookies={}
for name in ('A','B'):
 cookies[name]={'upload':set(),'download':set()}
 for j in range(4):
  p=spawn(EXE[name],f'rebind-{name}-ul-{j}');active.append(p);info=open_retry(p,'OPEN 4 1 1 1 0 43003','rebind-ul');cookies[name]['upload'].add(info['sockets'][0]['cookie']);write(p,'BULK rebind 120000 65536 0')
 p=spawn(EXE[name],f'rebind-{name}-dl');active.append(p);info=open_retry(p,'OPEN 4 1 4 1 0 43005','rebind-dl');cookies[name]['download']={s['cookie'] for s in info['sockets']}
def covered(s):return all(all(any(b.get('cookie')==cookie and b.get(d+'_class') and b.get('covered') for b in bindings(s)) for cookie in cookies[n][d]) for n in ('A','B') for d in ('upload','download'))
wait(covered,60)
for phase,caps in [('remove',[C]),('readd',[C,cap('A',prio='low'),cap('B',prio='high')])]:
 begin=time.monotonic();applied=configure(caps,ub=16_000_000,db=16_000_000);ack=time.monotonic();s=wait(covered,60) if phase=='readd' else applied
 record('rebind-continuity-transition',phase=phase,edit_to_ack=ack-begin,edit_to_coverage=time.monotonic()-begin,status=s,C_settings=next(x for x in s['configured_caps'] if x['application']==C['application']))
 assert next(x for x in s['configured_caps'] if x['application']==C['application'])==C
transition_end.append(time.monotonic());thread.join(90);time.sleep(.3);c1=c_leaf();gate_after=api().get('socket_authorization') or {};rx=peerop('stats');received=[rx.get('rebindC'+str(j),{}) for j in range(6)]
binding1=next(b for b in bindings() if b.get('cookie')==cookie)
checks={'stream_spans_all_edits':bool(stream_end) and stream_end[0]>transition_end[0] and received[0]['first_ns']<first_edit_ns and received[-1]['last_ns']>int(transition_end[0]*1e9),'C_binding_not_replaced':binding1.get('bound_at')==binding0.get('bound_at'),'no_new_fast_grant':gate_after.get('published')==gate_before.get('published'),'C_settings_preserved':next(c for c in status()['configured_caps'] if c['application']==C['application'])==C,'C_leaf_not_recreated':c0['handle']==c1['handle'] and stat(c1,'bytes')>=stat(c0,'bytes'),'C_upload_coverage_every_datagram':delta(c0,c1,'packets')==sum(x['sent'] for x in stream),'C_byte_units_exact':delta(c0,c1,'bytes')==sum(x['sent'] for x in stream)*1242,'C_delivery':all(g.get('received')==s['sent']==1250 for s,g in zip(stream,received)),'C_no_reorder':all(g.get('reordered')==0 for g in received),'fast_remains_lifetime':gate_after.get('ownership_renewal_required') is False and gate_after.get('window_ms')==0 and gate_after.get('fast_packets',0)-gate_before.get('fast_packets',0)==7500,'no_gate_failure':not gate_after.get('failure') and not gate_after.get('handoff_failed')}
results['rebind-unrelated-game']=checks;record('rebind-unrelated-game',checks=checks,first_edit_ns=first_edit_ns,last_coverage_ns=int(transition_end[0]*1e9),cookie=cookie,binding_before=binding0,binding_after=binding1,sender=stream,receiver=received,class_before=c0,class_after=c1,gate_before=gate_before,gate_after=gate_after,scope='C UDP upload class + independent saved download setting; UDP download not supported or claimed')
stopchild(u)
for p in active:stopchild(p)
