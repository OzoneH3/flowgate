# Included by extensions.py inside its guest harness.
from measure import *
def tc(dev=DEV):return json.loads(cmd('tc','-s','-j','class','show','dev',dev))
def tc_snapshot():
 begin=time.monotonic();s=status();ifb=((s.get('kernel') or {}).get('download') or {}).get('interface')
 out={'time':begin,'upload':tc(),'download':tc(ifb) if ifb else [],'status':s};out['end']=time.monotonic();return out
def stopchild(p):
 if p.poll() is None:p.terminate();p.wait(10)

def budget_checks(a,b):
 out={}
 for dr in ('upload','download'):
  c0=klass(a[dr],'fff0');c1=klass(b[dr],'fff0')
  out[dr]=delta(c0,c1,'bytes')<=charged_bound(16_000_000,b['end']-a['time'],c0.get('burst',0),c0.get('cburst',0))
 return out

def saturated(a,b,direction):
 c0=klass(a[direction],'fff0');c1=klass(b[direction],'fff0');seconds=b['end']-a['time']
 return delta(c0,c1,'bytes')*8/seconds>=.9*16_000_000 and delta(c0,c1,'overlimits')>0

# P1: unchanged continuously-backlogged senders; four actual sockets/app/direction.
configure([cap('A',prio='low'),cap('B',prio='high')],ub=16_000_000,db=16_000_000)
ups={};downs={};keys={};dlcookies={};ulcookies={};active=[]
for n in ('A','B'):
 ups[n]=[];keys[n]=[];ulcookies[n]=set()
 for j in range(4):
  u=spawn(EXE[n],f'p1-{n}-ul-{j}');active.append(u);ups[n].append(u);i=open_retry(u,'OPEN 4 1 1 1 0 43003','p1-ul');keys[n].append(flowkey('tcp',i));ulcookies[n].add(i['sockets'][0]['cookie'])
 d=spawn(EXE[n],f'p1-{n}-dl');active.append(d);downs[n]=d;di=open_retry(d,'OPEN 4 1 4 1 0 43005','p1-dl');dlcookies[n]={x['cookie'] for x in di['sockets']}
wait(lambda s:all(all(any(x['app']==appkey(n) and x.get('download_class') and x.get('cookie')==cookie for x in bindings(s)) for cookie in dlcookies[n]) for n in ('A','B')),60)
for us in ups.values():
 for u in us:write(u,'BULK priority 240000 65536 0')
p1_ms=int(os.environ.get('ACCEPTANCE_P1_WINDOW_MS','4000'));assert p1_ms in (4000,8000)
shares={}
for phase in ('A-low','A-high','normal-control','A-low-repeat'):
 cfg=[] if phase=='normal-control' else [cap('A',prio='low' if phase in ('A-low','A-low-repeat') else 'high'),cap('B',prio='high' if phase in ('A-low','A-low-repeat') else 'low')]
 configure(cfg,ub=16_000_000,db=16_000_000)
 binding_start=time.monotonic()
 try:
  if phase!='normal-control':
   wait(lambda s:all(all(any(x['app']==appkey(n) and x.get('upload_class') and x.get('cookie')==cookie for x in bindings(s)) for cookie in ulcookies[n]) and all(any(x['app']==appkey(n) and x.get('download_class') and x.get('cookie')==cookie for x in bindings(s)) for cookie in dlcookies[n]) for n in ('A','B')),60)
  else:
   wait(lambda s:not any(x.get('upload_class') or x.get('download_class') for x in bindings(s)),60)
 except RuntimeError as exc:
  if 'wait timeout' not in str(exc):raise
  shares[phase]=[];results['P1-binding-'+phase]={'result':'Inconclusive'}
  record('P1-phase-binding',phase=phase,result='Inconclusive',reason='binding timeout',seconds=time.monotonic()-binding_start,status=status())
  continue
 record('P1-phase-binding',phase=phase,seconds=time.monotonic()-binding_start,status=status(),upload_cookies={k:sorted(v) for k,v in ulcookies.items()},download_cookies={k:sorted(v) for k,v in dlcookies.items()})
 for d in downs.values():write(d,'DRAIN 2000')
 for d in downs.values():line(d)
 windows=[]
 for win in range(2):
  a=tc_snapshot();before=peerop('bulk');start=time.monotonic()
  for d in downs.values():write(d,'DRAIN '+str(p1_ms))
  got={n:line(d,20) for n,d in downs.items()};after=peerop('bulk');elapsed=time.monotonic()-start;b=tc_snapshot()
  ul={n:sum(after.get(k,{}).get('bytes',0)-before.get(k,{}).get('bytes',0) for k in keys[n])*8/elapsed/1e6 for n in ('A','B')}
  dl={n:g['bytes']*8e3/g['elapsed_ns'] for n,g in got.items()}
  checks=budget_checks(a,b)
  windows.append({'ul_payload_mbps':ul,'dl_payload_mbps':dl,'checks':checks,'before':a,'after':b,'receiver':got,'saturation':{dr:saturated(a,b,dr) for dr in ('upload','download')},'priority_effect':'assessed after repeated swap/control by SPEC v2.1'})
  results['P1-'+phase+'-'+str(win)]=checks
 shares[phase]=windows;record('P1-priority',phase=phase,windows=windows,normal_control='both unconfigured; shared fffe default class' if phase=='normal-control' else None,offered='4 continuously backlogged TCP sockets/app/direction; no cap; identical offered workload across swaps')
from priority_assess import assess,assess_game
for direction in ('upload','download'):
 assessment=assess(shares,direction) if all(len(shares.get(p,[]))==2 for p in ('A-low','A-high','normal-control','A-low-repeat')) else {'result':'Inconclusive','reason':'phase binding timeout'};record('P1-effect',direction=direction,**assessment);results['P1-effect-'+direction]={'result':assessment['result']}
for p in active:stopchild(p)
wait(lambda s:not bindings(s),60)

if os.environ.get('ACCEPTANCE_P1_ONLY')!='1':
 # P2: small game datagrams, 64 bytes x125pps =64 kbit/s payload; bulk OTHER app.
 u=spawn('gamma','p2-game');open_retry(u,'OPEN 4 0 1 1 0 43001','p2-game')
 bulk=spawn('beta','p2-bulk');open_retry(bulk,'OPEN 4 1 1 1 0 43003','p2-bulk')
 ask(u,'SEND p2warm 125 8000');write(bulk,'BULK p2 240000 65536 0')
 p2={}
 for repeat in range(3):
  for phase in ('reference','normal','game-high','game-low'):
   cfg=[] if phase in ('reference','normal') else [cap('C',prio='high' if phase=='game-high' else 'low'),cap('B',prio='low' if phase=='game-high' else 'high')]
   configure(cfg,ub=0 if phase=='reference' else 16_000_000)
   time.sleep(2);a=tc_snapshot();before_fast=fast();rtt=ask(u,'PING rttp2%02d%s 500 8000 64'%(repeat,phase[:3]));b=tc_snapshot()
   value={'repeat':repeat,'phase':phase,'echo_rtt':rtt,'before':a,'after':b,'fast_delta':fast()-before_fast,'payload_offer_kbps':64,'actual_elapsed_ns':rtt['elapsed_ns'],'saturated':saturated(a,b,'upload') if phase!='reference' else False,'loss':{'sent':rtt['sent'],'received':rtt['received'],'sender_errors':rtt['send_errors'],'unclassified':rtt['sent']-rtt['send_errors']-rtt['received'],'scope':'echo loss has no exact drop-site attribution; not silently shaping loss'}}
   p2.setdefault(phase,[]).append(value);record('P2-game',**value)
   results['P2-'+str(repeat)+'-'+phase]={'delivery':rtt['received']==rtt['sent']-rtt['send_errors'],'fast_used':fast()>before_fast if mode=='fast' else True}
 # Report variance; don't pretend a tiny difference proves a priority benefit.
 normal=[x['echo_rtt']['p95_ms'] for x in p2['normal']];high=[x['echo_rtt']['p95_ms'] for x in p2['game-high']]
 benefit=sum(normal)/3-sum(high)/3;variance=max(max(normal)-min(normal),max(high)-min(high))
 state=assess_game(p2['normal'],p2['game-high'])['result']
 results['P2-benefit']={'result':state}
 record('P2-benefit',normal=normal,game_high=high,mean_difference_ms=benefit,spread_ms=variance,result=state)
 stopchild(u);stopchild(bulk)
