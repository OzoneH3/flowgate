# Initial shaping coverage / per-cookie binding latency, not a settled cap test.
from measure import *
configure([cap('A',2_000_000)],ub=16_000_000)
game=spawn('gamma','binding-game');open_retry(game,'OPEN 4 0 1 1 0 43001','binding-game');ask(game,'SEND bindingwarm 125 8000')
base=json.loads(cmd('tc','-s','-j','class','show','dev',DEV));start=time.monotonic();hits=fast();clients=[];cookies={};keys=[]
write(game,'SEND bindingGame 1000 8000')
for i in range(2):
 p=spawn('alpha','cold-binding-'+str(i));t=time.monotonic();info=open_retry(p,'OPEN 4 1 1 1 0 43003','cold-binding');clients.append(p);cookie=info['sockets'][0]['cookie'];cookies[cookie]={'open_at':t,'first_class_at':None};keys.append(flowkey('tcp',info));write(p,'BULK initial 6000 65536 0')
samples=[]
while time.monotonic()<start+7:
 s=status();now=time.monotonic()
 for b in bindings(s):
  c=b.get('cookie')
  if c in cookies and b.get('upload_class') and cookies[c]['first_class_at'] is None:cookies[c]['first_class_at']=now
 samples.append({'at':now,'bindings':bindings(s),'classes':json.loads(cmd('tc','-s','-j','class','show','dev',DEV))})
 time.sleep(.1)
for p in clients:line(p,15);stopchild(p)
sent=line(game,15);time.sleep(.3);got=peerop('stats').get('bindingGame',{})
last=json.loads(cmd('tc','-s','-j','class','show','dev',DEV));escape={}
for minor in ('fffe','fff1'):
 escape[minor]=snapshot_delta(klass(base,minor),klass(last,minor))
for v in cookies.values():v['binding_latency_seconds']=v['first_class_at']-v['open_at'] if v['first_class_at'] is not None else None
c_sent_charge=sent['sent']*1242;c_received_charge=got.get('received',0)*1242
a_escape_bounds={'minimum':escape['fffe']['bytes']-c_sent_charge,'maximum':escape['fffe']['bytes']-c_received_charge,'result':'Inconclusive' if got.get('received',0)!=sent['sent'] or escape['fffe']['bytes']<c_sent_charge else 'Observed','C_sent_charged_estimate':c_sent_charge,'C_received_charge':c_received_charge}
# fffe also contains C's known game traffic: report its exact sent/receiver counts,
# never attribute the entire default-class count to A without subtracting it.
record('initial-coverage',mode=mode,per_socket=cookies,samples=samples,default_bypass_deltas=escape,A_escape_bytes=a_escape_bounds,game_sender=sent,game_receiver=got,fast_delta=fast()-hits,raw_initial_ul=peerop('bulk'),note='default includes unconfigured C game; do not attribute whole fffe delta to A; pre-class TCP bytes are coverage escape, not settled-cap overshoot')
results['initial-binding']={'every_cookie_reached_class':all(v['first_class_at'] is not None for v in cookies.values()),'established_game_delivery':got.get('received')==sent['sent'],'game_fast_use':fast()>hits if mode=='fast' else True}
stopchild(game)
