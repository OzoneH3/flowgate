# Causal startup ordering trace: bounded diagnostic backend overlay, same real
# production lifetime authorization; sequence observer only in the peer.
configure([],enabled=False)
record('clock-pair',monotonic_ns=time.monotonic_ns(),boottime_ns=time.clock_gettime_ns(time.CLOCK_BOOTTIME),suspend_during_test=False)
mode=os.environ['ACCEPTANCE_MODE']
def fast():return (api().get('socket_authorization') or {}).get('fast_packets',0)
def stopchild(p):
 if p.poll() is None:p.terminate();p.wait(10)
u=spawn('alpha','established-order-control');open_retry(u,'OPEN 4 0 1 1 0 43001','steady-order');ask(u,'SEND orderwarm 125 8000');time.sleep(1)
steady=[]
def stream():
 for part in range(3):steady.append(ask(u,f'SEND ordersteady{part} 1250 8000'))
t=threading.Thread(target=stream);t.start()
for delay in (8000,1000):
 for round in range(9):
  p=spawn('alpha',f'order-{delay}-{round}');i=open_retry(p,'OPEN 4 0 1 1 0 43001','order-open');tag=f'order{delay}r{round}'
  before=fast();begin=time.monotonic_ns();sent=ask(p,f'SEND {tag} 125 {delay}');end=time.monotonic_ns();time.sleep(.3);got=peerop('stats').get(tag,{})
  record('startup-order',tag=tag,socket=i,sender=sent,receiver=got,arrivals=peerop('arrivals:'+tag),start_ns=begin,end_ns=end,fast_delta=fast()-before,interval_us=delay,gate=api().get('socket_authorization'))
  stopchild(p)
t.join();time.sleep(.3)
record('established-order-control',sender=steady,receiver={k:v for k,v in peerop('stats').items() if k.startswith('ordersteady')})
stopchild(u)
# These are observational defect-localization runs, never automatic acceptance.
results['trace-completed']={'result':'Pass'}
