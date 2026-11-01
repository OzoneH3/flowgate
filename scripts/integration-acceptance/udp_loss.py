# Exact drop-site separation: ONE UDP socket, no A TCP traffic, above the UL cap.
# Fast acceptance is before TC, so fast hits can include packets later shaped out.
from measure import *
configure([cap('A',2_000_000)])
u=spawn('alpha','udp-only-cap');info=open_retry(u,'OPEN 4 0 1 1 0 43001','udp-only-cap');ask(u,'SEND onlyWarm 125 8000')
wait(lambda s:any(b.get('cookie')==info['sockets'][0]['cookie'] and b.get('upload_class') for b in bindings(s)),30)
def udp_snap():
 s=api();return {'time':time.monotonic(),'tc':json.loads(cmd('tc','-s','-j','class','show','dev',DEV)),'qdisc':json.loads(cmd('tc','-s','-j','qdisc','show','dev',DEV)),'gate':s.get('socket_authorization'),'queue':s.get('queue_health')}
a=udp_snap();xs=htb_leaf(a['tc']);assert len(xs)==1,xs;handle=xs[0]['handle'];sent=ask(u,'SEND onlyLoss 3000 667');b=udp_snap();until=time.monotonic()+3
while sum(q.get('backlog',q.get('stats',{}).get('backlog',0)) for q in b['qdisc'] if q.get('parent')==handle)>0 and time.monotonic()<until:time.sleep(.05);b=udp_snap()
time.sleep(.3);rx=peerop('stats').get('onlyLoss',{});end=htb_leaf(b['tc']);assert len(end)==1,end
charged=snapshot_delta(xs[0],end[0]);drops=queue_drop(b['qdisc'],handle)-queue_drop(a['qdisc'],handle);missing=sent['sent']-rx.get('received',0)
checks={'receiver_equals_dequeued':rx.get('received',0)==charged['packets'],'sent_equals_dequeued_plus_leaf_drops':sent['sent']==charged['packets']+drops,'charged_bytes_exact':charged['bytes']==charged['packets']*1242,'nonvacuous':sent['sent']+sent['errors']==3000}
results['udp-only-loss']=checks
record('udp-only-loss',mode=mode,checks=checks,sender=sent,receiver=rx,charged=charged,leaf_drops=drops,missing=missing,unclassified=max(0,missing-drops),before=a,after=b,scope='one UDP flow only; intentional cap saturation; excluded from unconstrained 10ms target')
stopchild(u)
