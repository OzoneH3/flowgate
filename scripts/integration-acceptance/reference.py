# Protection off + shaper disabled; same application traffic as a core cell.
assert os.environ['ACCEPTANCE_MODE']=='off'
configure([],enabled=False)
assert qdiscs()==original
assert not (status().get('kernel') or {}).get('download',{}).get('interface')
u=spawn('alpha','reference-game');open_retry(u,'OPEN 4 0 1 1 0 43001','reference-game')
v=spawn('beta','reference-other');open_retry(v,'OPEN 4 0 1 1 0 43001','reference-other')
initial=ask(u,'SEND refstart 125 8000');ask(v,'SEND refother 125 8000');time.sleep(.5)
record('refstartup',sender=initial,receiver=peerop('stats').get('refstart',{}))
sent=ask(u,'SEND refquiet 75 8000');time.sleep(.3);rx=peerop('stats').get('refquiet',{})
rtt=ask(u,'PING rttref 30 8000');ask(v,'SEND refcross 30 8000');time.sleep(.2)
record('reference',phase='quiet',sender=sent,receiver=rx,echo_rtt=rtt,matched_core=True)
results['refquiet']={'delivery':rx.get('received')==75,'echo_delivery':rtt['received']==30}
ps=[];keys=[]
for j in range(2):
 x=spawn('alpha','reference-ul-'+str(j));i=open_retry(x,'OPEN 4 1 1 1 0 43003','reference-ul');keys.append(flowkey('tcp',i));ps.append(x)
d=spawn('alpha','reference-dl');open_retry(d,'OPEN 4 1 1 1 0 43005','reference-dl');ps.append(d)
for x in ps[:2]:write(x,'BULK load 1000000 65536 0')
ask(d,'DRAIN 2000')
for win in range(2):
 first=peerop('bulk');start=time.monotonic();tag='refbulk'+str(win)
 write(u,'SEND '+tag+' 375 8000');dl=ask(d,'DRAIN 3000');sent=line(u,10);last=peerop('bulk');elapsed=time.monotonic()-start;rx=peerop('stats').get(tag,{})
 record('reference',phase='bulk',window=win,sender=sent,receiver=rx,download_receiver=dl,bulk_upload_bytes=sum(last.get(k,{}).get('bytes',0)-first.get(k,{}).get('bytes',0) for k in keys),elapsed=elapsed,matched_core=True,shaping_disabled=True,protection_off=True)
 results['refbulk'+str(win)]={'delivery':rx.get('received')==375}
for x in [u,v]+ps:x.terminate();x.wait(10)
