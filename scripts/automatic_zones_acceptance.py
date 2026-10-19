"""Real v4/v6 receiver proof with no external routing or manual zone flags."""
import subprocess,json,time

def check(g):
 api,run,log,cmd,wait=[g[k]for k in ['api','RUN','log','cmd','wait']]
 peerpid=g['peer'].pid
 def peerip(*args):return cmd('nsenter','--net=/proc/'+str(peerpid)+'/ns/net','ip',*args)
 addresses=[('10.23.4.5','local'),('100.101.2.3','local'),('fd7a:115c:a1e0::123','local'),('fdca:1234::5','local'),('1.1.1.1','internet'),('2606:4700:4700::1111','internet'),('9.9.9.2','local'),('2606:4700:ffff::2','local'),('8.8.8.8','internet'),('2001:4860:ffff::2','internet')]
 for ip,_ in addresses:
  v6=':'in ip;peerip(*(['-6']if v6 else[]),'addr','add',ip+('/128'if v6 else'/32'),'dev','fgpeer',*(['nodad']if v6 else[]))
  cmd('ip',*(['-6']if v6 else[]),'route','add',ip+('/128'if v6 else'/32'),'via','fd79::2'if v6 else'10.79.0.2','dev','fghost')
 # Public-address physical LAN; connected scope needs both an address and route.
 cmd('ip','addr','add','9.9.9.1/24','dev','fghost');cmd('ip','route','del','9.9.9.2/32')
 cmd('ip','-6','addr','add','2606:4700:ffff::1/64','dev','fghost','nodad');cmd('ip','-6','route','del','2606:4700:ffff::2/128')
 peerip('route','add','9.9.9.1/32','dev','fgpeer')
 peerip('-6','route','add','2606:4700:ffff::1/128','dev','fgpeer')
 # Names deliberately resemble VPNs; they never determine permission or scope.
 cmd('ip','link','add','tailscale0','type','dummy');cmd('ip','link','set','tailscale0','up')
 cmd('ip','tunnel','add','ppp0','mode','gre','local','10.79.0.1','remote','10.79.0.2','dev','fghost')
 peerip('tunnel','add','fgvpn','mode','gre','local','10.79.0.2','remote','10.79.0.1','dev','fgpeer')
 cmd('ip','link','set','ppp0','up');peerip('link','set','fgvpn','up')
 for v6,host,peer in [(False,'100.126.0.1/30','100.126.0.2/30'),(True,'fd7a:115c:a1e0:ffff::1/64','fd7a:115c:a1e0:ffff::2/64')]:
  cmd('ip',*(['-6']if v6 else[]),'addr','add',host,'dev','ppp0',*(['nodad']if v6 else[]))
  peerip(*(['-6']if v6 else[]),'addr','add',peer,'dev','fgvpn',*(['nodad']if v6 else[]))
 for ip,_ in addresses:
  if ip.startswith(('9.9.9.','2606:4700:ffff:')):continue
  v6=':'in ip
  cmd('ip',*(['-6']if v6 else[]),'route','replace',ip+('/128'if v6 else'/32'),'via','fd7a:115c:a1e0:ffff::2'if v6 else'100.126.0.2','dev','ppp0')
 cmd('ip','addr','add','8.8.8.1/24','dev','ppp0')
 cmd('ip','route','replace','8.8.8.8/32','dev','ppp0')
 peerip('route','add','8.8.8.1/32','dev','fgvpn')
 cmd('ip','-6','addr','add','2001:4860:ffff::1/64','dev','ppp0','nodad')
 cmd('ip','-6','route','replace','2001:4860:ffff::2/128','dev','ppp0')
 peerip('-6','route','add','2001:4860:ffff::1/128','dev','fgvpn')
 listener=subprocess.Popen(['nsenter','--net=/proc/'+str(peerpid)+'/ns/net','python3',str(g['ROOT']/'scripts/automatic-zone-peer.py'),str(run)],stdout=subprocess.PIPE,text=True)
 assert listener.stdout.readline().strip()=='READY'
 time.sleep(3) # let IPv6 link-local DAD settle on newly created fixture links
 try:
  initial=wait(lambda:(lambda s:s if s['network_zones']['network_state']=='ready'and any(a['prefix']=='9.9.9.1/24'for a in s['network_zones']['network']['addresses'])else None)(api()))
  gen=initial['generation'];assert initial['network_zones']['model']=='automatic-peer-v1'
  def zone(zone,action):
   s=api();d=dict(direction='outgoing',protocol='*',action=action,remote_address='*',local_port=0,remote_port=0,disabled=False,expires='0001-01-01T00:00:00Z');target=dict(zone=zone,scope='machine');rev=s['network_zones']['revision']
   p=api('zone-rule-preview',generation=gen,zone_revision=rev,zone_target=target,observed_draft=d);assert not p.get('error'),p
   sv=api('zone-rule-save',generation=gen,zone_revision=rev,zone_target=target,observed_draft=d,preview_token=p['zone_preview']['token']);assert not sv.get('error'),sv
   assert sv['saved_rule']['schema']==6 and sv['saved_rule']['filter']['zone_model']=='automatic-peer-v1';return sv['saved_rule']
  def send(ip,zone,allowed,proto):
   log('CHECK '+ip+' '+proto+' '+zone+' allowed='+str(allowed))
   f=run/'automatic-received.log';before=len(f.read_text().splitlines())if f.exists()else 0
   g['ask'](g['children']['alpha'],'send',protocol=proto,v6=':'in ip,host=ip,port=45050 if proto=='tcp'else 45051,timeout_ms=700)
   g['ask'](g['children']['alpha'],'settle')
   (run/'last-send.json').write_text(json.dumps(api(),indent=2))
   if allowed:wait(lambda:f.exists()and len(f.read_text().splitlines())==before+1)
   else:time.sleep(.15);assert(len(f.read_text().splitlines())if f.exists()else 0)==before,(ip,proto,'leaked')
   def event():return next((e for e in reversed(api().get('events',[]))if e['flow']['direction']=='outgoing'and e['flow']['protocol']==proto and e['flow']['remote'].startswith('['+ip+']:'if ':'in ip else ip+':')),None)
   def historical():
    result=api('decision-log',decision_query={'limit':100})
    return next((r for r in result.get('decision_log',{}).get('records',[])if r.get('flow',{}).get('direction')=='outgoing'and r.get('flow',{}).get('protocol')==proto and r.get('flow',{}).get('remote','').startswith('['+ip+']:'if ':'in ip else ip+':')),None)
   ev=wait(lambda:event()or historical());assert ev['flow']['network_scope']['zone']==zone,(ip,ev);return ev
  for allowedzone in ['local','internet']:
   rules=[zone('local','allow'if allowedzone=='local'else'block'),zone('internet','allow'if allowedzone=='internet'else'block')]
   for ip,z in addresses:
    for proto in ['udp','tcp']:send(ip,z,z==allowedzone,proto)
   for r in rules:g['delete'](r)
   log('PASS automatic '+allowedzone+'-only actual TCP+UDP IPv4/IPv6 delivery; private/routed GRE work-VPN fixture, CGNAT/ULA, public physical LAN and public routed/tunnel-subnet peers; no manual destination zones')
  # Pending decision keeps its immutable target and deadline over topology updates.
  g['ask'](g['children']['alpha'],'send',protocol='udp',v6=False,host='9.9.9.2',port=45051,timeout_ms=4000)
  held=wait(lambda:next((e for e in api().get('events',[])if e['state']=='awaiting-decision'and e['flow']['remote'].startswith('9.9.9.2:')),None))
  deadline=held['deadline'];rev=api()['network_zones']['revision']
  cmd('ip','route','add','9.9.9.2/32','via','10.79.0.2','dev','fghost')
  s=wait(lambda:(lambda s:s if s['network_zones']['revision']!=rev and next((e for e in s.get('events',[])if e['id']==held['id']),{}).get('flow',{}).get('network_scope',{}).get('zone')=='internet'else None)(api()))
  current=next(e for e in s.get('events',[])if e['id']==held['id']);assert current['deadline']==deadline and current['id']==held['id']
  r=api('decide',generation=gen,id=held['id'],action='block',scope='once');assert not r.get('error'),r
  rules=[zone('local','block'),zone('internet','allow')];send('9.9.9.2','internet',True,'udp')
  for r in rules:g['delete'](r)
  (run/'automatic-result.json').write_text(json.dumps(dict(pass_=True,network_zones=s['network_zones'],pending_before=held,pending_after=current,rules=api().get('rules',[])),indent=2))
  assert api().get('rules',[])==[]
  log('PASS live route revision changes public LAN to routed Internet; pending ID/deadline unchanged; refreshed Internet-only receiver delivery; rules0')
 finally:listener.terminate();listener.wait(5)
