# Production manager/classifier driver owns shaping only after the normal daemon
# is Disabled. The normal daemon continues enforcing the unchanged fixture rules.
configure([],enabled=False)
assert status()['status']=='Disabled' and not childpids()
normal_status=status
controller=launch([P/'classifier-driver',DEV,P,R/'classifier-controller'],'classifier-driver')
assert line(controller)['ready']
def dc(op,**kw):
 response=ask(controller,json.dumps(dict(op=op,**kw)))
 assert not response.get('error'),response
 return response.get('result',response)
def status():return dc('status')
config={'enabled':True,'schema':3,'caps':[cap('A',10_000_000,14_000_000),cap('A',8_000_000,12_000_000,scope='local'),cap('A',4_000_000,6_000_000,scope='internet')]}
s=dc('configure',config=config);wait(lambda v:v['applied_version']==s['version'],60)
u=spawn('alpha','reclassification-ul');info=open_retry(u,'OPEN 4 1 2 1 0 43003','reclassification-ul')
keys=['tcp:10.79.0.1:'+str(x['port']) for x in info['sockets']]
d=spawn('alpha','reclassification-dl');open_retry(d,'OPEN 4 1 2 1 0 43005','reclassification-dl')
wait(lambda v:len(bindings(v))==4 and all(b.get('zone')=='local' for b in bindings(v)),60)
write(u,'BULK reclass 90000 65536 0')
observations=[]
for zone,bands in [('local',{'ul':(6.4,8.8),'dl':(9.6,13.2)}),('internet',{'ul':(3.2,4.4),'dl':(4.8,6.6)}),('',{'ul':(8,11),'dl':(11.2,15.4)})]:
 dc('zone',zone=zone)
 snap=wait(lambda v:len(bindings(v))==4 and all(b.get('zone')==zone and b.get('covered') for b in bindings(v)),60)
 ask(d,'DRAIN 3000');a=peerop('bulk');t=time.monotonic();got=ask(d,'DRAIN 8000');b=peerop('bulk');elapsed=time.monotonic()-t
 rates={'ul':sum(b.get(k,{}).get('bytes',0)-a.get(k,{}).get('bytes',0) for k in keys)*8/elapsed/1e6,'dl':got['bytes']*8e3/got['elapsed_ns']}
 checks=checked('reclassification-'+(zone or 'unknown'),rates,bands)
 pin=json.loads((R/'classifier-controller'/'owner.json').read_text())['pin'];health=json.loads(cmd(P/'kernel','health',pin))
 observations.append({'zone':zone,'rates':rates,'checks':checks,'snapshot':snap,'health':health})
 record('reclassification',**observations[-1])
cookies=[sorted(row['cookie'] for row in x['health']['bindings']) for x in observations]
ids=[sorted({(row['minor'],row['download']) for row in x['health']['bindings']}) for x in observations]
results['reclassification-map']={'same_live_cookies':cookies[0]==cookies[1]==cookies[2] and len(cookies[0])==4,'distinct_child_binding_each_zone':len({json.dumps(v) for v in ids})==3}
record('reclassification-map',checks=results['reclassification-map'],class_ids=ids,deny=deny_check('reclass'))
u.terminate();u.wait();d.terminate();d.wait();wait(lambda v:not bindings(v),60)
s=dc('configure',config={'enabled':False,'schema':3,'caps':[]});wait(lambda v:v['status']=='Disabled',60)
dc('stop');controller.wait(20)
status=normal_status
