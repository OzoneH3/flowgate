# Narrow final API/direction-transition cases, no repetition of run1/3 matrix.
allcap=cap('A',9_000_000,14_000_000);local=cap('A',8_000_000,scope='local')
configure([allcap,local]);before=status()
for schema,expected,label in [(2,before['version'],'legacy_schema2'),(3,before['version']-1,'stale_version')]:
 r=request('upload-configure',generation=GEN,expected_version=expected,upload_config={'enabled':False,'caps':[],'schema':schema})
 after=status();ok=bool(r.get('error') or r.get('error_code')) and after['version']==before['version'] and after['configured_caps']==before['configured_caps'];results[label]={'refused_without_mutation':ok};record('api-refusal',label=label,response=r,unchanged=ok)
# Submit once and deliberately close the socket without reading its receipt.
pending=[allcap,local,cap('A',dl=6_000_000,scope='internet')]
q={'version':1,'operation':'upload-configure','generation':GEN,'expected_version':before['version'],'upload_config':{'enabled':True,'caps':pending,'schema':3}}
with socket.socket(socket.AF_UNIX) as lost:
 lost.connect(str(API));lost.sendall((json.dumps(q)+'\n').encode())
reconciled=wait(lambda s:s['version']==before['version']+1 and s['applied_version']==s['version'],40)
results['lost-ack']={'read_reconciles_single_submission':reconciled['configured_caps']==pending or {json.dumps(c,sort_keys=True) for c in reconciled['configured_caps']}=={json.dumps(c,sort_keys=True) for c in pending}}
record('lost-ack',submitted_once=True,reconciled=reconciled,checks=results['lost-ack'])
configure([allcap,local])
d=spawn('alpha','direction-dl');open_retry(d,'OPEN 4 1 2 1 0 43005','direction-dl');wait(lambda s:len(bindings(s))==2,60)
def direction_state(label):
 # Class identity and queue handles are captured from kernel state, not API ACK.
 pin=json.loads((R/'controller'/'owner.json').read_text())['pin'];health=json.loads(cmd(P/'kernel','health',pin));snap=status();ifb=snap['kernel']['download']['interface']
 ask(d,'DRAIN 3000');got=ask(d,'DRAIN 5000');rate=got['bytes']*8e3/got['elapsed_ns']
 out={'label':label,'download_Mbit':rate,'download_ids':sorted({row['download'] for row in health['bindings']}),'health':health,'snapshot':snap,'classes':json.loads(cmd('tc','-s','-j','class','show','dev',ifb)),'qdiscs':json.loads(cmd('tc','-j','qdisc','show','dev',ifb))}
 record('direction-transition',**out);return out
original_dir=direction_state('zone-ul-plus-all-dl')
configure([allcap]);removed=direction_state('last-zone-removed')
configure([allcap,cap('A',4_000_000,scope='internet')]);added=direction_state('internet-ul-added')
def handles(state):return sorted((q.get('kind'),q.get('handle'),q.get('parent')) for q in state['qdiscs'])
results['direction-preservation']={'download_ids_stable':original_dir['download_ids']==removed['download_ids']==added['download_ids'],'download_handles_stable':handles(original_dir)==handles(removed)==handles(added),'download_delivery_capped':all(11.2<=x['download_Mbit']<=15.4 for x in (original_dir,removed,added))}
d.terminate();d.wait();wait(lambda s:not bindings(s),60)
record('direction-results',checks=results['direction-preservation'],deny=deny_check('direction'))
