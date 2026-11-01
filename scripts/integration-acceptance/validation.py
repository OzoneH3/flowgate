# Real CAS/API refusal and pure controller-math agreement, inside the guest only.
import importlib.util,hashlib
spec=importlib.util.spec_from_file_location('frozen_controller',P/'controller.py');controller=importlib.util.module_from_spec(spec);spec.loader.exec_module(controller)
def cfg(caps=None,ub=0,db=0,schema=3):return {'enabled':True,'schema':schema,'caps':caps or [],'upload_budget_bits_per_second':ub,'download_budget_bits_per_second':db}
def rejected(label,config,code=None,stale=False):
 before=status();r=request('upload-configure',generation=GEN,expected_version=before['version']-1 if stale else before['version'],upload_config=config)
 checks={'rejected':bool(r.get('error')),'unchanged':status()['version']==before['version']}
 if code:checks['expected_error']=code in str(r.get('error',''))
 results[label]=checks;record('validation',label=label,checks=checks,response=r)
rejected('V1-all-normal-only',cfg([cap('A',prio='normal')]),code='invalid native application cap')
for value in (15_999_999,10_001_000_000):rejected('V3-budget-'+str(value),cfg(ub=value),code='invalid budget')
for value in (999_999,1_001_000_000):rejected('V4-cap-'+str(value),cfg([cap('A',value)]),code='invalid native application cap')
rejected('invalid-critical',cfg([cap('A',prio='critical')]),code='invalid')
rejected('invalid-scope',cfg([cap('A',1_000_000,scope='public')]),code='invalid')
rejected('V8-stale',cfg(),code='stale_version',stale=True)
# Explicit zone Normal is valid and distinct from inheritance.
s=configure([cap('A',prio='normal',scope='local')],ub=16_000_000)
results['V2-zone-explicit-normal']={'stored_override':any(c.get('scope')=='local' and c.get('traffic_priority')=='normal' for c in s['configured_caps'])}
rejected('V7-stored-zone-old-schema',cfg(schema=2),code='schema_upgrade_required')
# Five zoned apps exceed16 nodes; non-running app keys are config validation only.
keys=[hashlib.sha256(('synthetic-config-'+str(i)).encode()).hexdigest() for i in range(17)]
zoned=[{'uid':0,'application':k,'bits_per_second':4_000_000,'scope':'local'} for k in keys[:5]]
rejected('V5-five-zoned-apps',cfg(zoned),code='class_capacity')
# All-scope17 first hits the class count, not floor admission.
flat=[{'uid':0,'application':k,'traffic_priority':'low'} for k in keys]
s=configure(flat[:16],ub=16_000_000);results['V6-sixteen-flat-admitted']={'stored_16':len(s['configured_caps'])==16}
rejected('V6-seventeen-class-capacity',cfg(flat,ub=16_000_000),code='class_capacity')
# Go/Python boundary equality: high zone makes the unspecified children250k.
for level in ('high','low'):
 caps=[cap('A',1_000_000,prio='low'),cap('A',prio=level,scope='local')]
 entry={'rate':1_000_000,'priority':'low','zones':{'local':{'priority':level}}}
 try:
  parent=controller.allocate(16_000_000,{'default':('normal',0),'a':('low',1_000_000)})['a'];child=controller.zone_tuples(entry,parent,'rate',True);python_accepted=True;python_result=child
 except ValueError as e:python_accepted=False;python_result=str(e)
 before=status();r=request('upload-configure',generation=GEN,expected_version=before['version'],upload_config=cfg(caps,ub=16_000_000));go_accepted=not bool(r.get('error'))
 if go_accepted:wait(lambda x:x['applied_version']==r['upload_shaping']['version'])
 checks={'reason':('allocation_below_minimum' in str(r.get('error',''))) if level=='high' else True,'Go_Python_agree':go_accepted==python_accepted,'intended_boundary':go_accepted==(level=='low')}
 results['V6-floor-'+level]=checks;record('validation-floor',level=level,checks=checks,go_response=r,python_result=python_result)
configure([],enabled=False)
