#!/usr/bin/env python3
"""Serial disconnected guest execution with explicit stage identities.
No host API calls, deployment, helper execution or protection changes.
"""
import argparse,pathlib,json,subprocess,sys,os,time
p=argparse.ArgumentParser();p.add_argument('plan',type=pathlib.Path);a=p.parse_args();plan=json.loads(a.plan.read_text());root=pathlib.Path(plan['workspace']).resolve();assert root.name=='.workspace';records=[]
def guests():
 found=[]
 for p in pathlib.Path('/proc').glob('[0-9]*/exe'):
  try:
   if pathlib.Path(os.readlink(p)).name.startswith('qemu-system-'):found.append(str(p.parent))
  except OSError:pass
 return found
for stage in plan['stages']:
 out=pathlib.Path(stage['output']).resolve();assert out.is_relative_to(root) and out.is_dir();assert not guests(),('competing guest',guests())
 started=time.time();print('START '+stage['name'],flush=True)
 with (out/'driver.log').open('x') as log:
  r=subprocess.run([sys.executable,str(pathlib.Path(__file__).with_name('vm.py')),'run','--workspace',str(root),'--output',str(out),'--timeout',str(stage.get('timeout',1200)),'--memory-mib',str(stage.get('memory_mib',2048))],stdout=log,stderr=subprocess.STDOUT)
 records.append(dict(stage,exit=r.returncode,wall_seconds=time.time()-started));a.plan.with_suffix('.results.json').write_text(json.dumps(records,indent=2));print('DONE '+stage['name']+' exit='+str(r.returncode),flush=True)
