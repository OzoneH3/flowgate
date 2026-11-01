#!/usr/bin/env python3
"""Run the finite core serially, preserving every failure and missing cell.
This orchestrator has no host API/deployment commands; see vm.py for isolation.
"""
import argparse,pathlib,subprocess,sys,json,hashlib
H=pathlib.Path(__file__).resolve().parent
p=argparse.ArgumentParser(description=__doc__)
for name in ['workspace','output','release','helpers','kernel','base-initrd']:p.add_argument('--'+name,type=pathlib.Path,required=True)
p.add_argument('--kernel-release',default='7.3.0-4-cachyos');p.add_argument('--timeout',type=int,default=1800);p.add_argument('--extensions',action='store_true');p.add_argument('--dry-run',action='store_true');a=p.parse_args()
assert a.output.resolve().is_relative_to(a.workspace.resolve())
assert (H/'spec/FROZEN.txt').is_file(),'expected results must be independently frozen first'
commands=[]
for mode,case in [('fast','core'),('protected','core'),('off','core'),('off','reference')]+([(m,'extensions') for m in ['fast','protected','off']] if a.extensions else []):
 out=a.output/(mode+'-'+case)
 base=[sys.executable,str(H/'vm.py')]
 stage=([sys.executable,str(H/'extensions-stage.py'),'--workspace',str(a.workspace),'--output',str(out),'--mode',mode] if case=='extensions' else base+['stage','--workspace',str(a.workspace),'--output',str(out),'--mode',mode,'--case',case])
 for name in ['release','helpers','kernel','base-initrd']:stage+=['--'+name,str(getattr(a,name.replace('-','_')))]
 stage+=['--kernel-release',a.kernel_release]
 run=base+['run','--workspace',str(a.workspace),'--output',str(out),'--timeout',str(a.timeout)]
 commands.append((stage,run))
if a.dry_run:
 print(json.dumps(commands,indent=2));sys.exit(0)
assert not a.output.exists(),'choose new series output; never overwrite evidence'
a.output.mkdir(parents=True)
(a.output/'series-inputs.json').write_text(json.dumps({str(f):hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted(H.rglob('*')) if f.is_file() and '__pycache__' not in str(f)},indent=2))
results=[]
for stage,run in commands:
 s=subprocess.run(stage)
 r=subprocess.run(run) if s.returncode==0 else None
 results.append({'stage':stage,'stage_exit':s.returncode,'run_exit':r.returncode if r else None})
 (a.output/'series-results.json').write_text(json.dumps(results,indent=2))
 # Independent modes continue even after a failed cell/guest.
subprocess.run([sys.executable,str(H/'report.py'),str(a.output),'--output',str(a.output/'core-report.json')],check=True)
sys.exit(0 if all(x['stage_exit']==0 and x['run_exit']==0 for x in results) else 1)
