#!/usr/bin/env python3
"""Stage reviewed extensions without changing the frozen core harness."""
import argparse,pathlib,hashlib,json,shutil,subprocess,importlib.util
H=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('acceptance_vm',H/'vm.py');vm=importlib.util.module_from_spec(spec);spec.loader.exec_module(vm)
p=argparse.ArgumentParser()
for n in ['workspace','output','release','helpers','kernel','base-initrd']:p.add_argument('--'+n,type=pathlib.Path,required=True)
p.add_argument('--modules',default='')
p.add_argument('--p1-window-ms',type=int,choices=[4000,8000],default=4000)
p.add_argument('--p1-only',action='store_true')
p.add_argument('--mode',choices=['fast','protected','off'],required=True);p.add_argument('--kernel-release',default='7.3.0-4-cachyos');a=p.parse_args();a.case='extensions';a.cells=''
vm.stage(a);out=a.output;o=out/'overlay';w=o/'work/m1'
files=['scope.py','priority.py','priority_assess.py','udp_loss.py','coverage_escape.py','policy_receiver.py','validation.py']
for n in files:shutil.copy2(H/n,w/n)
if a.modules:
 selected=a.modules.split(',');assert set(selected)<=set(n[:-3] for n in files if n!='priority_assess.py')
 prelude=(H/'extensions.py').read_text().split("exec(compile",1)[0]
 (w/'case.py').write_text(prelude+''.join("exec(compile((P/"+repr(n+'.py')+").read_text(),str(P/"+repr(n+'.py')+"),'exec'),globals())\n" for n in selected))
if a.p1_only:
 assert a.modules=='priority'
 (w/'case.py').write_text("import os\nos.environ['ACCEPTANCE_P1_WINDOW_MS']="+repr(str(a.p1_window_ms))+"\nos.environ['ACCEPTANCE_P1_ONLY']='1'\n"+(w/'case.py').read_text())
(out/'extension-provenance.json').write_text(json.dumps({n:vm.sha(H/n) for n in files},indent=2))
with (out/'overlay-extensions.gz').open('wb') as f:
 find=subprocess.Popen(['find','.','-print0'],cwd=o,stdout=subprocess.PIPE);cpio=subprocess.Popen(['cpio','--null','-o','--format=newc','--owner=0:0'],cwd=o,stdin=find.stdout,stdout=subprocess.PIPE,stderr=subprocess.PIPE);find.stdout.close();subprocess.run(['gzip','-1'],stdin=cpio.stdout,stdout=f,check=True);cpio.stdout.close();assert cpio.wait()==0 and find.wait()==0
with (out/'initramfs.gz').open('wb') as f:
 for src in [a.base_initrd,out/'overlay-extensions.gz']:
  with src.open('rb') as x:shutil.copyfileobj(x,f)
(out/'image-hashes.json').write_text(json.dumps({n:vm.sha(out/n) for n in ['vmlinuz','initramfs.gz']},indent=2))
(out/'extensions-staged.json').write_text(json.dumps({str(f.relative_to(o)):vm.sha(f) for f in o.rglob('*') if f.is_file()},indent=2))
