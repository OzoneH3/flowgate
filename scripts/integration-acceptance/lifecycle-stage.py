#!/usr/bin/env python3
"""Stage existing kernel receiver/recovery tests, never execute them on host."""
import argparse,pathlib,hashlib,json,shutil,subprocess,sys,importlib.util
H=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('acceptance_vm',H/'vm.py');vm=importlib.util.module_from_spec(spec);spec.loader.exec_module(vm)
p=argparse.ArgumentParser()
for n in ['workspace','output','release','helpers','kernel','base-initrd','tests']:p.add_argument('--'+n,type=pathlib.Path,required=True)
p.add_argument('--kernel-release',default='7.3.0-4-cachyos');a=p.parse_args();a.mode='protected';a.case='reference';a.cells=''
vm.stage(a);out=a.output;o=out/'overlay';w=o/'work/m1'
(w/'run.py').write_text('''import os,pathlib,subprocess,json,hashlib
P=pathlib.Path('/work/m1');R=pathlib.Path('/work/.workspace/m1');R.mkdir(parents=True,exist_ok=True)
assert os.environ['FLOWGATE_PARENT_NETNS']!=os.readlink('/proc/self/ns/net')
os.environ['FLOWGATE_DISPOSABLE_VM']='1'
os.environ['FLOWGATE_PARENT_BOOT_ID']=(P/'parent-boot-id.txt').read_text()
os.environ['FLOWGATE_SOCKET_SESSION_RUN']=str(R/'session-test')
(R/'session-test').mkdir(mode=0o700)
def run(args,name):
 r=subprocess.run(args,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=120);(R/(name+'.txt')).write_text(r.stdout);return r
before=json.loads(subprocess.check_output(['bpftool','-j','prog','show']))
assert pathlib.Path('/proc/sys/kernel/random/boot_id').read_text()!=(P/'parent-boot-id.txt').read_text()
assert 'rdinit=/init' in pathlib.Path('/proc/cmdline').read_text()
subprocess.run(['modprobe','-r','xt_bpf'],check=True)
steps=[]
for binary,regex,name in [('socketgrant.test','^TestColdBootINETMatchDependency$','coldboot'),('socketgrant.test','^TestConnectionKernelReceiver$','kernel-receiver'),('hostfirewall.test','^TestRoutedProtectionSessionPrivateNamespace$','crash-recovery')]:
 r=run([str(P/binary),'-test.v','-test.timeout=100s','-test.run='+regex],name)
 steps.append({'name':name,'exit':r.returncode,'result':'Pass' if r.returncode==0 and '--- PASS:' in r.stdout and '--- SKIP:' not in r.stdout else 'Fail'})
 (R/'lifecycle-results.json').write_text(json.dumps(steps,indent=2))
after=json.loads(subprocess.check_output(['bpftool','-j','prog','show']))
(R/'lifecycle-inventory.json').write_text(json.dumps({'before':before,'after':after,'program_ids_unchanged':{x['id'] for x in before}=={x['id'] for x in after}},indent=2))
(R/'ruleset-after.json').write_bytes(subprocess.check_output(['nft','-j','list','ruleset']))
raise SystemExit(0 if all(x['result']=='Pass' for x in steps) and {x['id'] for x in before}=={x['id'] for x in after} else 1)
''')
(w/'parent-boot-id.txt').write_text(pathlib.Path('/proc/sys/kernel/random/boot_id').read_text())
for n in ['socketgrant.test','hostfirewall.test']:
 shutil.copy2(a.tests/n,w/n)
# Add only binaries and their dynamic dependencies to the immutable overlay.
for exe in ['/usr/bin/bpftool',str(a.tests/'socketgrant.test'),str(a.tests/'hostfirewall.test')]:
 if exe.startswith('/usr/bin/'):
  dst=o/exe.lstrip('/');dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(exe,dst)
 r=subprocess.run(['ldd',exe],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
 assert r.returncode==0 or 'not a dynamic' in r.stdout or 'statically linked' in r.stdout,r.stdout
 for s in r.stdout.split():
  if s.startswith('/') and pathlib.Path(s).is_file():
   dst=o/s.lstrip('/');dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(s,dst)
(out/'lifecycle-provenance.json').write_text(json.dumps({'stage':vm.sha(H/'lifecycle-stage.py'),'tests':{n:vm.sha(a.tests/n) for n in ['socketgrant.test','hostfirewall.test']},'compile_provenance':json.loads((a.tests/'kernel-tests-build.json').read_text())},indent=2))
# Repack and rehash after the deliberate guest-only test overlay changes.
with (out/'overlay-lifecycle.gz').open('wb') as f:
 find=subprocess.Popen(['find','.','-print0'],cwd=o,stdout=subprocess.PIPE);cpio=subprocess.Popen(['cpio','--null','-o','--format=newc','--owner=0:0'],cwd=o,stdin=find.stdout,stdout=subprocess.PIPE,stderr=subprocess.PIPE);find.stdout.close();subprocess.run(['gzip','-1'],stdin=cpio.stdout,stdout=f,check=True);cpio.stdout.close();assert cpio.wait()==0 and find.wait()==0
with (out/'initramfs.gz').open('wb') as f:
 for src in [a.base_initrd,out/'overlay-lifecycle.gz']:
  with src.open('rb') as x:shutil.copyfileobj(x,f)
(out/'image-hashes.json').write_text(json.dumps({n:vm.sha(out/n) for n in ['vmlinuz','initramfs.gz']},indent=2))
(out/'lifecycle-staged.json').write_text(json.dumps({str(f.relative_to(o)):vm.sha(f) for f in o.rglob('*') if f.is_file()},indent=2))
