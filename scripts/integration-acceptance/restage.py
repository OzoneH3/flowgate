#!/usr/bin/env python3
"""Copy an immutable staged VM to a new output, optionally replacing test inputs.
Never overwrite a prior run or execute a host helper/daemon.
"""
import argparse,pathlib,subprocess,shutil,json,hashlib
p=argparse.ArgumentParser();p.add_argument('--from-run',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);p.add_argument('--base-initrd',type=pathlib.Path,required=True);p.add_argument('--backend',type=pathlib.Path);p.add_argument('--controller',type=pathlib.Path);p.add_argument('--extra-module',action='append',default=[]);p.add_argument('--replace-file',action='append',default=[]);p.add_argument('--binary',action='append',default=[]);a=p.parse_args();src=a.from_run.resolve();out=a.output.resolve();assert '.workspace' in src.parts and '.workspace' in out.parts and not out.exists();out.mkdir()
subprocess.run(['cp','--reflink=auto','-a',str(src/'overlay'),str(out/'overlay')],check=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
w=out/'overlay/work/m1';changes={}
for f,name in [(a.backend,'flowgate-new'),(a.controller,'controller.py')]:
 if f:changes[name]={'old':sha(w/name),'new':sha(f)};shutil.copy2(f,w/name)
for module in a.extra_module:
 for line in subprocess.check_output(['modprobe','-S','7.3.0-4-cachyos','--show-depends',module],text=True).splitlines():
  if line.startswith('insmod '):
   source=pathlib.Path(line.split()[1]);dest=out/'overlay/usr/lib/modules'/str(source).split('/modules/',1)[1];dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,dest)
 g=out/'overlay/guest-run.sh';s=g.read_text().replace('cd /work','cd /work\nmodprobe '+module,1);g.write_text(s)
 changes['module:'+module]='guest-only prerequisite'
for spec in a.replace_file+a.binary:
 origin,name=spec.split('=',1);source=pathlib.Path(origin);relative=pathlib.Path(name);assert not relative.is_absolute() and '..' not in relative.parts
 dest=out/'overlay'/relative;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,dest);changes[name]={'source':str(source),'sha256':sha(source)}
 if spec in a.binary:
  r=subprocess.run(['ldd',str(source)],capture_output=True,text=True);assert r.returncode==0 or 'statically linked' in r.stdout or 'not a dynamic' in r.stdout
  for token in r.stdout.split():
   if token.startswith('/') and pathlib.Path(token).is_file():
    dest=out/'overlay'/token.lstrip('/');dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(token,dest)
for f in src.glob('*.json'):
 if f.name not in ('execution.json','command.json','image-hashes.json'):shutil.copy2(f,out/f.name)
shutil.copy2(src/'vmlinuz',out/'vmlinuz')
(out/'restage-provenance.json').write_text(json.dumps({'source_run':str(src),'source_image_sha256':sha(src/'initramfs.gz'),'changes':changes},indent=2))
with (out/'replacement-overlay.gz').open('wb') as dst:
 find=subprocess.Popen(['find','.','-print0'],cwd=out/'overlay',stdout=subprocess.PIPE);cpio=subprocess.Popen(['cpio','--null','-o','--format=newc','--owner=0:0'],cwd=out/'overlay',stdin=find.stdout,stdout=subprocess.PIPE,stderr=subprocess.PIPE);find.stdout.close();subprocess.run(['gzip','-1'],stdin=cpio.stdout,stdout=dst,check=True);cpio.stdout.close();assert cpio.wait()==find.wait()==0
with (out/'initramfs.gz').open('wb') as dst:
 for f in (a.base_initrd,out/'replacement-overlay.gz'):
  with f.open('rb') as stream:shutil.copyfileobj(stream,dst)
(out/'image-hashes.json').write_text(json.dumps({n:sha(out/n) for n in ('vmlinuz','initramfs.gz')},indent=2))
