#!/usr/bin/env python3
import argparse,pathlib,subprocess,json,hashlib,shutil
p=argparse.ArgumentParser();p.add_argument('--output',type=pathlib.Path,required=True);p.add_argument('--backend',type=pathlib.Path,required=True);a,rest=p.parse_known_args()
H=pathlib.Path(__file__).resolve().parent;out=a.output.resolve();assert '.workspace' in out.parts and '.workspace' in a.backend.resolve().parts
subprocess.run(['python3',str(H/'extensions-stage.py'),'--output',str(out),'--modules','validation',*rest],check=True)
o=out/'overlay';w=o/'work/m1';shutil.copy2(a.backend,w/'flowgate-new');shutil.copy2(H/'startup-trace.py',w/'case.py')
f=w/'peer.py';s=f.read_text().replace("'highest':-1", "'highest':-1,'arrivals':[]").replace("  if seq in row['seen']:","  if len(row['arrivals'])<2000:row['arrivals'].append([seq,now,ts])\n  if seq in row['seen']:")
s=s.replace(" if op=='setup':", " if op.startswith('arrivals:'):\n  with lock:value=stats.get(op.split(':',1)[1],{}).get('arrivals',[])\n  print(json.dumps(value),flush=True);continue\n if op=='setup':")
f.write_text(s)
base=pathlib.Path(rest[rest.index('--base-initrd')+1]);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
(out/'trace-provenance.json').write_text(json.dumps({'backend_sha256':sha(a.backend),'case_sha256':sha(H/'startup-trace.py'),'peer_sha256':sha(f),'test_only':True},indent=2))
with (out/'startup-overlay.gz').open('wb') as dst:
 find=subprocess.Popen(['find','.','-print0'],cwd=o,stdout=subprocess.PIPE);cpio=subprocess.Popen(['cpio','--null','-o','--format=newc','--owner=0:0'],cwd=o,stdin=find.stdout,stdout=subprocess.PIPE,stderr=subprocess.PIPE);find.stdout.close();subprocess.run(['gzip','-1'],stdin=cpio.stdout,stdout=dst,check=True);cpio.stdout.close();assert cpio.wait()==find.wait()==0
with (out/'initramfs.gz').open('wb') as dst:
 for src in (base,out/'startup-overlay.gz'):
  with src.open('rb') as stream:shutil.copyfileobj(stream,dst)
(out/'image-hashes.json').write_text(json.dumps({n:sha(out/n) for n in ('vmlinuz','initramfs.gz')},indent=2))
