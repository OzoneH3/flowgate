#!/usr/bin/env python3
"""Stage real-collector accounting evidence, never starts a host collector."""
import argparse,pathlib,subprocess,json,hashlib,shutil
p=argparse.ArgumentParser();p.add_argument('--output',type=pathlib.Path,required=True);p.add_argument('--case-file',type=pathlib.Path);p.add_argument('--backend',type=pathlib.Path);p.add_argument('--collector',type=pathlib.Path);p.add_argument('--sender',type=pathlib.Path);a,rest=p.parse_known_args()
H=pathlib.Path(__file__).resolve().parent;out=a.output.resolve();assert '.workspace' in out.parts
subprocess.run(['python3',str(H/'extensions-stage.py'),'--output',str(out),'--modules','validation',*rest],check=True)
o=out/'overlay';w=o/'work/m1';release=pathlib.Path(rest[rest.index('--release')+1]);base=pathlib.Path(rest[rest.index('--base-initrd')+1])
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
manifest=json.loads((release/'manifest.json').read_text());helper=release/'udp-collector';assert sha(helper)==manifest['files']['udp-collector'];shutil.copy2(a.collector or helper,w/'udp-collector')
if a.backend:shutil.copy2(a.backend,w/'flowgate-new')
if a.sender:
 for name in ['alpha','beta','gamma','denied']:shutil.copy2(a.sender,w/name)
for tok in subprocess.check_output(['ldd',str(helper)],text=True).split():
 if tok.startswith('/') and pathlib.Path(tok).is_file():
  dst=o/tok.lstrip('/');dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(tok,dst)
f=w/'common.py';s=f.read_text().replace(" if os.environ.get('ACCEPTANCE_MODE')=='fast':", " args += ['--udp-helper',str(P/'udp-collector'),'--allow-traffic-control']\n if os.environ.get('ACCEPTANCE_MODE')=='fast':");f.write_text(s)
case=a.case_file or H/'accounting.py';assert case.resolve().is_relative_to(H);shutil.copy2(case,w/'case.py')
(out/'accounting-provenance.json').write_text(json.dumps({'helper_sha256':sha(w/'udp-collector'),'backend_sha256':sha(w/'flowgate-new'),'test_sha256':sha(case),'test_harness_changes_authorization':False,'candidate_backend_override':bool(a.backend),'candidate_collector_override':bool(a.collector),'sender_sha256':sha(w/'alpha')},indent=2))
with (out/'accounting-overlay.gz').open('wb') as dst:
 find=subprocess.Popen(['find','.','-print0'],cwd=o,stdout=subprocess.PIPE);cpio=subprocess.Popen(['cpio','--null','-o','--format=newc','--owner=0:0'],cwd=o,stdin=find.stdout,stdout=subprocess.PIPE,stderr=subprocess.PIPE);find.stdout.close();subprocess.run(['gzip','-1'],stdin=cpio.stdout,stdout=dst,check=True);cpio.stdout.close();assert cpio.wait()==find.wait()==0
with (out/'initramfs.gz').open('wb') as dst:
 for src in (base,out/'accounting-overlay.gz'):
  with src.open('rb') as stream:shutil.copyfileobj(stream,dst)
(out/'image-hashes.json').write_text(json.dumps({n:sha(out/n) for n in ('vmlinuz','initramfs.gz')},indent=2))
