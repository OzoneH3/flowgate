#!/usr/bin/env python3
"""Stage/run disconnected TCG acceptance cells. Never contacts the host API.
All output paths must be beneath the supplied workspace. Inputs are hash-recorded.
"""
import argparse, pathlib, json, hashlib, subprocess, shutil, base64, os, sys
HERE=pathlib.Path(__file__).resolve().parent

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def under(p,root):
 p=p.resolve();assert p.is_relative_to(root.resolve()),('outside workspace',str(p));return p

def stage(a):
 assert (HERE/'spec/FROZEN.txt').is_file(),'RESEARCH expected-result freeze required'
 root=a.workspace.resolve();out=under(a.output,root);assert not out.exists(),'preserve evidence: choose a new output'
 out.mkdir(parents=True);o=out/'overlay';w=o/'work/m1';w.mkdir(parents=True)
 release=a.release.resolve();manifest=json.loads((release/'manifest.json').read_text())
 # Bundle helper manifests use files; refuse unverified backend/helper input.
 (out/'release-identity.json').write_text(json.dumps({'release':manifest.get('release'),'source':manifest.get('source'),'manifest_sha256':sha(release/'manifest.json'),'backend_sha256':sha(release/'flowgate')},indent=2))
 names=['flowgate','probe','kernel','classify.bpf.o','controller.py']
 for n in names:
  assert sha(release/n)==manifest['files'][n],('release mismatch',n)
  shutil.copy2(release/n,w/('flowgate-new' if n=='flowgate' else n))
 for n in ['alpha','beta','gamma','denied']:shutil.copy2(a.helpers/'sender',w/n)
 shutil.copy2(a.helpers/'inspect',w/'inspect')
 for n in ['common.py','peer.py','matrix.json','measure.py','priority.py','priority_assess.py']:shutil.copy2(HERE/n,w/n)
 shutil.copy2(HERE/(a.case+'.py'),w/'case.py')
 shutil.copytree(HERE/'spec',w/'spec')
 (w/'run.py').write_text("import common\ncommon.run('core')\n")
 files=['/usr/bin/tc','/usr/bin/ethtool','/usr/lib/libxtables.so.12']
 for exe in ['/usr/bin/tc','/usr/bin/ethtool',str(a.helpers/'sender'),str(a.helpers/'inspect')]+[str(release/n) for n in ['flowgate','probe','kernel']]:
  r=subprocess.run(['ldd',exe],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
  assert r.returncode==0 or 'not a dynamic' in r.stdout or 'statically linked' in r.stdout,r.stdout
  for tok in r.stdout.split():
   if tok.startswith('/') and pathlib.Path(tok).is_file():files.append(tok)
 for src in set(files):
  dst=o/src.lstrip('/');dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(src,dst)
 mods=['dummy','xt_bpf','nft_compat','nf_conntrack_netlink','veth','netdevsim','nf_tables','nfnetlink_queue','nft_queue','nft_ct','nf_conntrack','inet_diag','tcp_diag','udp_diag','sch_htb','cls_bpf','cls_matchall','act_gact','sch_ingress','ifb','act_mirred','virtio_net','virtio_console','sch_fq_codel']
 for name in mods:
  for line in subprocess.check_output(['modprobe','-S',a.kernel_release,'--show-depends',name],text=True).splitlines():
   if line.startswith('insmod '):
    src=pathlib.Path(line.split()[1]);dst=o/'usr/lib/modules'/a.kernel_release/src.relative_to('/lib/modules/'+a.kernel_release);dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(src,dst)
 for src in pathlib.Path('/usr/lib/modules',a.kernel_release).glob('modules.*'):
  dst=o/'usr/lib/modules'/a.kernel_release/src.name;dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(src,dst)
 # Internal netdevsim pair; QEMU has no host-visible uplink/share/socket bridge.
 (o/'guest-run.sh').write_text('''#!/bin/sh
set -eu
[ "$(uname -r)" = "'''+a.kernel_release+'''" ]
cd /work
mkdir -p /sys/fs/bpf
mount -t bpf bpf /sys/fs/bpf
mkdir -p /sys/fs/bpf/m0
for m in xt_bpf nft_compat sch_htb cls_bpf cls_matchall act_gact sch_ingress ifb act_mirred sch_fq_codel netdevsim; do modprobe "$m"; done
export FLOWGATE_PARENT_NETNS="$(readlink /proc/self/ns/net)"
export ACCEPTANCE_MODE="'''+a.mode+'''"
export ACCEPTANCE_CELLS="'''+a.cells+'''"
trap 'python3 /work/m1/export.py' EXIT
echo fq_codel > /proc/sys/net/core/default_qdisc
mkdir -p /var/run/netns
ip netns add shaping
echo '10 1' > /sys/bus/netdevsim/new_device
echo '11 1' > /sys/bus/netdevsim/new_device
sleep 1
a=$(ls /sys/bus/netdevsim/devices/netdevsim10/net/ | head -1)
b=$(ls /sys/bus/netdevsim/devices/netdevsim11/net/ | head -1)
ia=$(cat /sys/class/net/$a/ifindex); ib=$(cat /sys/class/net/$b/ifindex)
exec 3</proc/self/ns/net
echo "3:$ia 3:$ib" > /sys/bus/netdevsim/link_device
exec 3<&-
ip link set "$a" name nsim0; ip link set "$b" name nsim1
ip link set nsim0 netns shaping; ip link set nsim1 netns shaping
ip netns exec shaping unshare --pid --fork --mount-proc sh -c 'ip link set lo up; mkdir -p /sys/fs/bpf; mount -t bpf bpf /sys/fs/bpf; mkdir -p -m 700 /work/.workspace/m1; exec python3 /work/m1/run.py'
''');(o/'guest-run.sh').chmod(0o755)
 (w/'export.py').write_text('''import pathlib,json,base64
print('M1_EXPORT_BEGIN',flush=True)
for f in sorted(pathlib.Path('/work/.workspace/m1').rglob('*')):
 if f.is_file() and f.suffix in ('.json','.err','.txt') and f.stat().st_size<=64*1024*1024:
  print(json.dumps({'name':str(f.relative_to('/work/.workspace/m1')).replace('/','__'),'b64':base64.b64encode(f.read_bytes()).decode()}),flush=True)
print('M1_EXPORT_END',flush=True)
''')
 inputs={str(p.resolve()):sha(p) for p in list(HERE.glob('*.py'))+[p for p in (HERE/'spec').rglob('*') if p.is_file()]+[HERE/'matrix.json',HERE/'EXPECTATIONS.txt',a.kernel,a.base_initrd,release/'manifest.json',a.helpers/'sender',a.helpers/'inspect']}
 staged={str(p.relative_to(o)):sha(p) for p in o.rglob('*') if p.is_file()}
 (out/'provenance.json').write_text(json.dumps({'inputs':inputs,'staged':staged,'mode':a.mode,'case':a.case,'kernel_release':a.kernel_release},indent=2))
 with (out/'overlay.gz').open('wb') as f:
  find=subprocess.Popen(['find','.','-print0'],cwd=o,stdout=subprocess.PIPE)
  cpio=subprocess.Popen(['cpio','--null','-o','--format=newc','--owner=0:0'],cwd=o,stdin=find.stdout,stdout=subprocess.PIPE,stderr=subprocess.PIPE);find.stdout.close()
  subprocess.run(['gzip','-1'],stdin=cpio.stdout,stdout=f,check=True);cpio.stdout.close();assert cpio.wait()==0 and find.wait()==0
 with (out/'initramfs.gz').open('wb') as f:
  for p in [a.base_initrd,out/'overlay.gz']:
   with p.open('rb') as src:shutil.copyfileobj(src,f)
 shutil.copy2(a.kernel,out/'vmlinuz')
 (out/'image-hashes.json').write_text(json.dumps({n:sha(out/n) for n in ['vmlinuz','initramfs.gz']},indent=2))
 print(out,flush=True)

def run(a):
 out=under(a.output,a.workspace);assert not (out/'serial.log').exists(),'never overwrite evidence'
 for n,digest in json.loads((out/'image-hashes.json').read_text()).items():assert sha(out/n)==digest,n
 args=['timeout',str(a.timeout),'qemu-system-x86_64','-accel','tcg,thread=single','-cpu','max','-smp','1','-m',str(a.memory_mib),'-no-reboot','-nographic','-monitor','none','-nic','none','-kernel',str(out/'vmlinuz'),'-initrd',str(out/'initramfs.gz'),'-append','console=ttyS0 rdinit=/init panic=1 quiet']
 (out/'command.json').write_text(json.dumps(args,indent=2))
 with (out/'serial.log').open('wb') as f:r=subprocess.run(args,stdout=f,stderr=subprocess.STDOUT)
 export=False;ev=out/'evidence';ev.mkdir()
 for line in (out/'serial.log').read_text(errors='replace').splitlines():
  if line.endswith('M1_EXPORT_BEGIN'):export=True;continue
  if line.endswith('M1_EXPORT_END'):export=False;continue
  if not export:continue
  try:item=json.loads(line)
  except json.JSONDecodeError:continue
  name=item['name'];assert pathlib.Path(name).name==name and name not in ('.','..')
  (ev/name).write_bytes(base64.b64decode(item['b64'],validate=True))
 ok=r.returncode==0 and 'VM_RESULT=0' in (out/'serial.log').read_text(errors='replace')
 (out/'execution.json').write_text(json.dumps({'exit':r.returncode,'guest_passed':ok}))
 print(json.dumps({'output':str(out),'guest_passed':ok}),flush=True)
 return 0 if ok else 1

if __name__=='__main__':
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('operation',choices=['stage','run']);ap.add_argument('--workspace',type=pathlib.Path,required=True);ap.add_argument('--output',type=pathlib.Path,required=True);ap.add_argument('--cells',default='');ap.add_argument('--case',choices=['core','extensions','reference'],default='core');ap.add_argument('--mode',choices=['fast','protected','off']);ap.add_argument('--release',type=pathlib.Path);ap.add_argument('--helpers',type=pathlib.Path);ap.add_argument('--kernel',type=pathlib.Path);ap.add_argument('--base-initrd',type=pathlib.Path);ap.add_argument('--kernel-release',default='7.3.0-4-cachyos');ap.add_argument('--timeout',type=int,default=1800);ap.add_argument('--memory-mib',type=int,choices=[2048,4096],default=2048)
 a=ap.parse_args();assert 1<=a.timeout<=3600
 if a.operation=='stage':
  assert all([a.mode,a.release,a.helpers,a.kernel,a.base_initrd]);assert all(c.isalnum() or c in '-,' for c in a.cells);stage(a)
 else:sys.exit(run(a))
