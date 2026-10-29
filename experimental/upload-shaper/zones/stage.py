import pathlib,shutil,subprocess,hashlib,json,os
base=pathlib.Path(__file__).resolve().parents[3];import sys
case=sys.argv[1] if len(sys.argv)>1 else 'receivers'
if case not in ('receivers','capacity','api','reclassification'):raise SystemExit('case must be receivers, capacity, api or reclassification')
d=base/'.workspace/zone-receiver';d.mkdir(parents=True,exist_ok=True);c=base/'.workspace/priority-continuation-guest/core-journey';o=d/'overlay-journey';shutil.rmtree(o,ignore_errors=True);w=o/'work/m1';w.mkdir(parents=True,exist_ok=True)
wt=base/'experimental/upload-shaper'
for src,name in [('helpers/probe','probe'),('helpers/kernel','kernel'),('helpers/classify.bpf.o','classify.bpf.o'),('helpers/inspect','inspect'),('helpers/sender','alpha'),('helpers/sender','beta'),('helpers/sender','gamma'),('helpers/sender','denied')]:shutil.copy2(c/src,w/name)
if case=='reclassification':shutil.copy2(d/'classifier-driver',w/'classifier-driver')
shutil.copy2(d/'flowgate-new',w/'flowgate-new');shutil.copy2(wt/'controller.py',w/'controller.py');shutil.copy2(wt/'tests/peer.py',w/'peer.py');shutil.copy2(base/'experimental/upload-shaper/zones/common.py',w/'common.py');shutil.copy2(base/'experimental/upload-shaper/zones'/(case+'.py'),w/'case.py');(w/'run.py').write_text('import common\ncommon.run('+repr(case)+')\n')
# Small dependency overlay; reuse the original bounded initramfs unchanged.
files=['/usr/bin/tc','/usr/bin/ethtool','/usr/lib/libxtables.so.12']
for exe in ['/usr/bin/tc','/usr/bin/ethtool',str(c/'helpers/kernel'),str(c/'helpers/sender')]:
 for line in subprocess.check_output(['ldd',exe],text=True).splitlines():
  for s in line.split():
   if s.startswith('/') and pathlib.Path(s).is_file():files.append(s)
for s in set(files):
 dst=o/s.lstrip('/');dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(s,dst)
(o/'guest-run.sh').write_text('''#!/bin/sh
set -eu
cd /work
mkdir -p /sys/fs/bpf
mount -t bpf bpf /sys/fs/bpf
mkdir -p /sys/fs/bpf/m0
for m in sch_htb cls_bpf cls_matchall act_gact sch_ingress ifb act_mirred virtio_net sch_fq_codel netdevsim virtio_console; do modprobe "$m"; done
parent=$(readlink /proc/self/ns/net)
export FLOWGATE_PARENT_NETNS="$parent"
trap 'python3 /work/m1/export.py' EXIT
echo fq_codel > /proc/sys/net/core/default_qdisc
mkdir -p /var/run/netns
ip netns add shaping
ip link set eth0 netns shaping
ip link set eth1 netns shaping
echo "10 1" > /sys/bus/netdevsim/new_device
echo "11 1" > /sys/bus/netdevsim/new_device
sleep 1
a=$(ls /sys/bus/netdevsim/devices/netdevsim10/net/ | head -1); b=$(ls /sys/bus/netdevsim/devices/netdevsim11/net/ | head -1)
ia=$(cat /sys/class/net/$a/ifindex); ib=$(cat /sys/class/net/$b/ifindex)
exec 3</proc/self/ns/net
echo "3:$ia 3:$ib" > /sys/bus/netdevsim/link_device
exec 3<&-
ip link set "$a" name nsim0; ip link set "$b" name nsim1
ip link set nsim0 netns shaping
ip link set nsim1 netns shaping
ip netns exec shaping unshare --pid --fork --mount-proc sh -c 'ip link set lo up; mkdir -p /sys/fs/bpf; mount -t bpf bpf /sys/fs/bpf; mkdir -p -m 700 /work/.workspace/m1; chmod 700 /work/.workspace/m1; exec python3 /work/m1/run.py'
''');(o/'guest-run.sh').chmod(0o755)
(w/'export.py').write_text('''import pathlib,json,base64
p=pathlib.Path('/work/.workspace/m1')
print('M1_EXPORT_BEGIN',flush=True)
for f in sorted(p.rglob('*')):
 if f.is_file() and f.suffix in ('.json','.err','.txt','.pprof') and f.stat().st_size<=(16 if f.name=='records.json' else 4)*1024*1024:
  print(json.dumps({'name':str(f.relative_to(p)).replace('/','__'),'b64':base64.b64encode(f.read_bytes()).decode()}),flush=True)
print('M1_EXPORT_END',flush=True)
''')
# Pin the replacement kernel and only required module dependencies. Host modules are not loaded.
release='7.3.0-4-cachyos'

mods=['nf_conntrack_netlink','veth','netdevsim','nf_tables','nfnetlink_queue','nft_queue','nft_ct','nf_conntrack','inet_diag','tcp_diag','udp_diag','sch_htb','cls_bpf','cls_matchall','act_gact','sch_ingress','ifb','act_mirred','virtio_net','virtio_console','sch_fq_codel']
for name in mods:
 for line in subprocess.check_output(['modprobe','-S',release,'--show-depends',name],text=True).splitlines():
  if line.startswith('insmod '):
   src=pathlib.Path(line.split()[1]);dst=o/'usr/lib/modules'/release/src.relative_to('/lib/modules/'+release);dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(src,dst)
for src in pathlib.Path('/usr/lib/modules/'+release).glob('modules.*'):
 dst=o/'usr/lib/modules'/release/src.name;dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(src,dst)
manifest={str(p.relative_to(o)):hashlib.sha256(p.read_bytes()).hexdigest() for p in o.rglob('*') if p.is_file()};(d/('staged-hashes.json')).write_text(json.dumps(manifest,indent=2)+'\n')
with (d/'overlay-journey.cpio.gz').open('wb') as out:
 find=subprocess.Popen(['find','.','-print0'],cwd=o,stdout=subprocess.PIPE)
 cpio=subprocess.Popen(['cpio','--null','-o','--format=newc','--owner=0:0'],cwd=o,stdin=find.stdout,stdout=subprocess.PIPE,stderr=subprocess.PIPE);find.stdout.close()
 gz=subprocess.run(['gzip','-1'],stdin=cpio.stdout,stdout=out,check=True);cpio.stdout.close();assert cpio.wait()==0;assert find.wait()==0
with (d/'initramfs-journey.gz').open('wb') as out:
 for src in [base/'.workspace/holder-work/initramfs.gz',d/'overlay-journey.cpio.gz']:
  with src.open('rb') as f:shutil.copyfileobj(f,out,1<<20)
print('Staged',len(manifest),'files; reused base initramfs, no runtime tree copy')
