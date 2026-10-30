"""Disposable guest only; no host privilege, network attachment, or service action."""
import pathlib,subprocess,json,hashlib,sys,base64
ROOT=pathlib.Path('/home/flowgate-user/Apps/flowgate')
C=ROOT/'.workspace/socket-auth-prototype'
for arm in ('control','candidate'):
 d=C/('.workspace/socket-shaping-'+arm)
 assert (d/'fixture-provenance.json').is_file(), 'stage reviewed fixtures first'
 out=d/'serial.log';assert not out.exists(),'refuse to overwrite test evidence'
 args=['timeout','900','qemu-system-x86_64','-accel','tcg,thread=single','-cpu','max','-smp','1','-m','2048','-no-reboot','-nographic','-monitor','none','-netdev','hubport,id=n0,hubid=0','-device','virtio-net-pci,netdev=n0,mq=off,mac=52:54:00:00:00:11','-netdev','hubport,id=n1,hubid=0','-device','virtio-net-pci,netdev=n1,mq=off,mac=52:54:00:00:00:12','-kernel',str(ROOT/'.workspace/shaping-m1/vmlinuz'),'-initrd',str(d/'initramfs-journey.gz'),'-append','console=ttyS0 rdinit=/init panic=1 quiet']
 (d/'run-provenance.json').write_text(json.dumps({'runner':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),'kernel':hashlib.sha256((ROOT/'.workspace/shaping-m1/vmlinuz').read_bytes()).hexdigest(),'initramfs':hashlib.sha256((d/'initramfs-journey.gz').read_bytes()).hexdigest(),'args':args},indent=2)+'\n')
 print('RUN shaping '+arm+' in disposable VM; bounded 900 seconds',flush=True)
 with out.open('wb') as f:r=subprocess.run(args,stdout=f,stderr=subprocess.STDOUT)
 text=out.read_text(errors='replace');export=False;ev=d/'evidence';ev.mkdir()
 for line in text.splitlines():
  if line=='M1_EXPORT_BEGIN':export=True;continue
  if line=='M1_EXPORT_END':export=False;continue
  if not export:continue
  try:item=json.loads(line)
  except json.JSONDecodeError:continue
  name=item.get('name','');assert name and pathlib.Path(name).name==name and name not in ('.','..')
  (ev/name).write_bytes(base64.b64decode(item['b64'],validate=True))
 passed=r.returncode==0 and 'VM_RESULT=0' in text and (ev/'success.json').is_file()
 print('shaping '+arm+': '+('PASS' if passed else 'FAIL')+' ; evidence: '+str(d),flush=True)
 if not passed:sys.exit(1)
