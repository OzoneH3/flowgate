import subprocess,sys,pathlib
p=pathlib.Path(__file__).resolve().parents[3]/'.workspace/zone-receiver'
args=['timeout','3600','qemu-system-x86_64','-accel','tcg,thread=single','-cpu','max','-smp','1','-m','2048','-no-reboot','-nographic','-monitor','none','-netdev','hubport,id=n0,hubid=0','-device','virtio-net-pci,netdev=n0,mq=off,mac=52:54:00:00:00:11','-netdev','hubport,id=n1,hubid=0','-device','virtio-net-pci,netdev=n1,mq=off,mac=52:54:00:00:00:12','-kernel',str(p.parent/'shaping-m1/vmlinuz'),'-initrd',str(p/'initramfs-journey.gz'),'-append','console=ttyS0 rdinit=/init panic=1 quiet']
c=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.STDOUT);passed=False
for line in c.stdout:
 sys.stdout.buffer.write(line);sys.stdout.buffer.flush()
 if line.strip()==b'VM_RESULT=0':passed=True
sys.exit(0 if c.wait()==0 and passed else 1)
