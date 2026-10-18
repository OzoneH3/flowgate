#!/usr/bin/python3
"""Local root recovery, independent of API, GUI, network and sudoers."""
import json,os,pathlib,subprocess,tempfile
if os.geteuid()!=0:raise SystemExit('Run as root from a local terminal')
root=pathlib.Path('/usr/local/lib/flowgate/current').resolve(strict=True)
# Persist intentional monitoring before stopping; no newer policy file is replaced.
path=pathlib.Path('/var/lib/flowgate/protection.json')
fd,name=tempfile.mkstemp(prefix='.recovery-',dir=path.parent)
with os.fdopen(fd,'w')as f:json.dump({'schema':1,'mode':'monitoring'},f);f.flush();os.fsync(f.fileno())
os.replace(name,path)
d=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(d);os.close(d)
subprocess.run(['systemctl','stop','flowgate.service'],check=True)
subprocess.run([str(root/'flowgate'),'protection-recover','--state','/run/flowgate-enforcement'],check=True)
subprocess.run(['systemctl','start','flowgate.service'],check=True)
print('Monitoring restored. Stored rules preserved, FlowGate interception removed; UDP restoration is independent. Inspect flowgate-control status.')
