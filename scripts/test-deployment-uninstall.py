#!/usr/bin/env python3
"""Unprivileged uninstall ordering trace. No systemd calls or host writes."""
import json,os,pathlib,subprocess,sys,tempfile,types
root=pathlib.Path(__file__).resolve().parents[1]
run=pathlib.Path(tempfile.mkdtemp(prefix='uninstall-trace-',dir=root/'.workspace'))
release=run/'release';release.mkdir()
names=['flowgate.service','flowgate-guard.service','50-flowgate-guard.conf']
targets={}
for full,name in zip(['/etc/systemd/system/flowgate.service','/etc/systemd/system/flowgate-guard.service','/etc/systemd/system/NetworkManager.service.d/50-flowgate-guard.conf'],names):
 p=run/name;p.write_text('owned '+name);(release/name).write_bytes(p.read_bytes());targets[full]=p
def path(value):
 value=str(value)
 if value=='/usr/local/lib/flowgate/current':return release
 return targets[value]
commands=[]
def execute(argv,**kw):
 assert kw.get('check')is True
 if argv[:3]==['systemctl','disable','--now']:
  assert not targets['/etc/systemd/system/NetworkManager.service.d/50-flowgate-guard.conf'].exists()
  assert commands[-1]==['systemctl','daemon-reload']
 commands.append(argv);return types.SimpleNamespace(returncode=0)
mods={'pathlib':types.SimpleNamespace(Path=path),'subprocess':types.SimpleNamespace(run=execute),'os':types.SimpleNamespace(geteuid=lambda:0)}
original={k:sys.modules[k]for k in mods}
try:
 sys.modules.update(mods)
 exec(compile((root/'deployment/uninstall.py').read_text(),'uninstall-under-test','exec'),{})
finally:sys.modules.update(original)
assert commands==[['/usr/local/sbin/flowgate-recover'],['systemctl','daemon-reload'],['systemctl','disable','--now','flowgate.service','flowgate-guard.service'],['systemctl','daemon-reload']]
assert all(not p.exists()for p in targets.values())
assert all((release/name).exists()for name in names)
(run/'result.json').write_text(json.dumps({'passed':True,'commands':commands,'label':'mocked uninstall ordering, not actual installed systemd'},indent=2))
print('PASS uninstall detaches NetworkManager dependency before stopping guard; immutable artifacts preserved; no host actions')
