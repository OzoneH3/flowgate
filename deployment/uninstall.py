#!/usr/bin/python3
"""Explicit local uninstall; preserves immutable rollback artifacts and all data."""
import os,pathlib,subprocess
if os.geteuid()!=0:raise SystemExit('Root required')
root=pathlib.Path('/usr/local/lib/flowgate/current').resolve(strict=True)
paths=[(pathlib.Path('/etc/systemd/system/flowgate.service'),'flowgate.service'),(pathlib.Path('/etc/systemd/system/flowgate-guard.service'),'flowgate-guard.service'),(pathlib.Path('/etc/systemd/system/NetworkManager.service.d/50-flowgate-guard.conf'),'50-flowgate-guard.conf')]
for path,name in paths:
 if path.exists()and path.read_bytes()!=(root/name).read_bytes():raise SystemExit(f'{path} changed; inspect before removing')
subprocess.run(['/usr/local/sbin/flowgate-recover'],check=True)
subprocess.run(['systemctl','disable','--now','flowgate.service','flowgate-guard.service'],check=True)
for path,_ in paths:path.unlink(missing_ok=True)
subprocess.run(['systemctl','daemon-reload'],check=True)
print('Daemon and startup disabled, owned interception removed. Policies, backup database and immutable releases preserved. Foreign networking unchanged.')
