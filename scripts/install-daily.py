#!/usr/bin/env python3
"""Authenticated, single-stage local installation. Never invoked by Electron.
Requires a prepared immutable-hash bundle and successful isolated acceptance.
Copies artifacts BEFORE stopping the old writer; no checkout path in the service.
"""
import argparse,hashlib,json,os,pathlib,shutil,socket,sqlite3,struct,subprocess,sys,tempfile,time

def classify_preflight(report):
 # Doctor never activates. Recognize its exact versioned prerequisite results;
 # a deferred result remains not_checked and must succeed at guarded startup.
 ready_codes={
  'dependency.ip':'executable_located','dependency.nft':'executable_located',
  'firewall.interfaces':'interfaces_inspected',
  'firewall.legacy.ip_tables_names':'legacy_tables_absent',
  'firewall.legacy.ip6_tables_names':'legacy_tables_absent',
  'firewall.ruleset':'ruleset_inspected','firewall.queue_census':'queue_census',
  'firewall.tailscale':'tailscale_client_supported',
 }
 deferred_codes={'firewall.activation':'not_attempted','firewall.queue_census':'probe_failed'}
 if report.get('schema_version')!=1 or not isinstance(report.get('checks'),list):
  raise ValueError('Unrecognized doctor report schema; old runtime preserved')
 refused=[];deferred=[];seen=set()
 for c in report['checks']:
  if not isinstance(c,dict)or not isinstance(c.get('id'),str):
   raise ValueError('Malformed doctor check; old runtime preserved')
  key=c['id']
  if not key.startswith('firewall.')and key not in ('dependency.ip','dependency.nft'):continue
  if key in seen:raise ValueError('Duplicate doctor prerequisite '+key)
  seen.add(key)
  if c.get('status')=='ready'and ready_codes.get(key)==c.get('code')and key in ready_codes:continue
  if c.get('status')=='not_checked'and deferred_codes.get(key)==c.get('code')and key in deferred_codes:
   deferred.append(c)
  else:refused.append(c)
 required=(set(ready_codes)-{'firewall.tailscale'})|{'firewall.activation'}
 if required-seen:raise ValueError('Missing doctor prerequisites: '+','.join(sorted(required-seen)))
 return refused,deferred

p=argparse.ArgumentParser();p.add_argument('--bundle',required=True);a=p.parse_args()
if os.geteuid()!=0:raise SystemExit('Run this prepared installer once with terminal sudo')
bundle=pathlib.Path(a.bundle).resolve(strict=True);manifest=json.loads((bundle/'manifest.json').read_text())
assert manifest['isolated_passed'] is True

def command(*argv,**kw):return subprocess.run(argv,check=True,text=True,**kw)
def output(*argv):return subprocess.check_output(argv,text=True)
def api(op='list',**q):
 with socket.socket(socket.AF_UNIX)as s:
  s.settimeout(10);s.connect('/run/flowgate-api/daemon.sock');cred=struct.unpack('3i',s.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12));assert cred[1]==0
  s.sendall((json.dumps(dict(version=1,operation=op,**q))+'\n').encode());r=json.loads(s.makefile('rb').readline());assert not r.get('error'),r
  return cred,r

def safe_dir(path,mode):
 path=pathlib.Path(path)
 for parent in [path,*path.parents]:
  if parent.exists():
   st=parent.lstat();assert parent.is_dir()and not parent.is_symlink()and st.st_uid==0 and st.st_mode&0o022==0,('unsafe root path',parent)
 if not path.exists():path.mkdir(mode=mode)
 return path

def atomic(path,data,mode=0o644):
 path=pathlib.Path(path);fd,tmp=tempfile.mkstemp(prefix='.flowgate-',dir=path.parent)
 try:
  with os.fdopen(fd,'wb')as f:f.write(data);f.flush();os.fsync(f.fileno());os.fchmod(f.fileno(),mode)
  os.replace(tmp,path);d=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(d);os.close(d)
 finally:
  if os.path.exists(tmp):os.unlink(tmp)

# All privileged execution comes from validated root-owned copied files.
base=safe_dir('/usr/local/lib/flowgate',0o755);releases=safe_dir(base/'releases',0o755)
release=releases/manifest['release'];assert release.name==manifest['release']and '/'not in release.name
if release.exists():raise SystemExit('Release already installed: inspect it instead of rerunning this stage')
release.mkdir(mode=0o755)
for name,expected in manifest['files'].items():
 assert '/'not in name and name not in ['.','..']
 data=(bundle/name).read_bytes();assert hashlib.sha256(data).hexdigest()==expected,(name,'hash mismatch')
 atomic(release/name,data,0o755 if name in manifest['executables']else 0o644)
atomic(release/'manifest.json',json.dumps(manifest,indent=2).encode())
run=safe_dir('/var/lib/flowgate',0o700);backups=safe_dir(run/'backups',0o700);backup=safe_dir(backups/manifest['release'],0o700)
# Readiness remains read-only and authoritative, before any runtime handoff.
report=json.loads(output(str(release/'flowgate'),'doctor','--json','--profile','both','--administrator'))
(backup/'preflight.json').write_text(json.dumps(report,indent=2))
refused,deferred=classify_preflight(report)
(backup/'preflight-disposition.json').write_text(json.dumps({'refused':refused,'deferred_to_guarded_activation':deferred},indent=2))
if refused:raise SystemExit('Readiness refused; old daemon preserved: '+json.dumps(refused))
cred,before=api();assert before['enforcement']['state']=='stopped', 'Stop/review existing enforcement before installing; never silently interrupt it'
assert before['permissions']['role']=='administrator'
os.umask(0o077)
(backup/'runtime-before.json').write_text(json.dumps(before,indent=2));(backup/'pid-before').write_text(str(cred[0]))
with open(f'/proc/{cred[0]}/cmdline','rb')as f:atomic(backup/'previous-argv.json',json.dumps([s.decode()for s in f.read().split(b'\0')if s]).encode(),0o600)
with open(f'/proc/{cred[0]}/exe','rb')as f:atomic(backup/'previous-daemon',f.read(),0o700)
# Online SQLite backups, never an inconsistent live database copy.
for name in ['rules.db','decisions.db']:
 path=run/name
 if path.exists():
  src=sqlite3.connect(f'file:{path}?mode=ro',uri=True);dst=sqlite3.connect(backup/name);src.backup(dst);dst.close();src.close();os.chmod(backup/name,0o600)
# Stage unit backups; preserve rather than overwrite an unrelated service.
for name in ['flowgate.service','flowgate-guard.service']:
 dest=pathlib.Path('/etc/systemd/system')/name
 if dest.exists():raise SystemExit(f'{dest} already exists; explicit upgrade path required, old runtime untouched')
config=safe_dir('/etc/flowgate',0o755)
if not (config/'zones.json').exists():
 z=before.get('network_zones')or{}
 atomic(config/'zones.json',json.dumps({'local':z.get('local_prefixes',[]),'internet':z.get('internet_prefixes',[])}).encode(),0o600)
# Monitoring first. Host acceptance explicitly activates continuous mode only
# after receiver setup and a fresh supported readiness check.
if not (run/'protection.json').exists():atomic(run/'protection.json',b'{"schema":1,"mode":"monitoring"}',0o600)
else:assert json.loads((run/'protection.json').read_text())['mode']=='monitoring','Existing desired mode needs explicit upgrade review'
old_link=os.readlink(base/'current')if(base/'current').is_symlink()else None
if (base/'current').exists()and not(base/'current').is_symlink():raise SystemExit('Unexpected current object, refusing replacement')
link=base/'.current-new';link.symlink_to(release);os.replace(link,base/'current')
for name in ['flowgate.service','flowgate-guard.service']:atomic(pathlib.Path('/etc/systemd/system')/name,(release/name).read_bytes())
drop=safe_dir('/etc/systemd/system/NetworkManager.service.d',0o755)
assert not(drop/'50-flowgate-guard.conf').exists()
atomic(drop/'50-flowgate-guard.conf',(release/'50-flowgate-guard.conf').read_bytes())
atomic('/usr/local/sbin/flowgate-control',(release/'control.py').read_bytes(),0o755)
atomic('/usr/local/sbin/flowgate-recover',(release/'recover.py').read_bytes(),0o755)
atomic('/usr/local/sbin/flowgate-uninstall',(release/'uninstall.py').read_bytes(),0o755)
command('systemd-analyze','verify','/etc/systemd/system/flowgate.service','/etc/systemd/system/flowgate-guard.service')
command(str(release/'flowgate'),'monitor-stop','--generation',before['generation'])
for _ in range(150):
 if not pathlib.Path(f'/proc/{cred[0]}').exists():break
 time.sleep(.1)
else:raise SystemExit('Old daemon has not exited; no second writer started')
try:
 command('systemd-analyze','verify','/etc/systemd/system/flowgate.service','/etc/systemd/system/flowgate-guard.service')
 command('systemctl','daemon-reload');command('systemctl','enable','flowgate-guard.service','flowgate.service');command('systemctl','start','flowgate.service')
 _,r=api();assert r['generation']!=before['generation']and r['protection']['state']=='stopped'
 assert r['build']['source']==manifest['source']and r['build']['executable_sha256']==manifest['files']['flowgate']
 assert(r.get('rules')or[])==(before.get('rules')or[]),'Policy inventory changed during handoff'
 command(sys.executable,str(release/'host-acceptance.py'),'--release',str(release),'--evidence',str(backup/'acceptance'))
 _,r=api();assert r['protection']['state']=='active'and r['protection']['profile']=='both'and r['traffic_monitor']['state']=='active'
 (backup/'runtime-final.json').write_text(json.dumps(r,indent=2))
 print('INSTALLED AND HOST-ACCEPTED',manifest['release'],r['generation']);print('Reboot acceptance still pending. Recovery: sudo /usr/local/sbin/flowgate-recover')
except Exception:
 # Never downgrade/delete schema4/process inventory. Use the tested new daemon
 # in monitoring mode, retain all evidence and root-owned previous artifact.
 print('INSTALL/ACCEPTANCE FAILED; restoring monitoring, not claiming protection',file=sys.stderr)
 subprocess.run(['/usr/local/sbin/flowgate-recover'],check=False)
 raise
