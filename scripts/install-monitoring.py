#!/usr/bin/env python3
"""Authenticated MONITORING-ONLY installation of a prepared immutable bundle.

Never starts protection, never runs the receiver/enforcement acceptance stage and
never installs the NetworkManager Requires= drop-in. Persists desired monitoring
before the first start, preserves rules or verifies their explicit startup migration/archive and all foreign
firewall/routing/Tailscale/bpftune state. Run once with terminal sudo.
"""
import argparse,hashlib,json,os,pathlib,socket,sqlite3,struct,subprocess,sys,tempfile,time

UNITS=['flowgate.service','flowgate-guard.service']
DROPIN='/etc/systemd/system/NetworkManager.service.d/50-flowgate-guard.conf'
TOOLS={'control.py':'/usr/local/sbin/flowgate-control','recover.py':'/usr/local/sbin/flowgate-recover','uninstall.py':'/usr/local/sbin/flowgate-uninstall'}
OWNED_TABLES={'flowgate_guard','flowgate_host'}
MONITORING=b'{"schema":1,"mode":"monitoring"}'

class Host:
 """Every privileged boundary. Tests substitute a temp-root/mocked implementation."""
 def path(self,p):return pathlib.Path(p)
 def run(self,*argv):return subprocess.run(argv,check=True,text=True,capture_output=True).stdout
 def api(self,op='list',**q):
  with socket.socket(socket.AF_UNIX)as s:
   s.settimeout(20);s.connect('/run/flowgate-api/daemon.sock')
   pid,uid,_=struct.unpack('3i',s.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12));assert uid==0,'API peer is not root'
   s.sendall((json.dumps(dict(version=1,operation=op,**q))+'\n').encode());r=json.loads(s.makefile('rb').readline())
   assert not r.get('error'),r
   return pid,r
 def daemon_pids(self):
  out=[]
  for p in pathlib.Path('/proc').iterdir():
   if p.name.isdigit():
    try:a=(p/'cmdline').read_bytes().split(b'\0')
    except OSError:continue
    if len(a)>1 and a[1]==b'serve' and a[0].endswith(b'/flowgate'):out.append(int(p.name))
  return out
 def sleep(self,s):time.sleep(s)
 def root_owned(self,st):return st.st_uid==0 and st.st_mode&0o022==0

def sha(b):return hashlib.sha256(b).hexdigest()

def atomic(h,path,data,mode=0o644):
 path=h.path(path);fd,tmp=tempfile.mkstemp(prefix='.flowgate-',dir=path.parent)
 try:
  with os.fdopen(fd,'wb')as f:f.write(data);f.flush();os.fsync(f.fileno());os.fchmod(f.fileno(),mode)
  os.replace(tmp,path)
 finally:
  if os.path.exists(tmp):os.unlink(tmp)

def safe_dir(h,path,mode):
 p=h.path(path)
 if p.exists():
  assert p.is_dir()and not p.is_symlink()and h.root_owned(p.lstat()),('unsafe root path',path)
 else:p.mkdir(mode=mode,parents=True)
 return p

def known_contents(h,name,release_dir):
 """Exact FlowGate-shipped bytes for a unit/drop-in from any retained immutable release."""
 known=set()
 for r in [release_dir,*sorted(h.path('/usr/local/lib/flowgate/releases').glob('*'))]:
  f=r/name
  if f.is_file():known.add(f.read_bytes())
 return known

def rule_inventory(db):
 """Read-only (id, version) inventory from a consistent backup copy."""
 if not db.exists():return []
 c=sqlite3.connect(f'file:{db}?mode=ro',uri=True)
 try:rows=c.execute('SELECT id,document FROM rules').fetchall()
 except sqlite3.OperationalError:rows=[]
 finally:c.close()
 return sorted((i,json.loads(d).get('version'))for i,d in rows)

def rule_documents(db):
 if not db.exists():return {},[]
 c=sqlite3.connect(f'file:{db}?mode=ro',uri=True)
 try:
  c.execute('BEGIN')
  rules={i:json.loads(d)for i,d in c.execute('SELECT id,document FROM rules')}
  exists=c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='archived_rules'").fetchone()
  archived=[(i,json.loads(d),reason)for i,d,reason in c.execute('SELECT rule_id,document,reason FROM archived_rules')]if exists else[]
  return rules,archived
 finally:c.close()

def verified_rule_transition(before_db,after_db,administrator_uid=1000):
 """Accept only exact root-scope migrations or losslessly archived cleanup."""
 before,old_archives=rule_documents(before_db);after,archives=rule_documents(after_db)
 # Only a new archive from this startup can explain a disappearing active rule.
 for previous in old_archives:
  if previous in archives:archives.remove(previous)
 if set(after)-set(before):raise RuntimeError('Unexpected new rule during installation')
 for rid,old in before.items():
  new=after.get(rid)
  if new is None:
   if not any(i==rid and d==old and reason in ('expired','replaced executable; no old process found')for i,d,reason in archives):
    raise RuntimeError('Rule disappeared without matching cleanup archive: '+rid)
   continue
  if new==old:continue
  f=old.get('filter')or{};uid=f.get('uid');path=old.get('executable','')
  native=lambda u:sha(f'{u}|native||{path}'.encode())
  name=pathlib.PurePosixPath(path).name.lower()
  interpreter=any(name==n or(name.startswith(n)and not name[len(n):].strip('0123456789.'))for n in ('python','bash','sh','dash','zsh','fish','perl','ruby','node','java','lua','php','mono','dotnet'))
  eligible=uid==administrator_uid and isinstance(uid,int)and uid>0 and not interpreter and not old.get('invocation') and path.startswith('/')and f.get('application')==native(uid)and not(old.get('preset')or f.get('process')or f.get('all_programs')or f.get('all_uids'))
  expected=dict(old)
  if eligible:expected['root_application']=native(0)
  else:expected.pop('root_application',None)
  if expected!=old:expected['version']=old.get('version',0)+1
  if new!=expected:raise RuntimeError('Unexpected rule mutation during installation: '+rid)
 return sorted((i,d.get('version'))for i,d in after.items())

def api_inventory(r):return sorted((x['id'],x.get('version'))for x in(r.get('rules')or[]))

def verify_monitoring(r,manifest,before_rules):
 problems=[]
 b=r.get('build')or{}
 if b.get('source')!=manifest['source']or b.get('executable_sha256')!=manifest['files']['flowgate']:problems.append(('build',b))
 p=r.get('protection')or{}
 if p.get('state')!='stopped'or p.get('desired_mode')!='monitoring':problems.append(('protection',p))
 if (r.get('enforcement')or{}).get('state')!='stopped':problems.append(('enforcement',r.get('enforcement')))
 if api_inventory(r)!=before_rules:problems.append(('rules',api_inventory(r),before_rules))
 if 'essential-system-networking-v1'not in(r.get('capabilities')or[]):problems.append(('capability','essential-system-networking-v1 missing'))
 return problems

def flowgate_tables(h):
 out=json.loads(h.run('nft','-j','list','tables'))
 return sorted({o['table']['name']for o in out.get('nftables',[])if 'table'in o and o['table']['name']in OWNED_TABLES})

def install(h,bundle,stamp):
 manifest=json.loads((bundle/'manifest.json').read_text());assert manifest['isolated_passed']is True
 base=safe_dir(h,'/usr/local/lib/flowgate',0o755);releases=safe_dir(h,'/usr/local/lib/flowgate/releases',0o755)
 name=manifest['release'];assert name and '/'not in name and name not in('.','..')
 release=releases/name
 # 1. Immutable release: verify every bundle hash; an existing identical release is reused, never altered.
 if release.exists():
  for f,want in manifest['files'].items():assert sha((release/f).read_bytes())==want,('installed release differs',f)
 else:
  staging=releases/('.staging-'+name);assert not staging.exists();staging.mkdir(mode=0o755)
  os.chmod(staging,0o755)  # explicit: the installer umask is 077; releases stay world-readable like earlier ones
  for f,want in manifest['files'].items():
   assert '/'not in f;data=(bundle/f).read_bytes();assert sha(data)==want,(f,'hash mismatch')
   atomic(h,staging/f,data,0o755 if f in manifest['executables']else 0o644)
  atomic(h,staging/'manifest.json',json.dumps(manifest,indent=2).encode())
  os.replace(staging,release)
 # 2. Refuse foreign unit/drop-in content before touching runtime.
 for u in UNITS:
  dest=h.path('/etc/systemd/system')/u
  if dest.exists()and dest.read_bytes()not in known_contents(h,u,release):raise SystemExit(f'{dest} is not FlowGate-shipped content; refusing, runtime untouched')
 drop=h.path(DROPIN)
 if drop.exists()and drop.read_bytes()not in known_contents(h,'50-flowgate-guard.conf',release):raise SystemExit(f'{drop} modified; refusing, runtime untouched')
 # 3. Current runtime: never interrupt active protection.
 running=h.daemon_pids();before=None
 if running:
  pid,before=h.api()
  if (before.get('protection')or{}).get('state','stopped')!='stopped'or(before.get('enforcement')or{}).get('state')!='stopped':
   raise SystemExit('FlowGate protection is active; stop it explicitly before a monitoring install')
 # An unavailable stopped daemon can be reinstalled only after proving that
 # no interception remains and persisted startup intent is monitoring.
 if not running and (base/'current').exists():
  state=h.path('/var/lib/flowgate/protection.json')
  if not state.exists()or json.loads(state.read_text()).get('mode')!='monitoring':raise RuntimeError('Stopped-service recovery requires persisted monitoring mode')
  if flowgate_tables(h):raise RuntimeError('Stopped-service recovery refused: interception tables remain')
 # 4. Consistent backups of all state that this install touches.
 data=safe_dir(h,'/var/lib/flowgate',0o700);backup=safe_dir(h,'/var/lib/flowgate/backups',0o700)/f'{name}-monitoring-{stamp}'
 backup.mkdir(mode=0o700)
 for db in['rules.db','decisions.db']:
  src=data/db
  if src.exists():
   s=sqlite3.connect(f'file:{src}?mode=ro',uri=True);d=sqlite3.connect(backup/db);s.backup(d);d.close();s.close();os.chmod(backup/db,0o600)
 before_rules=rule_inventory(backup/'rules.db')
 for src in[data/'protection.json',*[h.path('/etc/systemd/system')/u for u in UNITS],drop,*map(h.path,TOOLS.values())]:
  if src.exists():atomic(h,backup/(src.name+'.previous'),src.read_bytes(),0o600)
 etc=h.path('/etc/flowgate')
 if etc.exists():
  for f in etc.iterdir():
   if f.is_file():atomic(h,backup/('etc-'+f.name),f.read_bytes(),0o600)
 cur=base/'current';old_link=os.readlink(cur)if cur.is_symlink()else None
 if cur.exists()and not cur.is_symlink():raise SystemExit('Unexpected current object; refusing')
 record={'release':name,'source':manifest['source'],'previous_current':old_link,'running_before':running,'runtime_before':before,'rules_before':before_rules,'stamp':stamp}
 atomic(h,backup/'install-record.json',json.dumps(record,indent=2).encode(),0o600)
 # 5. Configuration: preserve zones; persist monitoring BEFORE any start.
 safe_dir(h,'/etc/flowgate',0o755)
 if not(etc/'zones.json').exists():
  z=(before or{}).get('network_zones')or{}
  atomic(h,etc/'zones.json',json.dumps({'local':z.get('local_prefixes',[]),'internet':z.get('internet_prefixes',[])}).encode(),0o600)
 atomic(h,data/'protection.json',MONITORING,0o600)
 # 6. Stop any old writer through its own lifecycle; never two database writers.
 if running:
  if (h.path('/etc/systemd/system')/'flowgate.service').exists():h.run('systemctl','stop','flowgate.service')
  else:h.run(str(release/'flowgate'),'monitor-stop','--generation',before['generation'])
  for _ in range(300):
   if not h.daemon_pids():break
   h.sleep(.1)
  else:raise SystemExit('Old daemon has not exited; no second writer started')
 # 7. Switch artifacts. Units only; the NM Requires= drop-in is deliberately absent.
 link=base/'.current-new'
 if link.is_symlink():link.unlink()
 link.symlink_to(release);os.replace(link,cur)
 for u in UNITS:atomic(h,h.path('/etc/systemd/system')/u,(release/u).read_bytes())
 if drop.exists():drop.unlink()
 for src,dest in TOOLS.items():atomic(h,dest,(release/src).read_bytes(),0o755)
 h.run('systemctl','daemon-reload')
 h.run('systemd-analyze','verify','/etc/systemd/system/flowgate.service','/etc/systemd/system/flowgate-guard.service')
 h.run('systemctl','disable','flowgate-guard.service')  # pulled in by flowgate.service only; never WantedBy network-pre
 h.run('systemctl','enable','flowgate.service')
 try:
  h.run('systemctl','start','flowgate.service')
  r=None
  for _ in range(200):
   try:_,r=h.api();break
   except (OSError,ValueError,AssertionError):h.sleep(.25)
  if r is None:raise RuntimeError('API did not become ready')
  expected_rules=verified_rule_transition(backup/'rules.db',data/'rules.db')
  problems=verify_monitoring(r,manifest,expected_rules)
  tables=flowgate_tables(h)
  if tables:problems.append(('owned interception tables present',tables))
  pids=h.daemon_pids()
  if len(pids)!=1:problems.append(('daemon processes',pids))
  if problems:raise RuntimeError('Monitoring verification failed: '+json.dumps(problems,default=str))
  final={'generation':r['generation'],'build':r['build'],'protection':r['protection'],'enforcement':r['enforcement'],'traffic_monitor':r.get('traffic_monitor'),'rules':api_inventory(r),'capabilities':r['capabilities'],'permissions':r.get('permissions'),'owned_tables':tables,'daemon_pids':pids,'nm_dropin_installed':h.path(DROPIN).exists()}
  atomic(h,backup/'runtime-final.json',json.dumps(final,indent=2).encode(),0o600)
  print('INSTALLED IN MONITORING ONLY',name,'generation',r['generation'],'rules',len(final['rules']),'protection stopped; no interception; backup',backup)
  print('Protection was NOT activated. No essential permissions were applied.')
  return final
 except Exception:
  print('MONITORING INSTALL FAILED; stopping the new service, current data retained (startup migrations may have run), no older database/executable restored',file=sys.stderr)
  subprocess_safe(h,'systemctl','stop','flowgate.service')
  subprocess_safe(h,'systemctl','disable','flowgate.service')
  subprocess_safe(h,str(release/'flowgate'),'protection-recover','--state','/run/flowgate-enforcement')
  print('Evidence:',backup,file=sys.stderr)
  raise

def subprocess_safe(h,*argv):
 try:h.run(*argv)
 except Exception as e:print('cleanup step failed:',argv,e,file=sys.stderr)

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--bundle',required=True);a=p.parse_args()
 if os.geteuid()!=0:raise SystemExit('Run this monitoring-only installer once with terminal sudo')
 os.umask(0o077)
 install(Host(),pathlib.Path(a.bundle).resolve(strict=True),time.strftime('%Y%m%dT%H%M%S'))
