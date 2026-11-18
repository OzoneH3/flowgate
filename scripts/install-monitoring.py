#!/usr/bin/env python3
"""Authenticated MONITORING-ONLY installation of a prepared immutable bundle.

Never starts protection, never runs the receiver/enforcement acceptance stage and
never installs the NetworkManager Requires= drop-in. Persists desired monitoring
before the first start, preserves rules or verifies their explicit startup migration/archive and all foreign
firewall/routing/Tailscale/bpftune state. Run once with terminal sudo.
"""

if not __debug__:
 raise RuntimeError('Optimized Python is unsupported: required verification checks would be disabled')

import sys
if __name__=='__main__' and not sys.flags.isolated:
 raise SystemExit('Use scripts/install-prepared.py; direct non-isolated installer execution is unsupported')

import fcntl,stat
from contextlib import closing
import argparse,hashlib,json,os,pathlib,socket,sqlite3,struct,subprocess,sys,tempfile,time

UNITS=['flowgate.service','flowgate-guard.service']
DROPIN='/etc/systemd/system/NetworkManager.service.d/50-flowgate-guard.conf'
TOOLS={'control.py':'/usr/local/sbin/flowgate-control','recover.py':'/usr/local/sbin/flowgate-recover','uninstall.py':'/usr/local/sbin/flowgate-uninstall'}
OWNED_TABLES={'flowgate_guard','flowgate_host'}
MONITORING=b'{"schema":1,"mode":"monitoring"}'

class Host:
 """Every privileged boundary. Tests substitute a temp-root/mocked implementation."""
 def path(self,p):return pathlib.Path(p)
 def run(self,*argv):return subprocess.run(argv,check=True,text=True,capture_output=True,timeout=90).stdout
 def api(self,op='list',timeout=5,*,allow_error=False,**q):
  with socket.socket(socket.AF_UNIX)as s:
   s.settimeout(timeout);s.connect('/run/flowgate-api/daemon.sock')
   pid,uid,_=struct.unpack('3i',s.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12));assert uid==0,'API peer is not root'
   s.sendall((json.dumps(dict(version=1,operation=op,**q))+'\n').encode());r=json.loads(s.makefile('rb').readline())
   if r.get('error') and not allow_error:raise RuntimeError(r['error'])
   return pid,r
 def daemon_pids(self):
  out=[]
  for p in pathlib.Path('/proc').iterdir():
   if p.name.isdigit():
    try:
     if p.stat().st_uid!=0:continue
     a=(p/'cmdline').read_bytes().split(b'\0')
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
 for parent in reversed([p,*p.parents]):
  if parent.is_symlink():raise RuntimeError('Symlink installation directory: '+str(parent))
  if not parent.exists():parent.mkdir(mode=mode if parent==p else 0o755)
  if not parent.is_dir()or not h.root_owned(parent.lstat()):raise RuntimeError('Unsafe installation directory: '+str(parent))
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

# Same rule as SCHEMA_GUARD in scripts/lib/update_and_start.py (checked by the
# consistency test). An undeclared ceiling keeps the prior value 6 only.
LEGACY_RULE_SCHEMA=6
def manifest_rule_schema(manifest):
 v=manifest.get('max_rule_schema')
 if v is None:return LEGACY_RULE_SCHEMA
 if type(v)is not int or not 1<=v<=64:raise RuntimeError('Manifest max_rule_schema invalid; current release retained')
 return v
def stored_rule_schemas(db):
 counts={}
 if not db.exists():return counts
 c=sqlite3.connect(f'file:{db}?mode=ro',uri=True)
 try:
  c.execute('BEGIN')
  try:rows=c.execute('SELECT document FROM rules').fetchall()
  except sqlite3.OperationalError as e:
   if 'no such table' not in str(e):raise
   rows=[]
 finally:c.close()
 for (document,) in rows:
  try:rule=json.loads(document)
  except ValueError:raise RuntimeError('Stored rule unreadable; current release retained')
  schema=rule.get('schema',0)if isinstance(rule,dict)else None
  if type(schema)is not int or schema<0:raise RuntimeError('Stored rule schema unreadable; current release retained')
  counts[schema]=counts.get(schema,0)+1
 return counts
def require_rule_schemas(db,ceiling):
 unsupported={s:n for s,n in stored_rule_schemas(db).items()if s>ceiling}
 if unsupported:
  detail=', '.join('%d rule(s) of schema %d'%(n,s)for s,n in sorted(unsupported.items()))
  raise RuntimeError('Candidate supports stored rule schemas up to %d, but %s exist; delete those rules first or install a build that declares support. Candidate not activated'%(ceiling,detail))

def repaired_preset_metadata(old,new):
 """Recognize metadata-only startup repair; never permit a policy-field change.

 Fresh discovery and intact preset digests are checked by the daemon. Here the
 independent installer checks the unchanged permission and its derived target.
 Unknown filter fields fail closed if the schema evolves.
 """
 p=old.get('preset');q=new.get('preset')
 if not isinstance(p,dict)or not isinstance(q,dict):return False
 if set(p)!=set(q)or set(p)!={'name','component','entry_id','revision','digest'}:return False
 if p['name']!='essential-system-networking'or q['name']!=p['name']or q['component']!=p['component']:return False
 if old.get('schema')!=5 or type(old.get('version'))is not int or not 0<old['version']<2**64-1:return False
 if type(new.get('version'))is not int or new['version']!=old['version']+1:return False
 for value in [p[k]for k in ('entry_id','revision','digest')]+[q[k]for k in ('entry_id','revision','digest')]:
  if not isinstance(value,str)or len(value)!=64 or any(c not in '0123456789abcdef'for c in value):return False
 if {k:v for k,v in old.items()if k not in ('preset','version')}!={k:v for k,v in new.items()if k not in ('preset','version')}:return False
 f=old.get('filter')
 fields='interface_index interface_name local_address peer_service zone_model network_zone all_programs all_uids application revision direction protocol remote_address local_port remote_port remote uid'.split()
 if not isinstance(f,dict)or set(f)-set(fields):return False
 target={k:f[k]for k in fields if k in f}
 if target.get('interface_name'):target.pop('interface_index',None)
 if 'peer_service'in target:
  peer=target['peer_service']
  if not isinstance(peer,dict)or set(peer)!={'application','revision','uid'}:return False
  target['peer_service']={k:peer[k]for k in ('application','revision','uid')}
 encoded=json.dumps([p['component'],target],ensure_ascii=False,separators=(',',':'))
 for char,escape in [('&','\\u0026'),('<','\\u003c'),('>','\\u003e'),('\u2028','\\u2028'),('\u2029','\\u2029')]:encoded=encoded.replace(char,escape)
 entry=sha(encoded.encode())
 return p['entry_id']!=entry and q['entry_id']==entry and p['digest']!=q['digest']

def verified_rule_transition(before_db,after_db,administrator_uid=1000):
 """Accept exact scope migrations, preset metadata repair or archived cleanup."""
 before,old_archives=rule_documents(before_db);after,archives=rule_documents(after_db)
 # Only a new archive from this startup can explain a disappearing active rule.
 for previous in old_archives:
  if previous in archives:archives.remove(previous)
 if set(after)-set(before):raise RuntimeError('Unexpected new rule during installation')
 for rid,old in before.items():
  new=after.get(rid)
  if new is None:
   if not any(i==rid and d==old and reason in ('expired','replaced executable; no old process found','superseded program scope')for i,d,reason in archives):
    raise RuntimeError('Rule disappeared without matching cleanup archive: '+rid)
   continue
  if new==old:continue
  if repaired_preset_metadata(old,new):continue
  f=old.get('filter')or{};uid=f.get('uid');path=old.get('executable','')
  native=lambda u:sha(f'{u}|native||{path}'.encode())
  eligible=old.get('share_with_root')is True and uid==administrator_uid and isinstance(uid,int)and uid>0 and path.startswith('/')and f.get('application')==native(uid)and not(old.get('preset')or f.get('process')or f.get('all_programs')or f.get('all_uids'))
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

def administrator_uid(h,existing):
 config=h.path('/etc/flowgate/administrator.json')
 if config.exists()or config.is_symlink():
  if config.is_symlink()or not config.is_file()or not h.root_owned(config.stat()):raise RuntimeError('Unsafe administrator configuration')
  uid=json.loads(config.read_text()).get('uid')
 elif existing:
  uid=1000  # Preserve the administrator of installations predating this config.
 else:
  try:uid=int(os.environ.get('SUDO_UID',''))
  except ValueError:raise RuntimeError('Fresh installation requires sudo from the intended desktop administrator')
 if type(uid)is not int or not 0<uid<2**32-1:raise RuntimeError('Invalid desktop administrator UID')
 return uid

class RollbackComplete(RuntimeError):
    """Exit 75 means the previous build/database pair is verified in monitoring."""


def snapshot_database(source, destination):
    with closing(sqlite3.connect(f'file:{source}?mode=ro', uri=True)) as src:
        with closing(sqlite3.connect(destination)) as dst:
            src.backup(dst)
    os.chmod(destination, 0o600)


def previous_release(h, base, releases):
    current = base / 'current'
    if not current.is_symlink():
        return None
    release = current.resolve(strict=True)
    if release.parent != releases or release.is_symlink():
        raise RuntimeError('Previous release is outside retained releases')
    manifest = previous_release_for_path(h, base, release)
    if not all(name in manifest['files'] for name in ['flowgate', 'launch', *UNITS, 'control.py', 'recover.py', 'uninstall.py']):
        raise RuntimeError('Previous release is incomplete')
    # Only a managed service can be restarted with a verified old configuration.
    if not h.path('/etc/systemd/system/flowgate.service').is_file():
        raise RuntimeError('Previous daemon is not a managed service')
    return release, manifest


def wait_api(h):
    deadline = time.monotonic() + 50
    for _ in range(200):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            return h.api(timeout=min(2, remaining))
        except (OSError, ValueError, RuntimeError, AssertionError):
            h.sleep(min(.25, max(0, deadline - time.monotonic())))
    raise RuntimeError('Daemon API did not become ready within verification deadline')


def wait_monitoring(h, manifest, expected_rules):
    pid, response = wait_api(h)
    problems = verify_monitoring(response, manifest, expected_rules)
    pids = h.daemon_pids()
    if len(pids) != 1 or pid not in pids:
        problems.append(('daemon processes', pids))
    if (response.get('build') or {}).get('modified') is not False:
        problems.append(('restored executable modified', response.get('build')))
    if flowgate_tables(h):
        problems.append(('interception tables remain', True))
    if problems:
        raise RuntimeError('Rollback verification failed: ' + json.dumps(problems, default=str))
    return response


def rollback(h, backup, data, base, previous, snapshot, unit_enabled):
    """Called only after the failed writer is stopped and interception is absent."""
    release, manifest = previous
    # Recheck immutable artifacts and every backup before touching any live file.
    checked = previous_release_for_path(h, base, release)
    if checked != manifest:
        raise RuntimeError('Previous release manifest changed during installation')
    for entry in snapshot.values():
        if entry and sha((backup / entry['file']).read_bytes()) != entry['sha256']:
            raise RuntimeError('Rollback backup integrity check failed')
    failed = backup / 'failed-state'
    if failed.exists():
        failed = pathlib.Path(tempfile.mkdtemp(prefix='failed-state-retry-', dir=backup))
    else:
        failed.mkdir(mode=0o700)
    for db in ['rules.db', 'decisions.db']:
        for suffix in ['', '-wal', '-shm', '-journal']:
            path = data / (db + suffix)
            if path.exists():
                atomic(h, failed / path.name, path.read_bytes(), 0o600)
    # Stopped writers only: stale WAL/SHM must never accompany the restored DB.
    for db in ['rules.db', 'decisions.db']:
        for suffix in ['-wal', '-shm', '-journal']:
            (data / (db + suffix)).unlink(missing_ok=True)
    for destination, entry in snapshot.items():
        path = h.path(destination)
        if entry is None:
            path.unlink(missing_ok=True)
        else:
            atomic(h, path, (backup / entry['file']).read_bytes(), entry['mode'])
    # Recovery always starts stopped, even if a pre-install intent was active.
    atomic(h, data / 'protection.json', MONITORING, 0o600)
    link = base / '.current-rollback'
    link.unlink(missing_ok=True)
    link.symlink_to(release)
    os.replace(link, base / 'current')
    h.run('systemctl', 'daemon-reload')
    h.run('systemd-analyze', 'verify', '/etc/systemd/system/flowgate.service', '/etc/systemd/system/flowgate-guard.service')
    h.run('systemctl', 'reset-failed', 'flowgate.service', 'flowgate-guard.service')
    for unit, enabled in unit_enabled.items():
        h.run('systemctl', 'enable' if enabled else 'disable', unit)
    h.run('systemctl', 'start', 'flowgate.service')
    response = wait_monitoring(h, manifest, rule_inventory(backup / 'rules.db'))
    atomic(h, backup / 'rollback-verified.json', json.dumps(response, indent=2).encode(), 0o600)
    return response


def restart_unchanged(h, base, data, previous):
    """Backup preparation failed; original executable and DB have never changed."""
    release, manifest = previous
    if (base / 'current').resolve(strict=True) != release:
        raise RuntimeError('Current changed during backup preparation')
    if previous_release_for_path(h, base, release) != manifest:
        raise RuntimeError('Original release changed during backup preparation')
    if h.daemon_pids() or flowgate_tables(h):
        raise RuntimeError('Cannot restart original daemon while a writer/interception remains')
    if json.loads((data / 'protection.json').read_bytes()).get('mode') != 'monitoring':
        raise RuntimeError('Original persisted protection intent is not monitoring')
    expected = rule_inventory(data / 'rules.db')
    h.run('systemctl', 'reset-failed', 'flowgate.service', 'flowgate-guard.service')
    h.run('systemctl', 'start', 'flowgate.service')
    return wait_monitoring(h, manifest, expected)


def previous_release_for_path(h, base, release):
    # Validate the candidate without changing current (it still points to the new build).
    releases = safe_dir(h, base / 'releases', 0o755)
    if release.parent != releases:
        raise RuntimeError('Invalid rollback release path')
    safe_dir(h, release, 0o755)
    path = release / 'manifest.json'
    if path.is_symlink() or not path.is_file() or not h.root_owned(path.stat()):
        raise RuntimeError('Unsafe rollback manifest')
    manifest = json.loads(path.read_bytes())
    for name, expected in manifest['files'].items():
        if name in ('', '.', '..') or '/' in name:
            raise RuntimeError('Invalid rollback filename')
        path = release / name
        if path.is_symlink() or not path.is_file() or not h.root_owned(path.stat()) or sha(path.read_bytes()) != expected:
            raise RuntimeError('Rollback artifact integrity check failed: ' + name)
    return manifest


def install(h, bundle, stamp):
    base = safe_dir(h, '/usr/local/lib/flowgate', 0o755)
    descriptor = os.open(base / '.install.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode) or not h.root_owned(status):
            raise RuntimeError('Unsafe installation lock')
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('Another FlowGate installation is in progress')
        return install_locked(h, bundle, stamp)
    finally:
        os.close(descriptor)


def install_locked(h,bundle,stamp, *, extra_config=None, verify_extra=None, standalone=False):
 manifest=json.loads((bundle/'manifest.json').read_text())
 if not standalone and manifest['isolated_passed'] is not True:
  raise RuntimeError('Prepared bundle did not pass legacy qualification')
 base=safe_dir(h,'/usr/local/lib/flowgate',0o755);releases=safe_dir(h,'/usr/local/lib/flowgate/releases',0o755)
 name=manifest['release'];assert name and '/'not in name and name not in('.','..')
 release=releases/name
 admin_uid=administrator_uid(h,(base/'current').exists())
 # 1. Immutable release: verify every bundle hash; an existing identical release is reused, never altered.
 if release.exists():
  for f,want in manifest['files'].items():assert sha((release/f).read_bytes())==want,('installed release differs',f)
 else:
  staging=pathlib.Path(tempfile.mkdtemp(prefix='.staging-'+name+'-',dir=releases))
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
  if (before.get('protection')or{}).get('state','stopped')!='stopped'or(before.get('protection')or{}).get('desired_mode')!='monitoring'or(before.get('enforcement')or{}).get('state')!='stopped':
   raise SystemExit('FlowGate protection is active; stop it explicitly before a monitoring install')
 # An unavailable stopped daemon can be reinstalled only after proving that
 # no interception remains and persisted startup intent is monitoring.
 if not running and (base/'current').exists():
  state=h.path('/var/lib/flowgate/protection.json')
  if not state.exists()or json.loads(state.read_text()).get('mode')!='monitoring':raise RuntimeError('Stopped-service recovery requires persisted monitoring mode')
  if flowgate_tables(h):raise RuntimeError('Stopped-service recovery refused: interception tables remain')
 cur=base/'current';old_link=os.readlink(cur)if cur.is_symlink()else None
 if cur.exists()and not cur.is_symlink():raise SystemExit('Unexpected current object; refusing')
 previous=None
 if old_link:
  try:
   previous=previous_release(h,base,releases)
   if previous and before:
    old_manifest=previous[1];build=before.get('build')or{}
    if build.get('source')!=old_manifest['source']or build.get('executable_sha256')!=old_manifest['files']['flowgate']or build.get('modified')is not False:
     raise RuntimeError('Running daemon does not match the previous release')
  except (OSError,ValueError,RuntimeError,KeyError)as error:
   previous=None
   print('Automatic rollback unavailable:',error,file=sys.stderr)
 unit_enabled={}
 for unit in UNITS:
  try:state=h.run('systemctl','is-enabled',unit).strip()
  except subprocess.CalledProcessError as error:state=(error.stdout or'').strip()
  unit_enabled[unit]=state in ('enabled','enabled-runtime','linked','linked-runtime')
 # Pure validation and backup-directory allocation precede any service stop.
 data=safe_dir(h,'/var/lib/flowgate',0o700)
 etc=safe_dir(h,'/etc/flowgate',0o755)
 backup=safe_dir(h,'/var/lib/flowgate/backups',0o700)/f'{name}-monitoring-{stamp}'
 backup.mkdir(mode=0o700)
 extra_config=extra_config or {}
 snapshot_paths=[*extra_config,data/'rules.db',data/'decisions.db',etc/'zones.json',etc/'administrator.json',*[h.path('/etc/systemd/system')/u for u in UNITS],drop,*map(h.path,TOOLS.values())]
 for path in [*snapshot_paths,data/'protection.json']:
  if path.is_symlink()or(path.exists()and not path.is_file()):raise RuntimeError('Unsafe installation state: '+str(path))
 quiesced=False
 try:
  # Quiesce the old writer BEFORE taking the rollback database snapshot.
  if running:
   if (h.path('/etc/systemd/system')/'flowgate.service').exists():h.run('systemctl','stop','flowgate.service')
   else:h.run(str(release/'flowgate'),'monitor-stop','--generation',before['generation'])
   for _ in range(300):
    if not h.daemon_pids():break
    h.sleep(.1)
   else:raise RuntimeError('Old daemon has not exited; no rollback snapshot or second writer started')
   quiesced=True
  # 4. Consistent backups of all state that this install touches.
  for db in['rules.db','decisions.db']:
   src=data/db
   if src.exists():
    snapshot_database(src,backup/db)
  before_rules=rule_inventory(backup/'rules.db')
  # Quiesced compatibility check before any release switch: a rule saved after
  # the preflight cannot reach a candidate that would refuse to load it.
  require_rule_schemas(backup/'rules.db',manifest_rule_schema(manifest))
  for src in[data/'protection.json',*[h.path('/etc/systemd/system')/u for u in UNITS],drop,*map(h.path,TOOLS.values())]:
   if src.exists():atomic(h,backup/(src.name+'.previous'),src.read_bytes(),0o600)
  if etc.exists():
   for f in etc.iterdir():
    if f.is_file():atomic(h,backup/('etc-'+f.name),f.read_bytes(),0o600)
  record={'release':name,'source':manifest['source'],'previous_current':old_link,'running_before':running,'runtime_before':before,'rules_before':before_rules,'stamp':stamp,'unit_enabled':unit_enabled}
  atomic(h,backup/'install-record.json',json.dumps(record,indent=2).encode(),0o600)
  snapshot={}
  for path in snapshot_paths:
   destination=str(path)
   if path.is_symlink():raise RuntimeError('Symlink installation state: '+destination)
   if not path.exists():snapshot[destination]=None;continue
   filename='rollback-'+str(len(snapshot))
   source=backup/path.name if path.name in ('rules.db','decisions.db')else path
   contents=source.read_bytes()
   atomic(h,backup/filename,contents,0o600)
   snapshot[destination]={'file':filename,'sha256':sha(contents),'mode':stat.S_IMODE(path.stat().st_mode)}
  atomic(h,backup/'rollback-files.json',json.dumps(snapshot,indent=2).encode(),0o600)
 except Exception as preparation_error:
  if quiesced and previous:
   try:
    response=restart_unchanged(h,base,data,previous)
   except Exception as recovery_error:
    print('Original daemon restart failed after backup error:',recovery_error,file=sys.stderr)
    subprocess_safe(h,'systemctl','stop','flowgate.service')
    subprocess_safe(h,'systemctl','disable','flowgate.service')
    raise preparation_error from recovery_error
   print('PREPARATION FAILED; unchanged original executable/database restarted and verified in monitoring. Evidence:',backup,file=sys.stderr)
   raise RollbackComplete('Backup preparation failed; unchanged previous daemon verified in monitoring')from preparation_error
  raise
 try:
  # 5. Configuration: preserve zones; persist monitoring BEFORE any start.
  safe_dir(h,'/etc/flowgate',0o755)
  atomic(h,etc/'administrator.json',json.dumps({'uid':admin_uid}).encode(),0o600)
  if not(etc/'zones.json').exists():
   z=(before or{}).get('network_zones')or{}
   atomic(h,etc/'zones.json',json.dumps({'local':z.get('local_prefixes',[]),'internet':z.get('internet_prefixes',[])}).encode(),0o600)
  atomic(h,data/'protection.json',MONITORING,0o600)
  for path, contents in extra_config.items():atomic(h,path,contents,0o600)
  # 7. Switch artifacts. Units only; the NM Requires= drop-in is deliberately absent.
  link=base/'.current-new'
  if link.is_symlink():link.unlink()
  link.symlink_to(release);os.replace(link,cur)
  for u in UNITS:atomic(h,h.path('/etc/systemd/system')/u,(release/u).read_bytes())
  if drop.exists():drop.unlink()
  for src,dest in TOOLS.items():
   safe_dir(h,pathlib.Path(dest).parent,0o755)
   atomic(h,dest,(release/src).read_bytes(),0o755 if src in manifest['executables'] else 0o644)
  h.run('systemctl','daemon-reload')
  h.run('systemd-analyze','verify','/etc/systemd/system/flowgate.service','/etc/systemd/system/flowgate-guard.service')
  h.run('systemctl','disable','flowgate-guard.service')  # pulled in by flowgate.service only; never WantedBy network-pre
  h.run('systemctl','enable','flowgate.service')
  h.run('systemctl','start','flowgate.service')
  _,r=wait_api(h)
  expected_rules=verified_rule_transition(backup/'rules.db',data/'rules.db',admin_uid)
  problems=verify_monitoring(r,manifest,expected_rules)
  tables=flowgate_tables(h)
  if tables:problems.append(('owned interception tables present',tables))
  pids=h.daemon_pids()
  if len(pids)!=1:problems.append(('daemon processes',pids))
  if problems:raise RuntimeError('Monitoring verification failed: '+json.dumps(problems,default=str))
  if verify_extra is not None:verify_extra(r)
  final={'generation':r['generation'],'build':r['build'],'protection':r['protection'],'enforcement':r['enforcement'],'traffic_monitor':r.get('traffic_monitor'),'rules':api_inventory(r),'capabilities':r['capabilities'],'permissions':r.get('permissions'),'owned_tables':tables,'daemon_pids':pids,'nm_dropin_installed':h.path(DROPIN).exists()}
  atomic(h,backup/'runtime-final.json',json.dumps(final,indent=2).encode(),0o600)
  print('INSTALLED IN MONITORING ONLY',name,'generation',r['generation'],'rules',len(final['rules']),'protection stopped; no interception; backup',backup)
  print('Protection was NOT activated. No essential permissions were applied.')
  return final
 except Exception as install_error:
  print('MONITORING INSTALL FAILED; attempting verified executable/database rollback',file=sys.stderr)
  try:
   h.run('systemctl','stop','flowgate.service')
   if h.daemon_pids():raise RuntimeError('Failed daemon still running; refusing database restore')
   h.run(str(release/'flowgate'),'protection-recover','--state','/run/flowgate-enforcement')
   if flowgate_tables(h):raise RuntimeError('Interception remains; refusing rollback start')
   if previous is None:raise RuntimeError('No verified previous managed release')
   response=rollback(h,backup,data,base,previous,snapshot,unit_enabled)
   print('ROLLBACK VERIFIED; previous release restored in monitoring:',response['build']['source'],'Evidence:',backup,file=sys.stderr)
  except Exception as rollback_error:
   print('ROLLBACK FAILED:',rollback_error,file=sys.stderr)
   subprocess_safe(h,'systemctl','stop','flowgate.service')
   subprocess_safe(h,'systemctl','disable','flowgate.service')
   subprocess_safe(h,str(release/'flowgate'),'protection-recover','--state','/run/flowgate-enforcement')
   print('Protection remains OFF, including after reboot. Use --recover-stopped for guarded monitoring-only recovery. Evidence:',backup,file=sys.stderr)
   raise install_error from rollback_error
  raise RollbackComplete('Update failed; previous executable and database restored and verified in monitoring. Evidence: '+str(backup))from install_error

def subprocess_safe(h,*argv):
 try:h.run(*argv)
 except Exception as e:print('cleanup step failed:',argv,e,file=sys.stderr)

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--bundle',required=True);a=p.parse_args()
 if os.geteuid()!=0:raise SystemExit('Run this monitoring-only installer once with terminal sudo')
 os.umask(0o077)
 try:install(Host(),pathlib.Path(a.bundle).resolve(strict=True),time.strftime('%Y%m%dT%H%M%S'))
 except RollbackComplete as error:
  print(error,file=sys.stderr);sys.exit(75)
