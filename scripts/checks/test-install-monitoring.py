#!/usr/bin/env python3
"""Focused monitoring-only installer checks: real transaction, temp root, mocked systemd/nft/API."""
import contextlib,hashlib,importlib.util,io,json,os,pathlib,sqlite3,sys,tempfile,unittest
sys.dont_write_bytecode=True
root=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('install_monitoring',root/'scripts/install-monitoring.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class FakeHost(m.Host):
 def __init__(self,base,running=False,protection='stopped',tables=(),api_rules=None,start_fails=False):
  self.base=base;self.calls=[];self.started=False;self.running=running;self.protection=protection;self.tables=list(tables);self.api_rules=api_rules;self.start_fails=start_fails;self.mode_at_start=None
 def path(self,p):
  p=str(p)
  if p.startswith(str(self.base))or not p.startswith('/'):return pathlib.Path(p)
  return self.base/p.lstrip('/')
 def root_owned(self,st):return True
 def sleep(self,s):pass
 def daemon_pids(self):return [42]if(self.started or self.running)else[]
 def run(self,*argv):
  self.calls.append(argv)
  if argv==('systemctl','start','flowgate.service'):
   self.mode_at_start=json.loads(self.path('/var/lib/flowgate/protection.json').read_text())['mode']
   if self.start_fails:raise RuntimeError('start failed')
   self.started=True
  if argv[:2]==('systemctl','stop')or 'monitor-stop'in argv:self.started=self.running=False
  if argv[-2:]==('list','tables'):return json.dumps({'nftables':[{'metainfo':{}}]+[{'table':{'family':'inet','name':n}}for n in self.tables]+[{'table':{'family':'inet','name':'tailscale'}}]})
  return ''
 def api(self,op='list',**q):
  if not(self.started or self.running):raise OSError('no socket')
  rules=self.api_rules if self.api_rules is not None else[{'id':'zone:a','version':3},{'id':'preset:b','version':1}]
  return 42,{'generation':'g-new'if self.started else'g-old','build':{'source':'SRC','executable_sha256':self.manifest_hash},'protection':{'state':self.protection,'desired_mode':'monitoring'},'enforcement':{'state':self.protection},'rules':rules,'capabilities':['essential-system-networking-v1'],'permissions':{'role':'administrator'}}

def fixture(base):
 bundle=base/'bundle';bundle.mkdir()
 files={'flowgate':b'#!flowgate','flowgate.service':b'[Unit]\nnew\n','flowgate-guard.service':b'[Unit]\nguard\n','50-flowgate-guard.conf':b'[Unit]\nRequires=flowgate-guard.service\n','control.py':b'c','recover.py':b'r','uninstall.py':b'u','host-acceptance.py':b'never'}
 for n,d in files.items():(bundle/n).write_bytes(d)
 manifest={'release':'SRC','source':'SRC','isolated_passed':True,'executables':['flowgate','control.py','recover.py','uninstall.py','host-acceptance.py'],'files':{n:hashlib.sha256(d).hexdigest()for n,d in files.items()}}
 (bundle/'manifest.json').write_text(json.dumps(manifest))
 old=base/'usr/local/lib/flowgate/releases/OLD';old.mkdir(parents=True)
 (old/'50-flowgate-guard.conf').write_bytes(b'[Unit]\nRequires=flowgate-guard.service\nAfter=flowgate-guard.service\n')
 (base/'usr/local/lib/flowgate/current').symlink_to(old)
 data=base/'var/lib/flowgate';data.mkdir(parents=True)
 db=sqlite3.connect(data/'rules.db');db.execute('CREATE TABLE rules(id TEXT PRIMARY KEY, document TEXT)')
 db.executemany('INSERT INTO rules VALUES(?,?)',[('zone:a',json.dumps({'schema':4,'version':3})),('preset:b',json.dumps({'schema':5,'version':1}))]);db.commit();db.close()
 (data/'protection.json').write_text('{"schema":1,"mode":"monitoring"}')
 for d in['etc/systemd/system/NetworkManager.service.d','etc/flowgate','usr/local/sbin']:(base/d).mkdir(parents=True)
 (base/'etc/flowgate/zones.json').write_text('{"local":["172.30.42.0/24"],"internet":[]}')
 return bundle,manifest

class MonitoringInstall(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(dir=root/'.workspace');self.base=pathlib.Path(self.tmp.name)
  self.bundle,self.manifest=fixture(self.base)
 def tearDown(self):self.tmp.cleanup()
 def host(self,**kw):h=FakeHost(self.base,**kw);h.manifest_hash=self.manifest['files']['flowgate'];return h
 def run_install(self,h):
  with contextlib.redirect_stdout(io.StringIO())as out,contextlib.redirect_stderr(io.StringIO()):
   r=m.install(h,self.bundle,'T')
  return r,out.getvalue()
 def test_absent_service_installs_monitoring_without_protection_or_nm_dependency(self):
  dbbytes=(self.base/'var/lib/flowgate/rules.db').read_bytes()
  h=self.host();final,out=self.run_install(h)
  self.assertEqual(h.mode_at_start,'monitoring','monitoring must be persisted before first start (previous desired was both)')
  self.assertFalse((self.base/m.DROPIN.lstrip('/')).exists())
  flat=[' '.join(c)for c in h.calls]
  self.assertNotIn('host-acceptance',' '.join(flat))
  self.assertFalse(any(c[:2]==('systemctl','enable')and 'flowgate-guard.service'in c for c in h.calls))
  self.assertIn(('systemctl','enable','flowgate.service'),h.calls)
  self.assertFalse(any('both'in c or 'incoming'in c for c in h.calls))
  self.assertEqual((self.base/'var/lib/flowgate/rules.db').read_bytes(),dbbytes,'database must be untouched')
  backup=self.base/'var/lib/flowgate/backups/SRC-monitoring-T'
  self.assertEqual(m.rule_inventory(backup/'rules.db'),[('preset:b',1),('zone:a',3)])
  self.assertEqual(json.loads((backup/'protection.json.previous').read_text())['mode'],'monitoring')
  self.assertEqual(json.loads((backup/'install-record.json').read_text())['previous_current'],str(self.base/'usr/local/lib/flowgate/releases/OLD'))
  self.assertTrue((self.base/'usr/local/lib/flowgate/releases/OLD').is_dir(),'old immutable bundle kept')
  self.assertEqual(oct((self.base/'usr/local/lib/flowgate/releases/SRC').stat().st_mode&0o777),'0o755')
  self.assertEqual(os.readlink(self.base/'usr/local/lib/flowgate/current'),str(self.base/'usr/local/lib/flowgate/releases/SRC'))
  self.assertEqual((self.base/'etc/flowgate/zones.json').read_text(),'{"local":["172.30.42.0/24"],"internet":[]}')
  self.assertEqual(final['owned_tables'],[]);self.assertFalse(final['nm_dropin_installed'])
  self.assertIn('INSTALLED IN MONITORING ONLY',out);self.assertIn('Protection was NOT activated',out)
 def test_leftover_flowgate_dropin_removed_foreign_refused_untouched(self):
  drop=self.base/m.DROPIN.lstrip('/')
  drop.write_bytes((self.base/'usr/local/lib/flowgate/releases/OLD/50-flowgate-guard.conf').read_bytes())
  h=self.host();self.run_install(h)
  self.assertFalse(drop.exists())
  self.assertTrue((self.base/'var/lib/flowgate/backups/SRC-monitoring-T/50-flowgate-guard.conf.previous').exists())
  self.tearDown();self.setUp();drop=self.base/m.DROPIN.lstrip('/');drop.write_bytes(b'[Unit]\nRequires=other.service\n')
  h=self.host()
  with self.assertRaises(SystemExit):self.run_install(h)
  self.assertEqual(h.calls,[]);self.assertEqual(json.loads((self.base/'var/lib/flowgate/protection.json').read_text())['mode'],'monitoring')
 def test_active_protection_is_never_interrupted(self):
  h=self.host(running=True,protection='active')
  with self.assertRaises(SystemExit):self.run_install(h)
  self.assertFalse(any(c[:2]==('systemctl','stop')or 'monitor-stop'in c for c in h.calls))
 def test_running_monitor_is_stopped_through_its_generation(self):
  h=self.host(running=True);self.run_install(h)
  self.assertIn('monitor-stop',[a for c in h.calls for a in c])
 def test_upgrade_of_installed_monitoring_service_uses_systemctl_stop(self):
  old=self.base/'usr/local/lib/flowgate/releases/OLD'
  for u in m.UNITS:(old/u).write_bytes(b'[Unit]\nold '+u.encode()+b'\n');(self.base/'etc/systemd/system'/u).write_bytes((old/u).read_bytes())
  (self.base/'var/lib/flowgate/protection.json').write_text('{"schema":1,"mode":"monitoring"}')
  h=self.host(running=True);final,_=self.run_install(h)
  self.assertIn(('systemctl','stop','flowgate.service'),h.calls)
  self.assertFalse(any('monitor-stop'in c for c in h.calls))
  self.assertEqual((self.base/'etc/systemd/system/flowgate.service').read_bytes(),(self.bundle/'flowgate.service').read_bytes())
  self.assertEqual(final['rules'],[('preset:b',1),('zone:a',3)])
 def test_verification_failures_stop_disable_and_never_restore_old_data(self):
  for kw in[dict(tables=['flowgate_host']),dict(api_rules=[{'id':'zone:a','version':3}]),dict(start_fails=True)]:
   self.tearDown();self.setUp();dbbytes=(self.base/'var/lib/flowgate/rules.db').read_bytes()
   h=self.host(running=True,**kw)
   with self.assertRaises(Exception):self.run_install(h)
   for want in[('systemctl','stop','flowgate.service'),('systemctl','disable','flowgate.service')]:self.assertIn(want,h.calls,kw)
   self.assertTrue(any('protection-recover'in c for c in h.calls))
   self.assertEqual((self.base/'var/lib/flowgate/rules.db').read_bytes(),dbbytes)
   self.assertEqual(json.loads((self.base/'var/lib/flowgate/protection.json').read_text())['mode'],'monitoring')
 def test_install_accepts_exact_startup_root_migration(self):
  rule={'id':'user:test','version':1,'executable':'/usr/bin/tool','filter':{'uid':1000,'application':m.sha(b'1000|native||/usr/bin/tool'),'revision':'v1'},'action':'allow'}
  dbpath=self.base/'var/lib/flowgate/rules.db'
  with sqlite3.connect(dbpath)as db:db.execute('INSERT INTO rules VALUES(?,?)',(rule['id'],json.dumps(rule)))
  migrated=dict(rule,version=2,root_application=m.sha(b'0|native||/usr/bin/tool'))
  h=self.host(api_rules=[{'id':'zone:a','version':3},{'id':'preset:b','version':1},migrated]);run=h.run
  def start_migration(*args):
   out=run(*args)
   if args==('systemctl','start','flowgate.service'):
    with sqlite3.connect(dbpath)as db:db.execute('UPDATE rules SET document=? WHERE id=?',(json.dumps(migrated),rule['id']))
   return out
  h.run=start_migration
  final,_=self.run_install(h)
  self.assertIn(('user:test',2),final['rules'])
  self.assertNotIn(('systemctl','disable','flowgate.service'),h.calls)
 def test_stopped_recovery_requires_monitoring_and_no_interception(self):
  (self.base/'var/lib/flowgate/protection.json').write_text('{"mode":"both"}')
  h=self.host()
  with self.assertRaises(RuntimeError):self.run_install(h)
  self.assertNotIn(('systemctl','start','flowgate.service'),h.calls)
  (self.base/'var/lib/flowgate/protection.json').write_text('{"mode":"monitoring"}')
  h=self.host(tables=['flowgate_host'])
  with self.assertRaises(RuntimeError):self.run_install(h)
  self.assertNotIn(('systemctl','start','flowgate.service'),h.calls)
 def test_tampered_bundle_refused_before_runtime(self):
  (self.bundle/'flowgate').write_bytes(b'tampered');h=self.host()
  with self.assertRaises(AssertionError):self.run_install(h)
  self.assertEqual(h.calls,[])


class MigrationVerification(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(dir=root/'.workspace');self.base=pathlib.Path(self.tmp.name)
  self.before=self.base/'before.db';self.after=self.base/'after.db'
  path='/usr/bin/tool';uid=1000
  self.rule={'id':'r','version':1,'executable':path,'action':'allow','filter':{'uid':uid,'application':m.sha(f'{uid}|native||{path}'.encode()),'revision':'v1'}}
  self.write(self.before,[self.rule]);self.write(self.after,[self.rule])
 def tearDown(self):self.tmp.cleanup()
 def write(self,path,rules,archives=()):
  if path.exists():path.unlink()
  with sqlite3.connect(path)as db:
   db.execute('CREATE TABLE rules(id TEXT, document TEXT)')
   db.executemany('INSERT INTO rules VALUES(?,?)',[(r['id'],json.dumps(r))for r in rules])
   db.execute('CREATE TABLE archived_rules(rule_id TEXT, document TEXT, reason TEXT)')
   db.executemany('INSERT INTO archived_rules VALUES(?,?,?)',[(r['id'],json.dumps(r),reason)for r,reason in archives])
 def test_exact_migration_and_repeat_install(self):
  new=dict(self.rule,version=2,root_application=m.sha(b'0|native||/usr/bin/tool'))
  self.write(self.after,[new]);self.assertEqual(m.verified_rule_transition(self.before,self.after),[('r',2)])
  self.write(self.before,[new]);self.assertEqual(m.verified_rule_transition(self.before,self.after),[('r',2)])
 def test_unrelated_mutation_or_missing_rule_rejected(self):
  for new in [dict(self.rule,version=2),dict(self.rule,action='block'),dict(self.rule,version=2,root_application='wrong')]:
   self.write(self.after,[new])
   with self.assertRaises(RuntimeError):m.verified_rule_transition(self.before,self.after)
  self.write(self.after,[])
  with self.assertRaises(RuntimeError):m.verified_rule_transition(self.before,self.after)
 def test_archived_cleanup_only(self):
  self.write(self.after,[],[(self.rule,'replaced executable; no old process found')])
  self.assertEqual(m.verified_rule_transition(self.before,self.after),[])
  self.write(self.before,[self.rule],[(self.rule,'replaced executable; no old process found')])
  with self.assertRaises(RuntimeError):m.verified_rule_transition(self.before,self.after)
  self.write(self.before,[self.rule])
  self.write(self.after,[],[(dict(self.rule,action='block'),'expired')])
  with self.assertRaises(RuntimeError):m.verified_rule_transition(self.before,self.after)

if __name__=='__main__':unittest.main(verbosity=2)
