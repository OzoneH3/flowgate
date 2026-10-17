#!/usr/bin/env python3
"""Root-in-user-namespace daemon foundation; never initial-root/host activation."""
import json,os,socket,sqlite3,subprocess,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
assert os.environ['FLOWGATE_PARENT_NETNS']!=os.readlink('/proc/self/ns/net')
run=Path(tempfile.mkdtemp(prefix='administrator-',dir=ROOT/'.workspace'))
api=run/'api';api.mkdir(mode=0o711);data=run/'data';data.mkdir(mode=0o700)
listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen()
principal=json.loads(subprocess.check_output([str(ROOT/'.workspace/flowgate'),'process',str(os.getpid())]))
rule={'schema':2,'id':'service-fixture','version':1,'action':'allow','priority':100,'created':'2026-10-17T00:00:00Z','expires':'0001-01-01T00:00:00Z','disabled':False,'executable':principal['executable'],'filter':{'application':principal['application']['key'],'revision':principal['application']['revision'],'uid':0,'direction':'incoming','protocol':'tcp','local_port':listener.getsockname()[1],'remote_address':'127.0.0.1'}}
with sqlite3.connect(data/'rules.db')as db:
 db.execute('CREATE TABLE rules(id TEXT PRIMARY KEY,document TEXT NOT NULL CHECK(length(document)<=16384))');db.execute('PRAGMA user_version=1');db.execute('INSERT INTO rules VALUES(?,?)',(rule['id'],json.dumps(rule)))
os.chmod(data/'rules.db',0o600)
def nft():return subprocess.check_output(['nft','-j','list','ruleset'])
before=nft();daemon=None
args=[str(ROOT/'.workspace/flowgate'),'serve','--socket',str(api/'s'),'--database',str(data/'rules.db'),'--uid','0','--administrator']
def call(operation='list',suffix='',**kw):
 with socket.socket(socket.AF_UNIX) as c:
  c.settimeout(4);c.connect(str(api/('s'+suffix)));c.sendall((json.dumps({'version':1,'operation':operation,**kw})+'\n').encode());raw=b''
  while b'\n' not in raw:
   chunk=c.recv(65536);assert chunk;raw+=chunk;assert len(raw)<4*1024*1024
 return json.loads(raw)
try:
 with (run/'daemon.log').open('w') as log:daemon=subprocess.Popen(args,stdout=log,stderr=log)
 end=time.monotonic()+10
 while True:
  assert daemon.poll() is None,(run/'daemon.log').read_text()
  try:
   state=call()
   if state.get('activity',{}).get('rows'):break
  except (OSError,ValueError):pass
  assert time.monotonic()<end;time.sleep(.05)
 assert state['mode']=='daemon-monitor' and state['enforcement']['state']=='stopped'
 assert state['permissions']==dict(role='administrator',observation_scope='machine',policy_scope='machine',can_manage_rules=True,can_decide=False)
 assert any(p['uid']==0 and p['pid']==os.getpid() for p in state['activity']['processes'].values())
 assert (api/'s').stat().st_mode&0o777==0o600
 blocked=call('decide',id='no-packet',action='allow',scope='once');assert blocked['error_code']=='unavailable'
 denied=call('rule-delete',suffix='.monitor',generation=state['generation'],id=rule['id'],expected_version=1);assert denied['error_code']=='read_only'
 rule['action']='block'
 saved=call('rule-save',generation=state['generation'],id=rule['id'],expected_version=1,rule=rule);assert 'error' not in saved,saved
 assert saved['saved_rule']['filter']['uid']==0 and saved['saved_rule']['version']==2
 # Even a stored Block has no packet effect in this root-start monitoring mode.
 client=socket.create_connection(listener.getsockname());client.sendall(b'not-enforced');accepted,_=listener.accept();assert accepted.recv(32)==b'not-enforced';accepted.close();client.close()
 second=subprocess.run([*args[:-1],'--socket',str(api/'other')],capture_output=True,text=True,timeout=5)
 assert second.returncode and 'another daemon owns' in second.stderr
 assert not (api/'other').exists()
 deleted=call('rule-delete',generation=state['generation'],id=rule['id'],expected_version=2);assert 'error' not in deleted,deleted
 assert nft()==before,'root monitoring startup changed firewall'
 print('PASS root namespace daemon: machine-visible real UID0 fixture, stored system-service edit/delete, conditional versions, read-only endpoint, no packet decisions, Block not enforced, 0600 socket, exclusive DB writer, nft unchanged',flush=True)
 print('NOTE real peer is UID0 inside the user namespace. Delegation to a non-root desktop UID is role/config-unit tested, not initial-root multi-UID authentication.',flush=True)
 print('EVIDENCE',run,flush=True)
finally:
 if daemon and daemon.poll()is None:daemon.terminate();daemon.wait(6)
 listener.close()
