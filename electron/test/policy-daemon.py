#!/usr/bin/env python3
"""Disposable non-enforcing namespace fixture; seeded rule is explicitly test data."""
import json,os,socket,sqlite3,subprocess,sys,time
from pathlib import Path
assert os.environ['FLOWGATE_PARENT_NETNS']!=os.readlink('/proc/self/ns/net')
run=Path(sys.argv[1]);binary=run/'flowgate'
api=run/'api';api.mkdir(mode=0o711);data=run/'data';data.mkdir(mode=0o700)
listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen()
p=json.loads(subprocess.check_output([str(binary),'process',str(os.getpid())]))
rule={'schema':2,'id':'ui-service-fixture','version':1,'action':'allow','priority':100,'created':'2026-10-17T00:00:00Z','expires':'0001-01-01T00:00:00Z','disabled':False,'executable':p['executable'],'filter':{'application':p['application']['key'],'revision':p['application']['revision'],'uid':0,'direction':'incoming','protocol':'tcp','local_port':listener.getsockname()[1],'remote_address':'127.0.0.1'}}
with sqlite3.connect(data/'rules.db')as db:
 db.execute('CREATE TABLE rules(id TEXT PRIMARY KEY,document TEXT NOT NULL CHECK(length(document)<=16384))');db.execute('PRAGMA user_version=1');db.execute('INSERT INTO rules VALUES(?,?)',(rule['id'],json.dumps(rule)))
os.chmod(data/'rules.db',0o600)
with (run/'daemon.log').open('w')as log: daemon=subprocess.Popen([str(binary),'serve','--socket',str(api/'s'),'--database',str(data/'rules.db'),'--uid','0','--administrator'],stdout=log,stderr=log)
try:
 end=time.monotonic()+10
 while not (api/'s.monitor').exists():
  assert daemon.poll() is None,(run/'daemon.log').read_text();assert time.monotonic()<end;time.sleep(.05)
 (run/'ready').write_text(json.dumps({'pid':daemon.pid,'fixture':'real isolated daemon, seeded test rule; enforcement stopped'}))
 sys.stdin.readline()
finally:
 daemon.terminate();daemon.wait(6);listener.close()
