#!/usr/bin/env python3
"""Read-only incident export. No service, policy, collector or firewall mutations."""
import json,os,pathlib,sqlite3,subprocess,time
if os.geteuid()!=0:raise SystemExit('Run once with terminal sudo for root-private incident evidence')
root=pathlib.Path(__file__).resolve().parents[1]
out=root/'.workspace'/('system-networking-'+str(time.time_ns()))
out.mkdir(mode=0o700)
uid=int(os.environ.get('SUDO_UID','1000'));gid=int(os.environ.get('SUDO_GID','1000'))
def save(name,value):
 p=out/name
 with p.open('x')as f:json.dump(value,f,indent=2)
 p.chmod(0o600);os.chown(p,uid,gid)
def capture(args):
 try:
  r=subprocess.run(args,text=True,capture_output=True,timeout=15)
  return {'argv':args,'returncode':r.returncode,'stdout':r.stdout[:2<<20],'stderr':r.stderr[:8192]}
 except Exception as e:return {'argv':args,'error':str(e)}
binary='/usr/local/lib/flowgate/current/flowgate'
services={}
for unit in ['systemd-resolved.service','NetworkManager.service','tailscaled.service']:
 info=capture(['systemctl','show',unit,'-p','MainPID','-p','ExecStart','-p','User','-p','ActiveState'])
 pid=next((s.split('=',1)[1]for s in info.get('stdout','').splitlines()if s.startswith('MainPID=')),'0')
 services[unit]={'unit':info,'process':capture([binary,'process',pid])if pid!='0'else None}
save('services.json',services)
for name,args in {
 'firewall.json':['nft','-j','list','ruleset'],
 'dns.json':['resolvectl','status'],
 'links.json':['ip','-j','address'],
 'routes.json':['ip','-j','route','show','table','all'],
 'sockets.json':['ss','-H','-tunap'],
 'journal.json':['journalctl','-u','flowgate.service','-u','flowgate-guard.service','--since','4 hours ago','--no-pager'],
 'units.json':['systemctl','status','flowgate.service','flowgate-guard.service','--no-pager'],
}.items():save(name,capture(args))
for name in ['protection.json','rules.db','decisions.db']:
 path=pathlib.Path('/var/lib/flowgate')/name
 if not path.exists():save(name+'.json',{'unavailable':'missing'});continue
 if name.endswith('.json'):save(name+'.json',json.loads(path.read_text()));continue
 # SQLite read-only transaction; never open a writer or copy a live database file.
 db=sqlite3.connect('file:'+str(path)+'?mode=ro',uri=True)
 try:
  if name=='rules.db':rows=db.execute('SELECT document FROM rules').fetchall()
  else:rows=db.execute('SELECT document FROM decisions WHERE at>=? ORDER BY seq DESC LIMIT 3000',(int((time.time()-14400)*1_000_000_000),)).fetchall()
  save(name+'.json',[json.loads(row[0])for row in rows])
 finally:db.close()
for name,path in [('owned-state.json','/run/flowgate-enforcement/instance.json'),('zones.json','/etc/flowgate/zones.json')]:
 try:save(name,json.loads(pathlib.Path(path).read_text()))
 except (OSError,ValueError)as e:save(name,{'unavailable':str(e)})
os.chown(out,uid,gid)
print('READ-ONLY EVIDENCE',out)
print('No enforcement, collector, policy, service or routing action was performed.')
