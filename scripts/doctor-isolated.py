#!/usr/bin/env python3
"""Read-only doctor acceptance. All conflicting objects live in disposable netns."""
import json,os,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
assert os.environ['FLOWGATE_PARENT_NETNS']!=os.readlink('/proc/self/ns/net')
run=Path(tempfile.mkdtemp(prefix='doctor-isolated-',dir=ROOT/'.workspace'))
state=run/'state';state.mkdir(mode=0o700)
api=run/'api';api.mkdir(mode=0o711)
collector=run/'collector';collector.mkdir(mode=0o755)
base=[str(ROOT/'.workspace/flowgate'),'doctor','--json','--state',str(state),'--controller-socket',str(api/'s'),'--udp-socket',str(collector/'s')]
def nft(*args):return subprocess.check_output(['nft',*args],text=True)
def rules():return [x for x in json.loads(nft('-j','list','ruleset'))['nftables'] if 'metainfo' not in x]
def links():return subprocess.check_output(['ip','-j','-d','link','show'])
def check(*args):
 before=rules(),links(),sorted(p.name for p in state.iterdir())
 report=json.loads(subprocess.check_output([*base,*args],text=True,timeout=30))
 assert (rules(),links(),sorted(p.name for p in state.iterdir()))==before,'doctor mutated fixtures'
 assert report['schema_version']==1
 return {c['id']:c for c in report['checks']}
c=check();assert c['firewall.ruleset']['status']=='ready',c
assert c['udp.helper']['status']=='ready' and c['udp.btf_hooks']['status']=='ready'
assert c['firewall.activation']['status']=='not_checked' and c['udp.attachment']['status']=='not_checked'
assert not (state/'instance.json').exists()
print('PASS healthy namespace: real nft/interface inspection, ELF/helper/BTF metadata; no queue bind/BPF load; rules/interfaces/state unchanged',flush=True)
c=check('--udp-helper',str(run/'missing-helper'));assert c['udp.helper']['code']=='helper_missing' and c['udp.helper']['status']=='optional_unavailable'
print('PASS missing optional helper is explicit, basic observer unaffected',flush=True)
nft('add','table','inet','flowgate_host')
c=check();assert c['firewall.ruleset']['code']=='instance_or_foreign_table'
p=subprocess.run([str(ROOT/'.workspace/flowgate'),'host-start','--state',str(state),'--socket',str(api/'s'),'--uid','0','--duration','10s','--timeout','1s'],capture_output=True,text=True,timeout=10)
assert p.returncode and '[instance_or_foreign_table]' in p.stderr,p.stderr
assert any(x.get('table',{}).get('name')=='flowgate_host' for x in rules())
nft('delete','table','inet','flowgate_host')
print('PASS foreign FlowGate table refused by shared doctor/startup preflight and never removed',flush=True)
nft('add','table','inet','doctor_conflict_fixture');nft('add','chain','inet','doctor_conflict_fixture','inspect');nft('add','rule','inet','doctor_conflict_fixture','inspect','meta','mark','set','0x1')
c=check();assert c['firewall.ruleset']['code']=='firewall_conflict'
nft('delete','table','inet','doctor_conflict_fixture')
print('PASS conflicting mark expression diagnosed without rule mutations or full ruleset output',flush=True)
stat=Path('/proc/self/stat').read_text().rsplit(') ',1)[1].split();record={'Profile':'incoming','Token':'a'*32,'PID':os.getpid(),'Start':stat[19],'NetNS':os.readlink('/proc/self/ns/net'),'State':'active','UID':0}
(state/'instance.json').write_text(json.dumps(record))
c=check();assert c['controller.status']['code']=='instance_active',c['controller.status']
(state/'instance.json').unlink();os.chmod(state,0o777)
c=check();assert c['runtime.state']['code']=='runtime_path_invalid';assert state.stat().st_mode&0o777==0o777
print('PASS existing non-stopped instance and unsafe runtime mode diagnosed without cleanup or chmod',flush=True)
os.chmod(state,0o700)
empty=run/'empty-path';empty.mkdir()
r=json.loads(subprocess.check_output(base,text=True,env=dict(os.environ,PATH=str(empty)),timeout=30))
assert all(next(c for c in r['checks'] if c['id']=='dependency.'+name)['code']=='dependency_missing' for name in ['ip','nft'])
print('PASS controlled missing required executables are definite blockers; no automatic install or privilege prompt',flush=True)
print('EVIDENCE',run,flush=True)
