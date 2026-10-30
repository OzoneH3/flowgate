"""Build a disposable VM overlay in workspace. Does not launch or attach on host."""
import pathlib,sys,hashlib,json
ROOT=pathlib.Path('/home/flowgate-user/Apps/flowgate')
CHECKOUT=ROOT/'.workspace/socket-auth-prototype'
HERE=CHECKOUT/'experiments/socket-auth'
arm=sys.argv[1] if len(sys.argv)>1 else ''
assert arm in ('control','candidate'), 'arm must be control or candidate'
bundle=ROOT/'.workspace/automatic-zone-releases/a70e572984e5c4c2a2c630697dadace9056fec9f/backend'
m=json.loads((bundle/'manifest.json').read_text())
for n in ('probe','kernel','classify.bpf.o','controller.py'):
 assert hashlib.sha256((bundle/n).read_bytes()).hexdigest()==m['files'][n],n
# Adapt the retained, bounded disposable-guest apparatus. Only fresh output dirs.
s=(CHECKOUT/'experimental/upload-shaper/zones/stage.py').read_text()
s=s.replace("base=pathlib.Path(__file__).resolve().parents[3];import sys", "base=ROOT;import sys")
s=s.replace("case=sys.argv[1] if len(sys.argv)>1 else 'receivers'", "case='receivers'")
s=s.replace("d=base/'.workspace/zone-receiver'", "d=CHECKOUT/('.workspace/socket-shaping-'+arm)")
s=s.replace("d.mkdir(parents=True,exist_ok=True)", "assert not d.exists(), 'preserve existing evidence';d.mkdir(parents=True)")
s=s.replace("shutil.copy2(c/src,w/name)", "shutil.copy2(bundle/name if name in ('probe','kernel','classify.bpf.o') else c/src,w/name)")
s=s.replace("shutil.copy2(d/'flowgate-new',w/'flowgate-new')", "shutil.copy2(CHECKOUT/'.workspace/socket-auth/production-flowgate',w/'flowgate-new')")
s=s.replace("wt/'controller.py'", "bundle/'controller.py'")
s=s.replace("wt/'tests/peer.py'", "HERE/'shaping-peer.py'")
s=s.replace("base/'experimental/upload-shaper/zones/common.py'", "HERE/'shaping-common.py'")
s=s.replace("base/'experimental/upload-shaper/zones'/(case+'.py')", "HERE/'shaping-case.py'")
s=s.replace("'import common\\ncommon.run('+repr(case)+')\\n'", "'import common\\ncommon.EXE[\"B\"]=\"beta\"\\ncommon.run(\"receivers\")\\n'")
s=s.replace("str(c/'helpers/sender')]", "str(c/'helpers/sender'),str(bundle/'probe'),str(bundle/'kernel'),str(CHECKOUT/'.workspace/socket-auth/production-flowgate')]")
s=s.replace("set -eu\ncd /work", "set -eu\nexport FLOWGATE_COEXIST_GATE="+('1' if arm=='candidate' else '0')+"\ncd /work")
s=s.replace("for m in sch_htb", "for m in xt_bpf nft_compat sch_htb")
s=s.replace("mods=['nf_conntrack_netlink'", "mods=['xt_bpf','nft_compat','nf_conntrack_netlink'")
s=s.replace("subprocess.check_output(['ldd',exe],text=True)", "ldd_output(exe)")
def ldd_output(exe):
 import subprocess
 r=subprocess.run(['ldd',exe],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
 assert r.returncode==0 or 'not a dynamic executable' in r.stdout or 'statically linked' in r.stdout,(exe,r.stdout)
 return r.stdout
d=CHECKOUT/('.workspace/socket-shaping-'+arm)
expanded=s
exec(compile(expanded,str(HERE/'shaping-stage-expanded.py'),'exec'),dict(globals()))
# Hash adapted source too so the transformation is fully reviewable.
(d/'stage-expanded.py').write_text(expanded)
(d/'fixture-provenance.json').write_text(json.dumps({str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in [HERE/'shaping-stage.py',HERE/'shaping-common.py',HERE/'shaping-peer.py',HERE/'shaping-case.py',CHECKOUT/'.workspace/socket-auth/production-flowgate',bundle/'manifest.json']},indent=2)+'\n')
