#!/usr/bin/env python3
"""Requires specific user approval: read host /proc using an isolated test socket."""
import os,pathlib,json,hashlib,subprocess,shutil,tempfile,time
ROOT=pathlib.Path('/home/flowgate-user/Apps/flowgate/.workspace/socket-auth-prototype')
if os.geteuid()!=0 or os.environ.get('FLOWGATE_HOST_CENSUS_APPROVED')!='1':
 raise SystemExit('Not authorized by ordinary isolated-run approval: requires explicit host census diagnostic approval and root.')
binary=ROOT/'.workspace/socket-auth/census-cost'
loader=ROOT.parent/'census-bottleneck/iterator/loader-v2'
assert hashlib.sha256(loader.read_bytes()).hexdigest()=='91e62cdc339fd58fcc13b09bd9f88017226d93ca92650675c127ebc4554e55e8'
out=pathlib.Path(tempfile.mkdtemp(prefix='host-census-',dir=ROOT/'.workspace/socket-auth'))
shutil.copyfile(loader,out/'loader');os.chmod(out/'loader',0o700)
def inventory():
 return {k:sorted(row['id'] for row in json.loads(subprocess.check_output(['bpftool','-j',k,'show'],text=True,timeout=3))) for k in ('prog','link')}
before=inventory();(out/'inventory-before.json').write_text(json.dumps(before))
(out/'provenance.json').write_text(json.dumps({str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in (pathlib.Path(__file__),binary,out/'loader',ROOT/'experiments/socket-auth/census-cost/main.go')},indent=2))
code=1
try:
 env=dict(os.environ,FLOWGATE_PARENT_NETNS=os.readlink('/proc/self/ns/net'),TMPDIR=str(out))
 # No PID namespace: real host process population is intentionally observed.
 # No host network packets; the program only connects (never sends) on private lo.
 command=['unshare','--net','--mount','--propagation','private','sh','-ec','ip link set lo up; exec "$1" --helper "$2" --out "$3"','census',str(binary),str(out/'loader'),str(out)]
 with (out/'output.log').open('w') as log:
  r=subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=20)
 code=r.returncode
finally:
 after=inventory();(out/'inventory-after-immediate.json').write_text(json.dumps(after))
 if after!=before:
  time.sleep(1);after=inventory()
 (out/'inventory-after.json').write_text(json.dumps(after))
 if after!=before:code=1
 uid,gid=ROOT.stat().st_uid,ROOT.stat().st_gid
 for p in out.iterdir():os.chown(p,uid,gid,follow_symlinks=False)
 os.chown(out,uid,gid)
 print('Result:',out,'exit',code,'; native holder timing only; no host policy/service changes')
raise SystemExit(code)
