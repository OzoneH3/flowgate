#!/usr/bin/env python3
"""Reviewed private production workloads: protection off, then three exact candidates."""
import hashlib,json,os,pathlib,subprocess,sys,tempfile
ROOT=pathlib.Path('/home/flowgate-user/Apps/flowgate/.workspace/socket-auth-prototype')
CHECK=ROOT/'experiments/socket-auth/production-endurance-check.py'
if os.geteuid()!=0:raise SystemExit('Requires the isolated lab launcher')
series=pathlib.Path(tempfile.mkdtemp(prefix='production-series-',dir=ROOT/'.workspace/socket-auth'))
owner=ROOT.stat();os.chown(series,owner.st_uid,owner.st_gid)
artifacts=[CHECK,ROOT/'experiments/socket-auth/production-long-compare.py',ROOT/'.workspace/socket-auth/production-flowgate',ROOT/'.workspace/socket-auth/routed-timed.exe',ROOT/'experiments/socket-auth/paired-results.py',pathlib.Path(__file__)]
(series/'provenance.json').write_text(json.dumps({str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in artifacts},indent=2))
status=0
try:
    for label in ('off','candidate-1','candidate-2','candidate-3'):
        print('RUN',label,'production path in private namespaces; bounded at 420 seconds',flush=True)
        # Each reviewed child owns its independent namespaces and timeout cleanup.
        result=subprocess.run([sys.executable,str(CHECK)],env=dict(os.environ,FLOWGATE_PRODUCTION_OFF='1' if label=='off' else '0'),text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        (series/(label+'.log')).write_text(result.stdout)
        path=None
        for line in result.stdout.splitlines():
            if line.startswith('Result: '):path=pathlib.Path(line.split(' ',2)[1])
        if result.returncode or path is None:
            print('FAIL',label,'; log:',series/(label+'.log'),flush=True);status=1;break
        (series/label).symlink_to(path/'candidate',target_is_directory=True)
        r=json.loads((path/'candidate/result.json').read_text())
        g=json.loads((path/'candidate/gate-final.json').read_text()) or {}
        rows={(s,i):v for t,s,i,v in json.loads((path/'candidate/wine-latency.json').read_text()) if t=='SAT_ALPHA_A'}
        summary=[]
        for sock in range(r['sockets_per_app']):
            vals=[rows[sock,i] for i in range(125,r['datagrams_per_socket']) if (sock,i) in rows]
            summary.append(dict(socket=sock,startup_lost=sum((sock,i) not in rows for i in range(125)),steady_lost=r['datagrams_per_socket']-125-len(vals),steady_max_ms=max(vals,default=None)))
        cpu=sum(json.loads((path/'candidate'/(x+'-cpu.json')).read_text())['cpu_seconds'] for x in ('round1','round2'))
        print(label+': '+json.dumps(dict(allowed=r['wine']['SAT_ALPHA_A']['datagrams'],offered=r['wine']['SAT_ALPHA_A']['sent'],cpu_s=round(cpu,2),renewal_gaps=g.get('renewal_gaps'),sockets=summary),separators=(',',':')),flush=True)
        if label!='off':
            subprocess.run([sys.executable,str(ROOT/'experiments/socket-auth/paired-results.py'),str(series),label],check=True)
finally:
    for p in series.iterdir():
        if not p.is_symlink():os.chown(p,owner.st_uid,owner.st_gid)
    print('Result:',series,'exit',status,'; no host deployment',flush=True)
raise SystemExit(status)
