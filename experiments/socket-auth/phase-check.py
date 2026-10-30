#!/usr/bin/env python3
"""Three bounded isolated observation-phase trials; no installation or host firewall changes."""
import hashlib,json,os,pathlib,shutil,signal,subprocess,sys,tempfile,time
ROOT=pathlib.Path('/home/flowgate-user/Apps/flowgate');BASE=ROOT/'.workspace/census-bottleneck';PROTO=ROOT/'.workspace/socket-auth-prototype';ART=PROTO/'.workspace/socket-auth'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def inventory():
    def read(cmd):
        p=subprocess.run(cmd,capture_output=True,text=True,timeout=10)
        if p.returncode: raise RuntimeError('read-only inventory failed: '+p.stderr)
        return json.loads(p.stdout)
    return {'links':read(['bpftool','-j','link','show']),
        'cgroup':read(['bpftool','-j','cgroup','show','/sys/fs/cgroup','effective']),
        'pins':sorted(str(p) for p in pathlib.Path('/sys/fs/bpf').rglob('*'))}

if '--inside' not in sys.argv:
    if os.geteuid()!=0:raise SystemExit('sudo required for isolated kernel iterator verification')
    uid,gid=ROOT.stat().st_uid,ROOT.stat().st_gid
    if uid==0:raise SystemExit('expected a non-root desktop fixture UID')
    run=pathlib.Path(tempfile.mkdtemp(prefix='ph-',dir=ROOT/'.workspace'));os.chown(run,uid,gid)
    (run/'tmp').mkdir(mode=0o700)
    shutil.copyfile(BASE/'iterator/loader-v2',run/'loader');os.chmod(run/'loader',0o700)
    artifacts=[ART/'phase-flowgate',ART/'phase-compare.py',ART/'phase-source-provenance.json',BASE/'iterator/identity-v2.test',run/'loader',pathlib.Path(__file__)]
    (run/'provenance.json').write_text(json.dumps({str(p):sha(p) for p in artifacts},indent=2)+'\n')
    shutil.copyfile(ART/'phase-source-provenance.json',run/'source-provenance.json')
    shutil.copytree(ART/'phase-source',run/'phase-source-overlay')
    before=inventory();(run/'host-before.json').write_text(json.dumps(before,indent=2)+'\n')
    pidfd=os.open('/proc/self/ns/pid',os.O_RDONLY);mntfd=os.open('/proc/self/ns/mnt',os.O_RDONLY)
    env=dict(os.environ,FLOWGATE_PARENT_NETNS=os.readlink('/proc/self/ns/net'),
        FLOWGATE_PARENT_PIDNS_ID=os.readlink('/proc/self/ns/pid'),
        FLOWGATE_ROOT_PIDNS_FD=str(pidfd),FLOWGATE_ROOT_MNTNS_FD=str(mntfd),
        FLOWGATE_FIXTURE_UID=str(uid),FLOWGATE_FIXTURE_GID=str(gid),TMPDIR=str(run/'tmp'),
        PYTHONDONTWRITEBYTECODE='1')
    status=0;proc=None
    try:
        for label in ['candidate-1','candidate-2','candidate-3']:
            print('RUN',label,'in private namespaces; bounded at 420 seconds',flush=True)
            with (run/(label+'.log')).open('w') as log:
                proc=subprocess.Popen(['unshare','--mount','--net','--pid','--cgroup','--fork','--kill-child=KILL','--mount-proc',
                    sys.executable,str(pathlib.Path(__file__).resolve()),'--inside',str(run),label],
                    env=env,pass_fds=(pidfd,mntfd),stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
                try: code=proc.wait(timeout=420)
                except subprocess.TimeoutExpired: os.killpg(proc.pid,signal.SIGKILL);proc.wait();code=124
            if code:
                print(f'FAIL {label}: exit={code}; log={run / (label + chr(46) + "log")}',flush=True);status=code;break
            result=json.loads((run/label/'result.json').read_text())
            allowed=result['wine']['SAT_ALPHA_A']
            drops=sum(result['queue_drop_logs'].values())
            measured=[v for k,v in result['native'].items() if k!='baseline']
            native_p99=max((v.get('p99_ms') or 0 for v in measured),default=0)
            cpu=sum(json.loads((run/label/(r+'-cpu.json')).read_text())['cpu_seconds'] for r in ['round1','round2'])
            gate=json.loads((run/label/'gate-final.json').read_text()) or {}
            renewal=gate.get('renewal_observer',{})
            lateness=[max(0,r['start_boot_ns']-r.get('due_boot_ns',r['start_boot_ns']))/1e6 for r in gate.get('renewal_timeline',[])]
            count=renewal.get('census_completed',0)
            wait_ms=renewal.get('slot_wait_wall_ns',0)/max(1,count)/1e6
            rows={(sock,seq):ms for token,sock,seq,ms in json.loads((run/label/'wine-latency.json').read_text()) if token=='SAT_ALPHA_A'}
            windows={}
            for sock in range(result['sockets_per_app']):
                windows[str(sock)]={}
                for name,start,end in [('startup_0_1s',0,125),('after_1s',125,result['datagrams_per_socket'])]:
                    values=sorted(rows[(sock,i)] for i in range(start,end) if (sock,i) in rows)
                    windows[str(sock)][name]={'offered':end-start,'missing':[i for i in range(start,end) if (sock,i) not in rows], 'observed_max_ms':max(values,default=None),'observed_p99_ms':values[min(len(values)-1,int(.99*len(values)))] if values else None,'observed_over_10ms':[i for i in range(start,end) if rows.get((sock,i),0)>10]}
            (run/label/'alignment-latency.json').write_text(json.dumps({'scope':'Observed latency, not added-vs-off; 1 second reporting window is not a loss exemption. Full sequences retained.','sockets':windows},indent=2)+'\n')
            steady=[{'socket':sock,'lost':len(v['after_1s']['missing']),'max_ms':v['after_1s']['observed_max_ms']} for sock,v in windows.items()]
            print(f"{label}: allowed={allowed['datagrams']}/{allowed['sent']} queue_drops={drops} native_p99_ms={native_p99:.3f} cpu_s={cpu:.2f} renewal_gaps={gate.get('renewal_gaps','n/a')} renewals={count} max_due_late_ms={max(lateness,default=0):.2f} wait_ms={wait_ms:.2f} groups={gate.get('renewal_groups',0)} grouped_flows={gate.get('grouped_flows',0)} post_slot_max_ms={renewal.get('max_post_slot_wall_ns',0)/1e6:.2f} alignment={json.dumps(gate.get('alignment',{}),separators=(',',':'))} observed_after_1s={json.dumps(steady,separators=(',',':'))}",flush=True)
    finally:
        if proc and proc.poll() is None:os.killpg(proc.pid,signal.SIGKILL);proc.wait()
        os.close(pidfd);os.close(mntfd)
        after=inventory();(run/'host-after.json').write_text(json.dumps(after,indent=2)+'\n')
        if before!=after:
            print('STOP: host BPF inventory changed; preserve evidence, no automatic cleanup of foreign objects.');status=status or 3
        (run/'loader').unlink(missing_ok=True)
        shutil.rmtree(run/'tmp')
        # Evidence and fixture trees are private workspace artifacts. Do not
        # follow Wine's drive links when returning ownership to the user.
        for parent,dirs,files in os.walk(run,followlinks=False):
            os.chown(parent,uid,gid,follow_symlinks=False)
            for name in dirs+files:os.chown(pathlib.Path(parent)/name,uid,gid,follow_symlinks=False)
        print('Result:',run,'exit',status,'; no deployment or host service operations.')
    raise SystemExit(status)

run=pathlib.Path(sys.argv[-2]);label=sys.argv[-1]
assert os.readlink('/proc/self/ns/net')!=os.environ['FLOWGATE_PARENT_NETNS']
assert os.readlink('/proc/self/ns/pid')!=os.environ['FLOWGATE_PARENT_PIDNS_ID']
subprocess.run(['ip','link','set','lo','up'],check=True)
pidfd=int(os.environ['FLOWGATE_ROOT_PIDNS_FD']);mntfd=int(os.environ['FLOWGATE_ROOT_MNTNS_FD'])
env=dict(os.environ,FLOWGATE_GATE_ENABLED='1')
if label in ('candidate-1','candidate-2','candidate-3'):
    # Prove the final loader handoff/type/tag check before timed work; retain
    # completed topology results, repeat only the short transfer check here.
    smoke=dict(env,FLOWGATE_ITERATOR_TEST_HELPER=str(run/'loader'))
    p=subprocess.run([str(BASE/'iterator/identity-v2.test'),'-test.run',
        '^TestFDIteratorRealHolderMatrix$/^transfers-and-churn$/^transfer_','-test.v','-test.timeout','30s'],
        cwd=ROOT/'internal/identity',env=smoke,timeout=40)
    if p.returncode:raise SystemExit(p.returncode)
    env['FLOWGATE_TEST_ITERATOR_HELPER']=str(run/'loader')
cmd=[sys.executable,str(ART/'phase-compare.py'),'--binary',str(ART/'phase-flowgate'),
    '--helper',str(ROOT/'.workspace/windows/table-probe.exe'),'--run',str(run/label),
    '--proton',str(ROOT/'.workspace/udp-capacity/proton'),'--data',str(ROOT/'.workspace/proton-launcher-fixture/data'),
    '--prefix-source',str(ROOT/'.workspace/proton-launcher-fixture/run11/prefix-a'),
    '--pe',str(ROOT/'.workspace/udp-capacity/timed.exe'),'--lwp','/home/flowgate-user/user_config/scripts/lwp',
    '--sockets','2','--datagrams','7500','--interval-ms','8','--native-pps','20',
    '--min-native-delivery','.001','--max-native-p99-ms','10000','--min-allowed-socket-share','.001']
raise SystemExit(subprocess.run(cmd,cwd=ROOT,env=env,pass_fds=(pidfd,mntfd)).returncode)
