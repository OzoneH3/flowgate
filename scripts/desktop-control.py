#!/usr/bin/env python3
"""Unprivileged terminal bridge. Only sudo owns authentication and host control.
The GUI reads bounded result files; root never writes into a user-supplied job path.
"""
import argparse
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser()
p.add_argument('--action',required=True,choices=['start','stop','recover','status'])
p.add_argument('--job',required=True)
p.add_argument('--token',default='')
p.add_argument('--backend',choices=['flowgate','electron-backend'],default='flowgate',help='Fixed workspace build for Start/fallback; pinned controller remains preferred')
a=p.parse_args()
job=Path(a.job)
assert job.is_absolute() and job.is_relative_to(ROOT/'.workspace')
st=job.lstat()
assert job.is_dir() and not job.is_symlink() and st.st_uid==os.getuid() and st.st_mode&0o077==0
assert not a.token or (len(a.token)==32 and all(c in '0123456789abcdef' for c in a.token))
profile='incoming'
if (job/'request.json').exists():
    request=json.loads((job/'request.json').read_text());profile=request.get('profile','incoming')
assert profile in ['incoming','both']
sequence=0
generation=a.token

def publish(phase,message=''):
    global sequence
    sequence+=1
    result={'version':1,'sequence':sequence,'phase':phase,'message':message[-16384:],'generation':generation}
    temporary=job/'result.new'
    with temporary.open('w') as f:json.dump(result,f)
    temporary.replace(job/'result.json')

def cancelled():return (job/'cancel').exists()
def authenticate():
    publish('authentication','Authenticate in the terminal. Closing/cancelling authentication does not start enforcement.')
    child=subprocess.Popen(['sudo','-v'])
    end=time.monotonic()+60
    while child.poll() is None:
        if cancelled() or time.monotonic()>end:
            child.terminate()
            try:child.wait(3)
            except subprocess.TimeoutExpired:child.kill();child.wait()
            return False
        time.sleep(.1)
    return child.returncode==0 and not cancelled()

try:
    print('FlowGate: '+a.action+' evaluation control. Qt remains unprivileged.',flush=True)
    if not authenticate():
        publish('cancelled','Authentication cancelled, failed or timed out; monitor remains available.')
        sys.exit(1)
    # Start pins this executing binary into a root-owned runtime snapshot. Later
    # control uses that snapshot, independent of a user rebuilding the workspace.
    binary=ROOT/'.workspace'/a.backend if a.action=='start' else Path('/run/flowgate/controller')
    if not binary.exists():binary=ROOT/'.workspace'/a.backend
    args=['sudo','-n',str(binary),'host-session','--action',a.action]
    if a.action=='start':args+=['--uid',str(os.getuid()),'--duration','5m','--timeout','30s','--profile',profile]
    if a.token:args+=['--token',a.token]
    if cancelled():publish('cancelled','Cancelled before activation.');sys.exit(1)
    publish('starting' if a.action=='start' else 'working')
    child=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    selector=selectors.DefaultSelector();selector.register(child.stdout,selectors.EVENT_READ)
    buffer=b'';output='';ready=False;stopped=False;deadline=time.monotonic()+30
    while child.poll() is None or selector.get_map():
        # Before readiness, Ctrl+C/Cancel terminates the foreground invocation.
        # If readiness races cancellation, this becomes a deliberate Stop; a
        # final acknowledgement is still required before the GUI says stopped.
        if cancelled() and child.poll() is None:
            child.terminate()
        if a.action=='start' and not ready and time.monotonic()>deadline and child.poll() is None:
            child.terminate()
        for key,_ in selector.select(.1):
            data=os.read(key.fd,4096)
            if not data:selector.unregister(key.fileobj);continue
            sys.stdout.buffer.write(data);sys.stdout.buffer.flush()
            buffer+=data
            if len(buffer)>65536:raise RuntimeError('Controller emitted an oversized line')
            while b'\n' in buffer:
                raw,buffer=buffer.split(b'\n',1);line=raw.decode(errors='replace');output=(output+line+'\n')[-16384:]
                if line.startswith('READY host-enforcement generation='):
                    generation=line.split('generation=',1)[1].split()[0];ready=True
                    publish('ready','Controller reports ready; GUI must verify the authenticated API and matching generation.')
                if line.startswith('STOPPED:'):stopped=True
    code=child.wait()
    if a.action=='start' and stopped and code==0:
        publish('stopped','Evaluation stopped; owned enforcement removed. FlowGate no longer controls traffic.')
    elif a.action in ['stop','recover'] and code==0:
        publish('stopped','Stop/recovery confirmed. FlowGate no longer controls traffic; saved rules retained.')
    elif a.action=='status' and code==0:
        info=json.loads(output)
        generation=info['record']['Token']
        publish('stopped' if info['state']=='stopped' and not info['table_present'] else 'status',output)
    elif code!=0:
        publish('unknown' if ready else ('cancelled' if cancelled() else 'failed'),output or 'Authentication/control command failed.')
    else:publish('unknown','Controller exited without confirmed cleanup; use status/recovery.')
except KeyboardInterrupt:
    publish("cancelled","Terminal authentication/control interrupted; check control status if activation had started.")
except Exception as e:
    publish('failed',str(e))
    print(str(e),file=sys.stderr)
