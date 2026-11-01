#!/usr/bin/env python3
"""Baseline-only controller timing overlay in an immutable disconnected guest.
No change to proof/selection; records bounded method spans, not permissions.
"""
import argparse,pathlib,subprocess,json,hashlib,shutil
p=argparse.ArgumentParser();p.add_argument('--output',type=pathlib.Path,required=True);p.add_argument('--candidate-backend',type=pathlib.Path);p.add_argument('--candidate-controller',type=pathlib.Path);p.add_argument('--binding-only',action='store_true');a,rest=p.parse_known_args()
H=pathlib.Path(__file__).resolve().parent;out=a.output.resolve()
assert '.workspace' in out.parts
subprocess.run(['python3',str(H/'extensions-stage.py'),'--output',str(out),'--modules','priority','--p1-only',*rest],check=True)
o=out/'overlay';w=o/'work/m1';
for candidate,name in ((a.candidate_backend,'flowgate-new'),(a.candidate_controller,'controller.py')):
 if candidate:
  assert '.workspace' in candidate.resolve().parts
  shutil.copy2(candidate,w/name)
f=w/'controller.py';before=hashlib.sha256(f.read_bytes()).hexdigest()
addition=r'''
# TEST-ONLY timing overlay; immutable diagnostic image, never a release artifact.
import atexit, signal
_fg_spans=[];_fg_truncated=False;_fg_total=0;_fg_last_flush=time.monotonic()
_fg_trace_path=Path('/work/.workspace/m1/rebind-spans.txt')
def _fg_flush(force=False):
    global _fg_last_flush
    if not force and time.monotonic()-_fg_last_flush<5:return
    start=time.monotonic()
    with _fg_trace_path.open('a') as stream:
        for span in _fg_spans:stream.write(json.dumps(span)+'\n')
        _fg_spans.clear()
        stream.write(json.dumps({'method':'trace_flush','start':start,'end':time.monotonic(),'truncated':_fg_truncated})+'\n')
    _fg_last_flush=time.monotonic()
atexit.register(lambda:_fg_flush(True))
def _fg_term(signum,frame):
    _fg_flush(True)
    raise SystemExit(128+signum)
signal.signal(signal.SIGTERM,_fg_term)
def _fg_wrap(name,fn):
    def run(self,*args,**kwargs):
        global _fg_truncated,_fg_total
        start=time.monotonic();ok=False
        req=args[0] if args and isinstance(args[0],dict) else {}
        label=str(args[0]) if args and not req else req.get('expected_cookie','')
        if name=='call':label=Path(str(args[0])).name+(' '+str(args[1]) if len(args)>1 else '')
        try:
            value=fn(self,*args,**kwargs);ok=True;return value
        finally:
            if _fg_total<16384:_fg_total+=1;_fg_spans.append({'method':name,'label':label[:80],'start':start,'end':time.monotonic(),'ok':ok})
            else:_fg_truncated=True
            if name=='status':_fg_flush()
    return run
for _name in ('call','verify','exists','set_cap','bind','set_policy','status','tick','query_tc','mutate','k'):
    setattr(Controller,_name,_fg_wrap(_name,getattr(Controller,_name)))
if hasattr(Controller,'bind_many'):
    Controller.bind_many=_fg_wrap('bind_many',Controller.bind_many)
'''
s=f.read_text();assert "if __name__ == '__main__':" in s;s=s.replace("if __name__ == '__main__':",addition+"\nif __name__ == '__main__':");f.write_text(s)
# Diagnostic-only repeat-phase status timeline: records Go discovery progress at 100 ms.
pf=w/'priority.py';ps=pf.read_text()
ps=ps.replace(" binding_start=time.monotonic()", """ binding_start=time.monotonic()
 trace_stop=threading.Event();trace_thread=None
 if phase=='A-low-repeat':
  def trace_status():
   with (P.parent/'.workspace/m1/rebind-status.txt').open('a') as stream:
    for _ in range(600):
     if trace_stop.is_set():break
     begin=time.monotonic()
     try:value=status()
     except Exception as exc:value={'error':str(exc)}
     stream.write(json.dumps({'start':begin,'end':time.monotonic(),'status':value})+'\\n');stream.flush()
     trace_stop.wait(.1)
  trace_thread=threading.Thread(target=trace_status,daemon=True);trace_thread.start()""")
ps="import threading\n"+ps
ps=ps.replace(" record('P1-phase-binding',phase=phase,seconds=", " trace_stop.set()\n if trace_thread:trace_thread.join(5)\n record('P1-phase-binding',phase=phase,seconds=")
ps=ps.replace(" configure(cfg,ub=16_000_000,db=16_000_000)"," if phase=='A-low-repeat':\n  probes=[]\n  for _ in range(20):\n   b=time.monotonic();tc();probes.append(time.monotonic()-b)\n  record('rebind-speed-normalizer',seconds=probes,median=sorted(probes)[len(probes)//2])\n configure(cfg,ub=16_000_000,db=16_000_000)")
if a.binding_only:
 ps=ps.replace("('A-low','A-high','normal-control','A-low-repeat')", "('A-low','normal-control','A-low-repeat')")
 ps=ps.replace(" configure(cfg,ub=16_000_000,db=16_000_000)"," edit_start=time.monotonic()\n configure(cfg,ub=16_000_000,db=16_000_000)")
 ps=ps.replace("phase=phase,seconds=time.monotonic()-binding_start,status=status()", "phase=phase,seconds=time.monotonic()-binding_start,edit_to_coverage=time.monotonic()-edit_start,status=status()")
 begin=ps.index(' for d in downs.values():write(d,');end=ps.index('for p in active:stopchild',begin)
 ps=ps[:begin]+" time.sleep(2)\n record('rebind-settled',phase=phase,status=status(),classes=tc())\n"+ps[end:]
 ps+="\nresults['rebind-measurement-complete']={'result':'Pass'}\n"
pf.write_text(ps)
(out/'diagnostic-overlay.json').write_text(json.dumps({'controller_original_sha256':before,'controller_instrumented_sha256':hashlib.sha256(f.read_bytes()).hexdigest(),'proof_behavior_changed':False,'candidate_backend_sha256':hashlib.sha256((w/'flowgate-new').read_bytes()).hexdigest(),'candidate_controller':bool(a.candidate_controller),'maximum_spans':16384,'mode':'test-only baseline timing'},indent=2))
with (out/'diagnostic-overlay.gz').open('wb') as dst:
    find=subprocess.Popen(['find','.','-print0'],cwd=o,stdout=subprocess.PIPE);cpio=subprocess.Popen(['cpio','--null','-o','--format=newc','--owner=0:0'],cwd=o,stdin=find.stdout,stdout=subprocess.PIPE,stderr=subprocess.PIPE);find.stdout.close();subprocess.run(['gzip','-1'],stdin=cpio.stdout,stdout=dst,check=True);cpio.stdout.close();assert cpio.wait()==find.wait()==0
base=pathlib.Path(rest[rest.index('--base-initrd')+1])
with (out/'initramfs.gz').open('wb') as dst:
    for src in (base,out/'diagnostic-overlay.gz'):
        with src.open('rb') as stream:shutil.copyfileobj(stream,dst)
(out/'image-hashes.json').write_text(json.dumps({n:hashlib.sha256((out/n).read_bytes()).hexdigest() for n in ('vmlinuz','initramfs.gz')},indent=2))
