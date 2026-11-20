#!/usr/bin/env python3
"""Fixed-backend argument checks with mocked auth/control. No sudo or enforcement."""
import contextlib,io,json,runpy,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2]
REAL_POPEN=subprocess.Popen
REAL_EXISTS=Path.exists
class BackendSelection(unittest.TestCase):
 def invoke(self,script,args,pinned=False):
  calls=[]
  def popen(argv,**kw):
   calls.append(argv)
   # Only an ordinary Python child supplies deterministic terminal output.
   return REAL_POPEN([sys.executable,'-c',"print('STOPPED: simulated control')" if argv!=['sudo','-v']else'pass'],**kw)
  def call(argv):calls.append(argv);return 0
  def exists(p):return pinned if str(p)=='/run/flowgate/controller'else REAL_EXISTS(p)
  with patch.object(sys,'argv',[script,*args]),patch('subprocess.Popen',popen),patch('subprocess.call',call),patch.object(Path,'exists',exists),contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
   # Bridge writes bytes to stdout.buffer; preserve that stream interface.
   output=io.TextIOWrapper(io.BytesIO(),encoding='utf-8')
   with contextlib.redirect_stdout(output):
    try:runpy.run_path(str(ROOT/'scripts'/script),run_name='__main__')
    except SystemExit as e:
     if e.code not in (None,0):return e.code,calls
  return 0,calls
 def test_udp_default_and_electron(self):
  for args,name in [([], 'flowgate'),(['--backend','electron-backend'],'electron-backend')]:
   code,calls=self.invoke('traffic-control.py',args)
   self.assertEqual(code,0);self.assertEqual(calls,[['sudo',str(ROOT/'.workspace'/name),'udp-start','--uid',str(__import__('os').getuid())]])
 def test_desktop_start_and_fallback(self):
  for args,name in [([], 'flowgate'),(['--backend','electron-backend'],'electron-backend')]:
   for action in ['start','stop']:
    with tempfile.TemporaryDirectory(dir=ROOT/'.workspace',prefix='bridge-selection-')as job:
     code,calls=self.invoke('desktop-control.py',['--action',action,'--job',job,*args])
     self.assertEqual(code,0);self.assertEqual(calls[0],['sudo','-v']);self.assertEqual(calls[1][:5],['sudo','-n',str(ROOT/'.workspace'/name),'host-session','--action'])
     self.assertEqual(json.loads(Path(job,'result.json').read_text())['phase'],'stopped')
 def test_desktop_prefers_pinned_controller(self):
  with tempfile.TemporaryDirectory(dir=ROOT/'.workspace',prefix='bridge-selection-')as job:
   code,calls=self.invoke('desktop-control.py',['--action','stop','--job',job,'--backend','electron-backend'],pinned=True)
   self.assertEqual(code,0);self.assertEqual(calls[1][2],'/run/flowgate/controller')
 def test_rejects_arbitrary_executables_before_auth(self):
  for script in ['desktop-control.py','traffic-control.py']:
   for backend in ['../other','/usr/bin/sh',str(ROOT/'build/electron-backend'),'unknown']:
    code,calls=self.invoke(script,['--backend',backend])
    self.assertEqual(code,2);self.assertEqual(calls,[])
if __name__=='__main__':unittest.main()
