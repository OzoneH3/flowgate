import hashlib,json,pathlib,sys,tempfile,unittest,contextlib,io
from unittest.mock import Mock,MagicMock,patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'lib'))
from launch_installed import launch
class LaunchTest(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=pathlib.Path(self.tmp.name);self.rev='a'*40
  (self.root/'deployment').mkdir();(self.root/'deployment/release-policy.json').write_text(json.dumps({'approved':[self.rev],'rejected':[]}))
  self.bundle=self.root/'.workspace/automatic-zone-releases'/self.rev;self.bundle.mkdir(parents=True);(self.bundle/'launch-ui').write_text('fixture')
  (self.bundle/'matched-manifest.json').write_text(json.dumps({'source':self.rev,'files':{'launch-ui':hashlib.sha256(b'fixture').hexdigest()}}))
  self.host=Mock();self.host.status.return_value={'generation':'same','build':{'source':self.rev,'modified':False}}
 def run_launch(self,**kw):
  with patch('launch_installed.released_gui',return_value=False):launch(self.root,self.host,**kw)
 def test_launch_only(self):
  self.run_launch();self.host.switch_gui.assert_called_once_with(self.root,self.bundle);self.assertEqual([c[0] for c in self.host.method_calls],['status','status','switch_gui'])
 def test_unapproved(self):
  self.host.status.return_value['build']['source']='b'*40
  with self.assertRaises(RuntimeError):self.run_launch()
  self.host.switch_gui.assert_not_called()
 def test_manifest_mismatch(self):
  (self.bundle/'launch-ui').write_text('modified')
  with self.assertRaises(RuntimeError):self.run_launch()
  self.host.switch_gui.assert_not_called()
 def test_dry(self):
  out=io.StringIO()
  with contextlib.redirect_stdout(out):self.run_launch(dry=True)
  self.assertIn('no update or daemon restart',out.getvalue());self.host.switch_gui.assert_not_called()
 def test_reuse(self):
  proc=MagicMock();proc.name='123'
  with patch('launch_installed.pathlib.Path.iterdir',return_value=[proc]),patch('launch_installed.start_time',return_value='1'),patch('launch_installed.released_gui',return_value=True),patch('launch_installed.os.readlink',return_value=str(self.bundle/'runtime/electron')):
   launch(self.root,self.host)
  self.host.switch_gui.assert_not_called()
 def test_rejected(self):
  (self.root/'deployment/release-policy.json').write_text(json.dumps({'approved':[self.rev],'rejected':[self.rev]}))
  with self.assertRaises(RuntimeError):self.run_launch()
  self.host.switch_gui.assert_not_called()
 def test_missing_or_modified_build(self):
  for build in (None,{'source':self.rev,'modified':True}):
   self.host.status.return_value={'generation':'same','build':build}
   with self.assertRaises(RuntimeError):self.run_launch()
  self.host.switch_gui.assert_not_called()
 def test_generation_changed(self):
  self.host.status.side_effect=[self.host.status.return_value,{'generation':'new','build':self.host.status.return_value['build']}]
  with self.assertRaises(RuntimeError):self.run_launch()
  self.host.switch_gui.assert_not_called()
if __name__=='__main__':unittest.main()
