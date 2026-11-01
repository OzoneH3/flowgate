import importlib.util,pathlib,tempfile,unittest
spec=importlib.util.spec_from_file_location('wine_trace',pathlib.Path(__file__).with_name('accounting-wine-trace.py'));wt=importlib.util.module_from_spec(spec);spec.loader.exec_module(wt)
class TraceReturns(unittest.TestCase):
 def test_struct_fields_are_not_return_values_and_resumes_keep_the_tid(self):
  # This directory is always beneath the explicitly supplied workspace TMPDIR.
  with tempfile.TemporaryDirectory(dir=pathlib.Path(__file__).resolve().parents[2]/'.workspace') as d:
   p=pathlib.Path(d)/'aAlpha-linux.txt';p.write_text('''12 1.0 sendmsg(22<UDP:[0.0.0.0:1]>, {msg_namelen=16, msg_iov=[{iov_base="aAlpha|0|125|xxx", iov_len=256}]}, 0) = 256 <0.1>
13 1.1 sendmsg(23<UDP:[0.0.0.0:2]>, {msg_namelen=16, msg_iov=[{iov_base="aAlpha|1|125|xxx", iov_len=256}]}, 0 <unfinished ...>
13 1.2 <... sendmsg resumed>) = -1 EAGAIN (Resource temporarily unavailable) <0.1>
''')
   r=wt.parse([p]);self.assertFalse(r['unsupported']);a=r['apps']['aAlpha'];self.assertEqual(a['successful_return_bytes'],256);self.assertEqual(a['failed_calls'],1);self.assertEqual(a['errno_counts'],{'EAGAIN':1})
if __name__=='__main__':unittest.main()
