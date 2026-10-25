#!/usr/bin/env python3
"""Execute the launcher with injected configuration/exec; never start a daemon."""
import json
import os
import pathlib
import runpy
import subprocess
import time
import unittest
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[2]
class Stopped(Exception):pass
class LaunchEnvironment(unittest.TestCase):
 def launch(self,extra):
  read=pathlib.Path.read_text;exists=pathlib.Path.exists
  def config(p,*args,**kw):
   if str(p)=='/etc/flowgate/zones.json':return json.dumps({'local':[],'internet':[]})
   return read(p,*args,**kw)
  def present(p):
   if str(p) in ['/etc/flowgate/administrator.json','/etc/flowgate/wine.json']:return False
   return exists(p)
  tuner=json.dumps([{'id':1,'attach_type':'cgroup_sock_ops','name':'bpftune_conn_fixture'}]).encode()
  with patch.dict(os.environ,{'PATH':'untrusted','LD_PRELOAD':'untrusted','PYTHONPATH':'untrusted','NOTIFY_SOCKET':'@fixture',**extra},clear=True), patch.object(pathlib.Path,'read_text',autospec=True,side_effect=config), patch.object(pathlib.Path,'exists',autospec=True,side_effect=present), patch.object(subprocess,'check_output',return_value=tuner), patch.object(time,'sleep'), patch.object(os,'execve',side_effect=Stopped) as execute:
   with self.assertRaises(Stopped):runpy.run_path(str(ROOT/'deployment/launch'),run_name='__main__')
  return execute.call_args.args
 def test_default_scrubs_environment(self):
  _,args,env=self.launch({})
  self.assertEqual(env,{'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8','NOTIFY_SOCKET':'@fixture'})
  self.assertEqual(args[1],'serve');self.assertIn('--restore-udp',args);self.assertIn('--allow-protection',args)
 def test_only_explicit_profile_directory_is_forwarded(self):
  _,args,env=self.launch({'FLOWGATE_PROFILE_DIR':'/private/profile;literal'})
  self.assertEqual(env['FLOWGATE_PROFILE_DIR'],'/private/profile;literal')
  self.assertEqual(set(env),{'PATH','LANG','NOTIFY_SOCKET','FLOWGATE_PROFILE_DIR'})
  self.assertNotIn('/private/profile;literal',args)
 def test_empty_opt_in_is_omitted(self):
  self.assertNotIn('FLOWGATE_PROFILE_DIR',self.launch({'FLOWGATE_PROFILE_DIR':''})[2])
if __name__=='__main__':unittest.main()
