#!/usr/bin/env python3
"""Focused checks for the reviewed-proposal gate in apply-essentials.py (no host access)."""
import importlib.util,json,pathlib,sys,unittest
sys.dont_write_bytecode=True
root=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('apply_essentials',root/'scripts/apply-essentials.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
EXCL='Excluded by review, not proposed: ppp0 (DNS 192.168.23.221:53); its configuration is unchanged'

def rule(k):
 comp,exe,d,proto,remote,rport,laddr,lport,ifn,uid,allp,peer=k
 f={'direction':d,'protocol':proto,'remote_address':remote,'remote_port':rport,'local_address':laddr,'local_port':lport,'interface_name':ifn,'uid':uid,'all_programs':allp,'application':'app-'+exe,'revision':'rev-'+exe}
 if peer:f['peer_service']={'uid':peer}
 r={'id':'preset:'+str(abs(hash(k))),'preset':{'component':comp},'filter':f}
 if exe!='ALL':r['executable']=exe
 return r

def preview(extra=(),issues=(EXCL,)):
 return {'rules':[rule(k)for k in sorted(m.reviewed(),key=str)]+list(extra),'preserved_rule_ids':[],'issues':list(issues)}

class Gate(unittest.TestCase):
 def test_dhcp_only_default_accepted(self):
  v=preview();self.assertEqual(len(v['rules']),2);self.assertEqual(m.check_preview(v),([],[]))
 def test_services_are_opt_in_without_localhost(self):
  self.addCleanup(m.OPTIONS.update, service_assistance=False)
  m.OPTIONS['service_assistance']=True
  v=preview();self.assertEqual(len(v['rules']),11);self.assertEqual(m.check_preview(v),([],[]))
  self.assertFalse(any(r['filter']['remote_address'].startswith('127.') for r in v['rules']))
 def test_work_vpn_tailscaled_and_broad_rules_refused(self):
  for k in[('dns',m.RESOLVED,'outgoing','udp','192.168.23.221',53,'',0,'ppp0',974,False,None),
           ('tailscale','/usr/bin/tailscaled','outgoing','tcp','*',443,'',0,'',0,False,None),
           ('dns',m.RESOLVED,'outgoing','udp','*',53,'',0,'enp7s0',974,False,None),
           ('dhcp','ALL','outgoing','udp','*',67,'',68,'ppp0',0,True,None)]:
   self.assertTrue(m.check_preview(preview([rule(k)]))[0],k)
 def test_exclusion_must_be_confirmed_and_no_other_issues(self):
  self.assertTrue(m.check_preview(preview(issues=()))[0])
  self.assertTrue(m.check_preview(preview(issues=(EXCL,'Time synchronization: unavailable')))[0])
 def test_overlap_and_identity_drift_refused(self):
  v=preview();v['preserved_rule_ids']=['user:x'];self.assertTrue(m.check_preview(v)[0])
  self.addCleanup(m.OPTIONS.update, service_assistance=False)
  m.OPTIONS['service_assistance']=True
  ident={m.RESOLVED:('app-'+m.RESOLVED,'older-revision')};self.assertTrue(m.check_preview(preview(),ident)[0])
 def test_dhcp_apply_preserves_existing_dns_and_stub_records(self):
  dns=rule(('dns',m.RESOLVED,'outgoing','udp','192.0.2.53',53,'',0,'test0',974,False,None))
  stub=rule(('dns-stub-client','ALL','outgoing','udp','127.0.0.53',53,'',0,'lo',0,True,974))
  plan=preview()['rules'];before=[dns,stub];after=before+plan
  m.verify_applied(before,after,plan)
  with self.assertRaises(RuntimeError):m.verify_applied(before,plan,plan)
  changed=json.loads(json.dumps(after));changed[0]['filter']['remote_address']='*'
  with self.assertRaises(RuntimeError):m.verify_applied(before,changed,plan)
 def test_reviewed_action_and_preset_must_match(self):
  plan=preview()['rules']
  for field,value in [('action','block'),('schema',99)]:
   changed=json.loads(json.dumps(plan));changed[0][field]=value
   with self.assertRaises(RuntimeError):m.verify_applied([],changed,plan)
  for field in ('name','component'):
   changed=json.loads(json.dumps(plan));changed[0]['preset'][field]='other'
   with self.assertRaises(RuntimeError):m.verify_applied([],changed,plan)
 def test_narrower_preview_reports_missing_not_problem(self):
  v=preview();v['rules']=v['rules'][1:];p,miss=m.check_preview(v);self.assertEqual(p,[]);self.assertEqual(len(miss),1)

if __name__=='__main__':unittest.main(verbosity=2)
