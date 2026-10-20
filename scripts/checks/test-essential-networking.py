#!/usr/bin/env python3
import copy,importlib.util,json,pathlib,unittest
root=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('essential',root/'scripts/review-essential-networking.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def process():return {'pid':450,'uid':974,'start_ticks':'1','netns':'net:[fixture]','mountns':'mnt:[private]','boot_id':'boot','cgroup':'0::/system.slice/systemd-resolved.service','executable':'/usr/lib/systemd/systemd-resolved','executable_revision':'revision','application':{'key':'resolver-key','revision':'revision','kind':'native','executable':'/usr/lib/systemd/systemd-resolved'}}
class Essential(unittest.TestCase):
 def test_explicit_scopes(self):
  p=m.proposal(process(),['172.30.42.250','fd7a:115c:a1e0::53'],[])
  self.assertEqual(len(p['items']),4);self.assertEqual(p['rules_saved'],0)
  for item in p['items']:
   f=item['candidate_rule']['filter'];self.assertEqual(f['uid'],974);self.assertEqual(f['direction'],'outgoing');self.assertEqual(f['remote_port'],53);self.assertNotIn('all_programs',f);self.assertNotIn('all_uids',f);self.assertNotIn('network_zone',f)
  (root/'.workspace/essential-policy-fixture.json').write_text(json.dumps(p,indent=2))
 def test_updates_and_user_edits_preserved(self):
  p=m.proposal(process(),['172.30.42.250'],[]);existing=copy.deepcopy(p['items'][0]['candidate_rule']);existing.update(disabled=True,action='block')
  q=m.proposal(process(),['172.30.42.250'],[existing]);self.assertEqual(q['items'][0]['disposition'],'preserve_existing_review_only');self.assertTrue(existing['disabled']);self.assertEqual(existing['action'],'block')
  changed=process();changed['application']['revision']='new';changed['executable_revision']='new'
  q=m.proposal(changed,['172.30.42.250'],[existing]);self.assertNotEqual(q['items'][0]['candidate_rule']['id'],existing['id']);self.assertEqual(q['items'][0]['disposition'],'proposed_not_saved')
 def test_incomplete_identity_not_service_name(self):
  for field in ['cgroup','mountns','executable_revision']:
   p=process();p[field]=''
   with self.assertRaises(ValueError):m.proposal(p,['172.30.42.250'],[])
 def test_current_dns_not_fallback_or_address_guess(self):
  self.assertEqual(m.dns_servers('Fallback DNS Servers: 8.8.8.8\n DNS Servers: 172.30.42.250 fd7a:115c:a1e0::53'),['172.30.42.250','fd7a:115c:a1e0::53'])
  for value in ['fe80::1%eth0','unknown','0.0.0.0','224.0.0.1']:
   with self.assertRaises(ValueError):m.dns_servers('DNS Servers: '+value)
if __name__=='__main__':unittest.main(verbosity=2)
