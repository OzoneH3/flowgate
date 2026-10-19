#!/usr/bin/env python3
"""Focused installer regression; AST-load pure checks/transaction, no host actions."""
import ast,contextlib,copy,io,json,pathlib,subprocess,types,unittest
root=pathlib.Path(__file__).resolve().parents[1]
tree=ast.parse((root/'scripts/install-daily.py').read_text())
scope={}
exec(compile(ast.Module(body=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='classify_preflight'],type_ignores=[]),'installer-classification','exec'),scope)
classify=scope['classify_preflight']
activation=json.loads('[{"id":"firewall.activation","status":"not_checked","code":"not_attempted","detail":"NFQUEUE exclusive binding, conntrack snapshot/mark updates and packet interception NOT attempted; startup preflight still required"}]')[0]
ready={'dependency.ip':'executable_located','dependency.nft':'executable_located','firewall.interfaces':'interfaces_inspected','firewall.legacy.ip_tables_names':'legacy_tables_absent','firewall.legacy.ip6_tables_names':'legacy_tables_absent','firewall.ruleset':'ruleset_inspected','firewall.queue_census':'queue_census','firewall.tailscale':'tailscale_client_supported'}
def report():return {'schema_version':1,'checks':[dict(id=k,status='ready',code=v,detail='fixture completed check')for k,v in ready.items()]+[copy.deepcopy(activation)]}

class InstallerReadiness(unittest.TestCase):
 def test_exact_user_diagnostic_is_deferred_not_ready(self):
  r=report();before=copy.deepcopy(r)
  old_refused=[c for c in r['checks']if c['id'].startswith('firewall.')and(c['status']=='blocked'or(c['status']=='not_checked'and c['id']!='firewall.queue_census'))]
  self.assertEqual(old_refused,[activation])
  refused,deferred=classify(r)
  self.assertEqual(refused,[]);self.assertEqual(deferred,[activation]);self.assertEqual(r,before)
 def test_real_blocker_still_refuses(self):
  for key,code in [('firewall.interfaces','firewall_conflict'),('dependency.nft','dependency_missing'),('firewall.queue_census','queue_occupied')]:
   r=report();c=next(c for c in r['checks']if c['id']==key);c.update(status='blocked',code=code)
   self.assertIn(c,classify(r)[0])
 def test_only_explicit_census_fallback_is_deferred(self):
  r=report();c=next(c for c in r['checks']if c['id']=='firewall.queue_census');c.update(status='not_checked',code='probe_failed')
  self.assertEqual(classify(r),([],[c,activation]))
  c['code']='permission_required';self.assertIn(c,classify(r)[0])
 def test_unknown_incomplete_and_failed_results_refuse(self):
  for patch in [dict(id='firewall.future',status='ready',code='new'),dict(id='firewall.activation',status='not_checked',code='probe_failed'),dict(id='firewall.activation',status='ready',code='not_attempted'),dict(id='firewall.ruleset',status='not_checked',code='probe_timeout'),dict(id='firewall.ruleset',status='optional_unavailable',code='missing')]:
   r=report();r['checks']=[c for c in r['checks']if c['id']!=patch['id']]+[patch]
   self.assertIn(patch,classify(r)[0])
  for edit in ['schema','missing','duplicate']:
   r=report()
   if edit=='schema':r['schema_version']=2
   if edit=='missing':r['checks']=r['checks'][1:]
   if edit=='duplicate':r['checks'].append(r['checks'][0])
   with self.assertRaises(ValueError):classify(r)
 def test_activation_or_acceptance_failure_recovers_never_success(self):
  # Execute the installer's actual final transaction, replacing every privileged
  # boundary. Both service activation and host acceptance failure must recover.
  transaction=next(n for n in tree.body if isinstance(n,ast.Try))
  for failure in ['activation','acceptance']:
   for recovery_status in [0,1]:
    calls=[];recoveries=[]
    def command(*argv,**kw):
     calls.append(argv)
     if(failure=='activation'and argv==('systemctl','start','flowgate.service'))or(failure=='acceptance'and '--evidence'in argv):
      raise subprocess.CalledProcessError(1,argv)
    def recover(argv,**kw):
     self.assertFalse(kw['check']);recoveries.append(argv);return types.SimpleNamespace(returncode=recovery_status)
    env={'command':command,'api':lambda:(None,{'generation':'new','protection':{'state':'stopped'},'build':{'source':'fixture','executable_sha256':'hash'},'rules':[]}),'before':{'generation':'old','rules':[]},'manifest':{'source':'fixture','files':{'flowgate':'hash'}},'release':pathlib.Path('/mock-immutable-release'),'backup':pathlib.Path('/mock-evidence'),'sys':types.SimpleNamespace(executable='python3',stderr=io.StringIO()),'subprocess':types.SimpleNamespace(run=recover),'json':json}
    output=io.StringIO()
    with contextlib.redirect_stdout(output),self.assertRaises(subprocess.CalledProcessError):
     exec(compile(ast.Module(body=[transaction],type_ignores=[]),'installer-actual-transaction','exec'),env)
    self.assertEqual(recoveries,[['/usr/local/sbin/flowgate-recover']]);self.assertNotIn('INSTALLED AND HOST-ACCEPTED',output.getvalue())

if __name__=='__main__':unittest.main(verbosity=2)
