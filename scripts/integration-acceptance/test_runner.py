#!/usr/bin/env python3
"""Harness integrity tests; no networking or kernel operations."""
import unittest,pathlib,json,tempfile,subprocess,sys,collections,argparse
H=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(H))
from measure import delta,MeasurementInconclusive
from priority_assess import assess

class Contract(unittest.TestCase):
 def test_full_finite_denominator(self):
  rows=json.loads((H/'spec/matrix-v2.json').read_text())['core']
  self.assertEqual(len(rows),144);self.assertEqual(len({r['id'] for r in rows}),144)
  self.assertEqual(collections.Counter(r['mode'] for r in rows),{'fast':48,'protected':48,'off':48})
  self.assertTrue(all('expected_v2' in r for r in rows))
 def test_missing_results_are_not_passes(self):
  root=H.parents[1]/'.workspace';root.mkdir(exist_ok=True)
  with tempfile.TemporaryDirectory(dir=root) as tmp:
   out=pathlib.Path(tmp)/'report.json'
   subprocess.run([sys.executable,str(H/'report.py'),tmp,'--output',str(out)],check=True,stdout=subprocess.PIPE)
   self.assertEqual(json.loads(out.read_text())['counts'],{'Not tested':144})
 def test_counter_reset_cannot_false_pass(self):
  with self.assertRaises(MeasurementInconclusive):delta({'handle':'1:1','stats':{'bytes':10}},{'handle':'1:1','stats':{'bytes':2}},'bytes')
  with self.assertRaises(MeasurementInconclusive):delta({'handle':'1:1'},{'handle':'1:2'},'bytes')
 def test_unsaturated_is_inconclusive_flat_is_fail(self):
  def data(saturated):
   return {p:[{'ul_payload_mbps':{'A':7,'B':7},'dl_payload_mbps':{'A':7,'B':7},'saturation':{'upload':saturated,'download':saturated}} for _ in range(2)] for p in ('A-low','A-high','normal-control','A-low-repeat')}
  self.assertEqual(assess(data(False),'upload')['result'],'Inconclusive')
  self.assertEqual(assess(data(True),'upload')['result'],'Fail')

class GameAssessment(unittest.TestCase):
 def test_phase_variance_excludes_effect(self):
  from priority_assess import assess_game
  def phase(v,saturated=True,loss=0):return [{'echo_rtt':{'p95_ms':x},'saturated':saturated,'loss':{'unclassified':loss}} for x in v]
  self.assertEqual(assess_game(phase([5,5.1,5.2]),phase([1,1.1,1.2]))['result'],'Pass')
  self.assertEqual(assess_game(phase([5,5.1,5.2],False),phase([1,1.1,1.2]))['result'],'Inconclusive')
  self.assertEqual(assess_game(phase([5,5.1,5.2]),phase([1,1.1,1.2],loss=1))['result'],'Fail')

class LossAssessment(unittest.TestCase):
 def test_budget_default_queue_is_not_unshaped(self):
  from assess_results import assess
  rows=json.loads((H/'spec/matrix-v2.json').read_text())['core']
  expected=next(r for r in rows if r['id']=='protected-none-normal-ul')
  def snap(drops):return {'tc':[{'class':'htb','handle':'1:fffe'}],'qdisc':[{'parent':'1:fffe','drops':drops}],'queue':{'sessions':[{'generation':'one','counters':{'deadline_rejections':'0'}}]}}
  raw={'id':expected['id'],'expected':expected,'status':'Inconclusive','windows':[{'window':0,'before':snap(0),'after':snap(8),'loss':{'missing':8,'sent_ok':100}}]}
  self.assertEqual(assess(raw)['status'],'Inconclusive')
  raw['windows'][0]['after']=snap(0)
  self.assertEqual(assess(raw)['status'],'Fail')
  self.assertEqual(raw['status'],'Inconclusive')
 def test_unpaired_counter_generation_is_unknown(self):
  from assess_results import queue_delta
  self.assertIsNone(queue_delta({'sessions':[]},{'sessions':[{'generation':'new','counters':{}}]}))

if __name__=='__main__':unittest.main()
