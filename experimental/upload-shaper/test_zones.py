"""Hierarchy/admission regression models, not receiver evidence."""
import copy
import unittest
import test_controller
m1 = test_controller.m1

class ZoneTests(unittest.TestCase):
    def fake(self):
        c=test_controller.TrafficPriorityTests().fake()
        c.refresh_during_apply=lambda: None
        return c
    def policy(self, c, zones=None, **kw):
        e={'rate':12_000_000,'download_rate':16_000_000,'priority':'high'}
        if zones is not None:e['zones']=zones
        c.set_policy({'apps':{'0:a':e},**kw})
    def test_cumulative_caps_leaf_priority_and_one_parent_allocation(self):
        c=self.fake()
        self.policy(c, {'local':{'rate':8_000_000,'priority':'low'},'internet':{'rate':4_000_000,'priority':'normal'}},upload_budget=40_000_000)
        c.set_cap('0:a',12_000_000,16_000_000,'high')
        a=c.apps['0:a'];p=c.class_state['ul'][a['minor']]
        children={z:c.class_state['ul'][m] for z,m in a['zone_minors'].items()}
        self.assertEqual(p[:2],(8_000_000,12_000_000))
        self.assertEqual(children['local'][1:],(8_000_000,2))
        self.assertEqual(children['internet'][1:],(4_000_000,1))
        self.assertEqual(children[''][1:],(12_000_000,0))
        self.assertLessEqual(sum(v[0] for v in children.values()),p[0])
        self.assertEqual(c.class_ids('0:a','local')[1],str(a['minor']))
        # Interior gets no explicit leaf qdisc.
        self.assertFalse(any(o[:3]==('tc','qdisc','add') and c.handle(a['minor']) in o for o in c.ops))
    def test_conversion_and_last_zone_delete_preserve_opposite_direction(self):
        c=self.fake();self.policy(c);c.set_cap('0:a',12_000_000,16_000_000,'high')
        dl=copy.deepcopy(c.class_state['dl']);minor=c.apps['0:a']['minor']
        c.bindings={'cookie':{'app':'0:a','zone':'local'}}
        for zones in ({'local':{'rate':4_000_000}},None):
            c.ops.clear();self.policy(c,zones)
            self.assertEqual(c.class_state['dl'],dl)
            self.assertFalse(any(o[0]=='tc' and c.ifb in o for o in c.ops))
            self.assertTrue(all(o[4]==str(minor) for o in c.ops if o[:2]==('k','bind')))
        self.assertEqual(c.class_ids('0:a','local'),(str(minor),str(minor)))
    def test_direction_removal_children_first(self):
        c=self.fake();self.policy(c,{'local':{'rate':4_000_000}});c.set_cap('0:a',12_000_000,16_000_000,'high')
        c.ops.clear();c.set_policy({'apps':{'0:a':{'download_rate':16_000_000,'zones':{'local':{'download_rate':4_000_000}}}}})
        deletes=[o[o.index('classid')+1] for o in c.ops if o[:3]==('tc','class','del') and c.dev in o]
        self.assertEqual(deletes[-1],c.handle(c.apps['0:a']['minor']))
        self.assertEqual(c.class_ids('0:a','local')[0],'0')
    def test_admission_is_before_mutation_and_counts_nodes(self):
        c=self.fake();before=copy.deepcopy(c.policy_apps)
        bad={'apps':{f'0:a{i}':{'zones':{'local':{'rate':4_000_000}}} for i in range(5)}}
        with self.assertRaisesRegex(ValueError,'class_capacity'):c.set_policy(bad)
        self.assertEqual(c.ops,[]);self.assertEqual(c.policy_apps,before)
        c.next_minor=m1.MAX_APP_MINOR-1
        with self.assertRaisesRegex(ValueError,'class_generation'):self.policy(c,{'local':{'rate':4_000_000}})
        self.assertEqual(c.ops,[])
    def test_priority_dormant_without_budget_and_child_floor_refusal(self):
        e={'priority':'high','zones':{'local':{'priority':'low'},'internet':{'priority':'normal'}}}
        t=m1.zone_tuples(e,(3_000_000,3_000_000,0),'rate',False)
        self.assertEqual(set(t.values()),{(1_000_000,3_000_000,0)})
        c=self.fake()
        with self.assertRaisesRegex(ValueError,'allocation_below_minimum'):
            c.set_policy({'upload_budget':16_000_000,'apps':{'0:a':{'rate':1_000_000,'zones':{'local':{'priority':'low'},'internet':{'priority':'high'}}}}})
        self.assertEqual(c.ops,[])
    def test_reclassification_withdraws_stale_map_and_unknown_uses_all(self):
        c=self.fake();self.policy(c,{'local':{'rate':4_000_000}});c.set_cap('0:a',12_000_000,16_000_000,'high')
        c.verify=lambda:None;c.exists=lambda _:True
        c.bindings={'cookie':{'app':'0:a','zone':'local','descriptor':{}}};c.ops.clear()
        c.rezone({'bindings':{'cookie':''}})
        self.assertEqual(c.ops[0],('k','del','cookie'))
        self.assertEqual(c.ops[-1],('k','bind','cookie',*c.class_ids('0:a','')))
        self.assertEqual(c.bindings['cookie']['zone'],'')
        c.exists=lambda _:False;c.rezone({'bindings':{'cookie':'internet'}})
        self.assertNotIn('cookie',c.bindings)
