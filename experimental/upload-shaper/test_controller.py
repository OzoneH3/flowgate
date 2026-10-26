import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('m1', Path(__file__).with_name('controller.py'))
m1 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m1)

class ModelTests(unittest.TestCase):
    def test_tc_batch_requires_complete_arrays(self):
        self.assertEqual(m1.decode_tc_batch('[]\n[{"handle":"123:","refcnt":2}]\n', 2),
                         [[], [{'handle':'123:'}]])
        for text, count in [('[]',2), ('[][]',1), ('{}',1), ('[1]',1), ('[]garbage',1), ('',1)]:
            with self.assertRaises((RuntimeError, ValueError)):
                m1.decode_tc_batch(text,count)

    def test_tc_query_failure_never_returns_partial_snapshot(self):
        from unittest.mock import patch
        import types
        c=self.fake()
        with patch.object(m1.subprocess,'run',return_value=types.SimpleNamespace(returncode=1,stdout='[]',stderr='failure')):
            with self.assertRaises(RuntimeError):c.query_tc([('qdisc','show')])

    def test_topology_batches_all_parents_and_preserves_foreign_filters(self):
        c=self.fake();c.link={};calls=[]
        def query(commands):
            calls.append(commands)
            if len(calls)==1:
                return [[], [{'class':'htb','handle':'123:fffe'},{'class':'htb','handle':'123:1'}], [], [], []]
            return [[], [{'kind':'bpf','pref':7}]]
        c.query_tc=query
        result=c.topology()
        self.assertEqual(len(calls),2)
        self.assertEqual(len(calls[0]),5)
        self.assertEqual(result['class_filters'],[{'parent':'123:1','filters':[{'kind':'bpf','pref':7}]}])

    def test_rate_and_queue_bounds(self):
        for value in (True, 0, -1, 999999, 1000000001, '1000000', 1.5):
            with self.assertRaises(ValueError):
                m1.rate(value)
        self.assertEqual(m1.rate(1000000), 1000000)
        self.assertEqual(m1.queue_bytes(1000000, 1500), 3125)
        self.assertEqual(m1.queue_bytes(4000000, 1500), 12500)
        self.assertEqual(m1.queue_bytes(1000000000, 1500), 262144)

    def test_segmentation_sizing_floors_and_bounds(self):
        gso = 65536
        # Two superpackets always fit; the bound grows to 16 superpackets.
        self.assertEqual(m1.queue_bytes(1000000, 1500, gso), 3 * gso)
        self.assertEqual(m1.queue_bytes(8000000, 1500, gso), 3 * gso)
        self.assertEqual(m1.queue_bytes(100000000, 1500, gso), 312500)
        self.assertEqual(m1.queue_bytes(1000000000, 1500, gso), 16 * gso)
        # Burst admits one whole superpacket; without segmentation the old rule holds.
        self.assertEqual(m1.burst_bytes(1000000, 1500, gso), gso)
        self.assertEqual(m1.burst_bytes(1000000, 1500), 3000)
        self.assertEqual(m1.burst_bytes(200000000, 1500, gso), 125000)
        c = self.fake(); c.mtu = 1500; c.link = {'gso_max_size': gso}
        c.compatibility = {'topology': 'veth-noqueue'}
        self.assertIn('3000', c.class_params(1000000))
        c.compatibility = {'topology': 'single-queue-default-fq_codel'}
        self.assertIn(str(gso), c.class_params(1000000))

    def fake(self):
        c = object.__new__(m1.Controller)
        c.verify = lambda: None
        c.fault = None; c.applying = False; c.partial = []
        c.bindings = {'cookie': {'app': 'uid:key'}}; c.apps = {'uid:key': {'minor': 1}}
        c.dev = 'test0'; c.next_minor=2
        import json
        c.counters = [{'packets': 0, 'bytes': 0} for _ in range(18)]
        c.health = {'config_until': 2**64-1, 'bindings': [{'cookie': 'cookie', 'minor': 1, 'until': 2**64-1}]}
        c.k = lambda *a: json.dumps(c.health if a[0]=='health' else c.counters)
        return c

    def test_status_never_claims_application_wide_coverage(self):
        c = self.fake()
        self.assertEqual(c.status()['status'], 'Active')
        self.assertFalse(c.status()['application_wide_guarantee'])
        c.counters[0]['packets'] = 1
        self.assertEqual(c.status()['status'], 'Partial')
        c.counters[0]['packets'] = 0; c.counters[17]['packets'] = 1
        self.assertEqual(c.status()['status'], 'Partial')
        c.counters[17]['packets'] = 0; c.health['config_until'] = 0
        self.assertEqual(c.status()['status'], 'Partial')
        self.assertEqual(c.status()['covered_bindings'], 0)
        c.applying = True
        self.assertEqual(c.status()['status'], 'Applying')
        c.fault = 'objects changed'
        self.assertEqual(c.status()['status'], 'Unsupported')

    def test_ownership_comparison_keeps_foreign_changes(self):
        a = {'refcnt': 2, 'options': {'direct_packets_stat': 0}, 'handle': '123:','id':7}
        b = dict(a, refcnt=3, options={'direct_packets_stat': 999})
        self.assertEqual(m1.structural(a), m1.structural(b))
        self.assertNotEqual(m1.structural(a), m1.structural(dict(b, id=8)))
        self.assertNotEqual(m1.structural(a), m1.structural(dict(b, handle='124:')))

    def test_live_change_keeps_class_and_creation_only_flow_count(self):
        c = self.fake(); c.apps = {'uid:key': {'minor': 3, 'rate': 4000000}}
        c.major=0x123; c.mtu=1500
        ops=[];c.mutate=lambda *a:ops.append(a)
        c.set_cap('uid:key',8000000)
        self.assertEqual(c.apps['uid:key']['minor'],3)
        self.assertEqual(c.apps['uid:key']['rate'],8000000)
        self.assertNotIn('flows',ops[1])
        self.assertIn('25000',ops[1])

    def test_retirement_unbinds_before_deleting_and_does_not_reuse_minor(self):
        c = self.fake();c.apps = {'uid:key': {'minor': 3}};c.major=0x123;c.next_minor=4
        c.bindings = {'one': {'app': 'uid:key'}, 'other': {'app': 'other'}}
        ops=[];c.k=lambda *a: ops.append(('kernel',a));c.mutate=lambda *a:ops.append(('tc',a))
        c.remove('uid:key')
        self.assertEqual(ops[0], ('kernel',('del','one')))
        self.assertEqual(ops[1][1][0:2], ('qdisc','del'))
        self.assertEqual(ops[2][1][0:2], ('class','del'))
        self.assertEqual(c.next_minor,4)
        self.assertEqual(set(c.bindings),{'other'})


    def test_churn_limit_is_concurrent_not_lifetime(self):
        c=self.fake();c.apps={};c.bindings={};c.major=0x123;c.mtu=1500;c.next_minor=1
        c.mutate=lambda *a:None
        c.k=lambda *a:None
        for i in range(40):
            c.set_cap('app',4000000)
            self.assertEqual(c.apps['app']['minor'],i+1)
            c.remove('app')
        c.next_minor=0xfffe
        with self.assertRaisesRegex(ValueError,'class_generation_exhausted'):
            c.set_cap('app',4000000)

class CompatibilityTests(unittest.TestCase):
    def topology(self):
        return {'qdiscs': [{'kind':'fq_codel','handle':'0:','root':True,'options':
            {'limit':10240,'flows':1024,'quantum':1514,'target':4999,'interval':99999,
             'memory_limit':33554432,'ecn':True,'drop_batch':64}}],
            'classes':[], 'egress':[], 'ingress':[], 'root_filters':[]}
    def test_narrow_nic_and_refusals(self):
        import copy
        link={'mtu':1500,'link_type':'ether','parentbus':'virtio','num_tx_queues':1,'flags':['UP','LOWER_UP'],'gso_max_size':65536,'gso_max_segs':65535}
        features={k:'off' for k in ('tcp-segmentation-offload','generic-segmentation-offload','tx-udp-segmentation','hw-tc-offload','scatter-gather')}
        check=lambda l,q,f: m1.compatibility(l,q,f,'fq_codel')['supported']
        self.assertTrue(check(link,self.topology(),features))
        self.assertFalse(check(dict(link,num_tx_queues=2),self.topology(),features))
        self.assertFalse(check(link,self.topology(),None))
        # Segmentation offloads are a recorded matrix, not a refusal; hardware TC offload is refused.
        for k in ('tcp-segmentation-offload','generic-segmentation-offload','tx-udp-segmentation','scatter-gather'):
            r=m1.compatibility(link,self.topology(),dict(features,**{k:'on'}),'fq_codel')
            self.assertTrue(r['supported'],r); self.assertEqual(r['segmentation']['profile'],'segmentation-capable')
            self.assertEqual(r['segmentation']['superpacket_bytes'],65536)
        # A missing hw-tc-offload flag is a refusal, never an implicit off.
        missing=dict(features);del missing['hw-tc-offload']
        self.assertFalse(check(link,self.topology(),missing))
        # The superpacket bound is the largest advertised maximum.
        big=m1.compatibility(dict(link,gso_ipv4_max_size=131072),self.topology(),features,'fq_codel')
        self.assertEqual(big['segmentation']['superpacket_bytes'],131072)
        self.assertEqual(m1.compatibility(link,self.topology(),features,'fq_codel')['segmentation']['profile'],'segmentation-off')
        self.assertFalse(check(link,self.topology(),dict(features,**{'hw-tc-offload':'on'})))
        # netdevsim (kernel NIC simulator) is accepted as a NIC bus; unknown buses and missing gso_max_size are not.
        self.assertTrue(check(dict(link,parentbus='netdevsim'),self.topology(),features))
        self.assertFalse(check(dict(link,parentbus='usb'),self.topology(),features))
        self.assertFalse(check(dict(link,gso_max_size=None),self.topology(),features))
        self.assertFalse(check(dict(link,gso_max_size=524288),self.topology(),features))
        for field in ['egress','ingress','root_filters','classes']:
            q=self.topology();q[field]=[{'foreign':True}];self.assertFalse(check(link,q,features))
        for mutation in [{'handle':'8000:'},{'kind':'mq'},{'options':{}}]:
            q=self.topology();q['qdiscs'][0].update(mutation);self.assertFalse(check(link,q,features))
        self.assertFalse(m1.compatibility(link,self.topology(),features,'pfifo_fast')['supported'])
    def test_pending_root_recovery_is_narrow(self):
        import json,copy
        c=object.__new__(m1.Controller);c.major=0x123;c.ids={'program':7}
        c.k=lambda *args:json.dumps(c.ids)
        c.original=self.topology();c.expected=copy.deepcopy(c.original)
        c.setup_step=['qdisc','replace','dev','test0','root']
        actual=copy.deepcopy(c.original);actual['qdiscs']=[{'kind':'htb','handle':'123:','root':True}]
        self.assertTrue(c.setup_topology_owned(actual))
        for key,addition in [('qdiscs',{'kind':'clsact','handle':'ffff:'}),('egress',{'kind':'bpf','pref':99}),('classes',{'kind':'htb','handle':'999:1'})]:
            other=copy.deepcopy(actual);other[key].append(addition)
            self.assertFalse(c.setup_topology_owned(other))
        c.expected=copy.deepcopy(actual)
        c.setup_step=['class','add','dev','test0','classid','123:fffe']
        actual['classes']=[{'class':'htb','handle':'123:fffe'}]
        self.assertTrue(c.setup_topology_owned(actual))
        c.setup_step=None
        self.assertFalse(c.setup_topology_owned(actual))

    def test_empty_journal_generation_guards(self):
        d={'major':0x123,'boot_id':'old','netns':'net:[1]','ifindex':2,'interface':'x','original':self.topology()}
        changed={'qdiscs':[{'kind':'pfifo_fast','handle':'0:'}],'classes':[]}
        check=lambda actual,pins,boot: m1.journal_empty(d,actual,pins,boot,'net:[1]',2,'x')
        self.assertTrue(check(self.topology(),False,'old'))
        self.assertFalse(check(changed,False,'old'))
        self.assertTrue(check(changed,False,'new'))
        self.assertFalse(check(changed,True,'new'))
        self.assertFalse(check({'qdiscs':[{'handle':'123:'}],'classes':[]},False,'new'))
        self.assertFalse(m1.journal_empty(d,self.topology(),False,'old','net:[2]',2,'x'))

    def test_feature_parser(self):
        self.assertEqual(m1.parse_features('Features for x:\n tcp-segmentation-offload: off [fixed]\n generic-segmentation-offload: on\n'),
                         {'tcp-segmentation-offload':'off','generic-segmentation-offload':'on'})

if __name__ == '__main__':
    unittest.main()
