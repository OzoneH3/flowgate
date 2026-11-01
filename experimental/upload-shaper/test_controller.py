import copy
import importlib.util
from pathlib import Path
import unittest
import time
import json

spec = importlib.util.spec_from_file_location('m1', Path(__file__).with_name('controller.py'))
m1 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m1)

def init_policy(c, ul=None):
    # Fakes bypass __init__: give them the session traffic-policy state.
    c.policy_apps = {}; c.budgets = {'ul': 0, 'dl': 0}; c.applied_budget = {'ul': 0, 'dl': 0}
    c.class_state = {'ul': dict(ul or {}), 'dl': {}}
    return c

class ModelTests(unittest.TestCase):
    def test_explicit_trial_never_weakens_default_namespace_or_topology_guards(self):
        for parent, host, uid, allowed in (('', False, 0, False), ('net:[1]', False, 0, False), ('net:[2]', False, 0, True), ('', True, 0, True), ('net:[2]', True, 0, False), ('', True, 1000, False)):
            if allowed: m1.validate_deployment_mode(parent, host, 'net:[1]', uid)
            else:
                with self.assertRaises(ValueError):m1.validate_deployment_mode(parent, host, 'net:[1]', uid)
        m1.validate_activation_topology({'supported':True,'topology':'single-queue-default-fq_codel'}, True)
        m1.validate_activation_topology({'supported':True,'topology':'veth-noqueue'}, False)
        with self.assertRaises(ValueError):m1.validate_activation_topology({'supported':True,'topology':'veth-noqueue'}, True)
        with self.assertRaises(ValueError):m1.validate_activation_topology({'supported':False,'topology':'single-queue-default-fq_codel','reasons':['foreign']}, True)

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

    def test_empty_socket_census_withdraws_binding_and_keeps_heartbeat(self):
        c=self.fake();c.base=Path('/unused');c.compatibility={'topology':'veth-noqueue'}
        c.bindings={'cookie':{'app':'uid:key','inode':1,'protocol':'udp','netns':'net:[1]', 'descriptor': {}}}
        c.apps={'uid:key':{'minor':1,'idle_since':m1.time.monotonic()}}
        calls=[];c.exists=lambda s:False;c.k=lambda *a:calls.append(a)
        c.tick()
        self.assertEqual(c.bindings,{})
        self.assertEqual(calls,[('del','cookie'),('beat',)])
        # A malformed worker reply is covered separately below.

    def test_socket_worker_fresh_requests_and_close_on_cleanup_refusal(self):
        c=self.fake();calls=[]
        class Worker:
            def call(self,*args):
                calls.append(args)
                return 'true' if len(calls)==1 else 'null'
            def close(self):calls.append('closed')
        c.socket_worker=Worker()
        self.assertTrue(c.exists({}))
        with self.assertRaises(RuntimeError): c.exists({})
        self.assertEqual(calls,[('exists','7b7d'),('exists','7b7d')])
        c.closed=False
        def refuse():raise RuntimeError('foreign topology')
        c.cleanup_objects=refuse
        with self.assertRaisesRegex(RuntimeError,'foreign topology'):c.close()
        self.assertEqual(calls[-1],'closed')

    def test_verified_topology_combines_only_matching_fresh_classes(self):
        import copy
        c=self.fake();c.link={}
        classes=[{'class':'htb','handle':'123:fffe'},{'class':'htb','handle':'123:1'}]
        calls=[]
        def query(commands):
            calls.append(commands)
            return [[],copy.deepcopy(classes),[],[],[],[],[{'kind':'bpf','pref':7}]]
        c.query_tc=query
        expected={'classes':copy.deepcopy(classes),'qdiscs':[]}
        result=c.topology(expected)
        self.assertEqual(len(calls),1)
        self.assertEqual(len(calls[0]),7)
        self.assertEqual(result['class_filters'],[{'parent':'123:1','filters':[{'kind':'bpf','pref':7}]}])
        for changed in [classes[:1],classes+[{'class':'htb','handle':'123:2'}],
                        [dict(classes[0],rate=1),classes[1]]]:
            c.query_tc=lambda commands:[[],changed,[],[],[],[],[]]
            with self.assertRaisesRegex(RuntimeError,'classes changed'):
                c.topology(expected)
        for bad in [classes+[classes[0]],[{'handle':'bad'}]]:
            with self.assertRaises(RuntimeError):c.topology({'classes':bad,'qdiscs':[]})

    def test_kernel_worker_requires_success_marker_and_reuses_only_process(self):
        import sys
        script = "import sys,json\nn=0\nfor line in sys.stdin:\n n+=1;print(json.dumps({'n':n}));print('\\x1eOK',flush=True)"
        w=m1.KernelWorker([sys.executable,'-u','-c',script])
        try:
            self.assertEqual(m1.json.loads(w.call('ids','/unused')),{'n':1})
            pid=w.process.pid
            self.assertEqual(m1.json.loads(w.call('ids','/unused')),{'n':2})
            self.assertEqual(w.process.pid,pid)
        finally:w.close()
        self.assertIsNone(w.process)

    def test_kernel_worker_complete_json_without_ack_is_failure(self):
        import sys
        for script in ["print('{}',flush=True);raise SystemExit(1)",
                       "print('{}');print('\\x1eBAD',flush=True)"]:
            w=m1.KernelWorker([sys.executable,'-u','-c',script])
            with self.assertRaises(RuntimeError):w.call('ids','/unused')
            self.assertIsNone(w.process)

    def test_kernel_worker_timeout_and_fragmented_ack(self):
        import sys
        w=m1.KernelWorker([sys.executable,'-u','-c',"import time;time.sleep(10)"],timeout=.05)
        with self.assertRaisesRegex(RuntimeError,'timed out'):w.call('ids','/unused')
        self.assertIsNone(w.process)
        script="import sys,time;sys.stdin.readline();sys.stdout.write('{}\\n\\x1eO');sys.stdout.flush();time.sleep(.02);print('K',flush=True)"
        w=m1.KernelWorker([sys.executable,'-u','-c',script])
        try:self.assertEqual(m1.json.loads(w.call('ids','/unused')),{})
        finally:w.close()

    def test_kernel_worker_argument_bound(self):
        w=m1.KernelWorker(['/unused'])
        for pin in ['a\nb','a'*1024]:
            with self.assertRaises(RuntimeError):w.call('ids',pin)
        self.assertIsNone(w.process)

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
        c.dev = 'test0'; c.next_minor=2; init_policy(c, {1: (1000000, 1000000, 0)})
        c.verified_at = time.monotonic(); c.verifications = 0; c.status_reports = 0  # fresh observation for legacy expectations
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
        c.major=0x123; c.mtu=1500; c.bindings={}; init_policy(c, {3: (4000000, 4000000, 0)})
        ops=[];c.mutate=lambda *a:ops.append(a)
        c.set_cap('uid:key',8000000)
        self.assertEqual(c.apps['uid:key']['minor'],3)
        self.assertEqual(c.apps['uid:key']['rate'],8000000)
        self.assertNotIn('flows',ops[1])
        self.assertIn('25000',ops[1])

    def test_retirement_unbinds_before_deleting_and_does_not_reuse_minor(self):
        c = self.fake();c.apps = {'uid:key': {'minor': 3}};c.major=0x123;c.next_minor=4;init_policy(c, {3: (4000000, 4000000, 0)})
        c.bindings = {'one': {'app': 'uid:key'}, 'other': {'app': 'other'}}
        ops=[];c.k=lambda *a: ops.append(('kernel',a));c.mutate=lambda *a:ops.append(('tc',a))
        c.remove('uid:key')
        self.assertEqual(ops[0], ('kernel',('del','one')))
        self.assertEqual(ops[1][1][0:2], ('qdisc','del'))
        self.assertEqual(ops[2][1][0:2], ('class','del'))
        self.assertEqual(c.next_minor,4)
        self.assertEqual(set(c.bindings),{'other'})


    def test_churn_limit_is_concurrent_not_lifetime(self):
        c=self.fake();c.apps={};c.bindings={};c.major=0x123;c.mtu=1500;c.next_minor=1;init_policy(c)
        c.mutate=lambda *a:None
        c.k=lambda *a:None
        for i in range(40):
            c.set_cap('app',4000000)
            self.assertEqual(c.apps['app']['minor'],i+1)
            c.remove('app')
        c.next_minor=0xfffe
        with self.assertRaisesRegex(ValueError,'class_generation_exhausted'):
            c.set_cap('app',4000000)

    def test_interrupted_ul_steps_refuse_even_when_topology_looks_unchanged(self):
        c = self.fake(); c.pending_setup = True; c.dev = 'eth0'
        for kind, op in [('qdisc', 'replace'), ('class', 'add'), ('qdisc', 'add')]:
            c.setup_step = [kind, op, 'dev', 'eth0', 'root']
            with self.assertRaisesRegex(RuntimeError, 'no exact durable intent'):
                c.reject_ambiguous_ul_step()
        c.setup_step = ['class', 'add', 'dev', 'ifb0']
        c.reject_ambiguous_ul_step()

    def test_pending_ul_detail_detects_foreign_options_and_clsact_cleanup(self):
        c = self.fake(); c.dev = 'eth0'
        htb = {'kind': 'htb', 'root': True, 'options': {'quantum': 1500}}
        clsact = {'kind': 'clsact'}
        observed = {'qdiscs': [htb, clsact], 'classes': [{'options': {'quantum': 1500}}]}
        c.detailed_queues = lambda dev: copy.deepcopy(observed)
        c.ul_detail_expected = c.ul_setup_details()
        actual = {'qdiscs': [{'kind': 'htb', 'root': True}]}
        c.verify_ul_checkpoint(actual)
        observed['qdiscs'].remove(clsact)  # cleanup removes clsact first
        c.verify_ul_checkpoint(actual)
        observed['classes'][0]['options']['quantum'] = 3000
        with self.assertRaisesRegex(RuntimeError, 'preserving resources'):
            c.verify_ul_checkpoint(actual)
        c.ul_detail_expected = None  # old pending journal has no detailed proof
        with self.assertRaisesRegex(RuntimeError, 'preserving resources'):
            c.verify_ul_checkpoint(actual)

    def test_reconcile_preserves_ambiguous_and_detail_mismatch(self):
        from unittest.mock import patch
        import tempfile, types, os
        root = Path(__file__).resolve().parents[2] / '.workspace'
        root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=root) as directory:
            c = self.fake(); c.state = Path(directory); c.manifest = c.state / 'owner.json'
            c.dev = 'eth0'; c.index = 2; c.ns = 'net:[test]'; c.link = {}; c.partial = []
            c.ifb_link = lambda: {'ifindex': 3}
            token = 'a' * 32
            actual = {'qdiscs': [{'kind': 'htb', 'root': True}], 'classes': [],
                      'egress': [], 'ingress': [], 'root_filters': []}
            c.topology = lambda *a: copy.deepcopy(actual)
            c.detailed_queues = lambda dev: {'qdiscs': [{'kind': 'htb', 'options': {'quantum': 3000}}], 'classes': []}
            deleted = []; c.cleanup_objects = lambda: deleted.append('cleanup')
            c.save = lambda: deleted.append('adopt')
            doc = {'schema': 1, 'token': token, 'pin': '/sys/fs/bpf/fg-m1-' + token,
                   'netns': c.ns, 'interface': c.dev, 'ifindex': c.index, 'major': 123,
                   'ifb': 'fgdl' + token[:8], 'ifb_index': 3, 'expected': actual, 'ids': {},
                   'pending_setup': True, 'original': {},
                   'ul_detail_expected': {'qdiscs': [{'kind': 'htb', 'options': {'quantum': 1500}}], 'classes': []}}
            for step in (['class', 'add', 'dev', 'eth0', 'classid', '123:fff0'], None):
                doc['setup_step'] = step
                c.manifest.write_text(json.dumps(doc)); (c.state / 'owner.new').write_text('uncommitted')
                fake_stat = types.SimpleNamespace(st_mode=0o100600, st_uid=0, st_size=1024)
                with patch.object(Path, 'lstat', return_value=fake_stat):
                    with self.assertRaisesRegex(RuntimeError, 'preserving resources'):
                        c.reconcile()
                self.assertEqual(json.loads(c.manifest.read_text()), doc)
                self.assertEqual(deleted, [])
                self.assertTrue((c.state / 'owner.new').exists())

    def test_pending_cleanup_progresses_past_clsact_to_ifb_and_root(self):
        from unittest.mock import MagicMock
        c = self.fake(); c.dev = 'eth0'; c.major = 0x123; c.pending_setup = True
        c.ifb = 'fgdltest'; c.pin = Path('/nonexistent-fg-test-pin')
        c.manifest = MagicMock(); c.original = {'qdiscs': []}
        htb = {'kind': 'htb', 'root': True, 'handle': c.handle()}
        c.expected = {'qdiscs': [htb, {'kind': 'clsact'}]}
        detail = {'qdiscs': [htb, {'kind': 'clsact'}], 'classes': [{'options': {'quantum': 1500}}]}
        c.detailed_queues = lambda dev: copy.deepcopy(detail)
        c.ul_detail_expected = c.ul_setup_details()
        c.verify = lambda: c.verify_ul_checkpoint(c.expected)
        c.ifb_link = lambda: {'ifindex': 3}
        calls = []
        def mutate(*args):
            c.verify(); calls.append(args)
            if 'clsact' in args:
                detail['qdiscs'] = [htb]; c.expected['qdiscs'] = [htb]
            elif 'root' in args:
                c.expected['qdiscs'] = []
        c.mutate = mutate
        c.link_mutate = lambda *args: (c.verify(), calls.append(('link',) + args))
        c.topology = lambda: c.original
        c.cleanup_objects()
        self.assertEqual([x[0] for x in calls], ['qdisc', 'link', 'qdisc'])
        c.manifest.unlink.assert_called_once()

    def test_policy_post_validation_exception_faults(self):
        c = self.fake(); init_policy(c); c.apps = {}; c.bindings = {}
        c.apply_policy = lambda: (_ for _ in ()).throw(ValueError('after first tc change'))
        with self.assertRaisesRegex(RuntimeError, 'policy application failed after validation'):
            c.set_policy({'apps': {}})
        self.assertFalse(c.applying)
        with self.assertRaises(ValueError):
            c.set_policy({'upload_budget': 1, 'apps': {}})

class StatusObservationTests(unittest.TestCase):
    """Status is an observation: it never verifies, renews or beats; verification is recorded by verify()
    callers at the verification START and only on success; labels/states change at 1/2/5 s."""
    def fake(self):
        c = object.__new__(m1.Controller)
        c.fault = None; c.applying = False; c.partial = []
        c.bindings = {'cookie': {'app': 'uid:key'}}; c.apps = {'uid:key': {'minor': 1}}
        c.dev = 'test0'; c.next_minor = 2; init_policy(c, {1: (1000000, 1000000, 0)}); c.verified_at = None; c.verifications = 0; c.status_reports = 0
        c.counters = [{'packets': 0, 'bytes': 0} for _ in range(18)]
        c.health = {'config_until': 2**64-1, 'bindings': [{'cookie': 'cookie', 'minor': 1, 'until': 2**64-1}]}
        c.kcalls = []
        def k(*a):
            c.kcalls.append(a[0])
            return json.dumps(c.health if a[0] == 'health' else c.counters)
        c.k = k
        c.compatibility = {'topology': 'veth-noqueue'}
        c.link = {}
        return c
    def test_status_never_verifies_renews_or_beats(self):
        c = self.fake(); calls = []
        c.verify = lambda: calls.append('verify')
        for _ in range(5): c.status()
        self.assertEqual(calls, [])
        self.assertEqual(c.status_reports, 5)
        self.assertFalse({'bind', 'beat'} & set(c.kcalls), c.kcalls)
    def test_unknown_before_first_verification_and_never_active(self):
        c = self.fake(); c.verify = lambda: None
        s = c.status()
        self.assertEqual((s['verified_age_ms'], s['verification'], s['status']), (None, 'unknown', 'Partial'))
    def test_boundaries_fresh_stale_unknown_withdrawn(self):
        c = self.fake(); c.verify = lambda: None; now = time.monotonic()
        for age, label, state in ((0.5, 'fresh', 'Active'), (1.5, 'stale', 'Partial'), (2.5, 'unknown', 'Partial'), (5.5, 'unknown', 'Partial')):
            c.verified_at = now - age; c.fault = None
            s = c.status()
            self.assertEqual((s['verification'], s['status']), (label, state), (age, s))
            self.assertTrue(abs(s['verified_age_ms'] - age * 1000) < 200, s['verified_age_ms'])
        self.assertIsNone(c.fault, 'status must not set a permanent fault')
        self.assertTrue(any('verification watchdog' in x for x in s['limitations']), s)
        self.assertEqual(s['covered_bindings'], 0)
        c.verified_at = time.monotonic()
        self.assertEqual(c.status()['status'], 'Active')
        c.fault = 'ownership mismatch'
        self.assertEqual(c.status()['status'], 'Unsupported')
    def test_binding_coverage_is_same_health_observation_and_never_authority(self):
        c = self.fake(); c.verified_at = time.monotonic()
        c.bindings['other'] = {'app': 'uid:other', 'cookie': 'other'}
        c.apps['uid:other'] = {'minor': 2}
        c.health['bindings'].append({'cookie': 'other', 'minor': 99, 'until': 2**64-1})
        s = c.status()
        self.assertEqual([b['covered'] for b in s['bindings']], [True, False])
        self.assertEqual(s['covered_bindings'], 1)
        self.assertNotIn('covered', c.bindings['cookie'])
        for condition in ('binding_expired', 'config_expired', 'watchdog', 'fault'):
            x = self.fake(); x.verified_at = time.monotonic()
            if condition == 'binding_expired': x.health['bindings'][0]['until'] = 0
            if condition == 'config_expired': x.health['config_until'] = 0
            if condition == 'watchdog': x.verified_at -= 6
            if condition == 'fault': x.fault = 'ownership changed'
            state = x.status()
            self.assertEqual(state['covered_bindings'], 0, condition)
            self.assertFalse(any(b['covered'] for b in state['bindings']), condition)
    def test_verify_records_start_anchor_only_on_success(self):
        c = self.fake()
        import types
        # Failed verification must not refresh the observation.
        c.get_link = lambda: (_ for _ in ()).throw(RuntimeError('link gone'))
        with self.assertRaises(RuntimeError): m1.Controller.verify(c)
        self.assertIsNone(c.verified_at); self.assertEqual(c.verifications, 0)
        # Successful verification: anchor at the START of verify.
        c.ns = 'net:[1]'; c.link = {'ifindex': 1}; c.expected = {'qdiscs': []}; c.ids = None; c.original = {}
        c.get_link = lambda: {'ifindex': 1}
        c.topology = lambda *a: (time.sleep(0.05), {'qdiscs': []})[1]
        import os as _os
        real = m1.os.readlink
        m1.os.readlink = lambda p: 'net:[1]'
        try:
            before = time.monotonic(); m1.Controller.verify(c); after = time.monotonic()
        finally:
            m1.os.readlink = real
        self.assertEqual(c.verifications, 1)
        self.assertTrue(before <= c.verified_at <= after - 0.04, (before, c.verified_at, after))
    def test_mutation_path_still_verifies(self):
        # Scope: mutate() only. tick() and bind() are exercised separately below.
        c = self.fake(); calls = []
        c.verify = lambda: calls.append('verify')
        c.call = lambda *a: None; c.save = lambda: None; c.topology = lambda: {'qdiscs': []}
        c.pending_setup = False; c.cleaning = False
        m1.Controller.mutate(c, 'class', 'change')
        self.assertEqual(calls, ['verify'])

    def test_tick_path_still_verifies_and_renews(self):
        c = self.fake(); calls = []
        c.verify = lambda: calls.append('verify')
        c.bindings = {'cookie': {'app': 'uid:key', 'inode': 7, 'protocol': 'tcp', 'netns': 'ns', 'descriptor': {}}}
        c.apps['uid:key']['idle_since'] = time.monotonic()
        c.exists = lambda s: True
        c.k = lambda *a: (calls.append(a[0]), 'OK')[1]
        m1.Controller.tick(c)
        self.assertEqual(calls, ['verify', 'bind', 'beat'], calls)

    def test_apply_checkpoint_revalidates_all_sockets_before_renewal(self):
        c = self.fake(); calls = []
        c.applying = True; c.pending_setup = False; c.cleaning = False; c.last_tick = 0
        c.verify = lambda: calls.append('verify')
        c.bindings = {
            'live': {'app': 'uid:key', 'descriptor': {'id': 'live'}},
            'gone': {'app': 'uid:key', 'descriptor': {'id': 'gone'}},
        }
        c.apps['uid:key']['idle_since'] = 0
        c.exists = lambda s: (calls.append('exists:' + s['id']), s['id'] == 'live')[1]
        c.k = lambda *a: calls.append(a)
        c.remove = lambda app: self.fail('checkpoint must not retire classes')
        m1.Controller.refresh_during_apply(c)
        self.assertEqual(calls[:3], ['verify', 'exists:live', 'exists:gone'])
        self.assertEqual(calls[3:], [('bind', 'live', '1', '0'), ('del', 'gone'), ('beat',)])
        self.assertEqual(set(c.bindings), {'live'})

    def test_apply_checkpoint_failure_cannot_renew_partial_evidence(self):
        c = self.fake(); calls = []
        c.applying = True; c.pending_setup = False; c.cleaning = False; c.last_tick = 0
        c.verify = lambda: None
        c.bindings = {'a': {'app': 'uid:key', 'descriptor': {'id': 'a'}},
                      'b': {'app': 'uid:key', 'descriptor': {'id': 'b'}}}
        def exists(d):
            if d['id'] == 'b': raise ValueError('incomplete socket observation')
            return True
        c.exists = exists; c.k = lambda *a: calls.append(a)
        with self.assertRaisesRegex(RuntimeError, 'maintenance during configuration failed'):
            m1.Controller.refresh_during_apply(c)
        self.assertEqual(calls, [])
        self.assertEqual(set(c.bindings), {'a', 'b'})

    def test_apply_checkpoint_write_failure_renews_only_prefix_and_never_beats(self):
        c = self.fake(); calls = []
        c.applying = True; c.pending_setup = False; c.cleaning = False; c.last_tick = 0
        c.verify = lambda: None
        c.bindings = {'a': {'app': 'uid:key', 'descriptor': {}},
                      'b': {'app': 'uid:key', 'descriptor': {}}}
        c.exists = lambda d: True
        def k(*args):
            calls.append(args)
            if args[:2] == ('bind', 'b'): raise ValueError('map write failed')
        c.k = k
        with self.assertRaisesRegex(RuntimeError, 'maintenance during configuration failed'):
            c.refresh_during_apply()
        self.assertEqual([x[:2] for x in calls], [('bind', 'a'), ('bind', 'b')])
        self.assertEqual(c.last_tick, 0)

    def test_slow_apply_checks_lease_before_next_tc_change(self):
        c = self.fake(); calls = []
        c.applying = True; c.pending_setup = False; c.cleaning = False; c.last_tick = 0
        c.tick = lambda retire_idle=True: calls.append(('tick', retire_idle))
        c.verify = lambda: calls.append('verify')
        c.call = lambda *a: calls.append('tc')
        c.topology = lambda: {'qdiscs': []}
        c.save = lambda: calls.append('save')
        m1.Controller.mutate(c, 'class', 'change')
        self.assertEqual(calls, [('tick', False), 'verify', 'tc', 'save'])

    def test_failed_apply_checkpoint_stops_before_tc_change(self):
        c = self.fake(); calls = []
        c.applying = True; c.pending_setup = False; c.cleaning = False; c.last_tick = 0
        def failed_tick(retire_idle=True):
            raise ValueError('socket evidence incomplete')
        c.tick = failed_tick
        c.verify = lambda: calls.append('verify')
        c.call = lambda *a: calls.append('tc')
        with self.assertRaisesRegex(RuntimeError, 'maintenance during configuration failed'):
            m1.Controller.mutate(c, 'class', 'change')
        self.assertEqual(calls, [])

    def test_status_age_sampled_after_health_rpcs(self):
        # A slow health RPC must not make the reported age younger than the report time.
        c = self.fake(); c.verified_at = time.monotonic()
        base_k = c.k
        def slow_k(name, *a):
            if name == 'health':
                time.sleep(0.3)
            return base_k(name, *a)
        c.k = slow_k
        r = m1.Controller.status(c)
        self.assertGreaterEqual(r['verified_age_ms'], 300, r)

class BindingBatchTests(unittest.TestCase):
    def fixture(self):
        c=object.__new__(m1.Controller);c.bindings={};events=[];c.last_tick=time.monotonic();c.tick=lambda retire_idle=False:None
        c.verify=lambda:events.append('verify')
        def bind(row,**kw):
            events.append(('bind',row['expected_cookie'],kw['verified'],kw.get('routes_seen')))
            if row.get('refuse'):raise ValueError('changed owner')
            c.bindings[row['expected_cookie']]={'app':row['expected_app']}
            return {'cookie':row['expected_cookie'],'app':row['expected_app']}
        c.bind=bind;c.k=lambda *args:events.append(args)
        return c,events
    def rows(self):return [{'expected_cookie':'one','expected_app':'0:alpha'},{'expected_cookie':'two','expected_app':'0:beta'}]
    def test_brackets_and_isolates_refused_member(self):
        c,events=self.fixture();rows=self.rows();rows[0]['refuse']=True
        result=c.bind_many({'bindings':rows})
        self.assertEqual(events[0],'verify');self.assertEqual(events[-1],'verify')
        self.assertEqual(events[1][2:],events[2][2:])
        self.assertEqual(result['bindings'][0]['error'],'changed owner')
        self.assertEqual(result['bindings'][1]['cookie'],'two')
        self.assertEqual(set(c.bindings),{'two'})
    def test_closing_failure_removes_all_batch_publications(self):
        c,events=self.fixture();n=[0]
        def verify():
            n[0]+=1
            if n[0]==2:raise RuntimeError('foreign topology')
        c.verify=verify
        with self.assertRaisesRegex(RuntimeError,'foreign topology'):c.bind_many({'bindings':self.rows()})
        self.assertEqual(c.bindings,{})
        self.assertEqual(events[-2:],[('del','one'),('del','two')])
    def test_precheck_failure_publishes_nothing(self):
        c,events=self.fixture()
        def refuse():raise RuntimeError('foreign topology')
        c.verify=refuse
        with self.assertRaises(RuntimeError):c.bind_many({'bindings':self.rows()})
        self.assertEqual(events,[])
    def test_long_batch_checkpoints_existing_bindings_without_retirement(self):
        from unittest.mock import patch
        c,events=self.fixture();clock=[0.0];c.last_tick=0;renewals=[]
        c.bindings['existing']={'app':'0:unrelated'}
        original_bind=c.bind
        def bind(row,**kw):
            clock[0]+=2.5
            return original_bind(row,**kw)
        def tick(retire_idle=True):
            self.assertFalse(retire_idle)
            self.assertIn('existing',c.bindings)
            renewals.append(clock[0]);c.last_tick=clock[0]
        c.bind=bind;c.tick=tick
        rows=[{'expected_cookie':str(i),'expected_app':'0:alpha'} for i in range(8)]
        with patch.object(m1.time,'monotonic',side_effect=lambda:clock[0]):c.bind_many({'bindings':rows})
        self.assertEqual(renewals,[2.5,5,7.5,10,12.5,15,17.5])
        self.assertIn('existing',c.bindings)

    def test_batch_bounds_and_duplicate_identity(self):
        c,events=self.fixture()
        for rows in ([],self.rows()*5,[self.rows()[0]]*2,[{}]):
            with self.assertRaises(ValueError):c.bind_many({'bindings':rows})
        self.assertEqual(events,[])

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

    def test_pending_default_class_under_budget_parent(self):
        import json,copy
        c=object.__new__(m1.Controller);c.major=0x123;c.ids={'program':7}
        c.k=lambda *args:json.dumps(c.ids)
        c.original=self.topology();base=copy.deepcopy(c.original)
        root={'kind':'htb','handle':'123:','root':True,'options':{'r2q':10,'default':'0xfff1','direct_qlen':1000}}
        leaf=lambda h:{'class':'htb','handle':h,'root':True,'prio':0,'rate':1,'ceil':1,'burst':2400,'cburst':2400}
        c.expected=dict(base,qdiscs=[root],classes=[leaf('123:fff1'),leaf('123:fff0')])
        c.setup_step=['class','add','dev','test0','parent','123:fff0','classid','123:fffe','htb','rate','100gbit']
        inner={k:v for k,v in leaf('123:fff0').items() if k!='prio'}
        child={'class':'htb','handle':'123:fffe','parent':'123:fff0','prio':0,'rate':1,'ceil':1,'burst':2400,'cburst':2400}
        ok=dict(c.expected,classes=[leaf('123:fff1'),child,inner])
        self.assertTrue(c.setup_topology_owned(ok))
        for bad in ([leaf('123:fff1'),child,dict(inner,rate=2)], [dict(leaf('123:fff1'),rate=2),child,inner]):
            self.assertFalse(c.setup_topology_owned(dict(c.expected,classes=bad)))

    def test_pending_default_leaf_marks_only_its_class(self):
        import json
        c=object.__new__(m1.Controller);c.major=0x123;c.ids={'program':7}
        c.k=lambda *args:json.dumps(c.ids);c.original=self.topology()
        root={'kind':'htb','handle':'123:','root':True,'options':{}}
        cls={'class':'htb','handle':'123:fffe','parent':'123:fff0','prio':0,'rate':1,'ceil':1}
        c.expected=dict(c.original,qdiscs=[root],classes=[cls])
        c.setup_step=['qdisc','add','dev','test0','parent','123:fffe','handle','fffe:','fq_codel']
        leafq={'kind':'fq_codel','handle':'fffe:','parent':'123:fffe'}
        self.assertTrue(c.setup_topology_owned(dict(c.expected,qdiscs=[root,leafq],classes=[dict(cls,leaf='fffe:')])))
        self.assertFalse(c.setup_topology_owned(dict(c.expected,qdiscs=[root,leafq],classes=[dict(cls,leaf='fffe:',rate=2)])))

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

class DownloadOwnershipTests(unittest.TestCase):
    def test_htb_major_filter_parents_are_inspected_on_nic_and_ifb(self):
        c=object.__new__(m1.Controller);c.dev='nic';c.ifb='owned';c.link={}
        c.ifb_link=lambda: {'ifindex':2}
        queries=[]
        def query(commands):
            out=[]
            for q in commands:
                queries.append(q);major='123:' if q[3]=='nic' else '234:'
                if q[0]=='qdisc':out.append([{'kind':'htb','root':True,'handle':major}])
                elif q[0]=='class':out.append([{'class':'htb','handle':major+'fffe'}])
                elif q[-2:]==('parent',major):out.append([{'kind':'matchall','pref':12}])
                else:out.append([])
            return out
        c.query_tc=query
        got=c.topology()
        self.assertEqual(got['class_filters'],[{'parent':'123:','filters':[{'kind':'matchall','pref':12}]}])
        self.assertEqual(got['ifb']['class_filters'],[{'parent':'234:','filters':[{'kind':'matchall','pref':12}]}])
        self.assertIn(('filter','show','dev','nic','root'),queries)
        self.assertIn(('filter','show','dev','owned','root'),queries)

    def test_pending_ifb_add_accepts_nested_program_id_only(self):
        import json
        c=object.__new__(m1.Controller);c.major=0x123;c.dl_major=0x234;c.ifb='fgdl12345678';c.ids={'program':7,'ingress':8}
        c.k=lambda *a:json.dumps(c.ids)
        c.original={'qdiscs':[]}
        c.expected={'qdiscs':[{'kind':'htb','handle':'123:','root':True},{'kind':'clsact','handle':'ffff:'}], 'classes':[], 'root_filters':[], 'class_filters':[], 'ingress':[], 'egress':[{'kind':'bpf','pref':10000,'options':{'handle':'0x1','prog':{'id':7}}}]}
        c.setup_step=['link','add',c.ifb,'address','02:00:00:00:00:01','type','ifb']
        actual=copy.deepcopy(c.expected);actual['ifb']={'qdiscs':[],'classes':[]}
        self.assertTrue(c.setup_topology_owned(actual))
        actual['egress'][0]['options']['prog']['id']=9
        self.assertFalse(c.setup_topology_owned(actual))

    def test_creation_identity_crash_boundaries(self):
        c = object.__new__(m1.Controller)
        c.token = '1234567890abcdef0123456789abcdef'; c.ifb = 'fgdl12345678'
        c.ifb_index = None; c.pending_setup = True
        c.setup_step = ['link','add',c.ifb,'address',c.ifb_address(),'type','ifb']
        link = {'ifname':c.ifb,'linkinfo':{'info_kind':'ifb'},'address':c.ifb_address(),'ifindex':4}
        self.assertTrue(c.ifb_identity_matches(link)) # crash after add, before save
        c.ifb_index = 4
        self.assertTrue(c.ifb_identity_matches(link))
        c.setup_step = ['link','set',c.ifb,'alias','flowgate:'+c.token]
        self.assertTrue(c.ifb_identity_matches(link)) # before alias RPC
        link['ifalias'] = 'flowgate:'+c.token
        self.assertTrue(c.ifb_identity_matches(link)) # after alias RPC, before save
        c.setup_step = None; c.pending_setup = False
        self.assertTrue(c.ifb_identity_matches(link))
        for key,value in [('ifname','foreign'),('address','02:00:00:00:00:01'),('ifindex',5),('ifalias',''),('ifalias','foreign')]:
            changed = dict(link); changed[key] = value
            self.assertFalse(c.ifb_identity_matches(changed),key)
        c.pending_setup = True; c.setup_step = ['link','set',c.ifb,'up']
        changed = dict(link); changed.pop('ifalias')
        self.assertFalse(c.ifb_identity_matches(changed))

    def test_ifb_recovery_preserves_previous_objects(self):
        c = object.__new__(m1.Controller); c.ifb = 'fgdl12345678'
        old = {'qdiscs': [{'kind': 'htb', 'handle': '200:', 'root': True}], 'classes': [],
               'root_filters': [], 'ingress': [], 'egress': [], 'class_filters': []}
        new = copy.deepcopy(old); new['classes'] = [{'class': 'htb', 'handle': '200:fffe'}]
        step = ['class', 'add', 'dev', c.ifb, 'parent', '200:']
        self.assertFalse(c.ifb_setup_delta_owned(old, new, step))  # legacy count-only intent is insufficient
        for field in ('root_filters', 'ingress', 'egress', 'class_filters'):
            foreign = copy.deepcopy(new); foreign[field] = [{'foreign': True}]
            self.assertFalse(c.ifb_setup_delta_owned(old, foreign, step))
        changed = copy.deepcopy(new); changed['qdiscs'][0]['handle'] = '201:'
        self.assertFalse(c.ifb_setup_delta_owned(old, changed, step))
        self.assertFalse(c.ifb_setup_delta_owned(old, new, ['link', 'set', c.ifb, 'up']))

    def test_ifb_creation_is_only_empty_noqueue(self):
        c = object.__new__(m1.Controller); c.ifb = 'fgdl12345678'
        self.assertTrue(c.ifb_setup_delta_owned({}, {'qdiscs': [], 'classes': []}, ['link','add',c.ifb,'type','ifb']))
        new = {'qdiscs': [{'kind': 'noqueue'}], 'classes': []}
        self.assertTrue(c.ifb_setup_delta_owned({}, new, ['link','add',c.ifb,'type','ifb']))
        new['classes'] = [{'foreign': True}]
        self.assertFalse(c.ifb_setup_delta_owned({}, new, ['link','add',c.ifb,'type','ifb']))

class PendingIFBIntentTests(unittest.TestCase):
    def controller(self):
        c = object.__new__(m1.Controller)
        c.setup_step = ['class', 'add', 'dev', 'fgdl01234567', 'parent', '200:', 'classid', '200:fffe', 'htb']
        c.ids = {'program': 1, 'ingress': 2}
        c.k = lambda *a: json.dumps(c.ids)
        c.expected = {'qdiscs': [{'kind': 'htb', 'handle': '100:'}], 'ifb': {
            'qdiscs': [{'kind': 'htb', 'handle': '200:', 'root': True}], 'classes': [],
            'root_filters': [], 'ingress': [], 'egress': [], 'class_filters': []}}
        before = {k: copy.deepcopy(c.expected['ifb'][k]) for k in ('qdiscs', 'classes')}
        after = copy.deepcopy(before)
        after['classes'] = [{'class': 'htb', 'handle': '200:fffe', 'root': True,
            'quantum': 1500, 'rate': 12500000000, 'ceil': 12500000000,
            'burst': 2400, 'cburst': 2400, 'linklayer': 'ethernet'}]
        c.setup_tc_intent = {'schema': 1, 'command': c.setup_step[:], 'before': before, 'after': after}
        c.observed = copy.deepcopy(after)
        c.detailed_queues = lambda dev: c.observed
        c.ifb = 'fgdl01234567'; c.evidence = []
        class Sink:
            def __truediv__(self, name): return self
            def write_text(self, text): c.evidence.append(json.loads(text))
        c.state = Sink()
        actual = copy.deepcopy(c.expected); actual['ifb']['classes'] = copy.deepcopy(after['classes'])
        return c, actual

    def test_intended_or_absent_only(self):
        c, actual = self.controller()
        c.verify_ifb_intent(actual)
        c.observed = c.setup_tc_intent['before']
        c.verify_ifb_intent(c.expected, allow_before=True)
        with self.assertRaises(RuntimeError): c.verify_ifb_intent(c.expected)
        self.assertTrue(c.evidence)

    def test_options_identity_and_unknown_fields_refuse_without_mutation(self):
        for field, value in [('quantum', 9000), ('rate', 1), ('ceil', 1), ('burst', 1),
                             ('cburst', 1), ('handle', '201:fffe'), ('root', False),
                             ('linklayer', 'atm'), ('foreign_option', True)]:
            c, actual = self.controller(); original = copy.deepcopy(c.expected)
            c.observed['classes'][0][field] = value
            with self.assertRaises(RuntimeError, msg=field): c.verify_ifb_intent(actual, True)
            self.assertEqual(c.expected, original); self.assertTrue(c.evidence)
        for field in ('root_filters', 'ingress', 'egress', 'class_filters'):
            c, actual = self.controller(); actual['ifb'][field] = [{'foreign': True}]
            with self.assertRaises(RuntimeError): c.verify_ifb_intent(actual, True)
        c, actual = self.controller(); actual['qdiscs'][0]['handle'] = '999:'
        with self.assertRaises(RuntimeError): c.verify_ifb_intent(actual, True)

    def test_root_leaf_options_and_parent_are_exact(self):
        for kind, options in [('htb', {'r2q': 10, 'default': '0xfffe', 'direct_qlen': 32}),
                              ('fq_codel', {'limit': 10240, 'flows': 1024, 'quantum': 1514,
                               'target': 4999, 'interval': 99999, 'memory_limit': 33554432,
                               'ecn': True, 'drop_batch': 64})]:
            for field in [*options, 'parent', 'handle', 'kind', 'unexpected']:
                c, actual = self.controller()
                q = {'kind': kind, 'handle': 'fffe:', 'parent': '200:fffe', 'options': options.copy()}
                c.setup_tc_intent['after']['qdiscs'] = [copy.deepcopy(q)]
                c.observed['qdiscs'] = [copy.deepcopy(q)]
                if field in options: c.observed['qdiscs'][0]['options'][field] = 'changed'
                else: c.observed['qdiscs'][0][field] = 'changed'
                with self.assertRaises(RuntimeError, msg=field): c.verify_ifb_intent(actual, True)
        for field in ('before', 'after'):
            c, actual = self.controller(); del c.setup_tc_intent[field]
            with self.assertRaises(RuntimeError): c.verify_ifb_intent(actual, True)
            self.assertTrue(c.evidence)

    def test_post_journal_checkpoint_keeps_detailed_authority(self):
        c, actual = self.controller(); c.ifb_detail_expected = copy.deepcopy(c.observed)
        c.verify_ifb_checkpoint(actual)
        c.observed['classes'][0]['quantum'] = 9000
        with self.assertRaises(RuntimeError): c.verify_ifb_checkpoint(actual)
        self.assertTrue(c.evidence)
        c.ifb_detail_expected = None
        with self.assertRaises(RuntimeError): c.verify_ifb_checkpoint(actual)

    def test_legacy_command_and_program_mismatch_refuse(self):
        for case in ('legacy', 'command', 'program'):
            c, actual = self.controller()
            if case == 'legacy': c.setup_tc_intent = None
            if case == 'command': c.setup_step = ['foreign']
            if case == 'program': c.k = lambda *a: '{"program": 99}'
            with self.assertRaises(RuntimeError): c.verify_ifb_intent(actual, True)
            self.assertTrue(c.evidence)

class TrafficPriorityTests(unittest.TestCase):
    def test_allocation_floors_clamp_scale_and_minimum(self):
        a = m1.allocate(40_000_000, {'default': ('normal', 0), 'l': ('low', 0), 'n': ('normal', 0), 'h': ('high', 0)})
        self.assertEqual({k: v[0] for k, v in a.items()}, {'default': 6_000_000, 'l': 4_000_000, 'n': 6_000_000, 'h': 8_000_000})
        self.assertEqual({k: v[2] for k, v in a.items()}, {'default': 1, 'l': 2, 'n': 1, 'h': 0})
        capped = m1.allocate(40_000_000, {'default': ('normal', 0), 'h': ('high', 1_000_000)})
        self.assertEqual(capped['h'], (1_000_000, 1_000_000, 0))
        # Review counterexample: 16 High apps capped at 1 Mbit/s, budget 16 Mbit/s.
        many = {'default': ('normal', 0), **{f'h{i}': ('high', 1_000_000) for i in range(16)}}
        r = m1.allocate(16_000_000, many)
        self.assertLessEqual(sum(v[0] for v in r.values()), 16_000_000 * 3 // 5)
        self.assertTrue(all(v[0] <= v[1] for v in r.values()))
        self.assertEqual(r['h0'][0], 1_000_000 * 9_600_000 // 18_400_000)
        self.assertEqual(r, m1.allocate(16_000_000, dict(reversed(list(many.items())))))  # order independent
        low = {'default': ('normal', 0), 'l': ('low', 1_000_000), **{f'h{i}': ('high', 0) for i in range(15)}}
        with self.assertRaisesRegex(ValueError, 'allocation_below_minimum'):
            m1.allocate(16_000_000, low)
        for b in (0, None):
            self.assertEqual(m1.budget(b), 0)
        for b in (15_999_999, 10_000_000_001, '16000000', True):
            with self.assertRaises(ValueError): m1.budget(b)

    def test_priority_only_entries_and_validation(self):
        self.assertEqual(m1.rates({'priority': 'high'}), (0, 0, 'high'))
        self.assertEqual(m1.rates({'rate': 2_000_000}), (2_000_000, 0, 'normal'))
        for bad in ({}, {'priority': 'normal'}, {'priority': 'critical'}, {'rate': 1}):
            with self.assertRaises(ValueError): m1.rates(bad)

    def fake(self):
        c = object.__new__(m1.Controller)
        init_policy(c)
        c.dev = 'nic0'; c.ifb = 'fgdl00000000'; c.major = 0x123; c.dl_major = 0x456; c.mtu = 1500
        c.ifb_index = 9; c.apps = {}; c.bindings = {}; c.next_minor = 1; c.applying = False
        c.default_leaf_options = {'ul': [], 'dl': []}
        c.compatibility = {'topology': 'veth-noqueue'}; c.link = {}
        c.ops = []
        c.mutate = lambda *a: c.ops.append(('tc',) + a)
        c.k = lambda *a: c.ops.append(('k',) + a)
        return c

    def tuples(self, ops):
        out = []
        for o in ops:
            if o[0] == 'tc' and o[1] == 'class' and 'rate' in o and 'bit' in o[o.index('rate') + 1] and 'gbit' not in o[o.index('rate') + 1]:
                out.append((int(o[o.index('rate') + 1][:-3]), int(o[o.index('ceil') + 1][:-3])))
        return out

    def test_mode_transitions_order_and_rate_le_ceil(self):
        c = self.fake()
        c.set_cap('0:cap', 8_000_000, 0, 'normal')   # legacy cap-only
        c.set_cap('0:pri', 0, 0, 'high')              # priority only: dormant without budget
        self.assertEqual(c.class_ids('0:pri'), ('0', '0'))
        self.assertEqual(c.class_state['ul'][1], (8_000_000, 8_000_000, 0))
        c.ops.clear()
        c.set_policy({'upload_budget': 40_000_000, 'apps': {'0:cap': {'rate': 8_000_000}, '0:pri': {'priority': 'high'}}})
        tc = [i for i, o in enumerate(c.ops) if o[0] == 'tc']
        publish = [i for i, o in enumerate(c.ops) if o[:2] == ('k', 'ulbudget')]
        self.assertEqual(publish and c.ops[publish[0]], ('k', 'ulbudget', '1'))
        self.assertGreater(publish[0], max(tc))           # marking only after the tree is ready
        self.assertTrue(all(r <= ce for r, ce in self.tuples(c.ops)))
        self.assertEqual(c.class_state['ul'][1], (6_000_000, 8_000_000, 1))   # floor clamp, cap ceiling
        self.assertEqual(c.class_state['ul'][2], (8_000_000, 40_000_000, 0))  # High, uncapped
        self.assertEqual(c.class_state['ul'][m1.DEFAULT_MINOR], (6_000_000, 40_000_000, 1))
        self.assertEqual(c.class_ids('0:pri'), ('2', '0'))   # no download budget: dormant on DL
        self.assertEqual(c.class_state['dl'], {})
        c.ops.clear()
        c.set_policy({'apps': {'0:cap': {'rate': 8_000_000}, '0:pri': {'priority': 'high'}}})
        first_tc = min(i for i, o in enumerate(c.ops) if o[0] == 'tc')
        self.assertEqual(c.ops[0], ('k', 'ulbudget', '0'))  # withdraw marking first
        self.assertLess(0, first_tc)
        self.assertEqual(c.class_state['ul'], {1: (8_000_000, 8_000_000, 0)})
        self.assertTrue(all(r <= ce for r, ce in self.tuples(c.ops)))

    def test_policy_rejects_atomically_and_removes_unconfigured(self):
        c = self.fake()
        c.set_cap('0:a', 4_000_000)
        c.set_cap('0:b', 4_000_000)
        before = (dict(c.budgets), dict(c.policy_apps), dict(c.class_state['ul']))
        bad = {'upload_budget': 16_000_000, 'apps': {'0:a': {'rate': 4_000_000}, '0:l': {'priority': 'low', 'rate': 1_000_000},
               **{f'0:h{i}': {'priority': 'high'} for i in range(14)}}}
        with self.assertRaisesRegex(ValueError, 'allocation_below_minimum'):
            c.set_policy(bad)
        self.assertEqual((c.budgets, c.policy_apps, c.class_state['ul']), before)
        c.set_policy({'apps': {'0:a': {'rate': 4_000_000}}})
        self.assertNotIn('0:b', c.apps)
        self.assertEqual(set(c.class_state['ul']), {1})

    def test_policy_validation_uses_desired_population_only(self):
        # Review replay: an old Low app capped 1 Mbit/s replaced by 15 High apps.
        c = self.fake()
        c.set_policy({'upload_budget': 16_000_000, 'apps': {'0:old': {'priority': 'low', 'rate': 1_000_000}}})
        c.set_cap('0:old', 1_000_000, 0, 'low')  # instantiated by a binding
        self.assertIn('0:old', c.apps)
        c.set_policy({'upload_budget': 16_000_000, 'apps': {f'0:h{i}': {'priority': 'high'} for i in range(15)}})
        self.assertNotIn('0:old', c.apps)
        self.assertEqual(c.class_state['ul'][m1.DEFAULT_MINOR][0], 457_142)

    def test_pure_decrease_resizes_leaf_and_withdrawal_has_flag(self):
        c = self.fake()
        c.set_cap('0:a', 8_000_000)
        c.ops.clear()
        c.set_cap('0:a', 4_000_000)
        leaf = [o for o in c.ops if o[:3] == ('tc', 'qdisc', 'change')]
        self.assertEqual(len(leaf), 1)
        self.assertEqual(leaf[0][leaf[0].index('memory_limit') + 1], str(m1.queue_bytes(4_000_000, 1500, 0)))
        calls = []
        c.pin = Path('/nonexistent'); c.withdraw_download()
        w = object.__new__(m1.Controller); w.pin = Path('/'); w.k = lambda *a: calls.append(a)
        import unittest.mock as um
        with um.patch.object(m1.Path, 'exists', return_value=True):
            w.withdraw_download()
        self.assertEqual(calls, [('download', '0', '0', '0')])

    def test_reserved_minors_and_bounds(self):
        self.assertEqual((m1.MAX_APP_MINOR, m1.BUDGET_MINOR, m1.BYPASS_MINOR, m1.DEFAULT_MINOR), (0xffef, 0xfff0, 0xfff1, 0xfffe))
        c = self.fake(); c.next_minor = 0xfff0
        with self.assertRaisesRegex(ValueError, 'class_generation_exhausted'):
            c.set_cap('0:x', 4_000_000)
        self.assertEqual(m1.Controller.setup_queue_key(('class', 'add', 'dev', 'x', 'parent', '1:', 'classid', '1:fff0', 'htb')), 'class:fff0')

if __name__ == '__main__':
    unittest.main()

class BindingRouteFreshnessTests(unittest.TestCase):
    def test_each_member_checks_current_route_even_for_the_same_ip_pair(self):
        c=object.__new__(m1.Controller);init_policy(c);c.bindings={};c.base=Path('/unused');c.ns='net:[1]';c.dev='owned0';c.last_tick=time.monotonic();c.verify=lambda:None;c.exists=lambda d:True;c.class_ids=lambda app,zone:(1,0);c.k=lambda *a:None
        app='0:alpha';c.apps={app:{'rate':2000000,'download_rate':0,'priority':'normal'}};routes=[];proofs=[]
        def call(*args):
            if args[0]=='ip':
                routes.append(args);return json.dumps([{'dev':'owned0' if len(routes)==1 else 'foreign0'}])
            proofs.append(args)
            return json.dumps({'application':{'key':'alpha'},'owners':[{'uid':0}], 'sockets':[{'cookie':'0000000000000001','netns':'net:[1]','family':2,'protocol':'tcp','local':'10.0.0.1:1','remote':'10.0.0.2:2','inode':1,'uid':0}]})
        c.call=call
        rows=[dict(protocol='tcp',local='10.0.0.1:'+str(n),remote='10.0.0.2:2',rate=2000000,expected_app=app,expected_cookie=f'{n:016x}') for n in (1,2)]
        reply=c.bind_many({'bindings':rows})
        self.assertEqual(len(routes),2);self.assertEqual(len(proofs),1)
        self.assertEqual(reply['bindings'][0]['cookie'],'0000000000000001')
        self.assertIn('selected interface',reply['bindings'][1]['error'])
