#!/usr/bin/env python3
"""M1 isolated, opt-in upload controller. Not wired into serve or the updater.
Socket binding is shaping accounting, NEVER permission authority.
"""
import argparse
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import signal
import stat
import subprocess
import sys
import time

MAX_APPS = 16
MAX_BINDINGS = 128
MIN_RATE = 1_000_000
MAX_RATE = 1_000_000_000
# Reserved class minors in both trees (application ids are 1..MAX_APP_MINOR).
MAX_APP_MINOR = 0xffef
BUDGET_MINOR = 0xfff0
BYPASS_MINOR = 0xfff1
DEFAULT_MINOR = 0xfffe
# Traffic priority: provisional FlowGate constants (validated in the isolated
# guest only; not NetLimiter behaviour and not kernel requirements).
PRIORITIES = ('low', 'normal', 'high')
HTB_PRIO = {'high': 0, 'normal': 1, 'low': 2}
FLOOR_PERCENT = {'low': 10, 'normal': 15, 'high': 20}
FLOOR_POOL = (3, 5)          # all floors together never exceed 60 % of the budget
MIN_FLOOR = 256_000
MIN_BUDGET = 16_000_000
MAX_BUDGET = 10_000_000_000


def priority(value):
    if value in (None, ''):
        return 'normal'
    if value not in PRIORITIES:
        raise ValueError('traffic priority must be low, normal or high')
    return value


def budget(value):
    if value in (None, 0):
        return 0
    if type(value) is not int or not MIN_BUDGET <= value <= MAX_BUDGET:
        raise ValueError('supported budget range: integer 16Mbit/s..10Gbit/s, or 0 for none')
    return value


def allocate(budget_bits, entries):
    """Pure deterministic floor allocation for ONE direction.

    entries: {key: (priority, cap)} for the configured population, including the
    aggregate default as ('normal', 0); cap 0 means uncapped. Returns
    {key: (floor, ceil, htb_prio)} with floor <= ceil = min(cap, budget) and
    sum(floor) <= 3/5 budget. Raises allocation_below_minimum rather than
    admitting a floor below MIN_FLOOR. Integer arithmetic only.
    """
    nominal = {k: min(budget_bits * FLOOR_PERCENT[prio] // 100, cap or budget_bits)
               for k, (prio, cap) in entries.items()}
    total = sum(nominal.values())
    pool = budget_bits * FLOOR_POOL[0] // FLOOR_POOL[1]
    out = {}
    for k in sorted(entries):
        prio, cap = entries[k]
        floor = nominal[k] if total <= pool else nominal[k] * pool // total
        if floor < MIN_FLOOR:
            raise ValueError('allocation_below_minimum')
        out[k] = (floor, min(cap or budget_bits, budget_bits), HTB_PRIO[prio])
    return out


def rate(value):
    if type(value) is not int or not MIN_RATE <= value <= MAX_RATE:
        raise ValueError('supported cap range: integer 1Mbit/s..1Gbit/s')
    return value


def rates(req):
    # Independent upload/download caps (absent/0 = none) plus one traffic
    # priority for both directions. At least one cap or a non-Normal priority.
    up, down = req.get('rate') or 0, req.get('download_rate') or 0
    prio = priority(req.get('priority'))
    if not up and not down and prio == 'normal':
        raise ValueError('upload/download rate or non-Normal traffic priority required')
    return (rate(up) if up else 0), (rate(down) if down else 0), prio


def queue_bytes(bits, mtu, gso=0):
    # At most ~25 ms of qdisc bytes, subject to a two-MTU floor; not TCP send buffers.
    # With segmentation offload one skb may carry gso bytes of payload (64 KiB by
    # default). fq_codel's memory_limit counts skb truesize (payload plus page and
    # header overhead), so the floor reserves three superpackets' worth to make
    # room for at least two queued superpackets; the bound grows to 16
    # superpackets so a sustained cap is not starved by one skb. CoDel target/interval are congestion-control parameters, not a hard
    # latency bound. Superpacket serialization and socket buffering still
    # matter; see the documented supported-rate profile.
    floor = max(2 * mtu, 3 * gso)
    ceiling = max(262144, 16 * gso)
    return min(ceiling, max(floor, bits // 8 // 40))


def burst_bytes(bits, mtu, gso=0):
    # HTB token-bucket size: ~5 ms of rate, never below two MTUs, and with
    # segmentation never below one superpacket (gso_max_size). Tokens refill at
    # the configured rate; a superpacket larger than the accumulated tokens is
    # still dequeued once the bucket is non-negative and the deficit is repaid
    # before the next dequeue. The transient excess over the long-run rate is
    # therefore bounded by one bucket (burst) plus at most one superpacket, not
    # a renewed free allowance per interval.
    return max(2 * mtu, gso, bits // 8 // 200)


def structural(value):
    if isinstance(value, dict):
        return {k: structural(v) for k, v in value.items()
                if k not in ('refcnt', 'direct_packets_stat')}
    if isinstance(value, list):
        return [structural(v) for v in value]
    return value


def decode_tc_batch(text, count):
    """tc emits one JSON array per show command, not a single outer array."""
    decoder = json.JSONDecoder()
    rows = []
    rest = text.lstrip()
    while rest:
        value, end = decoder.raw_decode(rest)
        if not isinstance(value, list) or not all(isinstance(x, dict) for x in value):
            raise RuntimeError('invalid traffic-control batch output')
        rows.append(structural(value))
        if len(rows) > count:
            raise RuntimeError('extra traffic-control batch output')
        rest = rest[end:].lstrip()
    if len(rows) != count:
        raise RuntimeError('incomplete traffic-control batch output')
    return rows


class KernelWorker:
    """Private bounded RPC; completion is an explicit native success ACK."""
    def __init__(self, command, timeout=3):
        self.timeout = timeout
        self.command = command
        self.process = None

    def close(self):
        p, self.process = self.process, None
        if p is None:
            return
        p.stdin.close()
        try:
            p.wait(timeout=.2)
        except subprocess.TimeoutExpired:
            p.kill(); p.wait()
        p.stdout.close()

    def call(self, op, pin, *args):
        words = list(map(str, (op, pin, *args)))
        if any(not re.fullmatch(r'[A-Za-z0-9_./:-]+', w) for w in words):
            raise RuntimeError('invalid kernel worker argument')
        wire = (' '.join(words) + '\n').encode()
        if len(wire) >= 1024:
            raise RuntimeError('kernel worker input bound')
        deadline = time.monotonic() + self.timeout
        try:
            if self.process is None:
                self.process = subprocess.Popen(self.command, stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
            p = self.process
            if p.poll() is not None or p.stdin.write(wire) != len(wire):
                raise RuntimeError('kernel worker exited or short write')
            data = b''
            with selectors.DefaultSelector() as sel:
                sel.register(p.stdout, selectors.EVENT_READ)
                while True:
                    left = deadline - time.monotonic()
                    if left <= 0 or not sel.select(left):
                        raise RuntimeError('kernel worker timed out')
                    part = os.read(p.stdout.fileno(), 65536)
                    if not part:
                        raise RuntimeError('kernel worker failed without completion')
                    data += part
                    if len(data) > 2 * 1024 * 1024:
                        raise RuntimeError('kernel worker output bound')
                    if b'\x1e' in data:
                        payload, ack = data.split(b'\x1e', 1)
                        if ack == b'OK\n':
                            return payload.decode()
                        if not b'OK\n'.startswith(ack):
                            raise RuntimeError('invalid kernel worker completion')
        except BaseException:
            self.close()
            raise


def compatibility(link, topology, features=None, default_qdisc=None):
    """Pure, conservative preflight. A positive result is not activation consent."""
    reasons = []
    kind = link.get('linkinfo', {}).get('info_kind')
    veth = kind == 'veth'
    # netdevsim is the kernel's software NIC simulator: TSO/GSO capable, default
    # fq_codel root. It exists only when root loads it and is accepted so the
    # isolated guest can prove segmentation handling; it is not a host device class.
    nic = (not kind and link.get('link_type') == 'ether'
           and link.get('parentbus') in ('pci', 'virtio', 'netdevsim'))
    if not (veth or nic):
        reasons.append('device must be veth or a directly attached PCI/virtio Ethernet NIC')
    # Superpacket bound: the largest of the per-family GSO maxima and the TSO
    # maximum the link advertises (BIG TCP may raise the IPv6 value).
    gso = max([v for v in (link.get('gso_max_size'), link.get('gso_ipv4_max_size'), link.get('tso_max_size')) if isinstance(v, int)] or [0])
    if nic and not 1500 <= gso <= 262144:
        reasons.append('gso_max_size unavailable or outside the bounded queue model (1500..262144)')
    if not 576 <= link.get('mtu', 0) <= 9000:
        reasons.append('MTU outside bounded queue model')
    if nic and ('UP' not in link.get('flags', []) or 'LOWER_UP' not in link.get('flags', [])):
        reasons.append('NIC must be administratively up with carrier')
    if nic and (link.get('master') or link.get('xdp')):
        reasons.append('enslaved devices and XDP are unsupported')
    if nic and link.get('num_tx_queues') != 1:
        reasons.append('only one transmit queue is supported; mq is unsupported')
    if any(topology.get(k) for k in ('classes', 'egress', 'ingress', 'root_filters', 'class_filters')):
        reasons.append('foreign classes or filters present')
    q = topology.get('qdiscs', [])
    root = q[0] if len(q) == 1 else {}
    default = (root.get('kind') == 'fq_codel' and root.get('handle') == '0:'
               and root.get('root') is True and default_qdisc in (None, 'fq_codel'))
    # Only the kernel-created default root, never an administrator-created handle.
    # Exact restoration is verified after deletion; custom options are refused.
    options = root.get('options', {})
    expected = {'limit': 10240, 'flows': 1024, 'quantum': link.get('mtu', 0)+14,
                'target': 4999, 'interval': 99999, 'memory_limit': 33554432,
                'ecn': True, 'drop_batch': 64}
    default = default and options == expected
    if not ((veth and root.get('kind') == 'noqueue') or (nic and default)):
        reasons.append('requires unmodified kernel default fq_codel handle 0 (veth: noqueue)')
    segmentation = None
    if nic:
        if features is None:
            reasons.append('offload state unavailable')
        else:
            # Segmentation offloads may be on or off: sizing uses gso_max_size, which
            # bounds superpackets regardless of flags (explicit UDP_SEGMENT builds
            # them even with every offload off). Hardware TC offload could move
            # classification/scheduling out of the kernel path we verify: refused.
            # Explicit observed 'off' is required: a missing or unparsable flag is refused.
            if features.get('hw-tc-offload') != 'off':
                reasons.append('hw-tc-offload must report off; controller never changes offloads')
            flags = {k: features.get(k) for k in ('tcp-segmentation-offload', 'generic-segmentation-offload',
                                                  'tx-udp-segmentation', 'scatter-gather')}
            segmentation = {'offloads': flags, 'gso_max_size': gso, 'gso_max_segs': link.get('gso_max_segs'),
                            'profile': 'segmentation-capable' if 'on' in flags.values() else 'segmentation-off',
                            'superpacket_bytes': gso, 'burst_floor_bytes': gso, 'leaf_memory_floor_bytes': 3 * gso,
                            'superpacket_serialisation_ms_at_1mbit': gso * 8 // 1000,
                            'recommended_min_rate_bps': gso * 8 * 10,
                            'leaf_memory_ceiling_bytes': max(262144, 16 * gso),
                            'udp_segment': 'per-segment accounting: UDP packets queued to userspace for attribution are segmented before the egress hook'}
    return {'supported': not reasons, 'topology': 'veth-noqueue' if veth else 'single-queue-default-fq_codel',
            'reasons': reasons, 'offloads': features, 'segmentation': segmentation,
            'default_qdisc_observed': default_qdisc, 'host_activation': False,
            'coverage': 'Partial: verified bound sockets only; first packets may escape'}


def parse_features(text):
    out = {}
    for line in text.splitlines():
        if ':' in line:
            key, value = line.strip().split(':', 1)
            value = value.strip().split()
            if value and value[0] in ('on', 'off'):
                out[key] = value[0]
    return out


def journal_empty(d, actual, pin_exists, boot, ns, index, dev):
    if pin_exists:
        return False
    previous_boot = d.get('boot_id') is not None and d['boot_id'] != boot
    if previous_boot:
        major = d.get('major')
        if type(major) is not int or not 0x100 <= major < 0xff00:
            return False
        prefix = f'{major:x}:'
        return not any(str(obj.get('handle', '')).startswith(prefix)
                       for obj in actual.get('qdiscs', []) + actual.get('classes', []))
    same_device = d.get('netns') == ns and d.get('ifindex') == index and d.get('interface') == dev
    return same_device and d.get('original') == actual


def validate_deployment_mode(parent, host_trial, current, uid):
    if uid != 0:
        raise ValueError('root required')
    if host_trial:
        if parent:
            raise ValueError('host-trial and lab parent namespace are mutually exclusive')
    elif not re.fullmatch(r'net:\[\d+\]', parent or '') or parent == current:
        raise ValueError('disposable child namespace or explicit host-trial startup opt-in required')

def validate_activation_topology(result, host_trial):
    if not result['supported']:
        raise ValueError('Unsupported: ' + '; '.join(result['reasons']))
    if host_trial and result['topology'] != 'single-queue-default-fq_codel':
        raise ValueError('Unsupported: host trial requires direct single-queue default-fq_codel NIC')

class Controller:
    def __init__(self, args):
        self.args = args
        self.dev = args.interface
        self.base = Path(args.helpers).resolve()
        self.state = Path(args.state).absolute()
        self.ns = os.readlink('/proc/self/ns/net')
        validate_deployment_mode(args.lab_parent_netns, getattr(args, 'host_trial', False), self.ns, os.geteuid())
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', self.dev):
            raise ValueError('invalid interface')
        self.state.mkdir(mode=0o700, parents=False, exist_ok=True)
        for p in [self.state, *self.state.parents]:
            st = p.lstat()
            if stat.S_ISLNK(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
                raise ValueError('state requires root-owned non-writable ancestors')
        if self.state.stat().st_mode & 0o777 != 0o700:
            raise ValueError('private state directory mode0700 required')
        self.lock = os.open(self.state / 'lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.link = self.get_link()
        self.index = self.link['ifindex']
        self.mtu = self.link['mtu']
        self.apps = {}
        self.bindings = {}
        self.next_minor = 1
        # Session-scoped traffic policy: configured population, per-direction
        # budgets (0 = none, legacy recipe) and applied class tuples.
        self.policy_apps = {}
        self.budgets = {'ul': 0, 'dl': 0}
        self.applied_budget = {'ul': 0, 'dl': 0}
        self.class_state = {'ul': {}, 'dl': {}}
        self.partial = []
        self.applying = True
        self.closed = False
        self.fault = None
        # Observation record of the last SUCCESSFUL verification (any caller): start anchor,
        # published only on success. Status reads report it and never refresh it.
        self.verified_at = None
        self.verifications = 0
        self.status_reports = 0
        self.manifest = self.state / 'owner.json'
        if self.manifest.exists():
            try:
                self.reconcile()
            finally:
                if getattr(self, 'kernel_worker', None):
                    self.kernel_worker.close()
        if getattr(args, 'cleanup_only', False):
            self.closed = True
            return
        before = self.topology()
        self.compatibility = self.preflight(before)
        validate_activation_topology(self.compatibility, getattr(args, 'host_trial', False))
        self.original = before
        self.token = secrets.token_hex(16)
        self.major = 0x100 + secrets.randbelow(0xfe00)
        # Download adapter: one owned IFB per generation with its own HTB major.
        self.dl_major = ((self.major - 0x100 + 1 + secrets.randbelow(0xfdff)) % 0xfe00) + 0x100
        self.ifb = 'fgdl' + self.token[:8]
        self.ifb_index = None
        if subprocess.run(['ip', '-j', 'link', 'show', 'dev', self.ifb], capture_output=True, timeout=3).returncode == 0:
            raise ValueError('Unsupported: owned IFB name already exists')
        self.pin = Path('/sys/fs/bpf') / ('fg-m1-' + self.token)
        self.pin.mkdir(mode=0o700)
        self.expected = before
        self.pending_setup = True
        self.setup_step = None
        self.setup_tc_intent = None
        self.setup_templates = {}
        self.ifb_detail_expected = None  # new generation, never inherit reconciled queues
        self.ids = None
        self.save()  # journal intent before any kernel object creation
        try:
            self.k('load', str(self.base / 'classify.bpf.o'))
            self.ids = json.loads(self.k('ids'))
            self.k('init', str(self.major))
            self.save()
            # Common tree in both modes: root (default = bypass) -> budget ->
            # {aggregate default, applications}; bypass beside the budget.
            self.mutate('qdisc', 'replace' if self.compatibility['topology'] != 'veth-noqueue' else 'add', 'dev', self.dev, 'root', 'handle', self.handle(), 'htb', 'default', f'{BYPASS_MINOR:x}')
            for minor, parent in ((BUDGET_MINOR, self.handle()), (BYPASS_MINOR, self.handle()), (DEFAULT_MINOR, self.handle(BUDGET_MINOR))):
                self.mutate('class', 'add', 'dev', self.dev, 'parent', parent, 'classid', self.handle(minor), 'htb', 'rate', '100gbit', 'ceil', '100gbit', 'quantum', str(self.mtu))
            default_options = ['limit', '128', 'memory_limit', '65536', 'flows', '128'] if self.compatibility['topology'] == 'veth-noqueue' else []
            self.mutate('qdisc', 'add', 'dev', self.dev, 'parent', self.handle(0xfffe), 'handle', 'fffe:', 'fq_codel', *default_options)
            self.mutate('qdisc', 'add', 'dev', self.dev, 'clsact')
            self.mutate('filter', 'add', 'dev', self.dev, 'egress', 'pref', '10000', 'handle', '1', 'bpf', 'da', 'pinned', str(self.pin / 'program'))
            # Ingress adapter: owned IFB (journalled name before creation), its own
            # HTB tree, then the ingress redirect program. Only bound packets are
            # redirected; everything else never touches the IFB.
            self.link_mutate('add', self.ifb, 'address', self.ifb_address(), 'type', 'ifb')
            self.link_mutate('set', self.ifb, 'alias', 'flowgate:' + self.token)
            self.link_mutate('set', self.ifb, 'mtu', str(self.mtu))
            self.link_mutate('set', self.ifb, 'up')
            self.mutate('qdisc', 'add', 'dev', self.ifb, 'root', 'handle', self.dl_handle(), 'htb', 'default', f'{BYPASS_MINOR:x}')
            for minor, parent in ((BUDGET_MINOR, self.dl_handle()), (BYPASS_MINOR, self.dl_handle()), (DEFAULT_MINOR, self.dl_handle(BUDGET_MINOR))):
                self.mutate('class', 'add', 'dev', self.ifb, 'parent', parent, 'classid', self.dl_handle(minor), 'htb', 'rate', '100gbit', 'ceil', '100gbit', 'quantum', str(self.mtu))
            self.mutate('qdisc', 'add', 'dev', self.ifb, 'parent', self.dl_handle(0xfffe), 'handle', 'fffe:', 'fq_codel', *default_options)
            self.k('download', str(self.dl_major), str(self.ifb_index), '0')
            self.mutate('filter', 'add', 'dev', self.dev, 'ingress', 'pref', '10000', 'handle', '2', 'bpf', 'da', 'pinned', str(self.pin / 'ingress'))
            self.pending_setup = False
            self.save()
            self.default_leaf_options = {'ul': default_options, 'dl': default_options}
            self.applying = False
            self.last_tick = 0.0
        except BaseException:
            # Reconciliation only removes objects matching the durable identity.
            # An interrupted mutation not represented in the journal refuses takeover.
            self.fault = 'startup incomplete; leases expire, inspect journal'
            if getattr(self, 'kernel_worker', None):
                self.kernel_worker.close()
            raise

    def call(self, *args):
        p = subprocess.run(list(map(str, args)), capture_output=True, text=True, timeout=3)
        if p.returncode:
            raise RuntimeError(' '.join(map(str, args))[:256] + ': ' + (p.stderr.strip()[:1024] or 'helper failed'))
        if len(p.stdout) > 2 * 1024 * 1024:
            raise RuntimeError('bounded helper output exceeded')
        return p.stdout

    def k(self, op, *args):
        if op not in ('ids', 'beat', 'health', 'stats', 'bind', 'del'):
            return self.call(self.base / 'kernel', op, self.pin, *args)
        if getattr(self, 'kernel_worker', None) is None:
            self.kernel_worker = KernelWorker([str(self.base / 'kernel'), 'serve'])
        return self.kernel_worker.call(op, self.pin, *args)

    def get_link(self):
        return json.loads(self.call('ip', '-d', '-j', 'link', 'show', 'dev', self.dev))[0]

    def exists(self, descriptor):
        # Fresh generation existence, never ownership/permission authority.
        if getattr(self, 'socket_worker', None) is None:
            self.socket_worker = KernelWorker([str(self.base / 'probe'), 'serve-sockets'])
        data = json.dumps(descriptor, separators=(',', ':')).encode().hex()
        result = json.loads(self.socket_worker.call('exists', data))
        if type(result) is not bool:
            raise RuntimeError('invalid exact socket response')
        return result

    def query_tc(self, commands, detailed=False):
        # Fresh read-only dumps, identical to the former individual processes.
        # No -force: any failed command invalidates the entire observation.
        # This is not an atomic kernel snapshot and does not cache authority.
        p = subprocess.run(['tc', *(['-d'] if detailed else []), '-j', '-batch', '-'],
                           input=''.join(' '.join(c) + '\n' for c in commands),
                           capture_output=True, text=True, timeout=3)
        if p.returncode or len(p.stdout) > 2 * 1024 * 1024:
            raise RuntimeError('traffic-control query batch failed: ' + p.stderr[:1024])
        return decode_tc_batch(p.stdout, len(commands))

    def topology(self, expected=None):
        fields = ('qdiscs', 'classes', 'egress', 'ingress', 'root_filters')
        commands = [('qdisc', 'show', 'dev', self.dev),
                    ('class', 'show', 'dev', self.dev),
                    ('filter', 'show', 'dev', self.dev, 'egress'),
                    ('filter', 'show', 'dev', self.dev, 'ingress'),
                    ('filter', 'show', 'dev', self.dev, 'root')]
        nic = self.link.get('linkinfo', {}).get('info_kind') != 'veth'
        def parents_for(classes, qdiscs):
            if len(classes) > MAX_APPS + 3:
                raise RuntimeError('Unsupported: class inspection bound exceeded')
            parents = [c.get('handle', '') for c in classes]
            roots = [q.get('handle', '') for q in qdiscs if q.get('root') and q.get('kind') == 'htb']
            if len(roots) > 1:
                raise RuntimeError('Unsupported: multiple classful roots')
            # TC_H_ROOT and an HTB major parent are distinct filter hooks.
            # Inspect both; a filter at major: is not reported by `show root`.
            parents += [p for p in roots if p not in parents]
            if (any(not re.fullmatch(r'[0-9a-fA-F]+:[0-9a-fA-F]*', p) for p in parents)
                    or len(set(parents)) != len(parents)):
                raise RuntimeError('Unsupported: unrecognized class identity')
            return parents
        # Expected classes select query targets, never supply observed evidence.
        # A successful finite process is required; fresh class equality below
        # proves that every actual parent was queried. Dumps are not atomic.
        combined = nic and expected is not None
        parents = parents_for(expected['classes'], expected['qdiscs']) if combined else []
        queries = [('filter', 'show', 'dev', self.dev, 'parent', p) for p in parents]
        rows = self.query_tc(commands + queries)
        out = dict(zip(fields, rows[:5]))
        out['classes'] = [x for x in out['classes'] if x.get('class') != 'fq_codel']
        if combined and out['classes'] != expected['classes']:
            raise RuntimeError('Unsupported: traffic-control classes changed; refusing observation')
        if nic:
            parents = parents_for(out['classes'], out['qdiscs'])
            out['class_filters'] = []
            if parents:
                filters = rows[5:] if combined else self.query_tc(
                    [('filter', 'show', 'dev', self.dev, 'parent', p) for p in parents])
                for parent, fs in zip(parents, filters):
                    if fs:
                        out['class_filters'].append({'parent': parent, 'filters': fs})
        if getattr(self, 'ifb', None) and self.ifb_link() is not None:
            rows = self.query_tc([('qdisc', 'show', 'dev', self.ifb), ('class', 'show', 'dev', self.ifb),
                                  ('filter', 'show', 'dev', self.ifb, 'root'),
                                  ('filter', 'show', 'dev', self.ifb, 'ingress'),
                                  ('filter', 'show', 'dev', self.ifb, 'egress')])
            rows[1] = [x for x in rows[1] if x.get('class') != 'fq_codel']
            parents = parents_for(rows[1], rows[0])
            filters = self.query_tc([('filter', 'show', 'dev', self.ifb, 'parent', p) for p in parents]) if parents else []
            out['ifb'] = {'qdiscs': rows[0], 'classes': [x for x in rows[1] if x.get('class') != 'fq_codel'],
                          'root_filters': rows[2], 'ingress': rows[3], 'egress': rows[4],
                          'class_filters': [{'parent': p, 'filters': f} for p, f in zip(parents, filters) if f]}
        return out

    def preflight(self, topology=None):
        link = self.get_link()
        self.link = link
        features = None
        default = None
        if link.get('linkinfo', {}).get('info_kind') != 'veth':
            try:
                features = parse_features(self.call('ethtool', '-k', self.dev))
                default = Path('/proc/sys/net/core/default_qdisc').read_text().strip()
            except (OSError, RuntimeError):
                pass
        return compatibility(link, self.topology() if topology is None else topology, features, default)

    def handle(self, minor=None):
        return f'{self.major:x}:' + (f'{minor:x}' if minor is not None else '')

    def dl_handle(self, minor=None):
        return f'{self.dl_major:x}:' + (f'{minor:x}' if minor is not None else '')

    def ifb_address(self):
        # Disjoint 40 random bits beside the name's 32; created atomically.
        return '02:' + ':'.join(self.token[i:i+2] for i in range(8, 18, 2))

    def ifb_identity_matches(self, link):
        if link.get('ifname') != self.ifb or link.get('linkinfo', {}).get('info_kind') != 'ifb' or link.get('address') != self.ifb_address():
            return False
        if self.ifb_index is not None and link.get('ifindex') != self.ifb_index:
            return False
        alias = link.get('ifalias', '')
        if alias == 'flowgate:' + self.token:
            return True
        # ip link add does not retain IFLA_IFALIAS on the tested kernel. The
        # name+MAC creation marker covers only these two journalled windows.
        return not alias and getattr(self, 'pending_setup', False) and getattr(self, 'setup_step', None) in (
            ['link', 'add', self.ifb, 'address', self.ifb_address(), 'type', 'ifb'],
            ['link', 'set', self.ifb, 'alias', 'flowgate:' + self.token])

    def ifb_link(self):
        # Owned IFB identity: journalled random name, kind ifb, recorded ifindex.
        if not getattr(self, 'ifb', None):
            return None
        p = subprocess.run(['ip', '-d', '-j', 'link', 'show', 'dev', self.ifb], capture_output=True, text=True, timeout=3)
        if p.returncode:
            return None
        link = json.loads(p.stdout)[0]
        if not self.ifb_identity_matches(link):
            raise RuntimeError('Unsupported: IFB ownership identity mismatch')
        if not getattr(self, 'pending_setup', False) and not getattr(self, 'cleaning', False) and 'UP' not in link.get('flags', []):
            raise RuntimeError('Unsupported: owned IFB is down')
        return link

    def link_mutate(self, op, name, *args):
        # ip-link mutation of the owned IFB only, journalled like tc mutations.
        self.verify()
        if getattr(self, 'pending_setup', False) and not getattr(self, 'cleaning', False):
            self.setup_step = ['link', op, name, *args]
            self.save()
        self.call('ip', 'link', op, 'dev' if op != 'add' else 'name', name, *args)
        if op == 'add':
            self.ifb_index = self.ifb_link()['ifindex']
        elif op == 'del':
            self.ifb_index = None
        self.expected = self.topology()
        if op != 'add':
            self.setup_step = None
        self.save()

    def save(self):
        data = {'schema': 1, 'token': self.token, 'major': self.major, 'pin': str(self.pin),
                'dl_major': getattr(self, 'dl_major', None), 'ifb': getattr(self, 'ifb', None), 'ifb_index': getattr(self, 'ifb_index', None),
                'netns': self.ns, 'interface': self.dev, 'ifindex': self.index,
                'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                'expected': self.expected, 'ids': self.ids, 'original': self.original, 'pending_setup': getattr(self, 'pending_setup', False), 'compatibility': getattr(self, 'compatibility', None), 'setup_step': getattr(self, 'setup_step', None),
                'setup_tc_intent': getattr(self, 'setup_tc_intent', None),
                'ifb_detail_expected': getattr(self, 'ifb_detail_expected', None),
                'link_identity': {k: self.link.get(k) for k in ('ifindex','address','parentbus','parentdev','link_type')}}
        p = self.state / 'owner.new'
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, 'w') as f:
                json.dump(data, f); f.flush(); os.fsync(f.fileno())
            os.replace(p, self.manifest)
            fd = os.open(self.state, os.O_DIRECTORY); os.fsync(fd); os.close(fd)
        finally:
            p.unlink(missing_ok=True)

    def verify(self):
        verify_started = time.monotonic()
        link = self.get_link()
        identity_fields = ('ifindex', 'address', 'parentbus', 'parentdev', 'link_type', 'mtu', 'num_tx_queues', 'gso_max_size', 'gso_ipv4_max_size', 'tso_max_size')
        if getattr(self, 'cleaning', False):
            identity_fields = tuple(k for k in identity_fields if k not in ('mtu', 'gso_max_size', 'gso_ipv4_max_size', 'tso_max_size'))
        if os.readlink('/proc/self/ns/net') != self.ns or any(link.get(k) != self.link.get(k) for k in identity_fields):
            raise RuntimeError('interface/namespace generation changed')
        if not getattr(self, 'cleaning', False) and getattr(self, 'original', {}).get('qdiscs', [{}])[0].get('kind') == 'fq_codel':
            setting = Path('/proc/sys/net/core/default_qdisc')
            if setting.exists() and setting.read_text().strip() != 'fq_codel':
                raise RuntimeError('Unsupported: default qdisc changed; restoration requires review')
        actual = self.topology(self.expected)
        if actual != self.expected:
            (self.state / 'ownership-mismatch.json').write_text(json.dumps({'expected': self.expected, 'actual': actual}))
            raise RuntimeError('Unsupported: traffic-control objects changed; refusing mutation')
        if self.ids is not None and json.loads(self.k('ids')) != self.ids:
            raise RuntimeError('Unsupported: kernel object identity changed')
        if getattr(self, 'ifb_index', None) is not None and not getattr(self, 'cleaning', False) and self.ifb_link() is None:
            raise RuntimeError('Unsupported: owned IFB disappeared')
        if (getattr(self, 'pending_setup', False) and 'ifb' in actual
                and getattr(self, 'setup_step', None) and len(self.setup_step) >= 4
                and self.setup_step[1:4] == ['add', 'dev', self.ifb]):
            # Recheck detailed intent before each cleanup mutation too; normal
            # steady-state observations intentionally retain their old contract.
            self.verify_ifb_intent(actual, allow_before=True)
        elif getattr(self, 'pending_setup', False) and 'ifb' in actual:
            self.verify_ifb_checkpoint(actual)
        self.verified_at = verify_started
        self.verifications = getattr(self, 'verifications', 0) + 1

    def detailed_queues(self, dev):
        q, c = self.query_tc([('qdisc', 'show', 'dev', dev),
                              ('class', 'show', 'dev', dev)], detailed=True)
        return {'qdiscs': q, 'classes': [x for x in c if x.get('class') != 'fq_codel']}

    @staticmethod
    def setup_queue_key(args):
        if args[:2] not in (('qdisc', 'add'), ('qdisc', 'replace'), ('class', 'add')):
            return None
        if args[0] == 'class' and 'htb' in args and 'classid' in args:
            # One template per reserved setup class (budget, bypass, default).
            return 'class:' + str(args[list(args).index('classid') + 1]).split(':')[-1]
        if args[0] == 'qdisc' and 'htb' in args and 'root' in args:
            return 'root'
        if args[0] == 'qdisc' and 'fq_codel' in args:
            return 'leaf'
        return None

    def prepare_ifb_intent(self, args):
        # The three fixed IFB operations repeat the already observed UL setup.
        # Capture each phase separately: adding a leaf also changes class.leaf.
        key = self.setup_queue_key(args)
        template = self.setup_templates.get(key)
        if template is None:
            raise RuntimeError('Unsupported: no validated setup template')
        def translate(value):
            if isinstance(value, dict):
                return {k: translate(v) for k, v in value.items()}
            if isinstance(value, list):
                return [translate(v) for v in value]
            if isinstance(value, str):
                if value == self.dev:
                    return self.ifb
                if value.startswith(self.handle()):
                    return self.dl_handle() + value[len(self.handle()):]
            return value
        command = translate(template['command'])
        command[1] = 'add'
        if command != list(args):
            raise RuntimeError('Unsupported: IFB command differs from setup template')
        link = self.ifb_link()
        if not link or link.get('mtu') != self.mtu or type(link.get('txqlen')) is not int:
            raise RuntimeError('Unsupported: IFB setup link parameters changed')
        after = translate(template['after'])
        # Kernel HTB default is device-dependent; make this option explicit.
        qlen = max(2, link['txqlen'])
        for q in after['qdiscs']:
            if q.get('kind') == 'htb' and q.get('root'):
                q['options']['direct_qlen'] = qlen
        if key == 'root':
            command += ['direct_qlen', str(qlen)]
        before = self.detailed_queues(self.ifb)
        previous = (getattr(self, 'ifb_detail_expected', None) if key != 'root' else
                    {k: self.expected['ifb'][k] for k in ('qdiscs', 'classes')})
        if before != previous:
            raise RuntimeError('Unsupported: IFB pre-operation details changed')
        return {'schema': 1, 'command': command, 'before': before,
                'after': after, 'template': template, 'mtu': self.mtu, 'txqlen': link['txqlen']}

    def verify_ifb_intent(self, actual, allow_before=False):
        intent = getattr(self, 'setup_tc_intent', None)
        observed = self.detailed_queues(self.ifb)
        valid = (isinstance(intent, dict) and intent.get('schema') == 1
                 and intent.get('command') == self.setup_step
                 and isinstance(intent.get('before'), dict) and isinstance(intent.get('after'), dict)
                 and self.ids and json.loads(self.k('ids')) == self.ids)
        # No change outside the owned IFB is licensed by this pending operation.
        valid = valid and {k: v for k, v in actual.items() if k != 'ifb'} == {
            k: v for k, v in self.expected.items() if k != 'ifb'}
        old, new = self.expected.get('ifb', {}), actual.get('ifb', {})
        valid = valid and {k: v for k, v in old.items() if k not in ('qdiscs', 'classes')} == {
            k: v for k, v in new.items() if k not in ('qdiscs', 'classes')}
        valid = valid and (observed == intent['after'] or
                          (allow_before and actual == self.expected and observed == intent['before']))
        if not valid:
            (self.state / 'pending-ifb-mismatch.json').write_text(json.dumps({
                'command': self.setup_step, 'intent': intent, 'expected': self.expected,
                'actual': actual, 'observed_details': observed}, indent=2))
            raise RuntimeError('Unsupported: pending IFB operation mismatch; preserving all resources; inspect pending-ifb-mismatch.json')
        return observed

    def verify_ifb_checkpoint(self, actual):
        # A successful TC-add journal save must not discard detailed authority
        # while startup is still pending (e.g. crash before the next operation).
        intended = getattr(self, 'ifb_detail_expected', None)
        if intended is None and not any(q.get('kind') == 'htb' for q in actual['ifb']['qdiscs']):
            return  # link-only creation, before the first TC operation
        observed = self.detailed_queues(self.ifb)
        if intended != observed:
            (self.state / 'pending-ifb-mismatch.json').write_text(json.dumps({
                'checkpoint': intended, 'actual': actual, 'observed_details': observed}, indent=2))
            raise RuntimeError('Unsupported: pending IFB checkpoint mismatch; preserving all resources; inspect pending-ifb-mismatch.json')

    def mutate(self, *args):
        self.verify()
        setting_up = getattr(self, 'pending_setup', False) and not getattr(self, 'cleaning', False)
        ifb_add = setting_up and len(args) >= 4 and args[1:4] == ('add', 'dev', self.ifb)
        if setting_up:
            self.setup_tc_intent = self.prepare_ifb_intent(args) if ifb_add else None
            self.setup_step = self.setup_tc_intent['command'] if ifb_add else list(args)
            self.save()  # durable exact intent BEFORE the kernel mutation
        self.call('tc', *(self.setup_step if ifb_add else args))
        actual = self.topology()
        if ifb_add:
            self.verify_ifb_intent(actual)
            self.ifb_detail_expected = self.setup_tc_intent['after']
        self.expected = actual
        if setting_up and len(args) >= 4 and args[2:4] == ('dev', self.dev):
            key = self.setup_queue_key(args)
            if key:
                self.setup_templates[key] = {'command': list(args), 'after': self.detailed_queues(self.dev)}
        # Cleanup may still need the creation marker for an alias-less IFB.
        if not getattr(self, 'cleaning', False):
            self.setup_step = None
            self.setup_tc_intent = None
        self.save()

    def reconcile(self):
        st = self.manifest.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077 or st.st_size > 65536:
            raise ValueError('invalid owner journal')
        d = json.loads(self.manifest.read_text())
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        valid_pin = (isinstance(d.get('token'), str) and re.fullmatch('[0-9a-f]{32}', d['token'])
                     and d.get('pin') == '/sys/fs/bpf/fg-m1-' + d['token'])
        if not valid_pin:
            raise ValueError('invalid ownership journal token')
        self.token = d['token']
        self.ifb, self.ifb_index = d.get('ifb'), d.get('ifb_index')
        self.pending_setup = d.get('pending_setup', False)
        self.setup_step = d.get('setup_step')
        if self.ifb and self.ifb != 'fgdl' + self.token[:8]:
            raise ValueError('Unsupported: journal IFB does not match ownership token')
        ifb_absent = not self.ifb or self.ifb_link() is None
        if (d.get('schema') == 1 and valid_pin and ifb_absent
                and journal_empty(d, self.topology(), Path(d['pin']).exists(), boot, self.ns, self.index, self.dev)):
            # No owned kernel state remains. Forget only our private stale journal;
            # never recreate old bindings or mutate a replacement interface.
            self.manifest.unlink()
            (self.state / 'owner.new').unlink(missing_ok=True)
            self.partial.append('previous generation has no owned objects; stale journal cleared')
            return
        if (d.get('schema') != 1 or d['netns'] != self.ns or d['ifindex'] != self.index
                or d['interface'] != self.dev or not re.fullmatch('[0-9a-f]{32}', d['token'])
                or d['pin'] != '/sys/fs/bpf/fg-m1-' + d['token']):
            raise ValueError('Unsupported: journal belongs to another namespace/interface')
        self.token, self.major, self.pin = d['token'], d['major'], Path(d['pin'])
        self.dl_major, self.ifb, self.ifb_index = d.get('dl_major'), d.get('ifb'), d.get('ifb_index')
        if self.ifb and not re.fullmatch('fgdl[0-9a-f]{8}', self.ifb):
            raise ValueError('Unsupported: journal names a foreign IFB')
        self.expected, self.ids = d['expected'], d['ids']
        self.original = d.get('original', {'qdiscs': [{'kind': 'noqueue', 'handle': '0:', 'root': True}], 'classes': [], 'egress': [], 'ingress': [], 'root_filters': []})
        if d.get('link_identity') and d['link_identity'] != {k: self.link.get(k) for k in ('ifindex','address','parentbus','parentdev','link_type')}:
            raise ValueError('Unsupported: interface identity changed')
        # A crash during atomic journal replacement may leave an uncommitted file.
        # Only after validating owner.json and interface identity may it be removed.
        (self.state / 'owner.new').unlink(missing_ok=True)
        self.pending_setup = d.get('pending_setup', False)
        self.setup_step = d.get('setup_step')
        self.setup_tc_intent = d.get('setup_tc_intent')
        self.ifb_detail_expected = d.get('ifb_detail_expected')
        actual = self.topology()
        if (self.pending_setup and self.setup_step and len(self.setup_step) >= 4
                and self.setup_step[1:4] == ['add', 'dev', self.ifb]):
            self.ifb_detail_expected = self.verify_ifb_intent(actual, allow_before=True)
            self.expected = actual
            self.save()
        elif self.pending_setup and actual != self.expected:
            if not self.setup_topology_owned(actual):
                raise ValueError('Unsupported: interrupted setup includes foreign objects')
            self.expected = actual
            self.save()
        self.verify()
        self.cleanup_objects()
        # Old bindings/caps are intentionally NOT restored from stale process data.
        self.partial.append('restart reconciled; fresh bindings required')

    def setup_topology_owned(self, actual):
        # Recovery is only for the initial fixed setup, never arbitrary live edits.
        # The random root handle and pinned IDs are journalled before creation.
        if not self.ids or json.loads(self.k('ids')) != self.ids:
            return False
        if actual == self.original:
            return True
        step = self.setup_step or []
        if len(step) < 2:
            return False
        changed = {k for k in actual if actual[k] != self.expected.get(k)}
        allowed = {'qdisc': {'qdiscs', 'ifb'}, 'class': {'classes', 'ifb'}, 'filter': {'egress', 'ingress'}, 'link': {'ifb'}}.get(step[0], set())
        if not changed or not changed <= allowed:
            return False
        # Previously journalled objects must be byte-for-byte structurally intact.
        for key in changed:
            old = self.expected.get(key, [])
            new = actual[key]
            if key == 'ifb':
                if not self.ifb_setup_delta_owned(old, new, step):
                    return False
                continue
            if step[0] == 'qdisc' and step[1] in ('add', 'replace') and 'root' in step:
                if len(new) != 1:
                    return False
            elif not all(obj in new for obj in old) or len(new) <= len(old):
                return False
        roots = [q for q in actual['qdiscs'] if q.get('root')]
        if len(roots) != 1 or roots[0].get('kind') != 'htb' or roots[0].get('handle') != self.handle():
            return False
        for q in actual['qdiscs']:
            if q in roots:
                continue
            if q.get('kind') == 'clsact' and q.get('handle') == 'ffff:':
                continue
            if q.get('kind') == 'fq_codel' and q.get('handle') == 'fffe:' and q.get('parent') == self.handle(0xfffe):
                continue
            return False
        setup_classes = {self.handle(m) for m in (BUDGET_MINOR, BYPASS_MINOR, DEFAULT_MINOR)}
        for c in actual['classes']:
            if c.get('class') != 'htb' or c.get('handle') not in setup_classes:
                return False
        if actual['root_filters'] or actual.get('class_filters'):
            return False
        for direction, prog, handle in (('egress', 'program', '0x1'), ('ingress', 'ingress', '0x2')):
            for f in actual[direction]:
                # tc emits a protocol/pref header followed by the concrete filter.
                if f.get('kind') != 'bpf' or f.get('pref') != 10000:
                    return False
                opt = f.get('options')
                if opt and (opt.get('id', opt.get('prog', {}).get('id')) != self.ids.get(prog) or opt.get('handle') != handle):
                    return False
        ifb = actual.get('ifb')
        if ifb is not None:
            if any(ifb.get(k) for k in ('root_filters', 'ingress', 'egress', 'class_filters')):
                return False
            for q in ifb['qdiscs']:
                if q.get('root') and q.get('kind') == 'htb' and q.get('handle') == self.dl_handle():
                    continue
                if q.get('kind') == 'fq_codel' and q.get('handle') == 'fffe:' and q.get('parent') == self.dl_handle(0xfffe):
                    continue
                if q.get('root') and q.get('kind') == 'noqueue' and len(ifb['qdiscs']) == 1:
                    continue  # freshly created IFB
                return False
            dl_classes = {self.dl_handle(m) for m in (BUDGET_MINOR, BYPASS_MINOR, DEFAULT_MINOR)}
            for c in ifb['classes']:
                if c.get('class') != 'htb' or c.get('handle') not in dl_classes:
                    return False
        return True

    def ifb_setup_delta_owned(self, old, new, step):
        # Recovery permits only the single write-ahead operation, never a blanket
        # acceptance of any tree under our root major. Token/ifindex are checked
        # separately by ifb_link(), including the crash-after-link-add window.
        if any(new.get(k) for k in ('root_filters', 'ingress', 'egress', 'class_filters')):
            return False
        if not old:
            return (step[:3] == ['link', 'add', self.ifb]
                    and not new.get('classes') and (not new.get('qdiscs') or
                    (len(new['qdiscs']) == 1 and new['qdiscs'][0].get('kind') == 'noqueue')))
        # TC-add recovery requires the durable detailed intent, never this
        # legacy link-creation identity check.
        return False

    def cleanup_objects(self):
        self.cleaning = True
        self.verify()
        q = self.expected['qdiscs']
        if any(x['kind'] == 'clsact' for x in q):
            self.mutate('qdisc', 'del', 'dev', self.dev, 'clsact')
        if self.pin.exists() and (self.pin / 'download').exists():
            try:
                self.k('download', '0', '0', '0')  # withdraw redirect before the IFB goes
            except RuntimeError:
                pass
        if getattr(self, 'ifb', None) and self.ifb_link() is not None:
            self.link_mutate('del', self.ifb)
        if any(x['kind'] == 'htb' and x['handle'] == self.handle() for x in q):
            self.mutate('qdisc', 'del', 'dev', self.dev, 'root', 'handle', self.handle())
        restoration_changed = self.topology() != self.original
        if self.pin.exists():
            for name in ['program', 'ingress', 'bindings', 'config', 'counters', 'download']:
                (self.pin / name).unlink(missing_ok=True)
            self.pin.rmdir()
        self.manifest.unlink(missing_ok=True)
        self.cleaning = False
        if restoration_changed:
            raise RuntimeError('Unsupported: owned objects removed but kernel default differs from original; inspect default_qdisc/MTU, no foreign restoration attempted')

    def gso(self):
        # Veth keeps the M1 sizing its evidence was recorded with; NIC topologies
        # size for the link's maximum superpacket.
        if (getattr(self, 'compatibility', None) or {}).get('topology', 'veth-noqueue') == 'veth-noqueue':
            return 0
        return max([v for v in (self.link.get('gso_max_size'), self.link.get('gso_ipv4_max_size'), self.link.get('tso_max_size')) if isinstance(v, int)] or [0])

    def class_params(self, bits):
        burst = burst_bytes(bits, self.mtu, self.gso())
        return ['htb', 'rate', str(bits) + 'bit', 'ceil', str(bits) + 'bit',
                'burst', str(burst), 'cburst', str(burst), 'quantum', str(self.mtu)]

    def tuple_params(self, t):
        # Complete class tuple (rate, ceil, prio); never individual fields.
        r, c, prio = t
        burst = burst_bytes(c, self.mtu, self.gso())
        return ['htb', 'rate', f'{r}bit', 'ceil', f'{c}bit', 'burst', str(burst),
                'cburst', str(burst), 'quantum', str(self.mtu), 'prio', str(prio)]

    def direction_device(self, d):
        return (self.dev, self.handle) if d == 'ul' else (self.ifb, self.dl_handle)

    def has_class(self, entry, d):
        cap = entry.get('rate' if d == 'ul' else 'download_rate', 0)
        return bool(cap) or (entry.get('priority', 'normal') != 'normal' and bool(self.budgets.get(d)))

    def entry_for(self, app):
        return self.policy_apps.get(app) or self.apps.get(app) or {}

    def targets(self, d):
        """Intended tuples for one direction: {minor: (rate, ceil, prio)} for
        instantiated application classes and the aggregate default, plus the
        budget parent. Allocation uses the CONFIGURED population."""
        b = self.budgets.get(d, 0)
        capkey = 'rate' if d == 'ul' else 'download_rate'
        # Only CONFIGURED applications (set_policy/bind/cap all record them in
        # policy_apps); instantiated classes about to be retired never count.
        live = {a['minor']: (app, self.policy_apps[app]) for app, a in self.apps.items()
                if app in self.policy_apps and self.has_class(self.policy_apps[app], d)}
        if not b:
            # Legacy recipe: independent hard caps, priority dormant.
            return {m: (e[capkey], e[capkey], 0) for m, (app, e) in live.items()}, None
        population = {'default': ('normal', 0)}
        for app, e in self.policy_apps.items():
            if self.has_class(e, d):
                population[app] = (e.get('priority', 'normal'), e.get(capkey, 0))
        alloc = allocate(b, population)
        out = {m: alloc[app] for m, (app, e) in live.items()}
        out[DEFAULT_MINOR] = alloc['default']
        return out, b

    def leaf_memory(self, ceil):
        return queue_bytes(ceil, self.mtu, self.gso())

    def apply_direction(self, d):
        """Ordered per-class batch for one direction: delete retired classes,
        shrink (min of old/new rate and ceil), parent budget, grow to final
        tuples (incl. prio) and create new classes, then leaf sizing. Every
        step keeps rate <= ceil per class. Mode transitions publish/withdraw
        the BPF budget flag around the TC changes."""
        if d == 'dl' and not getattr(self, 'ifb', None):
            return
        dev, root = self.direction_device(d)
        state = self.class_state[d]
        want, b = self.targets(d)
        b = b or 0
        was_budget = bool(self.applied_budget.get(d))
        self.applied_budget_before = self.applied_budget.get(d, 0)
        before = dict(state)
        if was_budget and not b:
            self.publish_budget(d, False)  # withdraw marking before legacy tree
        for minor in [m for m in state if m != DEFAULT_MINOR and m not in want]:
            self.mutate('qdisc', 'del', 'dev', dev, 'parent', root(minor), 'handle', f'{minor:x}:')
            self.mutate('class', 'del', 'dev', dev, 'classid', root(minor))
            del state[minor]
        for minor, new in want.items():
            old = state.get(minor)
            if old and old != new:
                mid = (min(old[0], new[0]), min(old[1], new[1]), old[2])
                if mid != old:
                    self.mutate('class', 'change', 'dev', dev, 'parent', root(BUDGET_MINOR), 'classid', root(minor), *self.tuple_params(mid))
                    state[minor] = mid
        if b != self.applied_budget.get(d):
            parent = ['htb', 'rate', f'{b}bit', 'ceil', f'{b}bit', 'burst', str(burst_bytes(b, self.mtu, self.gso())), 'cburst', str(burst_bytes(b, self.mtu, self.gso())), 'quantum', str(self.mtu)] if b else ['htb', 'rate', '100gbit', 'ceil', '100gbit', 'quantum', str(self.mtu)]
            if b and not was_budget:
                # Entering budget mode: the aggregate default leaves 100gbit
                # before the parent shrinks (complete tuple, rate <= ceil).
                dflt = want[DEFAULT_MINOR]
                self.mutate('class', 'change', 'dev', dev, 'parent', root(BUDGET_MINOR), 'classid', root(DEFAULT_MINOR), *self.tuple_params(dflt))
                self.mutate('qdisc', 'change', 'dev', dev, 'parent', root(DEFAULT_MINOR), 'handle', 'fffe:', 'fq_codel', 'limit', '128', 'memory_limit', str(self.leaf_memory(b)))
                state[DEFAULT_MINOR] = dflt
            self.mutate('class', 'change', 'dev', dev, 'parent', root(), 'classid', root(BUDGET_MINOR), *parent)
            if not b and was_budget:
                # Back to the setup recipe for the aggregate default.
                self.mutate('class', 'change', 'dev', dev, 'parent', root(BUDGET_MINOR), 'classid', root(DEFAULT_MINOR), 'htb', 'rate', '100gbit', 'ceil', '100gbit', 'quantum', str(self.mtu), 'prio', '0')
                opts = self.default_leaf_options.get(d) or ['limit', '10240', 'memory_limit', '33554432']
                self.mutate('qdisc', 'change', 'dev', dev, 'parent', root(DEFAULT_MINOR), 'handle', 'fffe:', 'fq_codel', *[o for i, o in enumerate(opts) if opts[i - (i % 2)] in ('limit', 'memory_limit')])
                state.pop(DEFAULT_MINOR, None)
            self.applied_budget[d] = b
        for minor, new in want.items():
            old = state.get(minor)
            if old is None and minor != DEFAULT_MINOR:
                self.mutate('class', 'add', 'dev', dev, 'parent', root(BUDGET_MINOR), 'classid', root(minor), *self.tuple_params(new))
                self.mutate('qdisc', 'add', 'dev', dev, 'parent', root(minor), 'handle', f'{minor:x}:', 'fq_codel', 'limit', '128', 'memory_limit', str(self.leaf_memory(new[1])), 'flows', '128', 'target', '5ms', 'interval', '100ms')
                state[minor] = new
                continue
            if old != new:
                self.mutate('class', 'change', 'dev', dev, 'parent', root(BUDGET_MINOR), 'classid', root(minor), *self.tuple_params(new))
            # Leaf sizing follows the ceiling as it was BEFORE this batch, so a
            # pure decrease (already final after the shrink step) is resized too.
            if minor != DEFAULT_MINOR and (before.get(minor) is None or before[minor][1] != new[1]):
                self.mutate('qdisc', 'change', 'dev', dev, 'parent', root(minor), 'handle', f'{minor:x}:', 'fq_codel', 'limit', '128', 'memory_limit', str(self.leaf_memory(new[1])), 'target', '5ms', 'interval', '100ms')
            elif minor == DEFAULT_MINOR and b and was_budget and self.applied_budget_before != b:
                self.mutate('qdisc', 'change', 'dev', dev, 'parent', root(minor), 'handle', 'fffe:', 'fq_codel', 'limit', '128', 'memory_limit', str(self.leaf_memory(b)))
            state[minor] = new
        if b and not was_budget:
            self.publish_budget(d, True)  # marking only after the tree is ready

    def publish_budget(self, d, on):
        if d == 'ul':
            self.k('ulbudget', '1' if on else '0')
        else:
            self.k('download', str(self.dl_major), str(self.ifb_index), '1' if on else '0')

    def apply_policy(self):
        self.applying = True
        try:
            # Validate both directions completely before the first mutation.
            for d in ('ul', 'dl'):
                self.targets(d)
            for d in ('ul', 'dl'):
                self.apply_direction(d)
            for app in self.apps:
                self.apps[app]['ul'] = self.class_state['ul'].get(self.apps[app]['minor'])
                self.apps[app]['dl'] = self.class_state['dl'].get(self.apps[app]['minor'])
            for c, bnd in self.bindings.items():
                self.k('bind', c, *self.class_ids(bnd['app']))
        finally:
            self.applying = False

    def set_policy(self, req):
        budgets = {'ul': budget(req.get('upload_budget')), 'dl': budget(req.get('download_budget'))}
        apps = req.get('apps') or {}
        if not isinstance(apps, dict) or len(apps) > MAX_APPS:
            raise ValueError('at most 16 configured applications')
        policy = {}
        for app, e in apps.items():
            if not isinstance(app, str) or not re.fullmatch(r'[0-9]+:.{1,512}', app, re.S) or '\n' in app:
                raise ValueError('invalid application key')
            up, down, prio = rates(e)
            policy[app] = {'rate': up, 'download_rate': down, 'priority': prio}
        old = (self.budgets, self.policy_apps)
        self.budgets, self.policy_apps = budgets, policy
        try:
            for d in ('ul', 'dl'):
                self.targets(d)
        except ValueError:
            self.budgets, self.policy_apps = old
            raise
        for app in [a for a in self.apps if a not in policy]:
            self.remove(app)
        for app, e in policy.items():
            if app in self.apps:
                self.apps[app].update(e)
        self.apply_policy()

    def set_cap(self, app, bits, download_bits=0, prio=None):
        bits = rate(bits) if bits else 0
        download_bits = rate(download_bits) if download_bits else 0
        prio = priority(prio if prio is not None else self.entry_for(app).get('priority'))
        if not bits and not download_bits and prio == 'normal':
            raise ValueError('upload/download rate or non-Normal traffic priority required')
        entry = {'rate': bits, 'download_rate': download_bits, 'priority': prio}
        if app not in self.apps:
            if len(self.apps) >= MAX_APPS:
                raise ValueError('concurrent class capacity reached')
            if self.next_minor > MAX_APP_MINOR:
                raise ValueError('class_generation_exhausted')
            minor = self.next_minor; self.next_minor += 1
            self.apps[app] = {'minor': minor, 'idle_since': time.monotonic(), 'ul': None, 'dl': None}
        previous = self.policy_apps.get(app)
        self.policy_apps[app] = entry
        self.apps[app].update(entry)
        try:
            self.apply_policy()
        except ValueError:
            if previous is None:
                self.policy_apps.pop(app, None)
            else:
                self.policy_apps[app] = previous
            raise
        a = self.apps[app]
        a['burst_bytes'] = burst_bytes(bits or download_bits or MIN_RATE, self.mtu, self.gso()); a['leaf_memory_limit'] = queue_bytes(bits or download_bits or MIN_RATE, self.mtu, self.gso())

    def class_ids(self, app):
        a = self.apps[app]
        return (str(a['minor'] if a['minor'] in self.class_state['ul'] else 0),
                str(a['minor'] if a['minor'] in self.class_state['dl'] else 0))

    def bind(self, req):
        bits, download_bits, prio = rates(req)
        self.verify()
        proto, local, remote = req['protocol'], req['local'], req['remote']
        if proto not in ('tcp', 'udp') or len(local) > 80 or len(remote) > 80:
            raise ValueError('unsupported flow')
        # Route is a bind-time coverage check, not routing/permission authority.
        remote_ip = remote.rsplit(':', 1)[0].strip('[]')
        local_ip = local.rsplit(':', 1)[0].strip('[]')
        ipaddress.ip_address(remote_ip); ipaddress.ip_address(local_ip)
        routes = json.loads(self.call('ip', '-j', 'route', 'get', remote_ip, 'from', local_ip))
        if len(routes) != 1 or routes[0].get('dev') != self.dev:
            raise ValueError('Unsupported: flow does not use selected interface')
        try:
            a = json.loads(self.call(self.base / 'probe', 'bind', proto, local, remote))
        except RuntimeError as e:
            raise ValueError('binding refused: ' + str(e)) from e
        s = a['sockets'][0]; cookie = s['cookie']
        if not re.fullmatch('[0-9a-f]{16}', cookie) or cookie in ('0000000000000000', 'ffffffffffffffff') or s['netns'] != self.ns:
            raise ValueError('missing socket generation')
        app = str(a['owners'][0]['uid']) + ':' + a['application']['key']
        if req.get('expected_app', app) != app:
            raise ValueError('fresh application differs from configured cap')
        if req.get('expected_cookie', cookie) != cookie:
            raise ValueError('socket generation changed before binding')
        if cookie not in self.bindings and len(self.bindings) >= MAX_BINDINGS:
            raise ValueError('binding capacity reached')
        descriptor = {key: s[key] for key in ('family', 'protocol', 'local', 'remote', 'inode', 'cookie', 'uid', 'netns')}
        descriptor['interface_index'] = s.get('interface_index', 0)
        if not self.exists(descriptor):
            raise ValueError('socket generation absent before binding')
        # Explicit rebind only; background lease maintenance never changes owner.
        if cookie in self.bindings and not req.get('rebind', False):
            if self.bindings[cookie]['app'] != app:
                raise ValueError('existing binding ownership differs; explicit rebind required')
        a = self.apps.get(app)
        if a is None or (a.get('rate'), a.get('download_rate', 0), a.get('priority', 'normal')) != (bits, download_bits, prio):
            self.set_cap(app, bits, download_bits, prio)
        self.k('bind', cookie, *self.class_ids(app))
        self.bindings[cookie] = {'app': app, 'inode': s['inode'], 'protocol': s['protocol'],
                                 'cookie': cookie, 'netns': s['netns'], 'bound_at': time.time(), 'descriptor': descriptor}
        self.apps[app]['idle_since'] = time.monotonic()
        return {'app': app, 'cookie': cookie, 'scope': 'socket-binding', 'status': 'Active'}

    def remove(self, app):
        if app not in self.apps:
            raise ValueError('unknown application cap')
        for c, b in list(self.bindings.items()):
            if b['app'] == app:
                self.k('del', c); del self.bindings[c]
        minor = self.apps[app]['minor']
        # Removing a cap releases new traffic immediately; pending leaf packets
        # may be purged. No class ID reuse within this controller generation.
        for d in ('ul', 'dl'):
            if minor in self.class_state[d]:
                dev, root = self.direction_device(d)
                self.mutate('qdisc', 'del', 'dev', dev, 'parent', root(minor), 'handle', f'{minor:x}:')
                self.mutate('class', 'del', 'dev', dev, 'classid', root(minor))
                del self.class_state[d][minor]
        del self.apps[app]

    def tick(self):
        tick_start = time.monotonic()
        self.verify()
        if self.compatibility['topology'] != 'veth-noqueue':
            current = parse_features(self.call('ethtool', '-k', self.dev))
            if current.get('hw-tc-offload') != 'off':
                raise RuntimeError('Unsupported: offload setting changed or unreadable: hw-tc-offload')
            watched = ('tcp-segmentation-offload', 'generic-segmentation-offload', 'tx-udp-segmentation')
            seen = {k: current.get(k) for k in watched}
            if seen != {k: (self.compatibility.get('offloads') or {}).get(k) for k in watched}:
                # Sizing derives from gso_max_size, not these flags: a change is
                # reported as a limitation, never silently absorbed or reverted.
                note = 'segmentation offload flags changed: ' + json.dumps(seen, sort_keys=True)
                if note not in self.partial:
                    self.partial.append(note)
        start = time.monotonic()
        live = {}
        # Complete all reads before renewing anything: a failed pass must not
        # silently extend only a prefix of the bindings.
        for c, b in list(self.bindings.items()):
            if time.monotonic() - start > 2:
                raise RuntimeError('socket existence pass time budget exceeded')
            live[c] = self.exists(b['descriptor'])
        self.existence_pass_ms = int((time.monotonic() - start) * 1000)
        self.existence_queries = len(live)
        renewal_start = time.monotonic()
        for c, b in list(self.bindings.items()):
            if not live[c]:
                self.k('del', c); del self.bindings[c]
            else:
                self.k('bind', c, *self.class_ids(b['app']))
                self.apps[b['app']]['idle_since'] = time.monotonic()
        for app, a in list(self.apps.items()):
            if time.monotonic() - a['idle_since'] > 10:
                self.remove(app)
        self.k('beat')
        completed = time.monotonic()
        previous = getattr(self, 'maintenance_completed', None)
        self.maintenance_completed = completed
        self.maintenance_cycles = getattr(self, 'maintenance_cycles', 0) + 1
        self.max_completion_gap_ms = max(getattr(self, 'max_completion_gap_ms', 0), int((completed - previous) * 1000) + 1 if previous is not None else 0)
        self.max_renewal_span_ms = max(getattr(self, 'max_renewal_span_ms', 0), int((completed - renewal_start) * 1000) + 1)
        self.last_tick = completed
        self.maintenance_pass_ms = int((self.last_tick - tick_start) * 1000) + 1
        self.max_maintenance_pass_ms = max(getattr(self, "max_maintenance_pass_ms", 0), self.maintenance_pass_ms)

    def verification_observation(self):
        # Age of the last successful verification measured from its START (conservative).
        if getattr(self, 'verified_at', None) is None:
            return None, 'unknown'
        age = time.monotonic() - self.verified_at
        return int(age * 1000), 'fresh' if age <= 1 else ('stale' if age <= 2 else 'unknown')

    def status(self):
        # Observation only: fresh kernel health/counters, plus the latest successful verification
        # with its age. No verification, no renewal, no beat, no mutation happens here.
        self.status_reports = getattr(self, 'status_reports', 0) + 1
        counters = json.loads(self.k('stats'))
        health = json.loads(self.k('health'))
        now = time.monotonic_ns()
        # Sampled AFTER the worker RPCs (each bounded by its own deadline), so a slow health read
        # cannot make the reported verification age younger than it is at report time.
        verified_age_ms, verification = self.verification_observation()
        live = {b['cookie']: b for b in health['bindings'] if b['until'] > now}
        covered_cookies = {c for c, b in self.bindings.items() if c in live and (str(live[c]['minor']), str(live[c].get('download', 0))) == self.class_ids(b['app'])}
        covered = len(covered_cookies)
        valid_until = min([health['config_until']] + [b['until'] for b in live.values()])
        if health['config_until'] <= now:
            covered = 0
        if self.fault:
            state = 'Unsupported'
            covered = 0
        elif verified_age_ms is not None and verified_age_ms > 5000:
            # No sufficiently recent successful verification (older than the lease): not proof the loop
            # stopped, but nothing current to report. This is not a latched controller fault.
            state = 'Partial'
            covered = 0
        elif self.applying:
            state = 'Applying'
        elif covered != len(self.bindings) or not self.bindings or self.partial or counters[0]['packets'] or counters[17]['packets'] or verification != 'fresh':
            state = 'Partial'
        else:
            state = 'Active'
        return {'status': state, 'coverage': 'observed socket bindings on selected interface only',
                'verified_age_ms': verified_age_ms, 'verification': verification,
                'verifications': self.verifications, 'status_reports': self.status_reports,
                'existence_pass_ms': getattr(self, 'existence_pass_ms', None),
                'maintenance_pass_ms': getattr(self, 'maintenance_pass_ms', None),
                'maintenance_cycles': getattr(self, 'maintenance_cycles', 0),
                'max_maintenance_pass_ms': getattr(self, 'max_maintenance_pass_ms', 0),
                'max_completion_gap_ms': getattr(self, 'max_completion_gap_ms', 0),
                'max_renewal_span_ms': getattr(self, 'max_renewal_span_ms', 0),
                'existence_queries': getattr(self, 'existence_queries', 0),
                'compatibility': getattr(self, 'compatibility', None),
                'application_wide_guarantee': False, 'covered_bindings': covered, 'interface': self.dev, 'lease_seconds': 5,
                'valid_for_ms': max(0, (valid_until - now) // 1000000),
                'fault': self.fault, 'limitations': (self.partial + (['verification watchdog: last successful verification start exceeds 5s'] if verified_age_ms is not None and verified_age_ms > 5000 else []))[-8:], 'apps': self.apps,
                'segmentation': {'superpackets_classified': counters[2], 'superpackets_unbound': counters[3],
                                 'segments_classified': counters[4]['packets'], 'segments_unbound': counters[4]['bytes'],
                                 'superpacket_bytes': self.gso() or None,
                                 'per_app_burst_bytes': {a: v.get('burst_bytes') for a, v in self.apps.items()},
                                 'per_app_leaf_memory_limit': {a: v.get('leaf_memory_limit') for a, v in self.apps.items()}},
                # Per-binding coverage is an observation from the SAME health read,
                # never an authority token or an application-wide guarantee.
                'bindings': [dict(b, covered=bool(covered and c in covered_cookies),
                                  download=bool(b.get('protocol') == 'tcp' and self.apps[b['app']].get('download_rate')),
                                  upload_class=self.apps[b['app']]['minor'] in self.class_state['ul'],
                                  download_class=bool(b.get('protocol') == 'tcp' and self.apps[b['app']]['minor'] in self.class_state['dl']))
                             for c, b in self.bindings.items()], 'next_minor': self.next_minor, 'counters': counters,
                # Traffic priority: configured budgets and the applied tuples. A
                # budget only governs connected host-local sockets; excluded
                # counters are measured evidence gaps, not proof of foreign traffic.
                'traffic_priority': {
                    'budgets': {'upload': self.budgets['ul'], 'download': self.budgets['dl']},
                    'applied_budgets': {'upload': self.applied_budget['ul'], 'download': self.applied_budget['dl']},
                    'default_class': {'upload': self.class_state['ul'].get(DEFAULT_MINOR), 'download': self.class_state['dl'].get(DEFAULT_MINOR)},
                    'apps': {a: {'priority': v.get('priority', 'normal'), 'upload': self.class_state['ul'].get(v['minor']), 'download': self.class_state['dl'].get(v['minor'])} for a, v in self.apps.items()},
                    'counters': {'upload_default_marked': counters[14], 'upload_excluded_no_exact_socket': counters[13],
                                 'upload_excluded_unsupported_format': counters[10], 'upload_lease_expired_bypass': counters[11],
                                 'download_default_redirected': counters[8], 'download_excluded_no_exact_socket': counters[12],
                                 'download_excluded_unsupported_format': counters[9]},
                    'activity': self.budget_activity(),
                    'scope': 'connected host-local sockets on the selected interface; floors are scheduler allocations, not delivery or latency guarantees'},
                # Ingress adapter telemetry: local delivery of bound established TCP
                # only; it cannot reclaim bandwidth already consumed on the link.
                'download': {'interface': getattr(self, 'ifb', None), 'redirected': counters[5], 'unbound_tcp': counters[6], 'bound_without_class': counters[7], 'scope': 'established native TCP sockets on the selected interface; UDP, listeners, fragments and IPv6 extension headers are uncovered'}}

    def budget_activity(self):
        # Measured parent-class counters (local shaping activity), NOT proof
        # that the budget is the end-to-end bottleneck or that priority worked.
        if not any(self.applied_budget.values()):
            return None
        try:
            cmds = [('-s', 'class', 'show', 'dev', self.dev, 'classid', self.handle(BUDGET_MINOR))]
            if getattr(self, 'ifb', None):
                cmds.append(('-s', 'class', 'show', 'dev', self.ifb, 'classid', self.dl_handle(BUDGET_MINOR)))
            out = {}
            for name, c in zip(('upload', 'download'), cmds):
                r = json.loads(self.call('tc', '-s', '-j', *c[1:]))
                st = (r[0].get('stats') if r else None) or {}
                out[name] = {k: st.get(k) for k in ('bytes', 'packets', 'drops', 'overlimits', 'backlog', 'qlen')}
            return out
        except (RuntimeError, ValueError, IndexError):
            return None

    def withdraw_download(self):
        # Best effort on fault: stop redirecting so a vanished/foreign IFB cannot
        # drop bound traffic while leases run out. Never touches firewall state.
        try:
            if getattr(self, 'pin', None) and (self.pin / 'download').exists():
                self.k('download', '0', '0', '0')
        except Exception:
            pass

    def close(self):
        if not self.closed:
            try:
                self.cleanup_objects(); self.closed = True
            finally:
                if getattr(self, 'kernel_worker', None):
                    self.kernel_worker.close()
                if getattr(self, 'socket_worker', None):
                    self.socket_worker.close()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--preflight', action='store_true')
    p.add_argument('--cleanup-only', action='store_true')
    p.add_argument('--interface', required=True)
    p.add_argument('--state', required=True)
    p.add_argument('--helpers', required=True)
    p.add_argument('--lab-parent-netns', default='')
    p.add_argument('--host-trial', action='store_true', help='explicit startup-only experimental host trial; no hardware certification')
    args = p.parse_args()
    if args.preflight:
        c = object.__new__(Controller); c.dev = args.interface
        result = c.preflight()
        result['deployment_mode'] = 'host-trial' if args.host_trial else 'structural-preflight-only'
        result['activation_authorized'] = False
        if args.host_trial and (args.lab_parent_netns or result['topology'] != 'single-queue-default-fq_codel'):
            result['supported'] = False
            result['reasons'].append('host trial requires no lab parent flag and direct single-queue default-fq_codel NIC')
        print(json.dumps(result), flush=True)
        return
    c = None
    def stop(*unused):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        c = Controller(args)
        if args.cleanup_only:
            print(json.dumps({'stopped': True}), flush=True)
            return
        print(json.dumps({'status': 'Applying', 'ready': True, 'scope': 'experimental host-trial' if args.host_trial else 'isolated M1'}), flush=True)
        poll = selectors.DefaultSelector(); poll.register(sys.stdin.buffer, selectors.EVENT_READ)
        buf = b''
        while True:
            if time.monotonic() - c.last_tick >= 1:
                try:
                    c.tick()
                except Exception as e:
                    c.fault = str(e); c.withdraw_download(); print(json.dumps({'status': 'Unsupported', 'error': str(e), 'leases': 'expire within5s'}), flush=True); break
            for key, _ in poll.select(.2):
                chunk = os.read(key.fileobj.fileno(), 4096)
                if not chunk:
                    return
                buf += chunk
                if len(buf) > 65536:  # one full 16-application policy fits
                    raise ValueError('bounded command buffer exceeded')
                while b'\n' in buf:
                    line, buf = buf.split(b'\n', 1)
                    try:
                        req = json.loads(line); op = req['op']
                        if op == 'bind':
                            result = c.bind(req)
                        elif op == 'cap':
                            if req['app'] not in c.apps: raise ValueError('unknown application')
                            c.set_cap(req['app'], req.get('rate') or 0, req.get('download_rate') or 0, req.get('priority')); result = c.status()
                        elif op == 'policy':
                            c.set_policy(req); result = c.status()
                        elif op == 'remove':
                            c.remove(req['app']); result = c.status()
                        elif op == 'status':
                            result = c.status()
                        elif op == 'stop':
                            c.close(); print(json.dumps({'stopped': True}), flush=True); return
                        else:
                            raise ValueError('unknown operation')
                        print(json.dumps(result), flush=True)
                    except (ValueError, KeyError) as e:
                        c.partial.append(str(e)); c.partial = c.partial[-8:]
                        print(json.dumps({'status': 'Partial', 'error': str(e)}), flush=True)
                    except Exception as e:
                        c.fault = str(e); print(json.dumps({'status': 'Unsupported', 'error': str(e)}), flush=True); return
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(json.dumps({'status': 'Unsupported', 'error': str(e)}), flush=True)
        sys.exit(1)
    finally:
        if c and not c.closed:
            try:
                c.close()
            except Exception as e:
                print(json.dumps({'status': 'Unsupported', 'cleanup_refused': str(e), 'leases': 'expire within5s'}), flush=True)


if __name__ == '__main__':
    main()
