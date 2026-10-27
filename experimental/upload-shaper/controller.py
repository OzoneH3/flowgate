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


def rate(value):
    if type(value) is not int or not MIN_RATE <= value <= MAX_RATE:
        raise ValueError('supported cap range: integer 1Mbit/s..1Gbit/s')
    return value


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
        self.pin = Path('/sys/fs/bpf') / ('fg-m1-' + self.token)
        self.pin.mkdir(mode=0o700)
        self.expected = before
        self.pending_setup = True
        self.setup_step = None
        self.ids = None
        self.save()  # journal intent before any kernel object creation
        try:
            self.k('load', str(self.base / 'classify.bpf.o'))
            self.ids = json.loads(self.k('ids'))
            self.k('init', str(self.major))
            self.save()
            self.mutate('qdisc', 'replace' if self.compatibility['topology'] != 'veth-noqueue' else 'add', 'dev', self.dev, 'root', 'handle', self.handle(), 'htb', 'default', 'fffe')
            self.mutate('class', 'add', 'dev', self.dev, 'parent', self.handle(), 'classid', self.handle(0xfffe), 'htb', 'rate', '100gbit', 'ceil', '100gbit', 'quantum', str(self.mtu))
            default_options = ['limit', '128', 'memory_limit', '65536', 'flows', '128'] if self.compatibility['topology'] == 'veth-noqueue' else []
            self.mutate('qdisc', 'add', 'dev', self.dev, 'parent', self.handle(0xfffe), 'handle', 'fffe:', 'fq_codel', *default_options)
            self.mutate('qdisc', 'add', 'dev', self.dev, 'clsact')
            self.mutate('filter', 'add', 'dev', self.dev, 'egress', 'pref', '10000', 'handle', '1', 'bpf', 'da', 'pinned', str(self.pin / 'program'))
            self.pending_setup = False
            self.save()
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

    def query_tc(self, commands):
        # Fresh read-only dumps, identical to the former individual processes.
        # No -force: any failed command invalidates the entire observation.
        # This is not an atomic kernel snapshot and does not cache authority.
        p = subprocess.run(['tc', '-j', '-batch', '-'],
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
        def parents_for(classes):
            if len(classes) > MAX_APPS + 1:
                raise RuntimeError('Unsupported: class inspection bound exceeded')
            parents = [c.get('handle', '') for c in classes]
            if (any(not re.fullmatch(r'[0-9a-fA-F]+:[0-9a-fA-F]*', p) for p in parents)
                    or len(set(parents)) != len(parents)):
                raise RuntimeError('Unsupported: unrecognized class identity')
            return parents
        # Expected classes select query targets, never supply observed evidence.
        # A successful finite process is required; fresh class equality below
        # proves that every actual parent was queried. Dumps are not atomic.
        combined = nic and expected is not None
        parents = parents_for(expected['classes']) if combined else []
        queries = [('filter', 'show', 'dev', self.dev, 'parent', p) for p in parents]
        rows = self.query_tc(commands + queries)
        out = dict(zip(fields, rows[:5]))
        out['classes'] = [x for x in out['classes'] if x.get('class') != 'fq_codel']
        if combined and out['classes'] != expected['classes']:
            raise RuntimeError('Unsupported: traffic-control classes changed; refusing observation')
        if nic:
            parents = parents_for(out['classes'])
            out['class_filters'] = []
            if parents:
                filters = rows[5:] if combined else self.query_tc(
                    [('filter', 'show', 'dev', self.dev, 'parent', p) for p in parents])
                for parent, fs in zip(parents, filters):
                    if fs:
                        out['class_filters'].append({'parent': parent, 'filters': fs})
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

    def save(self):
        data = {'schema': 1, 'token': self.token, 'major': self.major, 'pin': str(self.pin),
                'netns': self.ns, 'interface': self.dev, 'ifindex': self.index,
                'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                'expected': self.expected, 'ids': self.ids, 'original': self.original, 'pending_setup': getattr(self, 'pending_setup', False), 'compatibility': getattr(self, 'compatibility', None), 'setup_step': getattr(self, 'setup_step', None),
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
        self.verified_at = verify_started
        self.verifications = getattr(self, 'verifications', 0) + 1

    def mutate(self, *args):
        self.verify()
        if getattr(self, 'pending_setup', False) and not getattr(self, 'cleaning', False):
            self.setup_step = list(args)
            self.save()
        self.call('tc', *args)
        self.expected = self.topology()
        self.setup_step = None
        self.save()

    def reconcile(self):
        st = self.manifest.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077 or st.st_size > 65536:
            raise ValueError('invalid owner journal')
        d = json.loads(self.manifest.read_text())
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        valid_pin = (isinstance(d.get('token'), str) and re.fullmatch('[0-9a-f]{32}', d['token'])
                     and d.get('pin') == '/sys/fs/bpf/fg-m1-' + d['token'])
        if (d.get('schema') == 1 and valid_pin
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
        self.expected, self.ids = d['expected'], d['ids']
        self.original = d.get('original', {'qdiscs': [{'kind': 'noqueue', 'handle': '0:', 'root': True}], 'classes': [], 'egress': [], 'ingress': [], 'root_filters': []})
        if d.get('link_identity') and d['link_identity'] != {k: self.link.get(k) for k in ('ifindex','address','parentbus','parentdev','link_type')}:
            raise ValueError('Unsupported: interface identity changed')
        # A crash during atomic journal replacement may leave an uncommitted file.
        # Only after validating owner.json and interface identity may it be removed.
        (self.state / 'owner.new').unlink(missing_ok=True)
        self.pending_setup = d.get('pending_setup', False)
        self.setup_step = d.get('setup_step')
        actual = self.topology()
        if self.pending_setup and actual != self.expected:
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
        allowed = {'qdisc': {'qdiscs'}, 'class': {'classes'}, 'filter': {'egress'}}.get(step[0], set())
        if not changed or not changed <= allowed:
            return False
        # Previously journalled objects must be byte-for-byte structurally intact.
        for key in changed:
            old = self.expected.get(key, [])
            new = actual[key]
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
        for c in actual['classes']:
            if c.get('class') != 'htb' or c.get('handle') != self.handle(0xfffe):
                return False
        if actual['ingress'] or actual['root_filters'] or actual.get('class_filters'):
            return False
        for f in actual['egress']:
            # tc emits a protocol/pref header followed by the concrete filter.
            if f.get('kind') != 'bpf' or f.get('pref') != 10000:
                return False
            opt = f.get('options')
            if opt and (opt.get('id') != self.ids.get('program') or opt.get('handle') != '0x1'):
                return False
        return True

    def cleanup_objects(self):
        self.cleaning = True
        self.verify()
        q = self.expected['qdiscs']
        if any(x['kind'] == 'clsact' for x in q):
            self.mutate('qdisc', 'del', 'dev', self.dev, 'clsact')
        if any(x['kind'] == 'htb' and x['handle'] == self.handle() for x in q):
            self.mutate('qdisc', 'del', 'dev', self.dev, 'root', 'handle', self.handle())
        restoration_changed = self.topology() != self.original
        if self.pin.exists():
            for name in ['program', 'bindings', 'config', 'counters']:
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

    def set_cap(self, app, bits):
        bits = rate(bits)
        self.applying = True
        if app not in self.apps:
            if len(self.apps) >= MAX_APPS:
                raise ValueError('concurrent class capacity reached')
            if self.next_minor > 0xfffd:
                raise ValueError('class_generation_exhausted')
            minor = self.next_minor; self.next_minor += 1
            self.mutate('class', 'add', 'dev', self.dev, 'parent', self.handle(), 'classid', self.handle(minor), *self.class_params(bits))
            self.mutate('qdisc', 'add', 'dev', self.dev, 'parent', self.handle(minor), 'handle', f'{minor:x}:', 'fq_codel', 'limit', '128', 'memory_limit', str(queue_bytes(bits, self.mtu, self.gso())), 'flows', '128', 'target', '5ms', 'interval', '100ms')
            self.apps[app] = {'minor': minor, 'rate': bits, 'idle_since': time.monotonic(),
                              'burst_bytes': burst_bytes(bits, self.mtu, self.gso()), 'leaf_memory_limit': queue_bytes(bits, self.mtu, self.gso())}
        else:
            a = self.apps[app]
            self.mutate('class', 'change', 'dev', self.dev, 'parent', self.handle(), 'classid', self.handle(a['minor']), *self.class_params(bits))
            self.mutate('qdisc', 'change', 'dev', self.dev, 'parent', self.handle(a['minor']), 'handle', f'{a["minor"]:x}:', 'fq_codel', 'limit', '128', 'memory_limit', str(queue_bytes(bits, self.mtu, self.gso())), 'target', '5ms', 'interval', '100ms')
            a['rate'] = bits
            a['burst_bytes'] = burst_bytes(bits, self.mtu, self.gso()); a['leaf_memory_limit'] = queue_bytes(bits, self.mtu, self.gso())
        self.applying = False

    def bind(self, req):
        bits = rate(req['rate'])
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
        if app not in self.apps or self.apps[app]['rate'] != bits:
            self.set_cap(app, bits)
        self.k('bind', cookie, str(self.apps[app]['minor']))
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
        self.mutate('qdisc', 'del', 'dev', self.dev, 'parent', self.handle(minor), 'handle', f'{minor:x}:')
        self.mutate('class', 'del', 'dev', self.dev, 'classid', self.handle(minor))
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
                self.k('bind', c, str(self.apps[b['app']]['minor']))
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
        covered_cookies = {c for c, b in self.bindings.items() if c in live and live[c]['minor'] == self.apps[b['app']]['minor']}
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
                'bindings': [dict(b, covered=bool(covered and c in covered_cookies)) for c, b in self.bindings.items()], 'next_minor': self.next_minor, 'counters': counters}

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
                    c.fault = str(e); print(json.dumps({'status': 'Unsupported', 'error': str(e), 'leases': 'expire within5s'}), flush=True); break
            for key, _ in poll.select(.2):
                chunk = os.read(key.fileobj.fileno(), 4096)
                if not chunk:
                    return
                buf += chunk
                if len(buf) > 8192:
                    raise ValueError('bounded command buffer exceeded')
                while b'\n' in buf:
                    line, buf = buf.split(b'\n', 1)
                    try:
                        req = json.loads(line); op = req['op']
                        if op == 'bind':
                            result = c.bind(req)
                        elif op == 'cap':
                            if req['app'] not in c.apps: raise ValueError('unknown application')
                            c.set_cap(req['app'], req['rate']); result = c.status()
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
