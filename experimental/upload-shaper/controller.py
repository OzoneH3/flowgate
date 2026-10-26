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


def queue_bytes(bits, mtu):
    # At most ~25 ms of qdisc bytes, subject to two-MTU floor; not TCP send buffers.
    return min(262144, max(2 * mtu, bits // 8 // 40))


def structural(value):
    if isinstance(value, dict):
        return {k: structural(v) for k, v in value.items()
                if k not in ('refcnt', 'direct_packets_stat')}
    if isinstance(value, list):
        return [structural(v) for v in value]
    return value


def compatibility(link, topology, features=None, default_qdisc=None):
    """Pure, conservative preflight. A positive result is not activation consent."""
    reasons = []
    kind = link.get('linkinfo', {}).get('info_kind')
    veth = kind == 'veth'
    nic = (not kind and link.get('link_type') == 'ether'
           and link.get('parentbus') in ('pci', 'virtio'))
    if not (veth or nic):
        reasons.append('device must be veth or a directly attached PCI/virtio Ethernet NIC')
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
    if nic:
        if features is None:
            reasons.append('offload state unavailable')
        else:
            for name in ('tcp-segmentation-offload', 'generic-segmentation-offload',
                         'tx-udp-segmentation', 'hw-tc-offload'):
                if features.get(name) != 'off':
                    reasons.append(name + ' must be off; controller never changes offloads')
    return {'supported': not reasons, 'topology': 'veth-noqueue' if veth else 'single-queue-default-fq_codel',
            'reasons': reasons, 'offloads': features, 'default_qdisc_observed': default_qdisc, 'host_activation': False,
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


class Controller:
    def __init__(self, args):
        self.args = args
        self.dev = args.interface
        self.base = Path(args.helpers).resolve()
        self.state = Path(args.state).absolute()
        self.ns = os.readlink('/proc/self/ns/net')
        if os.geteuid() != 0 or args.lab_parent_netns == self.ns:
            raise ValueError('root in a disposable child network namespace required')
        if not re.fullmatch(r'net:\[\d+\]', args.lab_parent_netns):
            raise ValueError('explicit parent namespace identity required')
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
        self.manifest = self.state / 'owner.json'
        if self.manifest.exists():
            self.reconcile()
        if getattr(args, 'cleanup_only', False):
            self.closed = True
            return
        before = self.topology()
        self.compatibility = self.preflight(before)
        if not self.compatibility['supported']:
            raise ValueError('Unsupported: ' + '; '.join(self.compatibility['reasons']))
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
            raise

    def call(self, *args):
        p = subprocess.run(list(map(str, args)), capture_output=True, text=True, timeout=3)
        if p.returncode:
            raise RuntimeError(' '.join(map(str, args))[:256] + ': ' + (p.stderr.strip()[:1024] or 'helper failed'))
        if len(p.stdout) > 2 * 1024 * 1024:
            raise RuntimeError('bounded helper output exceeded')
        return p.stdout

    def k(self, op, *args):
        return self.call(self.base / 'kernel', op, self.pin, *args)

    def get_link(self):
        return json.loads(self.call('ip', '-d', '-j', 'link', 'show', 'dev', self.dev))[0]

    def topology(self):
        fields = {'qdiscs': ('qdisc', 'show'), 'classes': ('class', 'show'),
                  'egress': ('filter', 'show'), 'ingress': ('filter', 'show'),
                  'root_filters': ('filter', 'show')}
        out = {}
        for name, command in fields.items():
            tail = {'egress': ['egress'], 'ingress': ['ingress'], 'root_filters': ['root']}.get(name, [])
            out[name] = structural(json.loads(self.call('tc', '-j', *command, 'dev', self.dev, *tail)))
        # FQ-CoDel exposes ephemeral flow buckets through class show; these are
        # runtime scheduler state, not administrator-created classes. The qdisc
        # itself and its options remain included in the ownership comparison.
        out['classes'] = [x for x in out['classes'] if x.get('class') != 'fq_codel']
        if self.link.get('linkinfo', {}).get('info_kind') != 'veth':
            if len(out['classes']) > MAX_APPS + 1:
                raise RuntimeError('Unsupported: class inspection bound exceeded')
            out['class_filters'] = []
            for c in out['classes']:
                parent = c.get('handle')
                if not parent:
                    raise RuntimeError('Unsupported: unrecognized class identity')
                fs = json.loads(self.call('tc', '-j', 'filter', 'show', 'dev', self.dev, 'parent', parent))
                if fs:
                    out['class_filters'].append({'parent': parent, 'filters': structural(fs)})
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
        link = self.get_link()
        identity_fields = ('ifindex', 'address', 'parentbus', 'parentdev', 'link_type', 'mtu', 'num_tx_queues')
        if getattr(self, 'cleaning', False):
            identity_fields = tuple(k for k in identity_fields if k != 'mtu')
        if os.readlink('/proc/self/ns/net') != self.ns or any(link.get(k) != self.link.get(k) for k in identity_fields):
            raise RuntimeError('interface/namespace generation changed')
        if not getattr(self, 'cleaning', False) and getattr(self, 'original', {}).get('qdiscs', [{}])[0].get('kind') == 'fq_codel':
            setting = Path('/proc/sys/net/core/default_qdisc')
            if setting.exists() and setting.read_text().strip() != 'fq_codel':
                raise RuntimeError('Unsupported: default qdisc changed; restoration requires review')
        actual = self.topology()
        if actual != self.expected:
            (self.state / 'ownership-mismatch.json').write_text(json.dumps({'expected': self.expected, 'actual': actual}))
            raise RuntimeError('Unsupported: traffic-control objects changed; refusing mutation')
        if self.ids is not None and json.loads(self.k('ids')) != self.ids:
            raise RuntimeError('Unsupported: kernel object identity changed')

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

    def class_params(self, bits):
        burst = max(2 * self.mtu, bits // 8 // 200)
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
            self.mutate('qdisc', 'add', 'dev', self.dev, 'parent', self.handle(minor), 'handle', f'{minor:x}:', 'fq_codel', 'limit', '128', 'memory_limit', str(queue_bytes(bits, self.mtu)), 'flows', '128', 'target', '5ms', 'interval', '100ms')
            self.apps[app] = {'minor': minor, 'rate': bits, 'idle_since': time.monotonic()}
        else:
            a = self.apps[app]
            self.mutate('class', 'change', 'dev', self.dev, 'parent', self.handle(), 'classid', self.handle(a['minor']), *self.class_params(bits))
            self.mutate('qdisc', 'change', 'dev', self.dev, 'parent', self.handle(a['minor']), 'handle', f'{a["minor"]:x}:', 'fq_codel', 'limit', '128', 'memory_limit', str(queue_bytes(bits, self.mtu)), 'target', '5ms', 'interval', '100ms')
            a['rate'] = bits
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
        # Explicit rebind only; background lease maintenance never changes owner.
        if cookie in self.bindings and not req.get('rebind', False):
            if self.bindings[cookie]['app'] != app:
                raise ValueError('existing binding ownership differs; explicit rebind required')
        if app not in self.apps or self.apps[app]['rate'] != bits:
            self.set_cap(app, bits)
        self.k('bind', cookie, str(self.apps[app]['minor']))
        self.bindings[cookie] = {'app': app, 'inode': s['inode'], 'protocol': s['protocol'],
                                 'cookie': cookie, 'netns': s['netns'], 'bound_at': time.time()}
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
        self.verify()
        if self.compatibility['topology'] != 'veth-noqueue':
            current = parse_features(self.call('ethtool', '-k', self.dev))
            for name in ('tcp-segmentation-offload', 'generic-segmentation-offload',
                         'tx-udp-segmentation', 'hw-tc-offload'):
                if current.get(name) != 'off':
                    raise RuntimeError('Unsupported: offload setting changed: ' + name)
        ss = json.loads(self.call(self.base / 'probe', 'sockets'))
        live = {(s['cookie'], s['inode'], s['protocol'], s['netns']) for s in ss if s['inode']}
        for c, b in list(self.bindings.items()):
            if (c, b['inode'], b['protocol'], b['netns']) not in live:
                self.k('del', c); del self.bindings[c]
            else:
                self.k('bind', c, str(self.apps[b['app']]['minor']))
                self.apps[b['app']]['idle_since'] = time.monotonic()
        for app, a in list(self.apps.items()):
            if time.monotonic() - a['idle_since'] > 10:
                self.remove(app)
        self.k('beat')
        self.last_tick = time.monotonic()

    def status(self):
        self.verify()
        counters = json.loads(self.k('stats'))
        health = json.loads(self.k('health'))
        now = time.monotonic_ns()
        live = {b['cookie']: b for b in health['bindings'] if b['until'] > now}
        covered = sum(1 for c, b in self.bindings.items() if c in live and live[c]['minor'] == self.apps[b['app']]['minor'])
        valid_until = min([health['config_until']] + [b['until'] for b in live.values()])
        if health['config_until'] <= now:
            covered = 0
        if self.fault:
            state = 'Unsupported'
        elif self.applying:
            state = 'Applying'
        elif covered != len(self.bindings) or not self.bindings or self.partial or counters[0]['packets'] or counters[17]['packets']:
            state = 'Partial'
        else:
            state = 'Active'
        return {'status': state, 'coverage': 'observed socket bindings on selected interface only',
                'compatibility': getattr(self, 'compatibility', None),
                'application_wide_guarantee': False, 'covered_bindings': covered, 'interface': self.dev, 'lease_seconds': 5,
                'valid_for_ms': max(0, (valid_until - now) // 1000000),
                'fault': self.fault, 'limitations': self.partial[-8:], 'apps': self.apps,
                'bindings': list(self.bindings.values()), 'next_minor': self.next_minor, 'counters': counters}

    def close(self):
        if not self.closed:
            self.cleanup_objects(); self.closed = True


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--preflight', action='store_true')
    p.add_argument('--cleanup-only', action='store_true')
    p.add_argument('--interface', required=True)
    p.add_argument('--state', required=True)
    p.add_argument('--helpers', required=True)
    p.add_argument('--lab-parent-netns', required=True)
    args = p.parse_args()
    if args.preflight:
        c = object.__new__(Controller); c.dev = args.interface
        print(json.dumps(c.preflight()), flush=True)
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
        print(json.dumps({'status': 'Applying', 'ready': True, 'scope': 'isolated M1'}), flush=True)
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
