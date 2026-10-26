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
        # M1's tested interface capability: one non-loopback Ethernet veth.
        # Physical/VPN/bridge integration is deliberately not enabled here.
        if self.link.get('linkinfo', {}).get('info_kind') != 'veth':
            raise ValueError('Unsupported: M1 isolated controller supports veth only')
        if not 576 <= self.link['mtu'] <= 9000:
            raise ValueError('Unsupported: MTU outside bounded queue model')
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
        before = self.topology()
        if before['classes'] or before['egress'] or before['ingress'] or before['root_filters']:
            raise ValueError('Unsupported: foreign traffic-control configuration')
        if len(before['qdiscs']) != 1 or before['qdiscs'][0].get('kind') != 'noqueue':
            raise ValueError('Unsupported: will not replace a foreign root/clsact')
        self.token = secrets.token_hex(16)
        self.major = 0x100 + secrets.randbelow(0xfe00)
        self.pin = Path('/sys/fs/bpf') / ('fg-m1-' + self.token)
        self.pin.mkdir(mode=0o700)
        self.expected = before
        self.ids = None
        self.save()  # journal intent before any kernel object creation
        try:
            self.k('load', str(self.base / 'classify.bpf.o'))
            self.ids = json.loads(self.k('ids'))
            self.k('init', str(self.major))
            self.save()
            self.mutate('qdisc', 'add', 'dev', self.dev, 'root', 'handle', self.handle(), 'htb', 'default', 'fffe')
            self.mutate('class', 'add', 'dev', self.dev, 'parent', self.handle(), 'classid', self.handle(0xfffe), 'htb', 'rate', '100gbit', 'ceil', '100gbit', 'quantum', str(self.mtu))
            self.mutate('qdisc', 'add', 'dev', self.dev, 'parent', self.handle(0xfffe), 'handle', 'fffe:', 'fq_codel', 'limit', '128', 'memory_limit', '65536', 'flows', '128')
            self.mutate('qdisc', 'add', 'dev', self.dev, 'clsact')
            self.mutate('filter', 'add', 'dev', self.dev, 'egress', 'pref', '10000', 'handle', '1', 'bpf', 'da', 'pinned', str(self.pin / 'program'))
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
        return out

    def handle(self, minor=None):
        return f'{self.major:x}:' + (f'{minor:x}' if minor is not None else '')

    def save(self):
        data = {'schema': 1, 'token': self.token, 'major': self.major, 'pin': str(self.pin),
                'netns': self.ns, 'interface': self.dev, 'ifindex': self.index,
                'expected': self.expected, 'ids': self.ids}
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
        if os.readlink('/proc/self/ns/net') != self.ns or self.get_link()['ifindex'] != self.index:
            raise RuntimeError('interface/namespace generation changed')
        actual = self.topology()
        if actual != self.expected:
            (self.state / 'ownership-mismatch.json').write_text(json.dumps({'expected': self.expected, 'actual': actual}))
            raise RuntimeError('Unsupported: traffic-control objects changed; refusing mutation')
        if self.ids is not None and json.loads(self.k('ids')) != self.ids:
            raise RuntimeError('Unsupported: kernel object identity changed')

    def mutate(self, *args):
        self.verify()
        self.call('tc', *args)
        self.expected = self.topology()
        self.save()

    def reconcile(self):
        st = self.manifest.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077 or st.st_size > 65536:
            raise ValueError('invalid owner journal')
        d = json.loads(self.manifest.read_text())
        if (d.get('schema') != 1 or d['netns'] != self.ns or d['ifindex'] != self.index
                or d['interface'] != self.dev or not re.fullmatch('[0-9a-f]{32}', d['token'])
                or d['pin'] != '/sys/fs/bpf/fg-m1-' + d['token']):
            raise ValueError('Unsupported: journal belongs to another namespace/interface')
        self.token, self.major, self.pin = d['token'], d['major'], Path(d['pin'])
        self.expected, self.ids = d['expected'], d['ids']
        self.verify()
        self.cleanup_objects()
        # Old bindings/caps are intentionally NOT restored from stale process data.
        self.partial.append('restart reconciled; fresh bindings required')

    def cleanup_objects(self):
        self.verify()
        q = self.expected['qdiscs']
        if any(x['kind'] == 'clsact' for x in q):
            self.mutate('qdisc', 'del', 'dev', self.dev, 'clsact')
        if any(x['kind'] == 'htb' and x['handle'] == self.handle() for x in q):
            self.mutate('qdisc', 'del', 'dev', self.dev, 'root', 'handle', self.handle())
        if self.pin.exists():
            for name in ['program', 'bindings', 'config', 'counters']:
                (self.pin / name).unlink(missing_ok=True)
            self.pin.rmdir()
        self.manifest.unlink(missing_ok=True)

    def class_params(self, bits):
        burst = max(2 * self.mtu, bits // 8 // 200)
        return ['htb', 'rate', str(bits) + 'bit', 'ceil', str(bits) + 'bit',
                'burst', str(burst), 'cburst', str(burst), 'quantum', str(self.mtu)]

    def set_cap(self, app, bits):
        bits = rate(bits)
        self.applying = True
        if app not in self.apps:
            if self.next_minor > MAX_APPS:
                raise ValueError('class generation budget exhausted; clean restart required')
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
        if len(self.bindings) >= MAX_BINDINGS:
            raise ValueError('binding capacity reached')
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
                'application_wide_guarantee': False, 'covered_bindings': covered, 'interface': self.dev, 'lease_seconds': 5,
                'fault': self.fault, 'limitations': self.partial[-8:], 'apps': self.apps,
                'bindings': list(self.bindings.values()), 'counters': counters}

    def close(self):
        if not self.closed:
            self.cleanup_objects(); self.closed = True


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--interface', required=True)
    p.add_argument('--state', required=True)
    p.add_argument('--helpers', required=True)
    p.add_argument('--lab-parent-netns', required=True)
    args = p.parse_args()
    c = None
    def stop(*unused):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        c = Controller(args)
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
