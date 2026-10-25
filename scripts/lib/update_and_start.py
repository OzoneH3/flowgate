#!/usr/bin/env python3
"""One-command update orchestration. The installer remains monitoring-only."""
import argparse
import base64
import hashlib
import json
import os
import pathlib
import signal
import socket
import stat
import struct
import subprocess
import sys
import time


UPDATE_HELPER = '/usr/local/libexec/flowgate-update-helper'
# Session variables carried to the relaunched GUI; nothing else is inherited.
GUI_READY = b'FlowGate: main window rendered'  # emitted on the main window's did-finish-load
GUI_START_TIMEOUT = 45
SESSION_KEYS = ('WAYLAND_DISPLAY', 'XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS', 'XDG_CURRENT_DESKTOP', 'XDG_SESSION_TYPE', 'XDG_SESSION_DESKTOP', 'DESKTOP_SESSION')


class GuiNotSwitched(RuntimeError):
    """The backend update is complete; only the GUI relaunch was not done."""


def wayland_socket(environment, uid=None):
    """Verified Wayland socket of this user for a session environment, else None.

    Evidence: a private runtime directory and a socket owned by this user that
    accepts a connection. Names and launch context alone are not trusted."""
    uid = os.getuid() if uid is None else uid
    runtime, display = environment.get('XDG_RUNTIME_DIR', ''), environment.get('WAYLAND_DISPLAY', '')
    if not runtime or not display or not os.path.isabs(runtime):
        return None
    try:
        st = os.stat(runtime)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != uid or st.st_mode & 0o077:
            return None
        path = display if os.path.isabs(display) else os.path.join(runtime, display)
        st = os.lstat(path)
        if not stat.S_ISSOCK(st.st_mode) or st.st_uid != uid:
            return None
        with socket.socket(socket.AF_UNIX) as probe:
            probe.settimeout(1)
            probe.connect(path)
        return path
    except OSError:
        return None


def session_bus(runtime, uid=None):
    """DBus address for a runtime directory's own bus socket, if verifiable."""
    uid = os.getuid() if uid is None else uid
    path = os.path.join(runtime, 'bus')
    try:
        st = os.lstat(path)
    except OSError:
        return None
    return 'unix:path=' + path if stat.S_ISSOCK(st.st_mode) and st.st_uid == uid else None


def supervise_gui(command, environment, log_path, timeout=GUI_START_TIMEOUT, poll=0.2):
    """Start the GUI detached and wait for its own readiness line.

    Returns the PID once the main window reports it loaded. An early exit or a
    missing readiness line is a GUI failure, never an update failure. Readiness
    is the GUI's load report, not proof of what the compositor displays."""
    log_path = pathlib.Path(log_path)
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, 'ab') as log:
            start = log.tell()
            child = subprocess.Popen(command, env=environment, stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
    except OSError as error:
        raise GuiNotSwitched('GUI launch failed: ' + str(error)) from error
    def output():
        with open(log_path, 'rb') as f:
            f.seek(start)
            return f.read(1 << 20)
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            # Exit is checked before readiness: a GUI that printed the line and
            # then exited is not reported as started.
            code = child.poll()
            text = output()
            if code is not None:
                tail = text.decode(errors='replace').strip().splitlines()[-3:]
                when = 'after reporting its main window loaded' if GUI_READY in text else 'before its main window loaded'
                raise GuiNotSwitched('new GUI exited with status ' + str(code) + ' ' + when + (': ' + ' | '.join(tail) if tail else '') + '; see ' + str(log_path))
            if GUI_READY in text:
                return child.pid
            time.sleep(poll)
    except OSError as error:
        raise GuiNotSwitched('GUI start could not be observed (PID ' + str(child.pid) + ', left running): ' + str(error)) from error
    raise GuiNotSwitched('new GUI (PID ' + str(child.pid) + ') did not report its main window loaded within ' + str(timeout) + ' s; left running; see ' + str(log_path))


DAEMON_SOCKETS = (b'/run/flowgate-api/daemon.sock', b'/run/flowgate-api/daemon.sock.monitor')
CMDLINE_LIMIT = 64 * 1024


def start_time(proc):
    """Process start time (clock ticks since boot) from /proc/<pid>/stat."""
    return (proc / 'stat').read_text().rsplit(')', 1)[1].split()[19]


def released_gui(proc, releases, uid=None):
    """Whether /proc entry `proc` is this user's released FlowGate GUI main process.

    Evidence is the executed file (/proc/<pid>/exe) at the exact release layout
    and the exact launch arguments update-and-start uses. Electron rewrites its
    main process command line into one string with switches first and positional
    values after them; both that form and the original argv must equal the
    expected launch exactly, so extra, duplicate, swapped or conflicting endpoint
    arguments, helper processes (--type) and oversized input never match."""
    uid = os.getuid() if uid is None else uid
    if proc.stat().st_uid != uid:
        return False
    exe = os.readlink(proc / 'exe')
    if exe.endswith(' (deleted)'):
        exe = exe[:-len(' (deleted)')]
    executable = pathlib.Path(exe)
    # Exact release layout: <releases>/<revision>/runtime/electron.
    if not executable.is_relative_to(releases) or len(executable.relative_to(releases).parts) != 3 or executable.parts[-2:] != ('runtime', 'electron'):
        return False
    with open(proc / 'cmdline', 'rb') as f:
        raw = f.read(CMDLINE_LIMIT + 1)
    if len(raw) > CMDLINE_LIMIT:
        return False
    app = os.fsencode(str(executable.parent.parent / 'electron'))
    monitor, control = DAEMON_SOCKETS[1], DAEMON_SOCKETS[0]
    parts = raw.split(b'\0')
    if parts and parts[-1] == b'':
        parts = parts[:-1]
    # Original argv as launched by launch-ui (argv[0] may be the launch path).
    if parts[1:] == [b'--ozone-platform=wayland', app, b'--observer', monitor, b'--control', control]:
        return True
    # Electron's rewritten form: the resolved executable, switches, then values.
    rewritten = b' '.join([os.fsencode(exe), b'--ozone-platform=wayland', b'--observer', b'--control', app, monitor, control])
    return parts == [rewritten]


def session_environment(environ):
    return {k: environ[k] for k in SESSION_KEYS if environ.get(k)}


def process_environment(proc):
    try:
        raw = (proc / 'environ').read_bytes()
    except OSError:
        return {}
    out = {}
    for item in raw.split(b'\0'):
        key, sep, value = item.partition(b'=')
        if sep:
            out[os.fsdecode(key)] = os.fsdecode(value)
    return out


def target_desktop(gui_environments, own_environment, uid=None):
    """Choose the desktop session for the new GUI before the old one is closed.

    Order: the session the replaced GUI was verifiably rendering in, then this
    updater's own session, then the single Wayland socket in this user's runtime
    directory. Conflicting or missing evidence returns (None, reason)."""
    uid = os.getuid() if uid is None else uid
    verified = {}
    for env in gui_environments:
        session = session_environment(env)
        path = wayland_socket(session, uid)
        if path:
            verified.setdefault(path, session)
    if len(verified) > 1:
        return None, 'running FlowGate GUIs use different desktop sessions (' + ', '.join(sorted(verified)) + ')'
    if verified:
        return next(iter(verified.values())), None
    own = session_environment(own_environment)
    if wayland_socket(own, uid):
        return own, None
    runtime = own.get('XDG_RUNTIME_DIR') or '/run/user/' + str(uid)
    try:
        candidates = sorted(p.name for p in pathlib.Path(runtime).iterdir() if p.name.startswith('wayland-') and not p.name.endswith('.lock'))
    except OSError:
        candidates = []
    # The updater's own session address may belong to another session: only
    # this runtime directory's verified bus socket is carried over.
    base = {k: v for k, v in own.items() if k != 'DBUS_SESSION_BUS_ADDRESS'}
    bus = session_bus(runtime, uid)
    if bus:
        base['DBUS_SESSION_BUS_ADDRESS'] = bus
    found = [dict(base, XDG_RUNTIME_DIR=runtime, WAYLAND_DISPLAY=name) for name in candidates]
    found = [env for env in found if wayland_socket(env, uid)]
    if len(found) == 1:
        return found[0], None
    if found:
        return None, 'several Wayland sessions in ' + runtime + ' and no running FlowGate GUI to identify the right one'
    return None, 'no verifiable Wayland session for this user (WAYLAND_DISPLAY/XDG_RUNTIME_DIR unset or socket not reachable)'


def say(message):
    print('==> ' + message, flush=True)


def verify_bundle(directory, manifest_name, revision):
    manifest = json.loads((directory / manifest_name).read_text())
    if manifest.get('source') != revision:
        raise RuntimeError('Bundle source does not match selected master')
    for name, expected in manifest['files'].items():
        path = directory / name
        if not path.resolve().is_relative_to(directory.resolve()):
            raise RuntimeError('Bundle path escapes release directory')
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise RuntimeError('Bundle hash mismatch: ' + str(path))
    return manifest


def mode(status):
    protection = status.get('protection') or {}
    selected = protection.get('desired_mode')
    if selected not in ('monitoring', 'incoming', 'both'):
        raise RuntimeError('Unknown protection mode; no update action taken')
    return selected


def at_mode(status, selected):
    p, e = status.get('protection') or {}, status.get('enforcement') or {}
    if selected == 'monitoring':
        return p.get('desired_mode') == selected and p.get('state') == 'stopped' and e.get('state') == 'stopped'
    return p.get('desired_mode') == selected and p.get('state') == 'active' and p.get('profile') == selected and e.get('state') == 'active' and e.get('profile') == selected


def matches(status, manifest):
    build = status.get('build') or {}
    return build.get('source') == manifest['source'] and build.get('executable_sha256') == manifest['files']['flowgate'] and build.get('modified') is False


# Stored-rule compatibility, shared verbatim by both privileged scripts below.
# A candidate that cannot load a stored active rule schema would refuse the whole
# rule database at startup (and fail closed under protection). A candidate's
# `version` declares max_rule_schema; an undeclared value keeps the prior ceiling
# 6. That only preserves earlier behaviour; it does not prove an old build
# supports schemas 0-6, and schema 7 or later always needs a positive declaration.
SCHEMA_GUARD = r"""
import json as _json, os as _os, sqlite3 as _sqlite3, subprocess as _subprocess
RULES_DB = '/var/lib/flowgate/rules.db'
LEGACY_RULE_SCHEMA = 6
def _bounded_schema(value, what):
    if type(value) is not int or not 1 <= value <= 64:
        raise RuntimeError(what + ' max_rule_schema invalid; current release retained')
    return value
def declared_rule_schema(fd):
    r = _subprocess.run(['/proc/self/fd/' + str(fd), 'version'], pass_fds=(fd,), capture_output=True, text=True, timeout=10)
    if r.returncode != 0:
        return None  # builds before `version` declare nothing: legacy ceiling
    try:
        v = _json.loads(r.stdout)
    except ValueError:
        raise RuntimeError('Candidate version output invalid; current release retained')
    if not isinstance(v, dict):
        raise RuntimeError('Candidate version output invalid; current release retained')
    return None if v.get('max_rule_schema') is None else _bounded_schema(v['max_rule_schema'], 'Candidate')
def candidate_rule_schema(declared, manifest):
    listed = (manifest or {}).get('max_rule_schema')
    if listed is not None and _bounded_schema(listed, 'Manifest') != declared:
        raise RuntimeError('Candidate rule schema declaration differs from its manifest; current release retained')
    return LEGACY_RULE_SCHEMA if declared is None else declared
def stored_rule_schemas(db):
    counts = {}
    if not _os.path.exists(db):
        return counts
    c = _sqlite3.connect('file:' + db + '?mode=ro', uri=True)
    try:
        c.execute('BEGIN')
        try:
            rows = c.execute('SELECT document FROM rules').fetchall()
        except _sqlite3.OperationalError as e:
            if 'no such table' not in str(e):
                raise
            rows = []
    finally:
        c.close()
    for (document,) in rows:
        try:
            rule = _json.loads(document)
        except ValueError:
            raise RuntimeError('Stored rule unreadable; current release retained')
        schema = rule.get('schema', 0) if isinstance(rule, dict) else None
        if type(schema) is not int or schema < 0:
            raise RuntimeError('Stored rule schema unreadable; current release retained')
        counts[schema] = counts.get(schema, 0) + 1
    return counts
def require_rule_schemas(db, ceiling):
    unsupported = {s: n for s, n in stored_rule_schemas(db).items() if s > ceiling}
    if unsupported:
        detail = ', '.join('%d rule(s) of schema %d' % (n, s) for s, n in sorted(unsupported.items()))
        raise RuntimeError('Candidate supports stored rule schemas up to %d, but %s exist; delete those rules first or install a build that declares support. Candidate not activated' % (ceiling, detail))
"""


# The privileged process receives bytes selected before authentication, never a
# path into the user's writable build tree. This is a local-source trust model,
# not a signature or proof that the selected source is trustworthy.
STAGE_INSTALL = SCHEMA_GUARD + r"""
import base64, hashlib, json, os, pathlib, subprocess, sys, tempfile
payload = json.load(sys.stdin)
base = pathlib.Path('/usr/local/lib/flowgate')
for path in reversed([base, *base.parents]):
    if not path.exists(): path.mkdir(mode=0o755)
    st = path.lstat()
    if path.is_symlink() or not path.is_dir() or st.st_uid != 0 or st.st_mode & 0o022:
        raise RuntimeError('Unsafe installation parent: ' + str(path))
with tempfile.TemporaryDirectory(prefix='.install-', dir=base) as temporary:
    stage = pathlib.Path(temporary)
    for name, encoded in payload['files'].items():
        if name in ('', '.', '..') or '/' in name:
            raise RuntimeError('Invalid staged filename')
        data = base64.b64decode(encoded, validate=True)
        (stage / name).write_bytes(data)
    manifest = json.loads((stage / 'manifest.json').read_bytes())
    for name, expected in manifest['files'].items():
        if name not in payload['files'] or hashlib.sha256((stage / name).read_bytes()).hexdigest() != expected:
            raise RuntimeError('Staged bundle hash mismatch')
    # The candidate installer may predate this check (a downgrade), so the
    # current tooling verifies stored schemas immediately before running it.
    fd = os.memfd_create('flowgate-rule-schema', 0)
    with os.fdopen(os.dup(fd), 'wb') as f: f.write((stage / 'flowgate').read_bytes())
    os.fchmod(fd, 0o500)
    require_rule_schemas(RULES_DB, candidate_rule_schema(declared_rule_schema(fd), manifest))
    os.close(fd)
    result = subprocess.run(['/usr/bin/python3', '-I', str(stage / 'install-monitoring.py'), '--bundle', str(stage)], check=False)
    sys.exit(result.returncode)
"""


# Run the already hash-verified candidate bytes read-only, before stopping the
# working release. An anonymous root-owned executable avoids writable-path races.
STAGE_PREFLIGHT = SCHEMA_GUARD + r"""
import base64, hashlib, json, os, subprocess, sys
payload = json.load(sys.stdin)
data = base64.b64decode(payload['binary'], validate=True)
if hashlib.sha256(data).hexdigest() != payload['sha256']:
    raise RuntimeError('Candidate preflight hash mismatch')
fd = os.memfd_create('flowgate-upgrade-check', 0)
with os.fdopen(os.dup(fd), 'wb') as f: f.write(data)
os.fchmod(fd, 0o500)
# Every profile, including monitoring: an unloadable rule database stops the
# daemon regardless of protection mode.
require_rule_schemas(RULES_DB, candidate_rule_schema(declared_rule_schema(fd), payload.get('manifest')))
if payload['profile'] == 'monitoring':
    print('Candidate supports every stored rule schema; firewall checks not needed for monitoring')
    sys.exit(0)
r = subprocess.run(['/proc/self/fd/'+str(fd), 'doctor', '--json', '--upgrade-preflight', '--state', '/run/flowgate-enforcement', '--profile', payload['profile']], pass_fds=(fd,), capture_output=True, text=True, timeout=25)
if r.returncode:
    raise RuntimeError('Candidate preflight failed: '+r.stderr[:4096])
v = json.loads(r.stdout)
if v.get('schema_version') != 1 or not isinstance(v.get('checks'), list) or not v['checks']:
    raise RuntimeError('Invalid candidate preflight result')
for c in v['checks']:
    if c.get('status') != 'ready' and not (c.get('id') == 'firewall.queue_census' and c.get('status') == 'not_checked'):
        raise RuntimeError('Candidate incompatible; current release retained: '+str(c.get('id'))+': '+str(c.get('detail')))
print('Candidate firewall compatibility verified before stopping protection')
"""

def snapshot_bundle(backend, expected_manifest=None):
    manifest_bytes = (backend / 'manifest.json').read_bytes()
    manifest = json.loads(manifest_bytes)
    if expected_manifest is not None and manifest != expected_manifest:
        raise RuntimeError('Bundle manifest changed before authentication')
    files = {'manifest.json': base64.b64encode(manifest_bytes).decode()}
    if 'install-monitoring.py' not in manifest['files']:
        raise RuntimeError('Installer missing from bundle manifest')
    for name, expected in manifest['files'].items():
        if name in ('', '.', '..', 'manifest.json') or '/' in name:
            raise RuntimeError('Invalid backend bundle filename')
        data = (backend / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise RuntimeError('Bundle changed before authentication: ' + name)
        files[name] = base64.b64encode(data).decode()
    return json.dumps({'files': files}).encode()


CONTROL_SOCKET = '/run/flowgate-api/daemon.sock'
DAEMON_PEER_UID = 0
# Bounded single-line responses: the daemon's own request bound is 16384 bytes.
RESPONSE_LIMIT = 1 << 20
REQUEST_TIMEOUT = 5


def essential_summary(status):
    """One explicit line about stored Essential preset records; never a coverage claim.

    status is the read-only essential-status result or None when it could not be
    obtained for the current daemon generation. Stored records may include
    disabled or expired rules and the revision is the current discovery
    revision, not an applied one, so the wording states exactly that.
    """
    if status is None:
        return 'Essential preset status unavailable; coverage not validated.'
    if not status['rule_ids']:
        return 'No stored Essential preset records; manual rules may provide coverage.'
    return ('Stored Essential preset records: %d (may include disabled/expired); discovery revision %s; coverage not validated.'
            % (len(status['rule_ids']), status['revision'] or 'unknown'))


class Host:
    def request(self, operation, **fields):
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(REQUEST_TIMEOUT)
            client.connect(CONTROL_SOCKET)
            _, uid, _ = struct.unpack('3i', client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != DAEMON_PEER_UID:
                raise RuntimeError('System daemon peer is not root')
            client.sendall(json.dumps(dict(fields, version=1, operation=operation)).encode() + b'\n')
            line = client.makefile('rb').readline(RESPONSE_LIMIT)
        if not line.endswith(b'\n'):
            raise RuntimeError('Daemon response truncated or oversized')
        response = json.loads(line)
        if not isinstance(response, dict):
            raise RuntimeError('Daemon response is not an object')
        return response

    def status(self):
        response = self.request('list')
        if response.get('error'):
            raise RuntimeError(response['error'])
        return {key: response.get(key) for key in ('generation', 'build', 'protection', 'enforcement')}

    def essential_status(self, generation):
        """Read-only stored-record summary bound to the expected daemon generation.

        Returns {'rule_ids': [...], 'revision': str} or None. None covers every
        failure: refusal, another generation, malformed/oversized/late replies.
        Nothing is retried and nothing stale is reused.
        """
        if not generation:
            return None
        try:
            response = self.request('essential-status', generation=generation)
        except (OSError, ValueError, RuntimeError):
            return None
        status = response.get('essential_status')
        if response.get('error') or response.get('generation') != generation or not isinstance(status, dict):
            return None
        rule_ids, revision = status.get('rule_ids'), status.get('revision')
        if not isinstance(rule_ids, list) or not all(isinstance(r, str) for r in rule_ids) or not isinstance(revision, str):
            return None
        return {'rule_ids': rule_ids, 'revision': revision}

    def installed(self):
        return pathlib.Path('/usr/local/lib/flowgate/current').exists()

    def prepare_install(self, backend, root, wine_discovery, expected_manifest=None):
        self.install_payload = snapshot_bundle(backend, expected_manifest)
        self.wine_source = (root / 'scripts/lib/configure_wine_discovery.py').read_text() if wine_discovery else None

    def authenticate(self):
        self.passwordless_update = False
        if pathlib.Path(UPDATE_HELPER).exists():
            result = subprocess.run(['sudo', '-n', UPDATE_HELPER, 'check'],
                                    capture_output=True, text=True, timeout=10)
            if result.returncode != 0 or result.stdout.strip() != 'flowgate-local-update-v2':
                raise RuntimeError('Passwordless update helper is unavailable, unauthorized or outdated (this update needs helper v2 with the stored-rule-schema check); rerun scripts/setup-passwordless-update.py before updating. Nothing was stopped')
            self.passwordless_update = True
            say('Using account-authorized passwordless update helper')
        else:
            subprocess.run(['sudo', '-v'], check=True)

    def privileged(self, operation, source, payload=None):
        if getattr(self, 'passwordless_update', False):
            command = ['sudo', '-n', UPDATE_HELPER, operation]
        else:
            command = ['sudo', '-n', '/usr/bin/python3', '-I', '-c', source]
        subprocess.run(command, input=payload, check=True)

    def preflight(self, backend, selected):
        # Runs for monitoring too: stored rule schemas are checked for every profile.
        files = json.loads(self.install_payload)['files']
        manifest = json.loads(base64.b64decode(files['manifest.json']))
        listed = {'max_rule_schema': manifest['max_rule_schema']} if 'max_rule_schema' in manifest else {}
        payload = json.dumps({'binary': files['flowgate'], 'sha256': manifest['files']['flowgate'], 'profile': selected, 'manifest': listed}).encode()
        self.privileged('preflight', STAGE_PREFLIGHT, payload)

    def install(self, backend):
        self.privileged('install', STAGE_INSTALL, self.install_payload)

    def configure_wine(self, root):
        self.privileged('configure-wine', self.wine_source)

    def action(self, backend, selected):
        # Existing typed client binds mutations to fresh generation/protection ID.
        subprocess.run([sys.executable, str(backend / 'control.py'), 'stop' if selected == 'monitoring' else selected], check=True)

    def sleep(self):
        time.sleep(.25)

    def switch_gui(self, root, bundle):
        # Only this user's released FlowGate main processes. Snapshot start time
        # and recheck before signalling so a reused PID is never targeted.
        processes = []
        releases = (root / '.workspace/automatic-zone-releases').resolve()
        for proc in pathlib.Path('/proc').iterdir():
            if not proc.name.isdigit():
                continue
            try:
                # Start time bookends the evidence: a PID recycled while it was
                # read never binds the old process's identity or environment.
                before = start_time(proc)
                if not released_gui(proc, releases):
                    continue
                environment = process_environment(proc)
                if start_time(proc) != before:
                    continue
                processes.append((proc, before, environment))
            except (OSError, ValueError, IndexError):
                continue
        # Resolve and verify the target desktop while the old GUI still runs; an
        # unverifiable target keeps it running instead of leaving no GUI at all.
        desktop, reason = target_desktop([environment for _, _, environment in processes], os.environ)
        processes = [(proc, start) for proc, start, _ in processes]
        if desktop is None:
            raise GuiNotSwitched(reason + ('; the running GUI was left open' if processes else '; no GUI started'))
        for proc, start in processes:
            try:
                fd = os.pidfd_open(int(proc.name))
                try:
                    if start_time(proc) == start:
                        signal.pidfd_send_signal(fd, signal.SIGTERM)
                finally:
                    os.close(fd)
            except (ProcessLookupError, FileNotFoundError):
                pass
        for _ in range(40):
            alive = []
            for proc, start in processes:
                try:
                    fields = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
                    if fields[19] == start and fields[0] != 'Z':
                        alive.append((proc, start))
                except FileNotFoundError:
                    pass
            if not alive:
                break
            self.sleep()
        else:
            raise GuiNotSwitched('Old FlowGate GUI did not exit; no duplicate GUI started')
        launch = str(bundle / 'launch-ui')
        environment = {k: v for k, v in os.environ.items() if k not in SESSION_KEYS}
        environment.update(desktop)
        say('Launching GUI on Wayland session ' + desktop['WAYLAND_DISPLAY'])
        pid = supervise_gui([launch, '--observer', '/run/flowgate-api/daemon.sock.monitor', '--control', '/run/flowgate-api/daemon.sock'], environment, bundle / '.workspace/gui-launch.log')
        say('GUI started (PID ' + str(pid) + '); main window reported loaded')


AUTOSTART_MARKER = 'X-FlowGate-Managed=true'


def login_entry_path():
    config = os.environ.get('XDG_CONFIG_HOME') or str(pathlib.Path.home() / '.config')
    if not os.path.isabs(config):
        raise ValueError('XDG_CONFIG_HOME must be absolute for login startup')
    return pathlib.Path(config) / 'autostart/flowgate.desktop'


def login_entry(bundle):
    # Desktop Entry Exec is not shell syntax. Escape reserved characters inside
    # its quoted executable token, then apply Desktop Entry string escaping.
    launch = str(bundle.resolve() / 'launch-ui')
    if any(c in launch for c in ('\n', '\r', '\x00')):
        raise ValueError('GUI launcher path contains a control character')
    quoted = ''.join('\\' + c if c in '\\"`$' else c for c in launch).replace('%', '%%')
    command = ('"' + quoted + '" --observer /run/flowgate-api/daemon.sock.monitor '
               '--control /run/flowgate-api/daemon.sock').replace('\\', '\\\\')
    return ('[Desktop Entry]\nType=Application\nName=FlowGate\n'
            'Comment=Monitor connection requests in the tray\nExec=' + command +
            '\nTerminal=false\n' + AUTOSTART_MARKER + '\n')


def configure_login_start(bundle, enable=False):
    """Enable only on request; refresh an existing managed entry on GUI updates.

    The session supplies its own display/bus environment at login. This starts
    only the user GUI; it never starts or changes firewall protection.
    """
    path = login_entry_path()
    old = None
    if path.is_symlink():
        raise ValueError('Refusing a symlink login entry: ' + str(path))
    if path.exists():
        st = path.stat()
        if st.st_uid != os.getuid() or not stat.S_ISREG(st.st_mode):
            raise ValueError('Login entry is not a regular file owned by this user')
        old = path.read_text()
        if AUTOSTART_MARKER not in old.splitlines():
            if enable:
                raise ValueError('Existing unmanaged login entry left unchanged: ' + str(path))
            return
    elif not enable:
        return
    if os.getuid() == 0:
        raise ValueError('GUI login startup must be configured as the desktop user')
    content = login_entry(bundle)
    if old is not None:
        # A desktop-settings opt-out survives release refreshes. Explicit enable
        # re-enables the entry without changing unrelated user configuration.
        for line in old.splitlines():
            if line.startswith(('Hidden=', 'X-GNOME-Autostart-enabled=')) and not enable:
                content += line + '\n'
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    import tempfile
    fd, temporary = tempfile.mkstemp(prefix='.flowgate-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    say('GUI login startup configured: ' + str(path))


def transition(host, backend, selected):
    try:
        host.action(backend, selected)
    except (OSError, subprocess.CalledProcessError):
        say('Control acknowledgement missing; checking state without replaying the action')
    for _ in range(120):
        status = host.status()
        if at_mode(status, selected):
            return status
        state = (status.get('protection') or {}).get('state')
        if state not in ('starting', 'stopping'):
            break
        host.sleep()
    reason = (status.get('protection') or {}).get('reason', 'No final state reported')
    raise RuntimeError('Protection did not reach ' + selected + ': ' + reason + '; inspect flowgate-control status. No action was replayed.')


def check_release_approval(root, revision):
    policy = json.loads((root / 'deployment/release-policy.json').read_text())
    if not isinstance(policy, dict) or any(not isinstance(policy.get(k), list) or not all(isinstance(v, str) for v in policy[k]) for k in ('approved', 'rejected')):
        raise ValueError('Invalid release approval policy; no host action taken')
    if revision in policy.get('rejected', []):
        raise RuntimeError('Rejected release: ' + revision + '; no host action taken')
    if revision not in policy.get('approved', []):
        raise RuntimeError('Release requires explicit review/approval: ' + revision + '; no host action taken')


def update(host, root, revision, *, dry=False, gui=True, profile="preserve", wine_discovery=False, recover_stopped=False, autostart=False, acknowledge_outgoing=False):
    check_release_approval(root, revision)
    if autostart and not gui:
        raise ValueError("--autostart requires GUI switching")
    bundle = root / '.workspace/automatic-zone-releases' / revision
    backend = root / '.workspace/daily-releases' / revision
    manifest = None
    if not dry or (bundle / 'matched-manifest.json').exists():
        verify_bundle(bundle, 'matched-manifest.json', revision)
        manifest = verify_bundle(backend, 'manifest.json', revision)
    try:
        before = host.status()
    except OSError:
        if host.installed() and not recover_stopped:
            raise RuntimeError('Installed daemon status unavailable; use --recover-stopped for guarded monitoring-only recovery. No action taken')
        before = None
    if recover_stopped and before is None:
        profile = 'monitoring'
    previous = mode(before) if before else 'monitoring'
    selected = previous if profile == "preserve" else profile
    def check_activation(current_mode, target, live=None):
        if target == 'both' and current_mode != 'both':
            warning = ('Enabling outgoing default-deny can block DNS, DHCP, VPN and kernel-origin traffic. '
                       'Review Essential networking and saved permissions; no permissions are added automatically. '
                       'Root-local recovery: sudo /usr/local/sbin/flowgate-recover. '
                       'Continuous protection has no automatic countdown.')
            say(warning)
            # Evidence for the review above, read-only and bound to the daemon
            # generation just observed; unavailable stays explicit.
            say(essential_summary(host.essential_status((live or {}).get('generation'))))
            if not dry and not acknowledge_outgoing:
                raise RuntimeError('Outgoing activation requires --acknowledge-outgoing-blocking after reviewing this warning; no action taken')
    check_activation(previous, selected, before)
    needs_install = wine_discovery or before is None or (not matches(before, manifest) if manifest else (before.get('build') or {}).get('source') != revision)
    if dry:
        if needs_install:
            say('Would authenticate sudo, stop protection, install and verify ' + revision)
        else:
            say('Matching daemon already running; no daemon restart needed')
        say(('Would enable generic Wine discovery; preserve valid rules; final protection mode: ' if wine_discovery else 'Would preserve existing Wine configuration and valid rules; final protection mode: ') + selected)
        if needs_install:
            say('Daemon startup would archive expired and confirmed obsolete native rules')
        if gui:
            say('Would close the old released GUI and launch ' + str(bundle / 'launch-ui'))
            if autostart:
                say('Would enable GUI login startup at ' + str(login_entry_path()))
        return
    stopped_for_update = False
    recovery_status = None
    rollback_verified = False
    try:
        if needs_install:
            # Authenticate before interrupting a running firewall. Re-read after
            # the password prompt so user changes during authentication win.
            host.prepare_install(backend, root, wine_discovery, manifest)
            host.authenticate()
            current = host.status() if before is not None else None
            selected = mode(current) if current is not None and profile == 'preserve' else selected
            check_activation(mode(current) if current is not None else 'monitoring', selected, current)
            host.preflight(backend, selected)
            checked_profile = selected
            current = host.status() if before is not None else None
            if current is not None:
                selected = mode(current) if profile == "preserve" else profile
                check_activation(mode(current), selected, current)
                if selected != checked_profile:
                    host.preflight(backend, selected)
                if not at_mode(current, 'monitoring'):
                    say('Stopping protection for the update; will restore ' + selected)
                    stopped_for_update = True
                    recovery_status = current
                    transition(host, backend, 'monitoring')
            if wine_discovery:
                host.configure_wine(root)
            try:
                host.install(backend)
            except subprocess.CalledProcessError as install_error:
                # Only the privileged installer emits 75 after restoring and
                # verifying the previous build/database pair in monitoring.
                rollback_verified = install_error.returncode == 75
                raise
            after = host.status()
            if not matches(after, manifest) or not at_mode(after, 'monitoring'):
                raise RuntimeError('Installed build/stopped-state verification failed')
        else:
            say('Matching daemon already running; no daemon restart needed')
        if needs_install or profile is not None:
            current = host.status()
            if not at_mode(current, selected):
                # A new install is expected to be monitoring. Only restoration
                # of an already active outgoing policy skips a new acknowledgement.
                check_activation(mode(recovery_status) if stopped_for_update else mode(current), selected, current)
                say('Restoring protection mode: ' + selected)
                transition(host, backend, selected)
        final = host.status()
        if not matches(final, manifest) or not at_mode(final, selected):
            raise RuntimeError('Final daemon build/protection verification failed')
        say('Update verified; protection mode: ' + selected)
    except Exception:
        if stopped_for_update:
            restored = False
            try:
                current = host.status()
                # Restore only the known original daemon: it must still own
                # its original generation and executable, or root must
                # have verified a matched executable/database rollback (exit 75).
                original_build = recovery_status.get('build') if recovery_status else None
                same_build = bool(original_build) and current.get('build') == original_build
                same_generation = recovery_status and current.get('generation') == recovery_status.get('generation')
                if same_build and current.get('generation') and (same_generation or rollback_verified) and at_mode(current, 'monitoring'):
                    transition(host, backend, mode(recovery_status))
                    restored = True
            except Exception as recovery_error:
                say('Previous protection could not be restored: ' + str(recovery_error))
            if restored:
                say('Update failed; previous daemon verified and its original protection mode restored.')
            else:
                say('Update incomplete; protection may remain OFF across reboot. Previous daemon could not be verified/restored. Use --recover-stopped for monitoring-only recovery, then explicitly start protection.')
        raise
    if gui:
        say('Switching to the matching GUI')
        host.switch_gui(root, bundle)
        try:
            configure_login_start(bundle, enable=autostart)
        except (OSError, ValueError) as error:
            raise GuiNotSwitched('matching GUI started, but login startup was not configured: ' + str(error)) from error


def main(argv=None, host=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=pathlib.Path, required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--no-gui', action='store_true')
    parser.add_argument('--autostart', action='store_true', help='Start this user GUI at login; refresh the matched release on future GUI updates')
    parser.add_argument('--wine-discovery', action='store_true')
    parser.add_argument('--recover-stopped', action='store_true')
    parser.add_argument('--profile', choices=('preserve', 'monitoring', 'incoming', 'both'), default='preserve', help='Preserve current mode by default; new installs stay monitoring')
    parser.add_argument('--acknowledge-outgoing-blocking', action='store_true', help='Acknowledge default-deny/DNS/DHCP lockout risk when enabling Both from another mode')
    args = parser.parse_args(argv)
    try:
        update(host or Host(), args.root.resolve(), args.revision, dry=args.dry_run, gui=not args.no_gui, profile=args.profile, wine_discovery=args.wine_discovery, recover_stopped=args.recover_stopped, autostart=args.autostart, acknowledge_outgoing=args.acknowledge_outgoing_blocking)
    except GuiNotSwitched as error:
        # Distinct from update failure: the daemon/protection result above stands.
        print('==> Backend update verified; GUI not switched: ' + str(error), file=sys.stderr, flush=True)
        sys.exit(3)
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        if isinstance(error, subprocess.CalledProcessError):
            sys.exit('Update failed: command exited ' + str(error.returncode) + '; see verification/recovery status above')
        sys.exit('Update failed: ' + str(error))


if __name__ == '__main__':
    main()
