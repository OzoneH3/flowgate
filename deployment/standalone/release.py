#!/usr/bin/python3
"""Install, recover or remove a verified standalone FlowGate release."""
import argparse
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path, PurePosixPath
import platform
import pwd
import re
import runpy
import shutil
import signal
import stat
import subprocess
import tarfile
import tempfile
import time
import uuid

BASE = Path('/usr/local/lib/flowgate')
DATA = Path('/var/lib/flowgate')
ETC = Path('/etc/flowgate')
TOOLS = Path('/usr/local/libexec/flowgate')
STATE = Path('/run/flowgate-enforcement')
UNITS = ('flowgate.service', 'flowgate-guard.service')
SHAPING = ETC / 'shaping.json'
LEGACY = Path('/usr/local/libexec/flowgate-update-helper')
LEGACY_GRANT = Path('/etc/sudoers.d/flowgate-local-update')
LOCAL = Path('/usr/local')
ADMIN_FILES = {
    'control.py': 'flowgate-control',
    'recover.py': 'flowgate-recover',
    'uninstall.py': 'flowgate-uninstall',
}
FILES = {
    **{name: str(LOCAL / 'sbin' / command) for name, command in ADMIN_FILES.items()},
    'release.py': str(TOOLS / 'release.py'),
    'install-monitoring.py': str(TOOLS / 'install-monitoring.py'),
    'flowgate-ui': '/usr/local/bin/flowgate-ui',
    'flowgate.desktop': '/usr/local/share/applications/flowgate.desktop',
    'flowgate.png': '/usr/local/share/icons/hicolor/256x256/apps/flowgate.png',
}
RELEASE_ID = re.compile(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9]+(?:\.[A-Za-z0-9]+)*)?-[a-f0-9]{12}')
HEX = re.compile(r'[a-f0-9]{64}')
MONITORING = b'{"schema":1,"mode":"monitoring"}'
RESCUE_ENTRY = b'#!/bin/sh\nexec /usr/bin/python3 -I /usr/local/libexec/flowgate/rescue-release.py recover "$@"\n'
SHA256SUM = '/usr/bin/sha256sum'
RUNUSER_DIRS = tuple(map(Path, ('/usr/sbin', '/usr/bin', '/sbin', '/bin')))
APPARMOR_PROFILE = Path('/etc/apparmor.d/flowgate-standalone-electron')
APPARMOR_USERNS = Path('/proc/sys/kernel/apparmor_restrict_unprivileged_userns')
APPARMOR_ENABLED = Path('/sys/module/apparmor/parameters/enabled')
APPARMOR_LOADED = Path('/sys/kernel/security/apparmor/profiles')
ELECTRON_PROFILE = b'''# Managed by the FlowGate standalone installer.
abi <abi/4.0>,
include <tunables/global>
profile flowgate-standalone-electron /usr/local/lib/flowgate/gui/[0-9]*/runtime/electron flags=(unconfined) {
  userns,
}
'''


def digest(path):
    with path.open('rb') as f:
        return subprocess.check_output([SHA256SUM], stdin=f).split()[0].decode('ascii')


def secure_file(path):
    mode = path.lstat()
    if not stat.S_ISREG(mode.st_mode) or mode.st_uid != 0 or mode.st_mode & 0o022:
        raise RuntimeError(f'Unsafe managed file: {path}')
    return path


def system_executable(name):
    # Root invokes this helper. Ignore PATH and reject links outside the system
    # directories, while allowing ordinary merged-/usr aliases.
    for directory in RUNUSER_DIRS:
        try:
            executable = (directory / name).resolve(strict=True)
            if executable.parent not in RUNUSER_DIRS:
                continue
            secure_file(executable)
            parents = [parent.lstat() for parent in executable.parents]
            if os.access(executable, os.X_OK) and all(
                stat.S_ISDIR(parent.st_mode) and parent.st_uid == 0 and not parent.st_mode & 0o022
                for parent in parents
            ):
                return str(executable)
        except (OSError, RuntimeError):
            continue
    raise RuntimeError(f'FlowGate requires an executable {name} in a trusted system directory (/usr/sbin, /usr/bin, /sbin, /bin)')


def system_runuser():
    return system_executable('runuser')


def electron_profile_exists():
    if not existing(APPARMOR_PROFILE):
        return False
    if secure_file(APPARMOR_PROFILE).read_bytes() != ELECTRON_PROFILE:
        raise RuntimeError(f'Edited or unmanaged AppArmor profile preserved: {APPARMOR_PROFILE}')
    return True


def electron_profile_parser():
    if APPARMOR_USERNS.is_file() and APPARMOR_USERNS.read_text().strip() == '1':
        return system_executable('apparmor_parser')
    return None


def install_electron_profile(parser):
    if parser is None:
        return
    present = electron_profile_exists()
    if not present:
        atomic(APPARMOR_PROFILE, ELECTRON_PROFILE, 0o644)
    else:
        secure_directory(APPARMOR_PROFILE.parent)
    try:
        subprocess.run([parser, '-r', '-T', str(APPARMOR_PROFILE)], check=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        if not present:
            APPARMOR_PROFILE.unlink()
            fsync_dir(APPARMOR_PROFILE.parent)
        raise


def remove_electron_profile():
    if not electron_profile_exists():
        return
    secure_directory(APPARMOR_PROFILE.parent)
    if APPARMOR_ENABLED.is_file() and APPARMOR_ENABLED.read_text().strip() == 'Y':
        if any(line.startswith('flowgate-standalone-electron ') for line in APPARMOR_LOADED.read_text().splitlines()):
            parser = system_executable('apparmor_parser')
            subprocess.run([parser, '-R', str(APPARMOR_PROFILE)], check=True, timeout=15)
    APPARMOR_PROFILE.unlink()
    fsync_dir(APPARMOR_PROFILE.parent)


def check_directory(path, status):
    if not stat.S_ISDIR(status.st_mode) or status.st_uid != 0 or status.st_mode & 0o022:
        raise RuntimeError(f'Unsafe managed directory: {path}')


def installation_files():
    # Verify the ancestors without following links or creating directories.
    for parent in reversed([LOCAL, *LOCAL.parents]):
        if existing(parent):
            check_directory(parent, parent.lstat())
    admin = LOCAL / 'sbin'
    if existing(admin):
        status = admin.lstat()
        if stat.S_ISLNK(status.st_mode):
            bin_dir = LOCAL / 'bin'
            if status.st_uid != 0 or os.readlink(admin) not in ('bin', str(bin_dir)):
                raise RuntimeError(f'Unexpected administrative directory alias: {admin}')
            # Operate on the real directory, leaving the distro alias intact.
            admin = bin_dir
            status = admin.lstat()
        check_directory(admin, status)
    return {**FILES, **{name: str(admin / command) for name, command in ADMIN_FILES.items()}}


def secure_directory(path):
    for parent in reversed([path, *path.parents]):
        try:
            parent.mkdir(mode=0o755)
        except FileExistsError:
            pass
        else:
            # The process umask is restrictive for backups. Public installed
            # binaries still need traversable root-owned parent directories.
            parent.chmod(0o755)
        check_directory(parent, parent.lstat())
    return path


def atomic(path, data, mode=0o600):
    secure_directory(path.parent)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as f:
        temporary = Path(f.name)
        try:
            os.fchmod(f.fileno(), mode)
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
            temporary.replace(path)
            fsync_dir(path.parent)
        finally:
            temporary.unlink(missing_ok=True)


def fsync_dir(path):
    fd = os.open(path, os.O_DIRECTORY | os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_record(path, value):
    atomic(path, (json.dumps(value, indent=2) + '\n').encode())


def read_record(path):
    return json.loads(secure_file(path).read_bytes())


@contextmanager
def locked():
    secure_directory(BASE)
    fd = os.open(BASE / '.install.lock', os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_RDWR, 0o600)
    try:
        secure_file(BASE / '.install.lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def archive_name(member):
    name = member.name
    path = PurePosixPath(name)
    if not path.parts or str(path) != name or path.is_absolute() or '..' in path.parts or (
        name != 'release.json' and path.parts[0] not in {'backend', 'gui'}
    ):
        raise RuntimeError(f'Invalid package path: {name}')
    return name


def unpack(bundle, expected, staging):
    if not HEX.fullmatch(expected):
        raise RuntimeError('Expected the trusted SHA256 digest of the archive')
    sealed = staging / 'archive'
    # Verify and read the same privately staged bytes.
    with bundle.open('rb') as source, sealed.open('xb') as output:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise RuntimeError('Package must be a regular file')
        limit = 512 * 1024 * 1024
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            if output.tell() + len(chunk) > limit:
                raise RuntimeError('Package compressed size exceeds limit')
            output.write(chunk)
    if digest(sealed) != expected:
        raise RuntimeError('Package size or SHA256 verification failed')
    payload = staging / 'payload'
    payload.mkdir()
    with tarfile.open(sealed, 'r:gz') as stream:
        header = stream.next()
        if header is None or header.name != 'release.json' or not header.isfile() or header.size > 1024 * 1024:
            raise RuntimeError('Missing or invalid release manifest')
        manifest = json.load(stream.extractfile(header))
        if manifest['schema'] != 1 or manifest['platform'] != 'linux-' + platform.machine():
            raise RuntimeError('Unsupported package platform or schema')
        release = manifest['release']
        if not RELEASE_ID.fullmatch(release) or not re.fullmatch(r'[a-f0-9]{40}', manifest['source']):
            raise RuntimeError('Invalid release ID or source')
        if release != f"{manifest['version']}-{manifest['source'][:12]}":
            raise RuntimeError('Release name does not match version and source')
        wanted = manifest['files']
        seen = set()
        visited = {'release.json'}
        total = 0
        while member := stream.next():
            name = archive_name(member)
            if name in visited or len(visited) > 2048:
                raise RuntimeError(f'Duplicate path or oversized package inventory: {name}')
            visited.add(name)
            target = payload / name
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile() or name not in wanted:
                raise RuntimeError(f'Unexpected package member: {name}')
            entry = wanted[name]
            if entry['mode'] not in (0o644, 0o755):
                raise RuntimeError(f'Invalid installed file mode: {name}')
            total += member.size
            if total > 1024 * 1024 * 1024:
                raise RuntimeError('Unpacked package exceeds size limit')
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as file:
                shutil.copyfileobj(stream.extractfile(member), file)
            if digest(target) != entry['sha256']:
                raise RuntimeError(f'Package member hash mismatch: {name}')
            target.chmod(entry['mode'])
            seen.add(name)
        if seen != set(wanted):
            raise RuntimeError('Missing package members')
    backend = read_record(payload / 'backend/manifest.json')
    actual = {name[8:]: entry['sha256'] for name, entry in wanted.items()
              if name.startswith('backend/') and name != 'backend/manifest.json'}
    if backend['source'] != manifest['source'] or backend['release'] != release or backend['files'] != actual:
        raise RuntimeError('Backend and matched manifest disagree')
    required = {*FILES, *UNITS, 'flowgate', 'launch', 'standalone-release.json'}
    if not required <= set(actual) or 'gui/runtime/electron' not in seen:
        raise RuntimeError('Package is missing a required entry point')
    return payload, manifest, backend


def module(path):
    secure_file(path)
    api = runpy.run_path(str(path))
    # Use the established installer and include each stable file in its backup.
    api['TOOLS'].update(installation_files())
    return api


def existing(path):
    return path.exists() or path.is_symlink()


def current_release():
    link = BASE / 'current'
    if not existing(link):
        return None
    if not link.is_symlink():
        raise RuntimeError('Invalid current release pointer')
    resolved = link.resolve(strict=True)
    if resolved.parent != BASE / 'releases':
        raise RuntimeError('Current release escaped the managed directory')
    return resolved


def owned_journal():
    directory = DATA / 'upload-experiment'
    if existing(directory) and (directory.is_symlink() or not directory.is_dir()):
        raise RuntimeError('Unexpected shaping state directory')
    return existing(directory / 'owner.json')


def check_mode(api, host, response, selected):
    protection = response.get('protection') or {}
    enforcement = response.get('enforcement') or {}
    if protection.get('desired_mode') != selected:
        return False
    if selected == 'monitoring':
        return (protection.get('state') == enforcement.get('state') == 'stopped'
                and not api['flowgate_tables'](host))
    return (protection.get('state') == enforcement.get('state') == 'active'
            and protection.get('profile') == enforcement.get('profile') == selected)


def wait_for(host, generation, predicate):
    deadline = time.monotonic() + 35
    while True:
        _, response = host.api()
        if generation != response['generation']:
            raise RuntimeError('Daemon changed during transition')
        if predicate(response):
            return response
        if time.monotonic() >= deadline:
            detail = (response.get('protection') or {}).get('reason', 'no settled state')
            raise RuntimeError(f'Transition did not settle: {detail}')
        time.sleep(.25)


def shaping_status(host, generation):
    _, response = host.api('upload-status', generation=generation, allow_error=True)
    if response.get('error'):
        if response.get('error_code') == 'unavailable':
            return {}
        raise RuntimeError(response['error'])
    return response.get('upload_shaping') or {}


def preflight(api, backend_dir, backend, desktop_config):
    host = api['Host']()
    former = current_release()
    old = None
    if former is not None:
        old = api['previous_release'](host, BASE, BASE / 'releases')
        if old is None:
            raise RuntimeError('Current release is not a verified managed predecessor')
    uid = api['administrator_uid'](host, former is not None)
    account = pwd.getpwuid(uid)
    previous_record = DATA / 'standalone.json'
    if existing(previous_record):
        installed_record = read_record(previous_record)
        if installed_record['uid'] != uid:
            raise RuntimeError('The enrolled desktop UID changed; inspect before upgrading')
        desktop_config = desktop_config or installed_record['desktop_config']
    desktop_config = desktop_config or str(Path(account.pw_dir) / '.config')
    if not Path(desktop_config).is_absolute() or Path(desktop_config).resolve().is_relative_to(
        Path('/usr/local/lib/flowgate')
    ) or '.workspace' in Path(desktop_config).parts:
        raise RuntimeError('Desktop config requires a standalone absolute location')
    if owned_journal():
        raise RuntimeError('Shaping ownership journal exists. Use verified shaping reconciliation separately.')
    if any(existing(path) for path in (LEGACY, LEGACY_GRANT)) and not (DATA / 'standalone.json').exists():
        print('Legacy update helper or privilege grant detected. Left for separately verified removal.')
    api['require_rule_schemas'](DATA / 'rules.db', api['manifest_rule_schema'](backend))
    daemon = backend_dir / 'flowgate'
    build = json.loads(host.run(str(daemon), 'version'))
    if build.get('source') != backend['source'] or build.get('max_rule_schema') != backend['max_rule_schema']:
        raise RuntimeError('Candidate executable has an incompatible build declaration')
    response = None
    selected = 'monitoring'
    extra_config = {}
    collector = None
    settings = None
    if old:
        _, response = host.api()
        selected = response['protection']['desired_mode']
        if selected not in ('monitoring', 'incoming', 'both') or not check_mode(api, host, response, selected):
            raise RuntimeError('Current protection is not settled')
        live = response['build']
        if live.get('source') != old[1]['source'] or live.get('executable_sha256') != old[1]['files']['flowgate'] or live.get('modified') is not False:
            raise RuntimeError('Running backend does not match the current release')
        shape = shaping_status(host, response['generation'])
        if (shape.get('status') not in ('Disabled', 'Unsupported', None) or
            shape.get('enabled') or shape.get('configured_caps') or
            shape.get('upload_budget_bits_per_second') or shape.get('download_budget_bits_per_second')):
            raise RuntimeError('Configured or active shaping requires a verified transition before upgrade')
        if shape.get('deployment_mode') == 'host-trial':
            interface = shape.get('interface')
            if shape.get('status') != 'Disabled' or not isinstance(interface, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', interface):
                raise RuntimeError('Host shaping interface or state cannot be preserved')
            if not existing(SHAPING):
                extra_config[SHAPING] = json.dumps({'interface': interface}).encode()
        settings = saved_settings(host, response, shape=shape)
        collector = (response.get('traffic_monitor') or {}).get('state')
        if collector not in (None, 'unavailable', 'active', 'stopped'):
            raise RuntimeError('Current collector is not settled')
        if selected != 'monitoring':
            checks = json.loads(host.run(str(daemon), 'doctor', '--json', '--upgrade-preflight',
                                         '--state', str(STATE), '--profile', selected))
            if checks.get('schema_version') != 1 or not checks.get('checks'):
                raise RuntimeError('Invalid candidate kernel preflight response')
            for check in checks['checks']:
                if check['status'] != 'ready' and not (
                    check['id'] == 'firewall.queue_census' and check['status'] == 'not_checked'
                ):
                    raise RuntimeError(f"Kernel preflight refused: {check['id']}: {check.get('detail')}")
    elif api['flowgate_tables'](host) or host.daemon_pids():
        raise RuntimeError('Existing FlowGate process or tables lack a managed installation')
    for path in (SHAPING, Path(api['DROPIN']), *(Path(x) for x in api['TOOLS'].values()),
                 *(Path('/etc/systemd/system') / name for name in UNITS)):
        if not existing(path):
            continue
        secure_file(path)
        if path == SHAPING:
            continue
        reverse = {Path(dest): name for name, dest in api['TOOLS'].items()}
        name = reverse.get(path, '50-flowgate-guard.conf' if path == Path(api['DROPIN']) else path.name)
        approved = {(backend_dir / name).read_bytes()}
        if old and name in old[1]['files']:
            approved.add((old[0] / name).read_bytes())
        if path.read_bytes() not in approved:
            raise RuntimeError(f'Existing path has unmanaged bytes: {path}')
    return host, old, response, selected, collector, extra_config, uid, desktop_config, settings


def desktop(user, config, program, action, preferences=None):
    account = pwd.getpwuid(user)
    command = [system_runuser(), '-u', account.pw_name, '--', '/usr/bin/env', '-i',
               'HOME=' + account.pw_dir, 'XDG_CONFIG_HOME=' + config, str(program), action]
    if preferences is not None:
        command.extend(['--import-preferences', str(preferences)])
    subprocess.run(command, check=True, timeout=10)


def immutable_tree(source, target, expected):
    secure_directory(target.parent)
    if not existing(target):
        with tempfile.TemporaryDirectory(dir=target.parent) as folder:
            stage = Path(folder) / 'tree'
            # Source was verified in a private stage on this same filesystem.
            # Rename it into place so an upgrade does not need another GUI copy.
            source.rename(stage)
            for directory in [stage, *[p for p in stage.rglob('*') if p.is_dir()]]:
                directory.chmod(0o755)
            stage.replace(target)
            fsync_dir(target.parent)
    secure_directory(target)
    paths = set()
    for path in target.rglob('*'):
        if path.is_symlink():
            raise RuntimeError(f'Unexpected symlink in {target}')
        if path.is_file():
            relative = path.relative_to(target).as_posix()
            entry = expected.get(relative)
            if not entry or digest(secure_file(path)) != entry['sha256'] or stat.S_IMODE(path.stat().st_mode) != entry['mode']:
                raise RuntimeError(f'Immutable payload differs: {path}')
            paths.add(relative)
    if paths != set(expected):
        raise RuntimeError(f'Incomplete payload: {target}')


def install(options, payload, manifest, backend):
    api = module(payload / 'backend/install-monitoring.py')
    if (DATA / 'standalone-pending.json').exists():
        raise RuntimeError('An interrupted update requires local recovery')
    host, old, before, selected, collector, config, uid, xdg, settings = preflight(
        api, payload / 'backend', backend, options.desktop_config,
    )
    parser = electron_profile_parser()
    if parser is not None:
        electron_profile_exists()
    if options.operation == 'preflight':
        print(f"Preflight passed for {manifest['release']}. Current protection: {selected}.")
        return
    if old is not None and old[0].name == manifest['release']:
        raise RuntimeError('This exact release is already installed')
    release = manifest['release']
    secure_directory(BASE / 'releases')
    for path in api['TOOLS'].values():
        secure_directory(Path(path).parent)
    gui_files = {name[4:]: entry for name, entry in manifest['files'].items() if name.startswith('gui/')}
    gui_payload = BASE / 'gui' / release
    immutable_tree(payload / 'gui', gui_payload, gui_files)
    desktop(uid, xdg, gui_payload / 'flowgate-ui', '--check-autostart', options.import_preferences)
    # The attachment covers only Electron under the immutable versioned GUI
    # tree. Keeping it across a release switch also covers a verified rollback.
    install_electron_profile(parser)

    # Pin the rescue executable and lifecycle script independently of current.
    rescue = secure_directory(BASE / 'rescue' / release)
    for name in ('flowgate', 'release.py', 'install-monitoring.py'):
        src = payload / 'backend' / name
        dest = rescue / name
        if existing(dest):
            if digest(secure_file(dest)) != digest(src):
                raise RuntimeError(f'Rescue artifact differs: {dest}')
        else:
            atomic(dest, src.read_bytes(), 0o755)

    stamp = time.strftime('%Y%m%dT%H%M%S') + '-' + uuid.uuid4().hex[:8]
    record = {
        'release': release, 'previous': old[0].name if old else None, 'stamp': stamp,
        'rescue': {name: digest(rescue / name) for name in ('flowgate', 'release.py', 'install-monitoring.py')},
        'files': backend['files'], 'gui': gui_files, 'uid': uid, 'desktop_config': xdg,
        'previous_mode': selected,
        'previous_unit_hashes': {name: old[1]['files'][name] for name in UNITS} if old else {},
    }
    if DATA.is_symlink():
        raise RuntimeError('Unsafe state directory')
    secure_directory(DATA.parent)
    DATA.mkdir(mode=0o700, exist_ok=True)
    if DATA.stat().st_uid != 0 or DATA.stat().st_mode & 0o077:
        raise RuntimeError('FlowGate state directory is not private')
    pending = DATA / 'standalone-pending.json'
    write_record(DATA / 'release-receipts' / (release + '.json'), record)
    write_record(pending, record)
    # Keep a fixed rescue entry point even during the first install or a power loss.
    atomic(TOOLS / 'rescue', RESCUE_ENTRY, 0o755)
    atomic(TOOLS / 'rescue-release.py', (rescue / 'release.py').read_bytes(), 0o755)

    def verify_extra(response):
        if settings is not None:
            verify_saved_settings(host, settings, response)
        restore_collector(host, collector, response)
        if owned_journal():
            raise RuntimeError('Shaping journal appeared during install')

    try:
        before_quiesce = prepare_switch(api, host, before, settings, selected)
        api['install_locked'](host, payload / 'backend', stamp, extra_config=config,
                              verify_extra=verify_extra, before_quiesce=before_quiesce, standalone=True)
    except PreflightChanged:
        pending.unlink()
        fsync_dir(DATA)
        raise
    except api['RollbackComplete']:
        pending.unlink()
        fsync_dir(DATA)
        raise RuntimeError('Previous release and database restored in monitoring') from None
    write_record(DATA / 'standalone.json', record)
    pending.unlink()
    fsync_dir(DATA)

    if selected != 'monitoring':
        _, after = host.api()
        try:
            host.api('protection-start', generation=after['generation'],
                     protection_id=after['protection']['id'], request_id=uuid.uuid4().hex, profile=selected)
            wait_for(host, after['generation'], lambda v: check_mode(api, host, v, selected))
        except Exception as exc:
            _, status = host.api()
            if not check_mode(api, host, status, selected):
                if check_mode(api, host, status, 'monitoring'):
                    raise RuntimeError(f'Installed in monitoring; restoring {selected} was refused: {exc}') from None
                raise RuntimeError(f'Restoring {selected} could not be verified; use local recovery') from exc
    desktop(uid, xdg, Path(FILES['flowgate-ui']), '--migrate-autostart', options.import_preferences)
    print(f"Installed {release}; protection mode {selected}. Launch with flowgate-ui.")


SHAPE_SETTINGS = (
    'status', 'enabled', 'interface', 'deployment_mode', 'configured_caps',
    'upload_budget_bits_per_second', 'download_budget_bits_per_second',
)
ZONE_OBSERVATIONS = {'revision', 'network_revision', 'network_state', 'network'}


def saved_settings(host, response, *, shape=None):
    generation = response['generation']
    if shape is None:
        shape = shaping_status(host, generation)
    zones = response.get('network_zones') or {}
    if zones.get('model') == 'automatic-peer-v1':
        zones = {key: value for key, value in zones.items() if key not in ZONE_OBSERVATIONS}
    receipt = host.api('connection-check-status', generation=generation, allow_error=True)[1]
    if receipt.get('error') and receipt.get('error_code') != 'unavailable':
        raise RuntimeError(receipt['error'])
    return {
        'shaping': {key: shape.get(key) for key in SHAPE_SETTINGS},
        'zones': zones,
        'connection_checks': receipt.get('connection_checks'),
    }


def verify_saved_settings(host, expected, response):
    actual = saved_settings(host, response)
    for name, value in expected.items():
        if actual[name] != value:
            raise RuntimeError(f'Saved {name} differs after switching the executable')


def restore_collector(host, expected, response):
    if expected not in ('active', 'stopped'):
        return
    observed = response.get('traffic_monitor') or {}
    if observed.get('state') != expected:
        host.api('traffic-start' if expected == 'active' else 'traffic-stop',
                 generation=response['generation'], collector_generation=observed.get('generation', ''))
        wait_for(host, response['generation'],
                 lambda value: (value.get('traffic_monitor') or {}).get('state') == expected)


class PreflightChanged(RuntimeError):
    """The verified transition has not reached service shutdown."""


def verify_before_switch(api, host, before, settings, protection):
    try:
        _, fresh = host.api()
        if fresh['generation'] != before['generation'] or fresh['protection'] != protection:
            raise RuntimeError('daemon or protection changed')
        if api['api_inventory'](fresh) != api['api_inventory'](before):
            raise RuntimeError('rules changed')
        old_collector = before.get('traffic_monitor') or {}
        new_collector = fresh.get('traffic_monitor') or {}
        if any(old_collector.get(key) != new_collector.get(key) for key in ('state', 'generation')):
            raise RuntimeError('collector changed')
        current = saved_settings(host, fresh)
        for name, value in settings.items():
            if current[name] != value:
                raise RuntimeError(f'{name} changed')
        if owned_journal():
            raise RuntimeError('shaping ownership journal appeared')
    except (OSError, RuntimeError, ValueError) as exc:
        raise PreflightChanged(f'State changed after preflight: {exc}. Retry from a fresh preflight.') from exc


def prepare_switch(api, host, before, settings, selected):
    if before is None:
        return None
    expected = before['protection']
    verify_before_switch(api, host, before, settings, expected)
    if selected != 'monitoring':
        host.api('protection-stop', generation=before['generation'], protection_id=expected['id'])
        stopped = wait_for(host, before['generation'], lambda state: check_mode(api, host, state, 'monitoring'))
        expected = stopped['protection']

    def before_quiesce():
        verify_before_switch(api, host, before, settings, expected)

    return before_quiesce


def rollback_build(api, host, record):
    """Downgrade the executable using the current database as the source."""
    previous = record.get('previous')
    if not previous:
        raise RuntimeError('No verified predecessor is recorded')
    old = BASE / 'releases' / previous
    receipt = DATA / 'release-receipts' / (previous + '.json')
    if not RELEASE_ID.fullmatch(previous) or not receipt.is_file():
        raise RuntimeError(
            'Previous release has no trusted standalone state contract. Current data and '
            'protection are untouched. Use a compatible package, or export and review the '
            'older install backup separately if you explicitly intend to discard later changes.'
        )
    prior = read_record(receipt)
    if prior['release'] != previous:
        raise RuntimeError('Previous release receipt does not match')
    current = current_release()
    if current != BASE / 'releases' / record['release']:
        raise RuntimeError('Current executable is not verified. Use local rescue before rollback.')
    candidate = api['previous_release_for_path'](host, BASE, old)
    installed = api['previous_release_for_path'](host, BASE, current)
    if candidate['files'] != prior['files'] or installed['files'] != record['files']:
        raise RuntimeError('Installed release does not match its verified receipt')
    contract = installed.get('state_compatibility')
    if not contract or contract != candidate.get('state_compatibility'):
        raise RuntimeError(
            'Previous executable does not declare compatibility with the current settings and '
            'database. No changes made. Select a compatible package or review the older '
            'backup separately without replacing current data.'
        )
    gui = BASE / 'gui' / previous
    if not gui.is_dir():
        raise RuntimeError('Matching previous desktop payload is unavailable')
    immutable_tree(gui, gui, prior['gui'])

    # This includes the stored-rule ceiling and shaping checks before Stop.
    host, _, before, selected, collector, config, uid, xdg, settings = preflight(
        api, old, candidate, record['desktop_config'],
    )
    if config:
        raise RuntimeError('Rollback would require unexpected changes to shaping configuration')
    stamp = time.strftime('%Y%m%dT%H%M%S') + '-' + uuid.uuid4().hex[:8]
    pending = DATA / 'standalone-pending.json'
    attempt = dict(
        prior, previous=current.name, stamp=stamp, previous_mode=selected,
        previous_unit_hashes={name: installed['files'][name] for name in UNITS},
        uid=uid, desktop_config=xdg,
    )
    write_record(pending, attempt)

    backup = DATA / 'backups' / (previous + '-monitoring-' + stamp)

    def verify_latest(response):
        newest = api['rule_documents'](backup / 'rules.db')
        if api['rule_documents'](DATA / 'rules.db') != newest:
            raise RuntimeError('The previous executable did not retain the newest rule documents')
        verify_saved_settings(host, settings, response)
        restore_collector(host, collector, response)

    try:
        before_quiesce = prepare_switch(api, host, before, settings, selected)
        api['install_locked'](host, old, stamp, verify_extra=verify_latest,
                              before_quiesce=before_quiesce, standalone=True)
    except PreflightChanged:
        pending.unlink()
        fsync_dir(DATA)
        raise
    except api['RollbackComplete']:
        pending.unlink()
        fsync_dir(DATA)
        raise RuntimeError(
            'Downgrade failed verification. The newer executable and latest state were '
            'restored in monitoring. No older database was activated.'
        ) from None
    write_record(receipt, attempt)
    write_record(DATA / 'standalone.json', attempt)
    pending.unlink()
    fsync_dir(DATA)
    print(f'Selected {previous} in monitoring with the latest saved rules and settings.')


def cleanup(api, host, record):
    if owned_journal():
        raise RuntimeError('Retained shaping ownership journal; verified reconciliation required')
    for name in UNITS:
        unit = Path('/etc/systemd/system') / name
        allowed = {record['files'][name], (record.get('previous_unit_hashes') or {}).get(name)}
        if existing(unit) and digest(secure_file(unit)) not in allowed:
            raise RuntimeError(f'Edited unit preserved: {unit}')
    rescue = BASE / 'rescue' / record['release'] / 'flowgate'
    if digest(secure_file(rescue)) != record['rescue']['flowgate']:
        raise RuntimeError('Rescue executable failed verification')
    atomic(DATA / 'protection.json', MONITORING)
    # Stop the consumer first. A legacy Requires edge may still bind
    # NetworkManager to the guard during an interrupted first migration.
    if (Path('/etc/systemd/system') / UNITS[0]).exists():
        host.run('systemctl', 'stop', UNITS[0])
    if host.daemon_pids():
        raise RuntimeError('Unexpected FlowGate process remains')
    host.run(str(rescue), 'protection-recover', '--state', str(STATE))
    if api['flowgate_tables'](host):
        raise RuntimeError('Interception remains; install and startup tools retained')


def restore_previous(api, host, record):
    if not record.get('previous'):
        raise RuntimeError('No verified previous release is recorded')
    old = BASE / 'releases' / record['previous']
    manifest = api['previous_release_for_path'](host, BASE, old)
    backup = DATA / 'backups' / (record['release'] + '-monitoring-' + record['stamp'])
    snapshot = read_record(backup / 'rollback-files.json')
    install_record = read_record(backup / 'install-record.json')
    allowed = {DATA / name for name in ('rules.db', 'decisions.db')}
    allowed.update({ETC / 'zones.json', ETC / 'administrator.json', SHAPING, Path(api['DROPIN'])})
    allowed.update(Path(path) for path in api['TOOLS'].values())
    allowed.update(Path('/etc/systemd/system') / name for name in UNITS)
    for name, item in snapshot.items():
        if Path(name) not in allowed or item is not None and not re.fullmatch(r'rollback-[0-9]+', item['file']):
            raise RuntimeError('Unsafe rollback inventory')
        if item is not None:
            secure_file(backup / item['file'])
    api['rollback'](host, backup, DATA, BASE, (old, manifest), snapshot, install_record['unit_enabled'])
    print(f'Restored {old.name} and its saved database in monitoring.')


def recover(options, api, host, record, pending):
    if options.rollback:
        if pending:
            raise RuntimeError('An installation is incomplete. Run recover without --rollback for failed-install recovery.')
        return rollback_build(api, host, record)
    cleanup(api, host, record)
    if options.stop_only:
        print('FlowGate stopped; monitoring intent saved and no managed interception remains.')
        return
    if pending and record.get('previous'):
        # Preserve the previous desktop login when reverting the first migration.
        # A standalone predecessor still uses the same stable launcher.
        launcher = Path(FILES['flowgate-ui'])
        if existing(launcher) and record.get('previous') and not (
            BASE / 'gui' / record['previous']
        ).is_dir():
            desktop(record['uid'], record['desktop_config'], launcher, '--restore-autostart')
        restore_previous(api, host, record)
        pending.unlink()
        fsync_dir(DATA)
        return
    selected = BASE / 'releases' / record['release']
    manifest = api['previous_release_for_path'](host, BASE, selected)
    try:
        active = current_release()
    except FileNotFoundError:
        active = None
    if active not in (selected, None):
        raise RuntimeError('Current points at a different release; use explicit rollback')
    if active is None:
        with tempfile.TemporaryDirectory(dir=BASE) as folder:
            link = Path(folder) / 'current'
            link.symlink_to(selected)
            link.replace(BASE / 'current')
            fsync_dir(BASE)
    api['reset_failed_units'](host)
    host.run('systemctl', 'start', 'flowgate.service')
    api['wait_monitoring'](host, manifest, api['rule_inventory'](DATA / 'rules.db'))
    if pending:
        write_record(DATA / 'release-receipts' / (record['release'] + '.json'), record)
        write_record(DATA / 'standalone.json', record)
        pending.unlink()
        fsync_dir(DATA)
    print('Monitoring recovered. Protection remains off.')


def uninstall(options, api, host, record, pending):
    if pending:
        raise RuntimeError('Resolve the interrupted install before uninstalling')
    electron_profile_exists()
    files = {Path(dst): record['files'][name] for name, dst in api['TOOLS'].items()}
    files.update({Path('/etc/systemd/system') / name: record['files'][name] for name in UNITS})
    for path, expected in files.items():
        if existing(path) and digest(secure_file(path)) != expected:
            raise RuntimeError(f'Edited managed file preserved: {path}')
    if existing(Path(api['DROPIN'])):
        raise RuntimeError('Legacy NetworkManager drop-in present; inspect before removal')
    link = BASE / 'current'
    release = BASE / 'releases' / record['release']
    if existing(link) and (not link.is_symlink() or link.resolve() != release):
        raise RuntimeError('Current points outside the registered installation')
    receipts_dir = DATA / 'release-receipts'
    registered = {record['release']: record}
    for path in receipts_dir.glob('*.json'):
        entry = read_record(path)
        if path.stem != entry['release'] or not RELEASE_ID.fullmatch(path.stem):
            raise RuntimeError(f'Invalid retained release receipt: {path}')
        registered[path.stem] = entry
    remove = []
    rescue_script_hashes = set()
    for release_name, entry in registered.items():
        gui = BASE / 'gui' / release_name
        if existing(gui):
            immutable_tree(gui, gui, entry['gui'])
            remove.append(gui)
        backend = BASE / 'releases' / release_name
        if existing(backend):
            manifest = api['previous_release_for_path'](host, BASE, backend)
            if manifest['files'] != entry['files'] or {p.name for p in backend.iterdir()} != {
                *entry['files'], 'manifest.json'
            }:
                raise RuntimeError(f'Additional or changed release files: {backend}')
            remove.append(backend)
        rescue = BASE / 'rescue' / release_name
        rescue_script_hashes.add(entry['rescue']['release.py'])
        if existing(rescue):
            secure_directory(rescue)
            if {p.name for p in rescue.iterdir()} != set(entry['rescue']) or any(
                digest(secure_file(rescue / name)) != checksum
                for name, checksum in entry['rescue'].items()
            ):
                raise RuntimeError(f'Changed rescue directory: {rescue}')
            remove.append(rescue)
    rescue_cli = TOOLS / 'rescue'
    rescue_script = TOOLS / 'rescue-release.py'
    if existing(rescue_cli) and secure_file(rescue_cli).read_bytes() != RESCUE_ENTRY:
        raise RuntimeError('Edited rescue launcher preserved')
    if existing(rescue_script) and digest(secure_file(rescue_script)) not in rescue_script_hashes:
        raise RuntimeError('Edited rescue tool preserved')
    launcher = Path(FILES['flowgate-ui'])
    login_helper = launcher if existing(launcher) else release / 'flowgate-ui'
    if existing(login_helper):
        desktop(record['uid'], record['desktop_config'], login_helper, '--check-autostart')
    cleanup(api, host, record)
    units = [name for name in UNITS if (Path('/etc/systemd/system') / name).exists()]
    if units:
        host.run('systemctl', 'disable', '--now', *units)
    if existing(login_helper):
        desktop(record['uid'], record['desktop_config'], login_helper, '--stop-installed')
        desktop(record['uid'], record['desktop_config'], login_helper, '--remove-autostart')
    remove_electron_profile()
    for name in UNITS:
        (Path('/etc/systemd/system') / name).unlink(missing_ok=True)
    host.run('systemctl', 'daemon-reload')
    for path in files:
        path.unlink(missing_ok=True)
    link.unlink(missing_ok=True)
    for root in remove:
        shutil.rmtree(root)
    for release_name in registered:
        (receipts_dir / (release_name + '.json')).unlink(missing_ok=True)
    rescue_cli.unlink(missing_ok=True)
    rescue_script.unlink(missing_ok=True)
    if options.purge:
        for root in (ETC, DATA):
            if root.is_symlink() or not root.is_dir() or root.stat().st_uid != 0:
                raise RuntimeError(f'Unsafe purge directory: {root}')
            shutil.rmtree(root)
    else:
        (DATA / 'standalone.json').unlink(missing_ok=True)
    print('FlowGate services and registered standalone releases removed. Legacy releases and user preferences retained.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    for operation in ('preflight', 'install'):
        command = sub.add_parser(operation)
        command.add_argument('--bundle', type=Path, required=True)
        command.add_argument('--sha256', required=True)
        command.add_argument('--desktop-config')
        command.add_argument('--import-preferences', type=Path)
    command = sub.add_parser('recover')
    mode = command.add_mutually_exclusive_group()
    mode.add_argument('--stop-only', action='store_true')
    mode.add_argument('--rollback', action='store_true')
    sub.add_parser('uninstall').add_argument('--purge', action='store_true')
    options = parser.parse_args()
    if os.sys.version_info < (3, 9):
        parser.error('FlowGate requires Python 3.9 or newer')
    if not os.access(SHA256SUM, os.X_OK):
        parser.error(f'FlowGate requires {SHA256SUM}')
    if options.operation in ('preflight', 'install') and (
        not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal')
    ):
        parser.error('System Python must support Linux pidfds to stop the installed desktop safely')
    if os.geteuid() != 0 or not __debug__ or not os.sys.flags.isolated:
        parser.error('Run as root using /usr/bin/python3 -I')
    if options.operation in ('preflight', 'install'):
        system_runuser()
    os.umask(0o077)
    os.environ['PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
    with locked():
        if options.operation in ('preflight', 'install'):
            with tempfile.TemporaryDirectory(prefix='.stage-', dir=BASE) as directory:
                payload, manifest, backend = unpack(options.bundle, options.sha256, Path(directory))
                install(options, payload, manifest, backend)
            return
        pending = DATA / 'standalone-pending.json'
        receipt = pending if pending.exists() else DATA / 'standalone.json'
        if not existing(receipt) and options.operation == 'uninstall':
            remove_electron_profile()
            print('No standalone installation is registered')
            return
        record = read_record(receipt)
        rescue = BASE / 'rescue' / record['release'] / 'install-monitoring.py'
        if digest(secure_file(rescue)) != record['rescue']['install-monitoring.py']:
            raise RuntimeError('Rescue installer failed verification')
        api = module(rescue)
        host = api['Host']()
        action = recover if options.operation == 'recover' else uninstall
        action(options, api, host, record, pending if receipt == pending else None)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, AssertionError) as exc:
        detail = (exc.stderr or '').strip() if isinstance(exc, subprocess.CalledProcessError) else ''
        raise SystemExit(f'FlowGate: {detail or exc}')
