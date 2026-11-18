#!/usr/bin/python3
"""Install, recover or remove a verified standalone FlowGate release."""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import pwd
import re
import runpy
import shutil
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
FILES = {
    'control.py': '/usr/local/sbin/flowgate-control',
    'recover.py': '/usr/local/sbin/flowgate-recover',
    'uninstall.py': '/usr/local/sbin/flowgate-uninstall',
    'release.py': str(TOOLS / 'release.py'),
    'install-monitoring.py': str(TOOLS / 'install-monitoring.py'),
    'flowgate-ui': '/usr/local/bin/flowgate-ui',
    'flowgate.desktop': '/usr/local/share/applications/flowgate.desktop',
    'flowgate.png': '/usr/local/share/icons/hicolor/256x256/apps/flowgate.png',
}
RELEASE_ID = re.compile(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9]+(?:\.[A-Za-z0-9]+)*)?-[a-f0-9]{12}')
HEX = re.compile(r'[a-f0-9]{64}')
MONITORING = b'{"schema":1,"mode":"monitoring"}'


def digest(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def secure_file(path):
    mode = path.lstat()
    if not stat.S_ISREG(mode.st_mode) or mode.st_uid != 0 or mode.st_mode & 0o022:
        raise RuntimeError(f'Unsafe managed file: {path}')
    return path


def secure_directory(path):
    for parent in reversed([path, *path.parents]):
        parent.mkdir(exist_ok=True, mode=0o755)
        status = parent.lstat()
        if not stat.S_ISDIR(status.st_mode) or status.st_uid != 0 or status.st_mode & 0o022:
            raise RuntimeError(f'Unsafe managed directory: {parent}')
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
    api['TOOLS'].update(FILES)
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
    return (response.get('protection') or {}).get('desired_mode') == selected and (
        response.get('protection') or {}
    ).get('state') == ('stopped' if selected == 'monitoring' else 'active') and (
        selected != 'monitoring' or not api['flowgate_tables'](host)
    )


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


def preflight(api, payload, backend, desktop_config):
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
    daemon = payload / 'backend/flowgate'
    build = json.loads(host.run(str(daemon), 'version'))
    if build.get('source') != backend['source'] or build.get('max_rule_schema') != backend['max_rule_schema']:
        raise RuntimeError('Candidate executable has an incompatible build declaration')
    response = None
    selected = 'monitoring'
    extra_config = {}
    collector = None
    if old:
        _, response = host.api()
        selected = response['protection']['desired_mode']
        if selected not in ('monitoring', 'incoming', 'both') or not check_mode(api, host, response, selected):
            raise RuntimeError('Current protection is not settled')
        live = response['build']
        if live.get('source') != old[1]['source'] or live.get('executable_sha256') != old[1]['files']['flowgate'] or live.get('modified') is not False:
            raise RuntimeError('Running backend does not match the current release')
        _, shape = host.api('upload-status', generation=response['generation'])
        shape = shape.get('upload_shaping') or {}
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
    for path in (SHAPING, Path(api['DROPIN']), *(Path(x) for x in FILES.values()),
                 *(Path('/etc/systemd/system') / name for name in UNITS)):
        if not existing(path):
            continue
        secure_file(path)
        if path == SHAPING:
            continue
        reverse = {Path(dest): name for name, dest in FILES.items()}
        name = reverse.get(path, '50-flowgate-guard.conf' if path == Path(api['DROPIN']) else path.name)
        approved = {(payload / 'backend' / name).read_bytes()}
        if old and name in old[1]['files']:
            approved.add((old[0] / name).read_bytes())
        if path.read_bytes() not in approved:
            raise RuntimeError(f'Existing path has unmanaged bytes: {path}')
    return host, old, response, selected, collector, extra_config, uid, desktop_config


def desktop(user, config, program, action, preferences=None):
    account = pwd.getpwuid(user)
    command = ['/usr/bin/runuser', '-u', account.pw_name, '--', '/usr/bin/env', '-i',
               'HOME=' + account.pw_dir, 'XDG_CONFIG_HOME=' + config, str(program), action]
    if preferences is not None:
        command.extend(['--import-preferences', str(preferences)])
    subprocess.run(command, check=True, timeout=10)


def immutable_tree(source, target, expected):
    secure_directory(target.parent)
    if not existing(target):
        with tempfile.TemporaryDirectory(dir=target.parent) as folder:
            stage = Path(folder) / 'tree'
            shutil.copytree(source, stage)
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
    host, old, before, selected, collector, config, uid, xdg = preflight(
        api, payload, backend, options.desktop_config,
    )
    if options.operation == 'preflight':
        print(f"Preflight passed for {manifest['release']}. Current protection: {selected}.")
        return
    if (DATA / 'standalone-pending.json').exists():
        raise RuntimeError('An interrupted update requires local recovery')
    if old is not None and old[0].name == manifest['release']:
        raise RuntimeError('This exact release is already installed')
    release = manifest['release']
    gui_files = {name[4:]: entry for name, entry in manifest['files'].items() if name.startswith('gui/')}
    gui_payload = BASE / 'gui' / release
    immutable_tree(payload / 'gui', gui_payload, gui_files)
    desktop(uid, xdg, gui_payload / 'flowgate-ui', '--check-autostart', options.import_preferences)

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
    DATA.mkdir(mode=0o700, exist_ok=True)
    if DATA.stat().st_uid != 0 or DATA.stat().st_mode & 0o077:
        raise RuntimeError('FlowGate state directory is not private')
    pending = DATA / 'standalone-pending.json'
    write_record(pending, record)
    # Keep a fixed rescue entry point even during the first install or a power loss.
    atomic(TOOLS / 'rescue', b'#!/bin/sh\nexec /usr/bin/python3 -I /usr/local/libexec/flowgate/rescue-release.py recover "$@"\n', 0o755)
    atomic(TOOLS / 'rescue-release.py', (rescue / 'release.py').read_bytes(), 0o755)

    if selected != 'monitoring':
        _, fresh = host.api()
        if (fresh['generation'], fresh['protection'], api['api_inventory'](fresh)) != (
            before['generation'], before['protection'], api['api_inventory'](before)
        ) or owned_journal():
            pending.unlink()
            raise RuntimeError('Host state changed after preflight')
        host.api('protection-stop', generation=before['generation'], protection_id=before['protection']['id'])
        wait_for(host, before['generation'], lambda v: check_mode(api, host, v, 'monitoring'))

    def verify_extra(response):
        if collector in ('active', 'stopped'):
            observed = response.get('traffic_monitor') or {}
            if observed.get('state') != collector:
                host.api('traffic-start' if collector == 'active' else 'traffic-stop',
                         generation=response['generation'], collector_generation=observed.get('generation', ''))
                wait_for(host, response['generation'],
                         lambda v: (v.get('traffic_monitor') or {}).get('state') == collector)
        if owned_journal():
            raise RuntimeError('Shaping journal appeared during install')

    try:
        api['install_locked'](host, payload / 'backend', stamp, extra_config=config,
                              verify_extra=verify_extra, standalone=True)
    except api['RollbackComplete']:
        pending.unlink()
        fsync_dir(DATA)
        raise RuntimeError('Previous release and database restored in monitoring') from None
    write_record(DATA / 'release-receipts' / (release + '.json'), record)
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
    allowed.update(Path(path) for path in FILES.values())
    allowed.update(Path('/etc/systemd/system') / name for name in UNITS)
    for name, item in snapshot.items():
        if Path(name) not in allowed or item is not None and not re.fullmatch(r'rollback-[0-9]+', item['file']):
            raise RuntimeError('Unsafe rollback inventory')
        if item is not None:
            secure_file(backup / item['file'])
    api['rollback'](host, backup, DATA, BASE, (old, manifest), snapshot, install_record['unit_enabled'])
    print(f'Restored {old.name} and its saved database in monitoring.')


def recover(options, api, host, record, pending):
    cleanup(api, host, record)
    if options.stop_only:
        print('FlowGate stopped; monitoring intent saved and no managed interception remains.')
        return
    if options.rollback or pending and record.get('previous'):
        # Preserve the previous desktop login when reverting the first migration.
        # A standalone predecessor still uses the same stable launcher.
        launcher = Path(FILES['flowgate-ui'])
        if existing(launcher) and record.get('previous') and not (
            BASE / 'gui' / record['previous']
        ).is_dir():
            desktop(record['uid'], record['desktop_config'], launcher, '--restore-autostart')
        restore_previous(api, host, record)
        if pending:
            pending.unlink()
        else:
            receipt = DATA / 'release-receipts' / (record['previous'] + '.json')
            if receipt.exists():
                write_record(DATA / 'standalone.json', read_record(receipt))
            else:
                (DATA / 'standalone.json').unlink()
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
    host.run('systemctl', 'reset-failed', *UNITS)
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
    files = {Path(dst): record['files'][name] for name, dst in FILES.items()}
    files.update({Path('/etc/systemd/system') / name: record['files'][name] for name in UNITS})
    for path, expected in files.items():
        if existing(path) and digest(secure_file(path)) != expected:
            raise RuntimeError(f'Edited managed file preserved: {path}')
    if existing(Path(api['DROPIN'])):
        raise RuntimeError('Legacy NetworkManager drop-in present; inspect before removal')
    gui = BASE / 'gui' / record['release']
    if existing(gui):
        immutable_tree(gui, gui, record['gui'])
    release = BASE / 'releases' / record['release']
    if existing(release):
        api['previous_release_for_path'](host, BASE, release)
        if {p.name for p in release.iterdir()} != {*record['files'], 'manifest.json'}:
            raise RuntimeError('Additional release files require ownership inspection')
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
    for name in UNITS:
        (Path('/etc/systemd/system') / name).unlink(missing_ok=True)
    host.run('systemctl', 'daemon-reload')
    for path in files:
        path.unlink(missing_ok=True)
    link = BASE / 'current'
    if link.is_symlink() and link.resolve() == release:
        link.unlink()
    for root in (gui, release):
        if root.is_dir():
            shutil.rmtree(root)
    if options.purge:
        for root in (ETC, DATA):
            if root.is_symlink() or not root.is_dir() or root.stat().st_uid != 0:
                raise RuntimeError(f'Unsafe purge directory: {root}')
            shutil.rmtree(root)
    else:
        (DATA / 'standalone.json').unlink(missing_ok=True)
    print('FlowGate services and managed active release removed. Previous releases and user preferences retained.')


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
    if os.geteuid() != 0 or not __debug__ or not os.sys.flags.isolated:
        parser.error('Run as root using /usr/bin/python3 -I')
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
