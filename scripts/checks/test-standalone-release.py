"""Focused package and lifecycle checks. No sudo, systemd or host networking."""
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import runpy
import stat
import subprocess
import sys
import tarfile
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
LIFECYCLE = ROOT / 'deployment/standalone'
release = runpy.run_path(str(LIFECYCLE / 'release.py'))
scope = release['unpack'].__globals__
ui = runpy.run_path(str(LIFECYCLE / 'flowgate-ui'))


class ReleaseChecks(unittest.TestCase):
    def setUp(self):
        (ROOT / 'build').mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / 'build')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def admin_layout(self):
        # Use real directory/symlink modes and targets, simulating root ownership.
        local = self.root / 'local'
        local.mkdir()
        (local / 'bin').mkdir()
        lstat = Path.lstat

        def owned(path):
            status = lstat(path)
            return types.SimpleNamespace(st_mode=status.st_mode, st_uid=0)

        paths = patch.dict(scope, LOCAL=local)
        owners = patch.object(Path, 'lstat', owned)
        for fixture in (paths, owners):
            fixture.start()
            self.addCleanup(fixture.stop)
        return local

    def assert_admin_destinations(self, directory):
        operations = {'TOOLS': {}}
        with patch.dict(scope, secure_file=lambda path: path), patch('runpy.run_path', return_value=operations):
            module = release['module'](self.root / 'verified-bootstrap')
        paths = module['TOOLS']
        for source, command in release['ADMIN_FILES'].items():
            self.assertEqual(paths[source], str(directory / command))
        for name in set(release['FILES']) - set(release['ADMIN_FILES']):
            self.assertEqual(paths[name], release['FILES'][name])

    def test_real_local_sbin(self):
        local = self.admin_layout()
        (local / 'sbin').mkdir()
        self.assert_admin_destinations(local / 'sbin')

    def test_local_sbin_alias_to_bin(self):
        local = self.admin_layout()
        sbin = local / 'sbin'
        for target in ('bin', str(local / 'bin')):
            with self.subTest(target=target):
                sbin.symlink_to(target)
                self.assert_admin_destinations(local / 'bin')
                self.assertEqual(os.readlink(sbin), target)
                sbin.unlink()

    def test_refuses_unexpected_local_sbin_alias(self):
        local = self.admin_layout()
        (local / 'other').mkdir()
        (local / 'sbin').symlink_to('other')
        with self.assertRaisesRegex(RuntimeError, 'Unexpected administrative directory alias'):
            release['installation_files']()

    def test_refuses_writable_admin_destination_or_parent(self):
        local = self.admin_layout()
        (local / 'sbin').symlink_to('bin')
        for directory in (local / 'bin', local):
            with self.subTest(directory=directory):
                directory.chmod(0o775)
                with self.assertRaisesRegex(RuntimeError, 'Unsafe managed directory'):
                    release['installation_files']()
                directory.chmod(0o755)

    def test_runuser_resolves_system_sbin_and_ignores_path(self):
        sbin = self.root / 'sbin'
        bin_dir = self.root / 'bin'
        local = self.root / 'local'
        for directory in (sbin, bin_dir, local):
            directory.mkdir()
        (local / 'runuser').touch(mode=0o755)
        (bin_dir / 'runuser').symlink_to(local / 'runuser')
        trust = Mock(return_value=types.SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o755))
        with patch.dict(scope, RUNUSER_DIRS=(sbin, bin_dir), secure_file=Mock()), \
                patch.dict(os.environ, PATH=str(local)), patch.object(Path, 'lstat', trust):
            with self.assertRaisesRegex(RuntimeError, 'trusted system directory'):
                release['system_runuser']()
            installed = sbin / 'runuser'
            installed.touch(mode=0o755)
            self.assertEqual(release['system_runuser'](), str(installed))

    def test_missing_runuser_stops_preflight_and_install_before_lock(self):
        locked = Mock()
        privileged_os = Mock(wraps=os)
        privileged_os.X_OK = os.X_OK
        privileged_os.geteuid.return_value = 0
        privileged_os.sys = types.SimpleNamespace(version_info=sys.version_info,
                                                   flags=types.SimpleNamespace(isolated=1))
        for operation in ('preflight', 'install'):
            with self.subTest(operation=operation), \
                    patch.dict(scope, RUNUSER_DIRS=(), locked=locked, os=privileged_os), \
                    patch('sys.argv', ['flowgate-release.py', operation, '--bundle', 'unused', '--sha256', '0' * 64]):
                with self.assertRaisesRegex(RuntimeError, 'requires an executable runuser'):
                    release['main']()
                locked.assert_not_called()

    def test_legacy_collector_requires_exact_failure_and_verified_noexec_pin(self):
        pinned = self.root / '.flowgate-udp-123'
        pinned.write_bytes(b'packaged helper')
        pinned.chmod(0o700)
        manifest = {'source': '13e3029ac2e4d2695b851cfb09710d9ab4bb8bf7',
                    'files': {'udp-collector': hashlib.sha256(pinned.read_bytes()).hexdigest()}}
        status = {'state': 'failed', 'available': True, 'reason_code': 'permission_required',
                  'generation': 'legacy-collector', 'reason': f'fork/exec {pinned}: permission denied'}
        target = release['collector_target']
        with patch.dict(scope, API_DIR=self.root, secure_file=lambda path: path,
                        check_directory=Mock()), patch('os.statvfs') as mount:
            mount.return_value.f_flag = os.ST_NOEXEC
            self.assertEqual(target({'traffic_monitor': status}, manifest), 'active')
            for changed_status, changed_manifest in (
                (dict(status, state='disabled'), manifest),
                (dict(status, state='starting'), manifest),
                (dict(status, generation=''), manifest),
                (dict(status, reason='BPF attach: permission denied'), manifest),
                (dict(status, reason=f'fork/exec {pinned}.elsewhere: permission denied'), manifest),
                (status, dict(manifest, source='different-build')),
            ):
                with self.subTest(status=changed_status, source=changed_manifest['source']):
                    with self.assertRaisesRegex(RuntimeError, 'Current collector is not settled'):
                        target({'traffic_monitor': changed_status}, changed_manifest)
            mount.return_value.f_flag = 0
            with self.assertRaisesRegex(RuntimeError, 'Current collector is not settled'):
                target({'traffic_monitor': status}, manifest)
            mount.return_value.f_flag = os.ST_NOEXEC
            pinned.write_bytes(b'different helper')
            with self.assertRaisesRegex(RuntimeError, 'Current collector is not settled'):
                target({'traffic_monitor': status}, manifest)

    def test_electron_profile_lifecycle_preserves_unmanaged_content(self):
        profile = self.root / 'flowgate-standalone-electron'
        foreign = self.root / 'foreign-profile'
        userns = self.root / 'restrict-userns'
        enabled = self.root / 'enabled'
        loaded = self.root / 'profiles'
        userns.write_text('0\n')
        enabled.write_text('Y\n')
        loaded.write_text('flowgate-standalone-electron (unconfined)\nforeign-profile (enforce)\n')
        foreign.write_text('independent policy')
        parser = '/usr/sbin/apparmor_parser'
        def write(path, content, mode):
            path.write_bytes(content)
            path.chmod(mode)
        with patch.dict(scope, APPARMOR_PROFILE=profile, APPARMOR_USERNS=userns,
                        APPARMOR_ENABLED=enabled, APPARMOR_LOADED=loaded, secure_file=lambda p: p,
                        secure_directory=Mock(), fsync_dir=Mock(), atomic=write,
                        system_executable=Mock(return_value=parser)), patch('subprocess.run') as run:
            self.assertIsNone(release['electron_profile_parser']())
            release['install_electron_profile'](None)
            self.assertFalse(profile.exists())
            userns.write_text('1\n')
            self.assertEqual(release['electron_profile_parser'](), parser)
            scope['system_executable'].assert_called_once_with('apparmor_parser')
            release['install_electron_profile'](parser)
            run.assert_called_once_with([parser, '-r', '-T', str(profile)], check=True, timeout=15)
            self.assertEqual(profile.read_bytes(), release['ELECTRON_PROFILE'])
            profile.write_text('edited policy')
            run.reset_mock()
            for action in (lambda: release['install_electron_profile'](parser), release['remove_electron_profile']):
                with self.assertRaisesRegex(RuntimeError, 'Edited or unmanaged AppArmor profile preserved'):
                    action()
            run.assert_not_called()
            self.assertEqual(profile.read_text(), 'edited policy')
            profile.write_bytes(release['ELECTRON_PROFILE'])
            release['remove_electron_profile']()
            run.assert_called_once_with([parser, '-R', str(profile)], check=True, timeout=15)
        self.assertFalse(profile.exists())
        self.assertEqual(foreign.read_text(), 'independent policy')
        self.assertEqual(userns.read_text(), '1\n')

    def archive(self, extra=None, *, schema=1, desktop_version=None):
        backend = {name: b'backend\n' for name in {*release['FILES'], *release['UNITS'],
                                                    'launch', 'flowgate', 'standalone-release.json'}}
        source = 'a' * 40
        version = '0.1.0-rc.1' if schema == 1 else '0.1.0-rc.1.dev-aaaaaaaaaaaa'
        name = release['release_id'](version, source)
        identity = {'release': name, 'source': source, 'version': version}
        if schema == 2:
            backend['standalone-release.json'] = json.dumps(identity).encode()
        sha = lambda data: hashlib.sha256(data).hexdigest()
        payload = {f'backend/{key}': value for key, value in backend.items()}
        payload['backend/manifest.json'] = json.dumps({
            'release': name, 'source': source,
            **({'version': version} if schema == 2 else {}),
            'files': {key: sha(value) for key, value in backend.items()},
        }).encode()
        payload['gui/runtime/electron'] = b'Electron'
        if schema == 2:
            payload['gui/matched-manifest.json'] = json.dumps(identity).encode()
            payload['gui/electron/package.json'] = json.dumps({'version': desktop_version or version}).encode()
        manifest = {
            **identity, 'schema': schema, 'platform': 'linux-' + platform.machine(),
            'files': {name: {'mode': 0o755, 'sha256': sha(data)} for name, data in payload.items()},
        }
        archive = self.root / 'bundle.tar.gz'
        with tarfile.open(archive, 'w:gz') as stream:
            for name, data in {'release.json': json.dumps(manifest).encode(), **payload}.items():
                member = tarfile.TarInfo(name)
                member.size = len(data)
                stream.addfile(member, io.BytesIO(data))
            if extra:
                stream.addfile(extra)
        return archive, sha(archive.read_bytes())

    def unpack(self, archive, digest):
        with patch.dict(scope, secure_file=lambda p: p):
            return release['unpack'](archive, digest, self.root)

    def test_verified_archive_produces_matching_payload(self):
        archive, digest = self.archive()
        path, manifest, backend = self.unpack(archive, digest)
        self.assertEqual(manifest['release'], backend['release'])
        self.assertEqual((path / 'gui/runtime/electron').read_bytes(), b'Electron')

    def test_versioned_archive_requires_a_single_identity(self):
        archive, digest = self.archive(schema=2)
        _, manifest, backend = self.unpack(archive, digest)
        self.assertEqual(manifest['version'], manifest['release'])
        self.assertEqual(manifest['version'], backend['version'])

    def test_versioned_archive_refuses_a_conflicting_desktop_version(self):
        archive, digest = self.archive(schema=2, desktop_version='0.1.0-rc.7')
        with self.assertRaisesRegex(RuntimeError, 'Electron package version differs'):
            self.unpack(archive, digest)

    def test_release_hashes_use_file_bytes_independent_of_filename(self):
        payload = self.root / '-archive\\name\nwith spaces'
        payload.write_bytes(b'\x00flowgate\xff\n')
        expected = hashlib.sha256(payload.read_bytes()).hexdigest()
        package = runpy.run_path(str(LIFECYCLE / 'package.py'))
        self.assertEqual(package['digest'](payload), expected)
        self.assertEqual(release['digest'](payload), expected)

    def test_refuses_wrong_digest_before_extracting(self):
        archive, _ = self.archive()
        with self.assertRaisesRegex(RuntimeError, 'SHA256'):
            self.unpack(archive, '0' * 64)
        self.assertFalse((self.root / 'payload').exists())

    def test_refuses_archive_path_escape(self):
        archive, digest = self.archive(tarfile.TarInfo('gui/../../escape'))
        with self.assertRaisesRegex(RuntimeError, 'Invalid package path'):
            self.unpack(archive, digest)

    def test_refuses_unlisted_symlink(self):
        link = tarfile.TarInfo('gui/escape')
        link.type = tarfile.SYMTYPE
        link.linkname = '/etc'
        archive, digest = self.archive(link)
        with self.assertRaisesRegex(RuntimeError, 'Unexpected package member'):
            self.unpack(archive, digest)

    def reload_environment(self):
        base = self.root / 'installed'
        release_dir = base / 'releases' / 'new'
        release_dir.mkdir(parents=True)
        (base / 'current').symlink_to(release_dir)
        env = {
            'WAYLAND_DISPLAY': 'wayland-fixture',
            'XDG_RUNTIME_DIR': str(self.root / 'session'),
            'XDG_CONFIG_HOME': str(self.root / 'config'),
            'XDG_CACHE_HOME': str(self.root / 'cache'),
        }
        Path(env['XDG_RUNTIME_DIR']).mkdir()
        return base, env

    def resolve_reload_directories(self, env, *, leave_real=None):
        # Model installed paths separately from the physical test checkout.
        # Keep the real release pointer and any directory under negative test.
        paths = {
            Path(env[key]): Path('/run/flowgate-test') / name
            for key, name in (
                ('XDG_RUNTIME_DIR', 'session'),
                ('XDG_CONFIG_HOME', 'config'),
                ('XDG_CACHE_HOME', 'cache'),
            )
            if key != leave_real
        }
        resolve = Path.resolve

        def installed_path(path, *args, **kwargs):
            return paths[path] if path in paths else resolve(path, *args, **kwargs)

        return patch.object(Path, 'resolve', installed_path)

    def test_reload_starts_current_installed_gui_when_closed(self):
        base, env = self.reload_environment()
        scope = ui['launch'].__globals__
        with patch.dict(os.environ, env, clear=True), self.resolve_reload_directories(env), \
                patch.dict(scope, BASE=base, stop_installed=Mock()), \
                patch('subprocess.run', return_value=types.SimpleNamespace(returncode=1)), \
                patch('subprocess.Popen') as start:
            start.return_value.wait.side_effect = subprocess.TimeoutExpired('electron', 1)
            ui['launch'](reload=True)
            scope['stop_installed'].assert_called_once()
        args, kwargs = start.call_args
        self.assertEqual(args[0][0], str(base / 'gui/new/runtime/electron'))
        self.assertTrue(kwargs['start_new_session'])

    def test_reload_reports_gui_startup_failure(self):
        base, env = self.reload_environment()
        scope = ui['launch'].__globals__
        with patch.dict(os.environ, env, clear=True), self.resolve_reload_directories(env), \
                patch.dict(scope, BASE=base, stop_installed=Mock()), \
                patch('subprocess.run', return_value=types.SimpleNamespace(returncode=1)), \
                patch('subprocess.Popen') as start:
            start.return_value.wait.return_value = 1
            with self.assertRaisesRegex(RuntimeError, r'status 1\).*Run flowgate-ui directly'):
                ui['launch'](reload=True)

    def test_reload_rejects_directories_resolving_under_workspace(self):
        base, env = self.reload_environment()
        scope = ui['launch'].__globals__
        inside = self.root / '.workspace/session'
        inside.mkdir(parents=True)
        alias = self.root / 'desktop-alias'
        alias.symlink_to(inside, target_is_directory=True)
        for key in ('XDG_RUNTIME_DIR', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME'):
            with self.subTest(directory=key):
                invalid = dict(env, **{key: str(alias)})
                stop = Mock()
                with patch.dict(os.environ, invalid, clear=True), \
                        self.resolve_reload_directories(invalid, leave_real=key), \
                        patch.dict(scope, BASE=base, stop_installed=stop), \
                        patch('subprocess.Popen') as start:
                    with self.assertRaisesRegex(RuntimeError, 'must be outside \\.workspace'):
                        ui['launch'](reload=True)
                    stop.assert_not_called()
                    start.assert_not_called()

    def test_reload_headless_does_not_stop_gui(self):
        with patch.dict(os.environ, {}, clear=True), \
                patch.dict(ui['launch'].__globals__, stop_installed=Mock()) as launcher, \
                patch('builtins.print'):
            ui['launch'](reload=True)
            launcher['stop_installed'].assert_not_called()

    def test_desktop_migration_preserves_opt_out_and_import(self):
        entry = self.root / 'autostart/flowgate.desktop'
        entry.parent.mkdir()
        old = (
            '[Desktop Entry]\nX-FlowGate-Managed=true\nHidden=true\n'
            f'Exec="/home/test/.workspace/automatic-zone-releases/{"a"*40}/launch-ui" '
            '--observer /run/flowgate-api/daemon.sock.monitor --control /run/flowgate-api/daemon.sock\n'
        )
        entry.write_text(old)
        preferences = self.root / 'preferences.json'
        preferences.write_text('{"width": 1600}')
        options = types.SimpleNamespace(remove_autostart=False, check_autostart=False,
                                        restore_autostart=False, enable_autostart=False,
                                        import_preferences=preferences)
        ui['configure_login'](options, self.root)
        self.assertIn('Exec=/usr/local/bin/flowgate-ui\n', entry.read_text())
        self.assertIn('Hidden=true\n', entry.read_text())
        self.assertEqual((self.root / 'flowgate/electron-preferences.json').read_bytes(),
                         preferences.read_bytes())
        options.restore_autostart = True
        ui['configure_login'](options, self.root)
        self.assertEqual(entry.read_text(), old)

    def test_foreign_login_entry_is_preserved(self):
        entry = self.root / 'flowgate.desktop'
        data = 'Exec=/usr/bin/different-app\nX-FlowGate-Managed=true\n'
        entry.write_text(data)
        with self.assertRaisesRegex(RuntimeError, 'not managed'):
            ui['managed_login'](entry)
        self.assertEqual(entry.read_text(), data)

    def test_cleanup_uses_independent_rescue_and_requires_verified_tables(self):
        host = Mock()
        pin = 'a' * 64
        record = {'release': 'candidate', 'rescue': {'flowgate': pin},
                  'files': {name: pin for name in release['UNITS']}}
        ops = {'flowgate_tables': Mock(return_value=['flowgate_guard'])}
        host.daemon_pids.return_value = []
        with patch.dict(scope, BASE=self.root, DATA=self.root, secure_file=lambda p: p,
                        digest=lambda p: pin, atomic=Mock(), owned_journal=lambda: False):
            with self.assertRaisesRegex(RuntimeError, 'Interception remains'):
                release['cleanup'](ops, host, record)
        self.assertTrue(str(host.run.call_args.args[0]).endswith('/rescue/candidate/flowgate'))

    def test_cleanup_refuses_shaping_conflict_before_service_changes(self):
        host = Mock()
        with patch.dict(scope, owned_journal=lambda: True):
            with self.assertRaisesRegex(RuntimeError, 'shaping ownership journal'):
                release['cleanup']({}, host, {})
        host.run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
