"""Focused package and lifecycle checks. No sudo, systemd or host networking."""
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import runpy
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
        (ROOT / '.workspace').mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / '.workspace')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def archive(self, extra=None):
        backend = {name: b'backend\n' for name in {*release['FILES'], *release['UNITS'],
                                                    'launch', 'flowgate', 'standalone-release.json'}}
        source = 'a' * 40
        name = '0.1.0-rc.1-aaaaaaaaaaaa'
        sha = lambda data: hashlib.sha256(data).hexdigest()
        payload = {f'backend/{key}': value for key, value in backend.items()}
        payload['backend/manifest.json'] = json.dumps({
            'release': name, 'source': source,
            'files': {key: sha(value) for key, value in backend.items()},
        }).encode()
        payload['gui/runtime/electron'] = b'Electron'
        manifest = {
            'schema': 1, 'platform': 'linux-' + platform.machine(), 'version': '0.1.0-rc.1',
            'release': name, 'source': source,
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

    def test_reload_switches_to_current_installed_gui(self):
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
        # Production refuses workspace-backed session paths. The mock keeps
        # all test directories private while preserving that check separately.
        scope = ui['launch'].__globals__
        with patch.dict(os.environ, env, clear=True), patch.dict(scope, BASE=base, stop_installed=Mock()), \
                patch.object(Path, 'resolve', autospec=True,
                             side_effect=lambda path, **_: release_dir if path.name == 'current' else Path('/fixture') / path.name), \
                patch('subprocess.run', return_value=types.SimpleNamespace(returncode=1)), \
                patch('subprocess.Popen') as start:
            start.side_effect = lambda *args, **kwargs: scope['stop_installed'].assert_called_once()
            ui['launch'](reload=True)
        args, kwargs = start.call_args
        self.assertEqual(args[0][0], str(base / 'gui/new/runtime/electron'))
        self.assertTrue(kwargs['start_new_session'])

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
