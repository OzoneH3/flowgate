"""Simulate user edits during standalone staging and immediately before quiesce."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import runpy
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
release = runpy.run_path(str(ROOT / 'deployment/standalone/release.py'))
scope = release['install'].__globals__
OLD = '0.1.0-aaaaaaaaaaaa'
NEW = '0.1.0-bbbbbbbbbbbb'



class StateFreshness(unittest.TestCase):
    def setUp(self):
        (ROOT / '.workspace').mkdir(exist_ok=True)
        temp = tempfile.TemporaryDirectory(dir=ROOT / '.workspace')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.payload = self.root / 'payload'
        (self.payload / 'backend').mkdir(parents=True)
        for name in ('flowgate', 'release.py', 'install-monitoring.py'):
            (self.payload / 'backend' / name).write_text(name)
        self.before = {
            'generation': 'legacy',
            'build': {'source': 'a' * 40, 'executable_sha256': 'a' * 64, 'modified': False},
            'rules': [{'id': 'rule', 'version': 1}],
            'protection': {'id': 'active-id', 'state': 'active', 'desired_mode': 'both'},
            'traffic_monitor': {'state': 'active', 'generation': 'collector-1'},
            'network_zones': {'model': 'automatic-peer-v1', 'local_prefixes': ['10.0.0.0/8']},
        }
        self.state = deepcopy(self.before)
        self.shape = {'status': 'Disabled', 'enabled': False}
        self.checks = {'enabled': True, 'revision': '1'}
        self.operations = []
        self.host = Mock()
        self.host.api.side_effect = self.request
        self.host_installer = Mock(side_effect=self.install_backend)
        self.api = {
            'api_inventory': lambda response: sorted(
                (rule['id'], rule['version']) for rule in response['rules']
            ),
            'install_locked': self.host_installer,
            'RollbackComplete': type('RollbackComplete', (RuntimeError,), {}),
            'DROPIN': str(self.root / 'dropin.conf'),
        }
        self.change = lambda: None
        self.change_before_quiesce = lambda: None
        self.base = self.root / 'lib'
        self.data = self.root / 'data'
        self.etc = self.root / 'etc'
        self.pending = self.data / 'standalone-pending.json'
        self.old = self.base / 'releases' / OLD
        self.old.mkdir(parents=True)
        (self.base / 'current').symlink_to(self.old)
        self.data.mkdir(mode=0o700)
        self.old_manifest = {'source': 'a' * 40,
                             'files': {name: 'a' * 64 for name in ('flowgate', *release['UNITS'])}}
        self.running = True
        self.host.daemon_pids.side_effect = lambda: [40] if self.running else []
        self.api.update(previous_release_for_path=Mock(return_value=self.old_manifest),
                        wait_api=lambda host: (40, deepcopy(self.state)),
                        restart_unchanged=self.restart_unchanged,
                        reset_failed_units=Mock(), wait_monitoring=self.wait_monitoring,
                        rule_inventory=Mock(return_value=[('rule', 1)]),
                        rollback=self.rollback)
        self.cleaned = Mock(side_effect=self.cleanup)

        def directory(path):
            path.mkdir(exist_ok=True, parents=True)
            return path

        def receipt(path, value):
            directory(path.parent)
            path.write_text(json.dumps(value))

        def atomic(path, data, mode):
            directory(path.parent)
            path.write_bytes(data)

        patcher = patch.dict(scope,
            BASE=self.base, DATA=self.data, ETC=self.etc, SHAPING=self.etc / 'shaping.json',
            TOOLS=self.root / 'tools', cleanup=self.cleaned,
            FILES={'flowgate-ui': str(self.root / 'bin/flowgate-ui')},
            module=lambda path: self.api, preflight=self.preflight,
            secure_directory=directory, digest=lambda path: 'a' * 64,
            secure_file=lambda path: path, read_record=lambda path: json.loads(path.read_text()),
            desktop=Mock(), immutable_tree=lambda *args: self.change(),
            atomic=atomic, write_record=receipt, fsync_dir=Mock(),
            owned_journal=lambda: False,
            check_mode=lambda api, host, state, selected: state['protection']['desired_mode'] == selected,
        )
        patcher.start()
        self.api['TOOLS'] = scope['FILES']
        self.host.run.side_effect = self.run_host
        receipt(self.data / 'standalone.json', {'release': OLD})
        self.addCleanup(patcher.stop)
        stat = Path.stat

        def stat_with_privileged_state(path, *args, **kwargs):
            value = stat(path, *args, **kwargs)
            if path == self.data:
                return SimpleNamespace(st_uid=0, st_mode=value.st_mode)
            return value

        owner = patch.object(Path, 'stat', stat_with_privileged_state)
        owner.start()
        self.addCleanup(owner.stop)

    def request(self, operation='list', **fields):
        self.operations.append(operation)
        if operation == 'upload-status':
            return 1, {'upload_shaping': deepcopy(self.shape)}
        if operation == 'connection-check-status':
            return 1, {'connection_checks': deepcopy(self.checks)}
        if operation == 'protection-stop':
            # The real predecessor accepts repeated Stop with the same ID.
            self.assertEqual(fields['protection_id'], self.state['protection']['id'])
            self.state['protection'].update(state='stopped', desired_mode='monitoring')
            self.save_intent('monitoring')
        if operation == 'protection-start':
            self.assertEqual(fields['protection_id'], self.state['protection']['id'])
            self.assertTrue(self.pending.exists())
            self.state['protection'] = {'id': 'restored-id', 'state': 'active',
                                        'desired_mode': fields['profile'], 'request_id': fields['request_id']}
            self.save_intent(fields['profile'])
        if operation == 'traffic-start':
            self.state['traffic_monitor'] = {'state': 'active', 'generation': 'restarted'}
        return 1, deepcopy(self.state)

    def preflight(self, *_):
        collector = self.before['traffic_monitor']['state']
        data = (self.host, (self.old, self.old_manifest), deepcopy(self.before),
                self.before['protection']['desired_mode'], collector, {}, 1000, '/home/test/.config')
        if 'verify_before_switch' in scope:
            return (*data, release['saved_settings'](self.host, self.before))
        return data

    def install_backend(self, host, path, stamp, *, verify_extra, before_quiesce=None, snapshot_ready, **kwargs):
        self.change_before_quiesce()
        if before_quiesce:
            before_quiesce()
        self.operations.append('systemctl-stop')
        snapshot_ready()
        self.state['generation'] = 'new-release'
        verify_extra(deepcopy(self.state))

    def install(self):
        release['install'](
            SimpleNamespace(operation='install', desktop_config=None, import_preferences=None),
            self.payload, {'release': NEW, 'files': {}}, {'files': {}},
        )

    def save_intent(self, mode):
        src = self.data / 'next-intent'
        src.write_text(json.dumps({'mode': mode}))
        src.replace(self.data / 'protection.json')

    def cleanup(self, *args):
        self.operations.append('cleanup')
        self.running = False
        self.state['protection'].update(state='stopped', desired_mode='monitoring')

    def run_host(self, *args):
        self.operations.append(args)
        if args == ('systemctl', 'start', 'flowgate.service'):
            self.running = True

    def wait_monitoring(self, host, manifest, rules):
        self.assertTrue(self.running)
        self.assertEqual(manifest, self.old_manifest)
        self.assertEqual(rules, [('rule', 1)])
        self.assertEqual(self.state['protection']['desired_mode'], 'monitoring')
        return self.state

    def restart_unchanged(self, host, base, data, previous):
        self.assertFalse(self.running)
        self.assertEqual(previous, (self.old, self.old_manifest))
        self.operations.append('restart-unchanged')
        self.running = True
        return self.wait_monitoring(host, previous[1], [('rule', 1)])

    def rollback(self, host, backup, data, base, previous, snapshot, enabled):
        self.assertFalse(self.running)
        self.assertIn('cleanup', self.operations)
        self.operations.append('rollback')
        (self.base / 'current').unlink()
        (self.base / 'current').symlink_to(self.old)
        self.running = True
        self.wait_monitoring(host, previous[1], [('rule', 1)])

    def stopped_collector(self):
        self.state['traffic_monitor'] = {'state': 'stopped', 'generation': 'collector-2'}

    def assert_refused(self, reason, *, protection_stopped=False):
        try:
            self.install()
        except RuntimeError as exc:
            self.assertRegex(str(exc), reason)
        else:
            self.fail(f'Install accepted changed state. Operations: {self.operations}')
        self.assertEqual('protection-stop' in self.operations, protection_stopped)
        self.assertNotIn('systemctl-stop', self.operations)
        self.assertNotIn('traffic-start', self.operations)
        self.assertFalse((self.data / 'standalone-pending.json').exists())

    def test_collector_stop_during_staging_is_not_overwritten(self):
        self.change = self.stopped_collector
        self.assert_refused('collector changed')
        self.assertEqual(self.state['traffic_monitor']['state'], 'stopped')

    def test_shaping_configured_during_staging_refuses_before_stop(self):
        def enable_shaping():
            self.shape.update(status='Applying', enabled=True, upload_budget_bits_per_second=32_000_000)

        self.change = enable_shaping
        self.assert_refused('shaping changed')

    def test_recheck_edit_while_monitoring_refuses_before_service_stop(self):
        self.before['protection'] = {'id': 'already-stopped', 'state': 'stopped', 'desired_mode': 'monitoring'}
        self.state = deepcopy(self.before)
        self.change = lambda: self.checks.update(enabled=False, revision='2')
        self.assert_refused('connection_checks changed')

    def test_collector_stop_after_protection_stop_refuses_before_quiesce(self):
        self.change_before_quiesce = self.stopped_collector
        self.assert_refused('collector changed', protection_stopped=True)
        self.assertIn('protection-start', self.operations)
        self.assertEqual(self.state['protection']['desired_mode'], 'both')
        self.assertEqual(self.state['traffic_monitor']['state'], 'stopped')

    def test_deliberate_concurrent_stop_is_not_undone(self):
        def deliberate_stop():
            self.request('protection-stop', protection_id=self.state['protection']['id'])
        self.change_before_quiesce = deliberate_stop
        self.assert_refused('Protection intent changed', protection_stopped=True)
        self.assertEqual(self.operations.count('protection-stop'), 2)
        self.assertNotIn('protection-start', self.operations)
        self.assertEqual(self.state['protection']['desired_mode'], 'monitoring')

    def test_deliberate_stop_racing_restoration_wins(self):
        self.change_before_quiesce = self.stopped_collector

        def request(operation='list', **fields):
            if operation == 'protection-start':
                self.request('protection-stop', protection_id=fields['protection_id'])
            return self.request(operation, **fields)

        self.host.api.side_effect = request
        self.assert_refused('collector changed', protection_stopped=True)
        self.assertEqual(self.operations.count('protection-start'), 1)
        self.assertEqual(self.operations.count('protection-stop'), 3)
        self.assertEqual(self.state['protection']['desired_mode'], 'monitoring')

    def test_pending_is_kept_if_protection_restoration_cannot_be_verified(self):
        self.change_before_quiesce = self.stopped_collector

        def request(operation='list', **fields):
            if operation == 'protection-start':
                raise RuntimeError('restore unavailable')
            return self.request(operation, **fields)

        self.host.api.side_effect = request
        with self.assertRaisesRegex(RuntimeError, 'Protection outcome could not be verified'):
            self.install()
        self.assertEqual(json.loads(self.pending.read_text())['previous_mode'], 'both')
        self.assertNotIn('systemctl-stop', self.operations)

    def recover(self):
        pending = self.pending if self.pending.exists() else None
        receipt = pending or self.data / 'standalone.json'
        release['recover'](SimpleNamespace(rollback=False, stop_only=False),
                           self.api, self.host, json.loads(receipt.read_text()), pending)

    def interrupt(self, point):
        def install_backend(host, path, stamp, *, before_quiesce, snapshot_ready, **kwargs):
            if point == 'running':
                raise KeyboardInterrupt
            before_quiesce()
            self.running = False
            if point != 'before-snapshot':
                record = json.loads(self.pending.read_text())
                backup = release['recovery_backup'](record)
                self.write_snapshot(backup, stamp)
                if point != 'manifest-just-written':
                    snapshot_ready()
                if point == 'missing-snapshot':
                    (backup / 'rollback-files.json').unlink()
                if point == 'invalid-snapshot':
                    (backup / 'rollback-0').write_bytes(b'bad snapshot')
                if point in ('missing-snapshot', 'invalid-snapshot'):
                    self.running = True
            raise KeyboardInterrupt

        self.host_installer.side_effect = install_backend
        with self.assertRaises(KeyboardInterrupt):
            self.install()
        self.assertTrue(self.pending.exists())

    def write_snapshot(self, backup, stamp):
        backup.mkdir(parents=True)
        files = [self.data / 'rules.db', self.data / 'decisions.db', self.etc / 'zones.json',
                 self.etc / 'administrator.json', Path(self.api['DROPIN']), *map(Path, self.api['TOOLS'].values())]
        snapshot = {str(path): None for path in files}
        for i, name in enumerate(release['UNITS']):
            filename = f'rollback-{i}'
            (backup / filename).write_bytes(name.encode())
            snapshot['/etc/systemd/system/' + name] = {'file': filename, 'mode': 0o644, 'sha256': 'a' * 64}
        (backup / 'rollback-files.json').write_text(json.dumps(snapshot))
        (backup / 'install-record.json').write_text(json.dumps({
            'release': NEW, 'stamp': stamp, 'previous_current': str(self.old),
            'unit_enabled': {name: True for name in release['UNITS']},
        }))

    def assert_recovery_repeatable(self, first_action):
        self.recover()
        self.assertFalse(self.pending.exists())
        self.assertTrue(self.running)
        self.assertEqual((self.base / 'current').resolve(), self.old)
        self.assertEqual('restart-unchanged' in self.operations, first_action == 'restart-unchanged')
        self.assertEqual('rollback' in self.operations, first_action == 'rollback')
        self.assertEqual(self.cleaned.call_count, int(first_action == 'rollback'))
        self.recover()
        self.assertTrue(self.running)
        self.assertFalse(self.pending.exists())
        self.before = deepcopy(self.state)
        self.host_installer.side_effect = self.install_backend
        self.install()
        self.assertFalse(self.pending.exists())

    def test_interrupted_with_predecessor_still_running_and_no_snapshot(self):
        self.interrupt('running')
        self.assert_recovery_repeatable('leave-running')

    def test_interrupted_immediately_before_snapshot_creation(self):
        self.interrupt('before-snapshot')
        self.assert_recovery_repeatable('restart-unchanged')

    def test_interrupted_as_snapshot_manifest_appears(self):
        self.interrupt('manifest-just-written')
        self.assert_recovery_repeatable('restart-unchanged')

    def test_interrupted_immediately_after_snapshot_creation(self):
        self.interrupt('after-snapshot')
        self.assert_recovery_repeatable('rollback')

    def test_missing_required_snapshot_does_not_stop_running_predecessor(self):
        self.interrupt('missing-snapshot')
        with self.assertRaisesRegex(RuntimeError, 'Required rollback snapshot is missing'):
            self.recover()
        self.cleaned.assert_not_called()
        self.assertTrue(self.running)
        self.assertTrue(self.pending.exists())

    def test_invalid_snapshot_does_not_stop_running_predecessor(self):
        self.interrupt('invalid-snapshot')
        digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
        with patch.dict(scope, digest=digest):
            with self.assertRaisesRegex(RuntimeError, 'Rollback backup integrity check failed'):
                self.recover()
        self.cleaned.assert_not_called()
        self.assertTrue(self.running)
        self.assertTrue(self.pending.exists())

    def test_unchanged_state_permits_handoff(self):
        self.install()
        self.assertIn('protection-stop', self.operations)
        self.assertIn('systemctl-stop', self.operations)


if __name__ == '__main__':
    unittest.main()
