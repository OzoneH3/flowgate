"""Simulate user edits during standalone staging and immediately before quiesce."""
from copy import deepcopy
from pathlib import Path
import runpy
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
release = runpy.run_path(str(ROOT / 'deployment/standalone/release.py'))
scope = release['install'].__globals__


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
        }
        self.change = lambda: None
        self.change_before_quiesce = lambda: None
        self.base = self.root / 'lib'
        self.data = self.root / 'data'

        def directory(path):
            path.mkdir(exist_ok=True, parents=True)
            return path

        def receipt(path, value):
            directory(path.parent)
            path.touch()

        def atomic(path, data, mode):
            directory(path.parent)
            path.write_bytes(data)

        patcher = patch.dict(scope,
            BASE=self.base, DATA=self.data, TOOLS=self.root / 'tools',
            FILES={'flowgate-ui': str(self.root / 'bin/flowgate-ui')},
            module=lambda path: self.api, preflight=self.preflight,
            secure_directory=directory, digest=lambda path: 'a' * 64,
            desktop=Mock(), immutable_tree=lambda *args: self.change(),
            atomic=atomic, write_record=receipt, fsync_dir=Mock(),
            owned_journal=lambda: False,
            check_mode=lambda api, host, state, selected: state['protection']['desired_mode'] == selected,
        )
        patcher.start()
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
            self.state['protection'] = {'id': 'monitoring-id', 'state': 'stopped', 'desired_mode': 'monitoring'}
        if operation == 'protection-start':
            self.state['protection'] = deepcopy(self.before['protection'])
        if operation == 'traffic-start':
            self.state['traffic_monitor'] = {'state': 'active', 'generation': 'restarted'}
        return 1, deepcopy(self.state)

    def preflight(self, *_):
        collector = self.before['traffic_monitor']['state']
        old = self.base / 'legacy', {'files': {name: 'a' * 64 for name in release['UNITS']}}
        data = (self.host, old, deepcopy(self.before),
                self.before['protection']['desired_mode'], collector, {}, 1000, '/home/test/.config')
        if 'verify_before_switch' in scope:
            return (*data, release['saved_settings'](self.host, self.before))
        return data

    def install_backend(self, host, path, stamp, *, verify_extra, before_quiesce=None, **kwargs):
        self.change_before_quiesce()
        if before_quiesce:
            before_quiesce()
        self.operations.append('systemctl-stop')
        self.state['generation'] = 'new-release'
        verify_extra(deepcopy(self.state))

    def install(self):
        release['install'](
            SimpleNamespace(operation='install', desktop_config=None, import_preferences=None),
            self.payload, {'release': 'candidate', 'files': {}}, {'files': {}},
        )

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

    def test_unchanged_state_permits_handoff(self):
        self.install()
        self.assertIn('protection-stop', self.operations)
        self.assertIn('systemctl-stop', self.operations)


if __name__ == '__main__':
    unittest.main()
