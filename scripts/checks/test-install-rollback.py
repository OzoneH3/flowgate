#!/usr/bin/env python3
"""Real SQLite/filesystem rollback; fake service/API boundaries, no host changes."""
import contextlib
import ast
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('monitoring_tests', ROOT / 'scripts/checks/test-install-monitoring.py')
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)
m = t.m

class RollbackHost(t.FakeHost):
    def __init__(self, base, new_hash, *, fail_old=False, stuck=False, residual=False, tamper=False, fail_switch=False):
        super().__init__(base, running=True)
        self.manifest_hash = new_hash
        self.fail_old, self.stuck, self.residual, self.tamper, self.fail_switch = fail_old, stuck, residual, tamper, fail_switch
        self.started_source = None
        self.started_states = []
        self.switch_failed = False
    def run(self, *argv):
        self.calls.append(argv)
        if argv[:2] == ('systemctl', 'is-enabled'):
            return 'enabled\n' if argv[-1] == 'flowgate.service' else 'disabled\n'
        if argv == ('systemctl', 'stop', 'flowgate.service'):
            if not (self.stuck and self.started_source == 'SRC'):
                # Simulate a final acknowledged rule edit during shutdown. The
                # rollback snapshot must include it, rather than an earlier copy.
                if self.running:
                    with contextlib.closing(sqlite3.connect(self.path('/var/lib/flowgate/rules.db'))) as db, db:
                        db.execute('INSERT INTO rules VALUES(?,?)', ('user:last-edit', json.dumps({'version': 9})))
                self.started = self.running = False
            return ''
        if 'protection-recover' in argv:
            self.tables = ['flowgate_host'] if self.residual else []
            return ''
        if argv[-2:] == ('list', 'tables'):
            return json.dumps({'nftables': [{'table': {'name': name}} for name in self.tables]})
        if argv == ('systemctl', 'daemon-reload') and self.fail_switch and not self.switch_failed:
            self.switch_failed = True
            raise RuntimeError('unit switch failed')
        if argv == ('systemctl', 'start', 'flowgate.service'):
            release = self.path('/usr/local/lib/flowgate/current').resolve()
            source = release.name
            self.started_source = source
            self.started_states.append((source, self.path('/var/lib/flowgate/protection.json').read_bytes()))
            if source == 'OLD' and self.fail_old:
                raise RuntimeError('old release also failed')
            self.started = True
            if source == 'SRC':
                # Failed startup migration changes the schema and rule version.
                with contextlib.closing(sqlite3.connect(self.path('/var/lib/flowgate/rules.db'))) as db, db:
                    db.execute('ALTER TABLE rules ADD COLUMN migrated TEXT')
                    db.execute('UPDATE rules SET document=? WHERE id=?', ('{"version":99}', 'zone:a'))
                self.path('/var/lib/flowgate/decisions.db').write_bytes(b'new log database')
                self.path('/var/lib/flowgate/rules.db-wal').write_bytes(b'failed writer wal evidence')
                if self.tamper:
                    for backup in self.path('/var/lib/flowgate/backups').glob('*/rollback-0'):
                        backup.write_bytes(b'corrupt backup')
            else:
                # A stale WAL must be removed before starting the previous build.
                if self.path('/var/lib/flowgate/rules.db-wal').exists():
                    raise RuntimeError('stale WAL survives restore')
            return ''
        return ''
    def api(self, op='list', **q):
        if not (self.started or self.running): raise OSError('no API')
        release = self.path('/usr/local/lib/flowgate/current').resolve()
        manifest = json.loads((release / 'manifest.json').read_text())
        if self.started_source == 'SRC':
            # Deliberate bad-build response after migration triggers rollback.
            source, rules = 'unexpected-build', []
        else:
            source = manifest['source']
            rules = [{'id': rid, 'version': version} for rid, version in m.rule_inventory(self.path('/var/lib/flowgate/rules.db'))]
        return 42, dict(generation='rollback-generation' if self.started_source == 'OLD' else 'original-generation',
                        build=dict(source=source, executable_sha256=manifest['files']['flowgate'], modified=False),
                        protection=dict(state='stopped', desired_mode='monitoring'), enforcement=dict(state='stopped'),
                        rules=rules, capabilities=['essential-system-networking-v1'])

class Rollback(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / '.workspace')
        self.base = pathlib.Path(self.temp.name)
        self.bundle, self.manifest = t.fixture(self.base)
        old = self.base / 'usr/local/lib/flowgate/releases/OLD'
        files = {name: b'old-' + data for name, data in {
            'flowgate': b'binary', 'launch': b'launcher', 'flowgate.service': b'unit',
            'flowgate-guard.service': b'guard', 'control.py': b'control', 'recover.py': b'recover', 'uninstall.py': b'uninstall'}.items()}
        for name, data in files.items(): (old / name).write_bytes(data)
        self.old_manifest = dict(source='OLD', files={name: hashlib.sha256(data).hexdigest() for name, data in files.items()})
        (old / 'manifest.json').write_text(json.dumps(self.old_manifest))
        for unit in m.UNITS: (self.base / 'etc/systemd/system' / unit).write_bytes(files[unit])
        self.zones = (self.base / 'etc/flowgate/zones.json').read_bytes()
        self.host = RollbackHost(self.base, self.manifest['files']['flowgate'])
    def tearDown(self): self.temp.cleanup()
    def install(self):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            m.install(self.host, self.bundle, 'test')
    def test_migration_failure_restores_pair_and_preserves_failed_state(self):
        with self.assertRaises(m.RollbackComplete): self.install()
        current = self.base / 'usr/local/lib/flowgate/current'
        self.assertEqual(current.resolve().name, 'OLD')
        dbpath = self.base / 'var/lib/flowgate/rules.db'
        self.assertEqual(m.rule_inventory(dbpath), [('preset:b', 1), ('user:last-edit', 9), ('zone:a', 3)])
        with contextlib.closing(sqlite3.connect(dbpath)) as db, db:
            self.assertEqual([r[1] for r in db.execute('PRAGMA table_info(rules)')], ['id', 'document'])
        backup = self.base / 'var/lib/flowgate/backups/SRC-monitoring-test'
        self.assertTrue((backup / 'rollback-verified.json').exists())
        self.assertEqual(m.rule_inventory(backup / 'failed-state/rules.db'), [('preset:b', 1), ('user:last-edit', 9), ('zone:a', 99)])
        self.assertEqual((backup / 'failed-state/rules.db-wal').read_bytes(), b'failed writer wal evidence')
        self.assertFalse((self.base / 'var/lib/flowgate/decisions.db').exists())
        self.assertEqual((self.base / 'etc/flowgate/zones.json').read_bytes(), self.zones)
        self.assertFalse((self.base / 'etc/flowgate/administrator.json').exists())
        self.assertEqual([source for source, _ in self.host.started_states], ['SRC', 'OLD'])
        self.assertTrue(all(json.loads(intent)['mode'] == 'monitoring' for _, intent in self.host.started_states))
        self.assertIn(('systemctl', 'enable', 'flowgate.service'), self.host.calls)
        self.assertNotIn(('systemctl', 'enable', 'flowgate-guard.service'), self.host.calls)
    def test_backup_error_restarts_unchanged_original_and_keeps_final_edit(self):
        with patch.object(m, 'snapshot_database', side_effect=OSError('backup disk full')):
            with self.assertRaises(m.RollbackComplete): self.install()
        self.assertEqual((self.base / 'usr/local/lib/flowgate/current').resolve().name, 'OLD')
        self.assertEqual([source for source, _ in self.host.started_states], ['OLD'])
        self.assertIn(('user:last-edit', 9), m.rule_inventory(self.base / 'var/lib/flowgate/rules.db'))
        self.assertNotIn(('systemctl', 'disable', 'flowgate.service'), self.host.calls)

    def test_unsafe_state_refused_before_stopping_old_daemon(self):
        config = self.base / 'etc/flowgate/zones.json'
        target = self.base / 'original-zones.json'
        target.write_bytes(config.read_bytes())
        config.unlink()
        config.symlink_to(target)
        with self.assertRaises(RuntimeError): self.install()
        self.assertNotIn(('systemctl', 'stop', 'flowgate.service'), self.host.calls)
        self.assertTrue(self.host.running)

    def test_unit_switch_failure_also_rolls_back(self):
        self.host.fail_switch = True
        with self.assertRaises(m.RollbackComplete): self.install()
        self.assertEqual([source for source, _ in self.host.started_states], ['OLD'])
    def test_failed_old_restart_stops_disables_and_does_not_signal_success(self):
        self.host.fail_old = True
        with self.assertRaises(Exception) as error: self.install()
        self.assertNotIsInstance(error.exception, m.RollbackComplete)
        self.assertFalse(self.host.started)
        self.assertIn(('systemctl', 'disable', 'flowgate.service'), self.host.calls)
    def test_still_running_new_writer_prevents_database_restore(self):
        self.host.stuck = True
        with self.assertRaises(Exception) as error: self.install()
        self.assertNotIsInstance(error.exception, m.RollbackComplete)
        self.assertEqual((self.base / 'usr/local/lib/flowgate/current').resolve().name, 'SRC')
        self.assertIn(('zone:a', 99), m.rule_inventory(self.base / 'var/lib/flowgate/rules.db'))
    def test_residual_interception_prevents_rollback_start(self):
        self.host.residual = True
        with self.assertRaises(Exception) as error: self.install()
        self.assertNotIsInstance(error.exception, m.RollbackComplete)
        self.assertNotIn('OLD', [source for source, _ in self.host.started_states])
    def test_corrupt_backup_refused_before_any_database_restore(self):
        self.host.tamper = True
        with self.assertRaises(Exception) as error: self.install()
        self.assertNotIsInstance(error.exception, m.RollbackComplete)
        self.assertEqual((self.base / 'usr/local/lib/flowgate/current').resolve().name, 'SRC')
    def test_verification_timeout_is_bounded_per_call_and_overall(self):
        from unittest.mock import Mock
        host = Mock()
        host.api.side_effect = OSError('unresponsive')
        with patch.object(m.time, 'monotonic', side_effect=[0, 0, 51, 51]):
            with self.assertRaisesRegex(RuntimeError, 'verification deadline'):
                m.wait_api(host)
        host.api.assert_called_once_with(timeout=2)

    def test_privileged_entry_emits_75_only_for_verified_rollback(self):
        tree = ast.parse((ROOT / 'scripts/install-monitoring.py').read_text())
        entry = tree.body[-1]
        scope = dict(vars(m), __name__='__main__')
        with patch.object(m.os, 'geteuid', return_value=0), patch.object(m.os, 'umask'), patch.object(m.sys, 'argv', ['installer', '--bundle', str(self.bundle)]), contextlib.redirect_stderr(io.StringIO()):
            def verified(*args): raise m.RollbackComplete('verified')
            scope['install'] = verified
            with self.assertRaises(SystemExit) as error:
                exec(compile(ast.Module(body=[entry], type_ignores=[]), 'privileged-entry', 'exec'), scope)
            self.assertEqual(error.exception.code, 75)

    def test_concurrent_installer_refused_before_stopping_service(self):
        import fcntl
        path = self.base / 'usr/local/lib/flowgate/.install.lock'
        with path.open('wb') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(RuntimeError, 'Another FlowGate installation'):
                self.install()
        self.assertNotIn(('systemctl', 'stop', 'flowgate.service'), self.host.calls)

    def test_original_process_must_match_retained_release(self):
        original_api = self.host.api
        def mismatch(*args, **kwargs):
            pid, response = original_api(*args, **kwargs)
            if self.host.running:
                response['build']['source'] = 'different-running-build'
            return pid, response
        self.host.api = mismatch
        with self.assertRaises(Exception) as error: self.install()
        self.assertNotIsInstance(error.exception, m.RollbackComplete)
        self.assertNotIn('OLD', [source for source, _ in self.host.started_states])

    def test_tampered_previous_release_is_never_started(self):
        (self.base / 'usr/local/lib/flowgate/releases/OLD/flowgate').write_bytes(b'changed')
        with self.assertRaises(Exception) as error: self.install()
        self.assertNotIsInstance(error.exception, m.RollbackComplete)
        self.assertNotIn('OLD', [source for source, _ in self.host.started_states])

if __name__ == '__main__': unittest.main(verbosity=2)
