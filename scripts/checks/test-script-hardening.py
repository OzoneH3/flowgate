#!/usr/bin/env python3
"""No privileged operations: snapshot, command isolation, and -O refusal."""
import ast
import base64
import hashlib
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('updater', ROOT / 'scripts/lib/update_and_start.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class Hardening(unittest.TestCase):
    def test_snapshot_is_frozen_and_isolated_command_uses_system_python(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.workspace') as tmp:
            directory = pathlib.Path(tmp)
            source = b"raise RuntimeError('test must not execute installer')\n"
            (directory / 'install-monitoring.py').write_bytes(source)
            (directory / 'manifest.json').write_text(json.dumps({'files': {'install-monitoring.py': hashlib.sha256(source).hexdigest()}}))
            h = m.Host(); h.prepare_install(directory, ROOT, False)
            (directory / 'install-monitoring.py').write_text('changed after authentication')
            (directory / 'json.py').write_text("raise RuntimeError('shadowed')")
            with patch.object(m.subprocess, 'run') as run:
                h.install(directory)
            args = run.call_args
            self.assertEqual(args.args[0][:5], ['sudo', '-n', '/usr/bin/python3', '-I', '-c'])
            payload = json.loads(args.kwargs['input'])
            self.assertEqual(base64.b64decode(payload['files']['install-monitoring.py']), source)
            self.assertNotIn('json.py', payload['files'])
            # A changed file cannot become the next selected snapshot unnoticed.
            with self.assertRaises(RuntimeError): m.snapshot_bundle(directory)

    def test_cleanup_timeout_still_restores_configuration(self):
        tree = ast.parse((ROOT / 'scripts/host-daily-acceptance.py').read_text())
        final = next(n.finalbody for n in tree.body if isinstance(n, ast.Try) and n.finalbody)
        child = Mock()
        child.poll.return_value = None
        child.wait.side_effect = [subprocess.TimeoutExpired('fixture', 5), 0]
        with tempfile.TemporaryDirectory(dir=ROOT / '.workspace') as tmp:
            restore, command = Mock(), Mock()
            scope = dict(owned={}, children={'a':child}, peer=None, oldzones={'local':[]},
                         write_zones=restore, cmd=command, evidence=pathlib.Path(tmp),
                         subprocess=subprocess, json=json, sys=sys)
            exec(compile(ast.Module(body=final, type_ignores=[]), 'cleanup', 'exec'), scope)
            child.kill.assert_called_once()
            restore.assert_called_once_with({'local':[]})
            self.assertIn(('systemctl', 'restart', 'flowgate.service'), [c.args for c in command.call_args_list])

    def test_isolated_installer_ignores_shadow_module(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.workspace') as tmp:
            directory = pathlib.Path(tmp)
            installer = directory / 'install-monitoring.py'
            installer.write_bytes((ROOT / 'scripts/install-monitoring.py').read_bytes())
            (directory / 'json.py').write_text("raise RuntimeError('shadow imported')")
            result = subprocess.run(['/usr/bin/python3', '-I', str(installer), '--help'], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn('shadow imported', result.stderr)

    def test_optimized_checks_fail_before_actions(self):
        for name in ['install-monitoring.py', 'install-daily.py', 'host-daily-acceptance.py',
                     'checks/test-deployment-recovery.py', 'checks/test-deployment-uninstall.py',
                     'checks/check-control-bridge.py', 'checks/check-udp-adapter.py']:
            with self.subTest(name=name):
                result = subprocess.run([sys.executable, '-O', str(ROOT / 'scripts' / name)],
                                        env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Optimized Python is unsupported', result.stderr)

if __name__ == '__main__': unittest.main()
