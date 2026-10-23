#!/usr/bin/env python3
"""Passwordless helper authorization and updater dispatch; no host mutations."""
import importlib.util
import io
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('setup_update', ROOT / 'scripts/setup-passwordless-update.py')
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)
import update_and_start as updater


class PasswordlessUpdate(unittest.TestCase):
    def helper(self):
        namespace = {'__name__': 'test_helper'}
        exec(compile(setup.helper_source(1000), '<helper>', 'exec'), namespace)
        return namespace['main']

    def test_authorization_and_argument_validation(self):
        main = self.helper()
        for uid, euid, args in [('1001', 0, ['check']), ('1000', 1000, ['check']),
                                ('1000', 0, ['install', 'extra']), ('1000', 0, ['shell'])]:
            with self.subTest(uid=uid, euid=euid, args=args), patch.dict(os.environ, SUDO_UID=uid), \
                 patch('os.geteuid', return_value=euid), patch.object(sys, 'argv', ['helper', *args]), \
                 patch('subprocess.run') as run:
                with self.assertRaises(SystemExit): main()
                run.assert_not_called()

    def test_check_has_no_side_effect(self):
        with patch.dict(os.environ, SUDO_UID='1000'), patch('os.geteuid', return_value=0), \
             patch.object(sys, 'argv', ['helper', 'check']), patch('sys.stdout', new_callable=io.StringIO) as out, \
             patch('subprocess.run') as run:
            self.assertEqual(self.helper()(), 0)
            self.assertEqual(out.getvalue().strip(), 'flowgate-local-update-v1')
            run.assert_not_called()

    def test_fixed_source_isolation_and_exit_code(self):
        class Input:
            buffer = io.BytesIO(b'{"files":{}}')
        with patch.dict(os.environ, SUDO_UID='1000', PYTHONPATH='/evil', PATH='/evil'), \
             patch('os.geteuid', return_value=0), patch.object(sys, 'argv', ['helper', 'install']), \
             patch('sys.stdin', Input()), patch('subprocess.run', return_value=subprocess.CompletedProcess([], 75)) as run:
            self.assertEqual(self.helper()(), 75)
            args, kw = run.call_args
            self.assertEqual(args[0], ['/usr/bin/python3', '-I', '-c', updater.STAGE_INSTALL])
            self.assertEqual(kw['input'], b'{"files":{}}')
            self.assertNotIn('PYTHONPATH', kw['env'])
            self.assertEqual(kw['cwd'], '/')
            self.assertEqual(kw['env']['SUDO_UID'], '1000')

    def test_sudoers_only_exact_helper_operations(self):
        source = setup.sudoers_source('desktop-user')
        self.assertEqual(source.count(updater.UPDATE_HELPER), 4)
        self.assertNotIn('*', source)
        self.assertNotIn('/usr/bin/python', source)
        self.assertNotIn('SETENV', source)
        for name in ['a\nALL', 'ALL', '%wheel', 'a,b', '#1000']:
            with self.assertRaises(ValueError): setup.sudoers_source(name)

    def test_dispatch_without_password_validation(self):
        host = updater.Host()
        with patch('pathlib.Path.exists', return_value=True), \
             patch('subprocess.run', return_value=subprocess.CompletedProcess([], 0, 'flowgate-local-update-v1\n')) as run:
            host.authenticate()
            host.privileged('install', 'not executable caller code', b'bundle')
            self.assertEqual(run.call_args.args[0], ['sudo', '-n', updater.UPDATE_HELPER, 'install'])
            self.assertFalse(any('-v' in c.args[0] for c in run.call_args_list))

    def test_broken_helper_never_falls_back_to_password_or_install(self):
        for code, output in [(1, ''), (0, 'wrong-version')]:
            with patch('pathlib.Path.exists', return_value=True), \
                 patch('subprocess.run', return_value=subprocess.CompletedProcess([], code, output)) as run:
                with self.assertRaises(RuntimeError): updater.Host().authenticate()
                self.assertEqual(run.call_count, 1)

    def test_real_sudoers_syntax(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.workspace') as directory:
            rule = pathlib.Path(directory) / 'sudoers'
            rule.write_text(setup.sudoers_source('desktop-user'))
            result = subprocess.run(['/usr/sbin/visudo', '-cf', str(rule)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_failed_validation_keeps_prior_authorization(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.workspace') as directory:
            rule = pathlib.Path(directory) / 'sudoers'
            rule.write_text('previous')
            with patch.object(setup, 'safe_parent'), patch('subprocess.run', side_effect=subprocess.CalledProcessError(1, 'visudo')):
                with self.assertRaises(subprocess.CalledProcessError):
                    setup.write_atomic(rule, 'invalid', 0o440, validate=True)
            self.assertEqual(rule.read_text(), 'previous')
            self.assertEqual(list(rule.parent.iterdir()), [rule])

    def test_setup_refuses_symlink_destination(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.workspace') as directory:
            target = pathlib.Path(directory) / 'target'
            target.write_text('untouched')
            link = pathlib.Path(directory) / 'link'
            link.symlink_to(target)
            with patch.object(setup, 'safe_parent'):
                with self.assertRaises(RuntimeError): setup.write_atomic(link, 'replacement', 0o755)
            self.assertEqual(target.read_text(), 'untouched')

    def test_existing_authenticated_path_remains(self):
        with patch('pathlib.Path.exists', return_value=False), patch('subprocess.run') as run:
            host = updater.Host()
            host.authenticate()
            self.assertEqual(run.call_args.args[0], ['sudo', '-v'])
            host.privileged('install', 'fixed', b'bytes')
            self.assertEqual(run.call_args.args[0], ['sudo', '-n', '/usr/bin/python3', '-I', '-c', 'fixed'])


if __name__ == '__main__':
    unittest.main()
