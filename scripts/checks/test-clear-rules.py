#!/usr/bin/env python3
"""clear-rules.py against a fake daemon socket; never touches a real daemon."""
import importlib.util
import io
import json
import pathlib
import socket
import sys
import tempfile
import threading
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('clear_rules', ROOT / 'scripts/clear-rules.py')
clear = importlib.util.module_from_spec(spec)
spec.loader.exec_module(clear)


def rule(id, version, preset=False):
    r = {'id': id, 'version': version, 'action': 'allow', 'executable': '/opt/' + id,
         'filter': {'application': 'k-' + id, 'direction': 'outgoing', 'protocol': '*', 'remote_address': '*'}}
    if preset:
        r['preset'] = {'name': 'essential-system-networking'}
    return r


class FakeDaemon:
    def __init__(self, rules, errors=None, read_only=False):
        self.rules, self.errors, self.read_only = list(rules), errors or {}, read_only
        self.deletes = []
        self.dir = tempfile.TemporaryDirectory(dir=ROOT / '.workspace')
        self.path = self.dir.name + '/s'
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.bind(self.path)
        self.sock.listen()
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            with c:
                q = json.loads(c.makefile().readline())
                if q['operation'] == 'list':
                    r = {'generation': 'g1', 'capabilities': [clear.CAPABILITY], 'rules': self.rules, 'read_only': self.read_only}
                else:
                    self.deletes.append(q)
                    code = self.errors.get(q['id'])
                    r = {'error_code': code, 'error': code} if code else {'deleted_rule': {'id': q['id'], 'version': q['expected_version']}}
                c.sendall((json.dumps(r) + '\n').encode())

    def close(self):
        self.sock.close()
        self.dir.cleanup()


class ClearRules(unittest.TestCase):
    def run_script(self, daemon, *args, answer='clear'):
        out = io.StringIO()
        code = clear.main(['--socket', daemon.path, *args], out=out, ask=lambda _: answer)
        return code, out.getvalue()

    def daemon(self, *a, **k):
        d = FakeDaemon(*a, **k)
        self.addCleanup(d.close)
        return d

    def test_dry_run_deletes_nothing(self):
        d = self.daemon([rule('a', 1), rule('b', 2)])
        code, out = self.run_script(d, '--dry-run')
        self.assertEqual((code, d.deletes), (0, []))
        self.assertIn('2 rule(s) to delete', out)

    def test_conditional_delete_keeps_essential_rules(self):
        d = self.daemon([rule('a', 3), rule('b', 0), rule('ess', 1, preset=True)])
        code, out = self.run_script(d)
        self.assertEqual(code, 0)
        self.assertEqual([(q['id'], q['generation'], q['expected_version']) for q in d.deletes], [('a', 'g1', 3), ('b', 'g1', 0)])
        self.assertIn('1 Essential rule(s) kept', out)

    def test_include_essential(self):
        d = self.daemon([rule('a', 1), rule('ess', 1, preset=True)])
        self.assertEqual(self.run_script(d, '--include-essential')[0], 0)
        self.assertEqual([q['id'] for q in d.deletes], ['a', 'ess'])

    def test_confirmation_required(self):
        d = self.daemon([rule('a', 1)])
        code, out = self.run_script(d, answer='yes')
        self.assertEqual((code, d.deletes), (1, []))
        self.assertIn('cancelled', out)

    def test_conflict_is_reported_not_retried(self):
        d = self.daemon([rule('a', 1), rule('stale', 4), rule('c', 1)], errors={'stale': 'version_conflict'})
        code, out = self.run_script(d, '--yes')
        self.assertEqual(code, 1)
        self.assertEqual([q['id'] for q in d.deletes], ['a', 'stale', 'c'])
        self.assertIn('deleted 2 rule(s); 1 not deleted', out)

    def test_inactive_protection_stops_early(self):
        d = self.daemon([rule('a', 1), rule('b', 1)], errors={'a': 'unavailable'})
        code, out = self.run_script(d, '--yes')
        self.assertEqual((code, len(d.deletes)), (1, 1))
        self.assertIn('only be changed while protection is active', out)

    def test_read_only_socket_refused(self):
        d = self.daemon([rule('a', 1)], read_only=True)
        self.assertEqual(self.run_script(d, '--yes')[0], 2)
        self.assertEqual(d.deletes, [])


if __name__ == '__main__':
    unittest.main()
