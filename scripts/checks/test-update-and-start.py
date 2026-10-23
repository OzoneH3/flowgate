#!/usr/bin/env python3
"""Unprivileged update orchestration: real manifests, simulated host transitions."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import shutil
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('updater', ROOT / 'scripts/lib/update_and_start.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def status(source='old', selected='both'):
    active = selected != 'monitoring'
    return dict(generation='g', build=dict(source=source, executable_sha256=hashlib.sha256(b'backend').hexdigest(), modified=False),
                protection=dict(state='active' if active else 'stopped', desired_mode=selected, profile=selected if active else 'both'),
                enforcement=dict(state='active' if active else 'stopped', profile=selected if active else 'both'))


class SourceStage(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT / '.workspace')
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        (self.root / 'scripts').mkdir()
        shutil.copyfile(ROOT / 'scripts/update-and-start.sh', self.root / 'scripts/update-and-start.sh')
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.log = self.root / 'calls'
        self.env = dict(os.environ, PATH=str(self.bin) + ':' + os.environ['PATH'], CALLS=str(self.log))
        self.tool('git', """#!/bin/sh
printf '%s\\n' "$*" >> "$CALLS"
case "$1" in
 branch) echo "${BRANCH:-master}";;
 diff) exit "${DIRTY:-0}";;
 config) exit 1;;
 rev-parse) if [ "$2" = HEAD ]; then echo revision; fi;;
 log) echo revision;;
 -c) if [ "${HANG:-0}" = 1 ]; then sleep 30; else exit "${PULL_EXIT:-0}"; fi;;
esac
""")
        # Use a real process-group timeout, with a short deadline in the fixture.
        self.tool('timeout', '#!/bin/sh\nshift 2\nexec /usr/bin/timeout --kill-after=1s 0.1s "$@"\n')
        self.tool('python3', '#!/bin/sh\necho COORDINATOR >> "$CALLS"\n')
        self.tool('sudo', '#!/bin/sh\necho SUDO >> "$CALLS"\nexit 99\n')
        (self.root / 'scripts/prepare-release.sh').write_text('#!/bin/sh\necho PREPARE >> "$CALLS"\n')
        (self.root / 'scripts/prepare-release.sh').chmod(0o755)
    def tool(self, name, content):
        p = self.bin / name
        p.write_text(content)
        p.chmod(0o755)
    def run_source(self, *args, **env):
        return subprocess.run(['sh', str(self.root / 'scripts/update-and-start.sh'), *args],
                              env=dict(self.env, **env), text=True, capture_output=True, timeout=5)
    def calls(self):
        return self.log.read_text() if self.log.exists() else ''
    def test_hung_fetch_times_out_before_prepare_or_control(self):
        r = self.run_source(HANG='1')
        self.assertEqual(r.returncode, 124, r.stderr)
        self.assertIn('--local', r.stderr)
        self.assertNotIn('PREPARE', self.calls())
        self.assertNotIn('COORDINATOR', self.calls())
        self.assertNotIn('SUDO', self.calls())
    def test_failed_fetch_never_falls_back_to_local(self):
        r = self.run_source(PULL_EXIT='17')
        self.assertEqual(r.returncode, 17)
        self.assertIn('no installation or protection action', r.stderr)
        self.assertNotIn('PREPARE', self.calls())
    def test_explicit_local_skips_fetch_but_keeps_source_guards(self):
        r = self.run_source('--local')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn('pull', self.calls())
        self.assertIn('COORDINATOR', self.calls())
        for env in ({'DIRTY': '1'}, {'BRANCH': 'topic'}):
            self.log.unlink()
            r = self.run_source('--local', **env)
            self.assertNotEqual(r.returncode, 0)
            self.assertNotIn('COORDINATOR', self.calls())
    def test_fetch_is_noninteractive_and_bounded(self):
        self.tool('timeout', '#!/bin/sh\nprintf "%s|%s|%s\\n" "$GIT_TERMINAL_PROMPT" "$GIT_SSH_COMMAND" "$*" >> "$CALLS"\nshift 2\nexec "$@"\n')
        r = self.run_source()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('0|ssh -oBatchMode=yes -oConnectTimeout=10 -oConnectionAttempts=1|--kill-after=5s 60s git', self.calls())


class FakeHost:
    def __init__(self, initial=None):
        self.current = initial or status()
        self.calls = []
        self.auth_error = self.install_error = self.lost_ack = self.start_error = False
    def status(self):
        self.calls.append('status')
        return self.current
    def installed(self):
        return True
    def prepare_install(self, backend, root, wine_discovery, expected_manifest=None):
        pass
    def authenticate(self):
        self.calls.append('authenticate')
        if self.auth_error:
            raise subprocess.CalledProcessError(1, 'sudo')
    def action(self, backend, selected):
        self.calls.append(selected)
        if self.start_error and selected != 'monitoring':
            raise subprocess.CalledProcessError(1, selected)
        self.current = status(self.current['build']['source'], selected)
        if self.lost_ack:
            raise subprocess.CalledProcessError(1, selected)
    def preflight(self, backend, selected):
        pass
    def install(self, backend):
        self.calls.append('install')
        assert m.at_mode(self.current, 'monitoring')
        if self.install_error:
            raise subprocess.CalledProcessError(1, 'install')
        self.current = status('new', 'monitoring')
    def configure_wine(self, root):
        assert m.at_mode(self.current, 'monitoring')
        self.calls.append('wine-discovery')
    def sleep(self):
        pass
    def switch_gui(self, root, bundle):
        self.calls.append('gui')


class Update(unittest.TestCase):
    def test_candidate_refusal_keeps_running_release(self):
        class Incompatible(FakeHost):
            def preflight(self, backend, selected):
                raise RuntimeError('candidate incompatible')
        h = Incompatible()
        with self.assertRaisesRegex(RuntimeError, 'candidate incompatible'):
            m.update(h, self.root, 'new', gui=False)
        self.assertNotIn('monitoring', h.calls)
        self.assertNotIn('install', h.calls)
        self.assertNotIn('both', h.calls)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT / '.workspace')
        self.root = pathlib.Path(self.tmp.name)
        for parent, filename in [('automatic-zone-releases', 'matched-manifest.json'), ('daily-releases', 'manifest.json')]:
            directory = self.root / '.workspace' / parent / 'new'
            directory.mkdir(parents=True)
            (directory / 'flowgate').write_bytes(b'backend')
            (directory / filename).write_text(json.dumps(dict(source='new', files={'flowgate': hashlib.sha256(b'backend').hexdigest()})))
    def tearDown(self):
        self.tmp.cleanup()
    def run_update(self, host, **kw):
        with contextlib.redirect_stdout(io.StringIO()):
            m.update(host, self.root, 'new', **kw)
    def test_explicit_stopped_recovery_enters_guarded_installer(self):
        class Stopped(FakeHost):
            def status(self):
                if not self.current: raise OSError('stopped')
                return super().status()
            def install(self, backend):
                self.calls.append('install')
                self.current=status('new','monitoring')
        h=Stopped();h.current=None
        with self.assertRaises(RuntimeError):self.run_update(h)
        self.assertNotIn('authenticate',h.calls)
        self.run_update(h,recover_stopped=True,gui=False)
        self.assertEqual([c for c in h.calls if c!='status'],['authenticate','install'])

    def test_active_update_authenticates_before_stop_then_restores_both_before_gui(self):
        h = FakeHost()
        self.run_update(h)
        self.assertEqual([c for c in h.calls if c != 'status'], ['authenticate', 'monitoring', 'install', 'both', 'gui'])
    def test_stopped_remains_stopped_and_incoming_restores_incoming(self):
        for selected in ['monitoring', 'incoming']:
            h = FakeHost(status(selected=selected))
            self.run_update(h, gui=False, profile="preserve")
            self.assertTrue(m.at_mode(h.current, selected))
            self.assertNotIn('both', h.calls)
            self.assertNotIn('gui', h.calls)
    def test_authentication_failure_cannot_stop_protection(self):
        h = FakeHost(); h.auth_error = True
        with self.assertRaises(subprocess.CalledProcessError): self.run_update(h)
        self.assertNotIn('monitoring', h.calls)
        self.assertNotIn('install', h.calls)
        self.assertTrue(m.at_mode(h.current, 'both'))
    def test_pre_switch_failure_restores_original_daemon_without_launching_gui(self):
        h = FakeHost(); h.install_error = True
        with self.assertRaises(subprocess.CalledProcessError): self.run_update(h)
        self.assertTrue(m.at_mode(h.current, 'both'))
        self.assertNotIn('gui', h.calls)
    def test_failed_install_after_daemon_switch_never_restores_old_mode(self):
        class Switched(FakeHost):
            def install(self, backend):
                self.current = status('new', 'monitoring')
                self.current['generation'] = 'new-generation'
                raise subprocess.CalledProcessError(1, 'install')
        h = Switched()
        with self.assertRaises(subprocess.CalledProcessError): self.run_update(h)
        self.assertNotIn('both', h.calls)
        self.assertNotIn('gui', h.calls)

    def test_verified_rollback_can_restore_old_mode_in_a_new_generation(self):
        class RolledBack(FakeHost):
            def install(self, backend):
                self.current = status('old', 'monitoring')
                self.current['generation'] = 'restored-generation'
                raise subprocess.CalledProcessError(75, 'install')
        for selected in ['both', 'incoming']:
            h = RolledBack(status('old', selected))
            with self.assertRaises(subprocess.CalledProcessError): self.run_update(h)
            self.assertTrue(m.at_mode(h.current, selected))
            self.assertEqual(h.calls.count(selected), 1)
            self.assertNotIn('gui', h.calls)

    def test_rollback_signal_with_wrong_build_cannot_activate(self):
        class WrongRollback(FakeHost):
            def install(self, backend):
                self.current = status('unexpected', 'monitoring')
                self.current['generation'] = 'restored-generation'
                raise subprocess.CalledProcessError(75, 'install')
        h = WrongRollback()
        with self.assertRaises(subprocess.CalledProcessError): self.run_update(h)
        self.assertNotIn('both', h.calls)

    def test_new_generation_without_verified_rollback_cannot_activate(self):
        class UnverifiedRestart(FakeHost):
            def install(self, backend):
                self.current = status('old', 'monitoring')
                self.current['generation'] = 'unverified-restart'
                raise subprocess.CalledProcessError(1, 'install')
        h = UnverifiedRestart()
        with self.assertRaises(subprocess.CalledProcessError): self.run_update(h)
        self.assertNotIn('both', h.calls)

    def test_lost_acknowledgements_are_reconciled_without_replaying_mutations(self):
        h = FakeHost(); h.lost_ack = True
        self.run_update(h)
        self.assertEqual(h.calls.count('monitoring'), 1)
        self.assertEqual(h.calls.count('both'), 1)
        self.assertTrue(m.at_mode(h.current, 'both'))
    def test_refused_start_is_not_repeated_or_reported_as_success(self):
        h = FakeHost(); h.start_error = True
        with self.assertRaises(RuntimeError): self.run_update(h)
        self.assertEqual(h.calls.count('both'), 1)
        self.assertNotIn('gui', h.calls)
    def test_current_release_does_not_restart_daemon(self):
        h = FakeHost(status('new'))
        self.run_update(h)
        self.assertEqual([c for c in h.calls if c != 'status'], ['gui'])
    def test_explicit_profile_is_applied_without_unnecessary_install(self):
        h = FakeHost(status('new', 'monitoring'))
        self.run_update(h, profile='both')
        self.assertIn('both', h.calls)
        self.assertNotIn('install', h.calls)
    def test_plain_command_starts_both_after_previously_stopped_install(self):
        h = FakeHost(status(selected='monitoring'))
        self.run_update(h)
        self.assertEqual([c for c in h.calls if c != 'status'], ['authenticate', 'install', 'both', 'gui'])
    def test_preserve_rechecks_user_mode_after_sudo_prompt(self):
        class ChangedDuringPrompt(FakeHost):
            def authenticate(self):
                super().authenticate()
                self.current = status(selected='incoming')
        h = ChangedDuringPrompt()
        self.run_update(h, profile='preserve')
        self.assertTrue(m.at_mode(h.current, 'incoming'))
        self.assertNotIn('both', h.calls)
    def test_discovery_is_explicit_and_restarts_even_matching_release(self):
        h = FakeHost(status(source='new'))
        self.run_update(h, profile='preserve', wine_discovery=True)
        self.assertEqual([c for c in h.calls if c != 'status'], ['authenticate', 'monitoring', 'wine-discovery', 'install', 'both', 'gui'])
    def test_discovery_dry_run_does_not_change_config(self):
        h = FakeHost()
        self.run_update(h, dry=True, wine_discovery=True)
        self.assertEqual(h.calls, ['status'])
    def test_dry_run_missing_manifest_and_null_build(self):
        import shutil
        shutil.rmtree(self.root / '.workspace')
        h = FakeHost(); h.current['build'] = None
        self.run_update(h, dry=True)
        self.assertEqual(h.calls, ['status'])

    def test_dry_run_is_read_only(self):
        h = FakeHost()
        self.run_update(h, dry=True)
        self.assertEqual(h.calls, ['status'])
    def test_gui_switch_signals_only_released_host_gui_through_pidfd(self):
        proc = self.root / '12345'; proc.mkdir()
        gui = self.root / '.workspace/automatic-zone-releases/old'
        args = [str(gui / 'runtime/electron'), '--ozone-platform=wayland', str(gui / 'electron'), '--observer', '/run/flowgate-api/daemon.sock.monitor', '--control', '/run/flowgate-api/daemon.sock']
        (proc / 'cmdline').write_bytes(('\0'.join(args) + '\0').encode())
        fields = ['S'] + ['0'] * 18 + ['99']
        (proc / 'stat').write_text('12345 (electron) ' + ' '.join(fields))
        private = self.root / '12346'; private.mkdir()
        (private / 'cmdline').write_bytes(('\0'.join(args[:-1] + ['/private/test.sock']) + '\0').encode())
        # Private fixture must never be closed as part of the desktop update.
        original = pathlib.Path.iterdir
        def listing(path):
            return iter([proc, private]) if str(path) == '/proc' else original(path)
        def exited(fd, sig):
            fields[0] = 'Z'
            (proc / 'stat').write_text('12345 (electron) ' + ' '.join(fields))
        h = m.Host()
        with patch.object(pathlib.Path, 'iterdir', listing), patch.object(m.os, 'pidfd_open', return_value=73) as opened, patch.object(m.signal, 'pidfd_send_signal', side_effect=exited) as sent, patch.object(m.os, 'close'), patch.object(m.os, 'execv') as launched:
            h.switch_gui(self.root, self.root / 'new-ui')
        opened.assert_called_once_with(12345)
        sent.assert_called_once_with(73, m.signal.SIGTERM)
        self.assertEqual(launched.call_args.args[0], str(self.root / 'new-ui/launch-ui'))
    def test_tampered_bundle_fails_before_sudo_or_stop(self):
        (self.root / '.workspace/daily-releases/new/flowgate').write_bytes(b'tampered')
        h = FakeHost()
        with self.assertRaises(RuntimeError): self.run_update(h)
        self.assertEqual(h.calls, [])
    def test_build_verification_failure_cannot_restore_protection(self):
        class WrongBuild(FakeHost):
            def install(self, backend):
                super().install(backend)
                self.current['build']['source'] = 'unexpected'
        h = WrongBuild()
        with self.assertRaises(RuntimeError): self.run_update(h)
        self.assertNotIn('both', h.calls)
        self.assertNotIn('gui', h.calls)


if __name__ == '__main__':
    unittest.main()
