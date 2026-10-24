#!/usr/bin/env python3
"""Unprivileged update orchestration: real manifests, simulated host transitions."""
import contextlib
import sqlite3
import base64
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
    def test_shell_preserves_mode_and_forwards_explicit_ack(self):
        self.tool('python3', '#!/bin/sh\nprintf "%s\\n" "$*" >> "$CALLS"\n')
        r = self.run_source('--local')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('--profile preserve', self.calls())
        self.log.unlink()
        r = self.run_source('--local', '--profile', 'both', '--acknowledge-outgoing-blocking')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('--profile both --acknowledge-outgoing-blocking', self.calls())
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

    def test_monitoring_target_refusal_happens_before_any_stop(self):
        class Refused(FakeHost):
            def preflight(self, backend, selected):
                self.calls.append('preflight-' + selected)
                raise RuntimeError('stored rule schema unsupported')
        h = Refused()
        with self.assertRaisesRegex(RuntimeError, 'stored rule schema unsupported'):
            m.update(h, self.root, 'new', gui=False, profile='monitoring')
        self.assertIn('preflight-monitoring', h.calls)
        self.assertNotIn('monitoring', h.calls)
        self.assertNotIn('install', h.calls)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT / '.workspace')
        self.root = pathlib.Path(self.tmp.name)
        environment = patch.dict(os.environ, XDG_CONFIG_HOME=str(self.root / 'config'))
        environment.start()
        self.addCleanup(environment.stop)
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
    def test_login_entry_only_after_successful_gui_switch(self):
        h = FakeHost()
        with patch.object(m, 'configure_login_start') as configured:
            self.run_update(h, autostart=True)
            configured.assert_called_once_with(self.root / '.workspace/automatic-zone-releases/new', enable=True)
            self.assertEqual(h.calls[-1], 'gui')
        with patch.object(h, 'switch_gui', side_effect=m.GuiNotSwitched('failed')), patch.object(m, 'configure_login_start') as configured:
            with self.assertRaises(m.GuiNotSwitched):
                self.run_update(h, autostart=True)
            configured.assert_not_called()
        with self.assertRaisesRegex(ValueError, 'requires GUI'):
            self.run_update(h, autostart=True, gui=False)

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
        self.run_update(h, profile='both', acknowledge_outgoing=True)
        self.assertIn('both', h.calls)
        self.assertNotIn('install', h.calls)
    def test_plain_command_preserves_monitoring_after_previously_stopped_install(self):
        h = FakeHost(status(selected='monitoring'))
        self.run_update(h)
        self.assertEqual([c for c in h.calls if c != 'status'], ['authenticate', 'install', 'gui'])
    def test_outgoing_activation_requires_ack_before_auth_or_stop(self):
        for selected in ('monitoring', 'incoming'):
            h = FakeHost(status(selected=selected))
            with self.assertRaisesRegex(RuntimeError, 'acknowledge-outgoing-blocking'):
                self.run_update(h, profile='both')
            self.assertFalse(any(c in h.calls for c in ('authenticate','monitoring','install','both','gui')))
    def test_plain_command_preserves_incoming_and_monitoring(self):
        for selected in ('monitoring', 'incoming'):
            h = FakeHost(status(selected=selected))
            self.run_update(h)
            self.assertTrue(m.at_mode(h.current, selected))
            self.assertNotIn('both', h.calls)
    def test_mode_change_during_auth_rechecks_outgoing_ack(self):
        class Changed(FakeHost):
            def authenticate(self):
                super().authenticate()
                self.current = status(selected='monitoring')
        h = Changed()
        with self.assertRaisesRegex(RuntimeError, 'acknowledge-outgoing-blocking'):
            self.run_update(h, profile='both')
        self.assertNotIn('install', h.calls)
        self.assertNotIn('both', h.calls)
    def test_late_mode_change_rechecks_ack_even_when_target_unchanged(self):
        class Changed(FakeHost):
            def __init__(self):
                super().__init__(); self.reads = 0
            def status(self):
                self.reads += 1
                if self.reads == 3: self.current = status(selected='monitoring')
                return super().status()
        h = Changed()
        with self.assertRaisesRegex(RuntimeError, 'acknowledge-outgoing-blocking'):
            self.run_update(h, profile='both')
        self.assertNotIn('install', h.calls)
        self.assertNotIn('both', h.calls)
    def test_fresh_default_install_stays_monitoring(self):
        class Fresh(FakeHost):
            def status(self):
                if self.current is None: raise OSError('no daemon')
                return super().status()
            def installed(self): return False
            def install(self, backend):
                self.calls.append('install'); self.current = status('new','monitoring')
        h = Fresh(); h.current = None
        self.run_update(h)
        self.assertTrue(m.at_mode(h.current,'monitoring'))
        self.assertNotIn('both',h.calls)
    def test_preserve_rechecks_user_mode_after_sudo_prompt(self):
        class ChangedDuringPrompt(FakeHost):
            def authenticate(self):
                super().authenticate()
                self.current = status(selected='incoming')
        h = ChangedDuringPrompt()
        self.run_update(h, profile='preserve')
        self.assertTrue(m.at_mode(h.current, 'incoming'))
        self.assertNotIn('both', h.calls)
    def test_preserve_restores_outgoing_enabled_by_user_during_auth(self):
        class ChangedDuringPrompt(FakeHost):
            def authenticate(self):
                super().authenticate()
                self.current = status(selected='both')
        h = ChangedDuringPrompt(status(selected='incoming'))
        self.run_update(h)
        self.assertTrue(m.at_mode(h.current,'both'))
        self.assertEqual(h.calls.count('both'),1)
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
        # Electron's rewritten main-process cmdline: one string, switches first.
        rewritten = [args[0], '--ozone-platform=wayland', '--observer', '--control', str(gui / 'electron'), '/run/flowgate-api/daemon.sock.monitor', '/run/flowgate-api/daemon.sock']
        (proc / 'cmdline').write_bytes((' '.join(rewritten) + '\0').encode())
        (proc / 'exe').symlink_to(gui / 'runtime/electron')
        fields = ['S'] + ['0'] * 18 + ['99']
        (proc / 'stat').write_text('12345 (electron) ' + ' '.join(fields))
        private = self.root / '12346'; private.mkdir()
        (private / 'cmdline').write_bytes(('\0'.join(args[:-1] + ['/private/test.sock']) + '\0').encode())
        (private / 'exe').symlink_to(gui / 'runtime/electron')
        # Private fixture must never be closed as part of the desktop update.
        original = pathlib.Path.iterdir
        def listing(path):
            return iter([proc, private]) if str(path) == '/proc' else original(path)
        def exited(fd, sig):
            fields[0] = 'Z'
            (proc / 'stat').write_text('12345 (electron) ' + ' '.join(fields))
        (proc / 'environ').write_bytes(b'WAYLAND_DISPLAY=gui-display\0XDG_RUNTIME_DIR=/gui-runtime\0SECRET=x\0')
        h = m.Host()
        desktop = dict(WAYLAND_DISPLAY='gui-display', XDG_RUNTIME_DIR='/gui-runtime')
        with patch.object(pathlib.Path, 'iterdir', listing), patch.object(m, 'target_desktop', return_value=(desktop, None)) as target, patch.object(m.os, 'pidfd_open', return_value=73) as opened, patch.object(m.signal, 'pidfd_send_signal', side_effect=exited) as sent, patch.object(m.os, 'close'), patch.object(m, 'supervise_gui', return_value=4242) as launched, patch.dict(m.os.environ, {'WAYLAND_DISPLAY': 'stale', 'KEEP': '1'}), contextlib.redirect_stdout(io.StringIO()):
            h.switch_gui(self.root, self.root / 'new-ui')
        # Only the released GUI's own session evidence is consulted.
        self.assertEqual(target.call_args.args[0], [dict(WAYLAND_DISPLAY='gui-display', XDG_RUNTIME_DIR='/gui-runtime', SECRET='x')])
        opened.assert_called_once_with(12345)
        sent.assert_called_once_with(73, m.signal.SIGTERM)
        self.assertEqual(launched.call_args.args[0][0], str(self.root / 'new-ui/launch-ui'))
        env = launched.call_args.args[1]
        self.assertEqual((env['WAYLAND_DISPLAY'], env['XDG_RUNTIME_DIR'], env['KEEP']), ('gui-display', '/gui-runtime', '1'))
    def test_recycled_pid_during_evidence_read_is_never_signalled(self):
        proc = self.root / '12345'; proc.mkdir()
        gui = self.root / '.workspace/automatic-zone-releases/old'
        (proc / 'cmdline').write_bytes(('\0'.join([str(gui / 'runtime/electron'), '--ozone-platform=wayland', str(gui / 'electron'), '--observer', '/run/flowgate-api/daemon.sock.monitor', '--control', '/run/flowgate-api/daemon.sock']) + '\0').encode())
        (proc / 'exe').symlink_to(gui / 'runtime/electron')
        original = pathlib.Path.iterdir
        def listing(path):
            return iter([proc]) if str(path) == '/proc' else original(path)
        # The start time changes between the reads that bookend the evidence.
        starts = iter(['99', '100'])
        with patch.object(pathlib.Path, 'iterdir', listing), patch.object(m, 'start_time', side_effect=lambda p: next(starts)), \
             patch.object(m, 'target_desktop', return_value=(None, 'no verifiable Wayland session')) as target, patch.object(m.signal, 'pidfd_send_signal') as sent:
            with self.assertRaises(m.GuiNotSwitched) as raised:
                m.Host().switch_gui(self.root, self.root / 'new-ui')
        self.assertEqual(target.call_args.args[0], [])  # no evidence from the recycled PID
        sent.assert_not_called()
        self.assertIn('no GUI started', str(raised.exception))
    def test_unverifiable_desktop_keeps_old_gui_and_launches_nothing(self):
        proc = self.root / '12345'; proc.mkdir()
        gui = self.root / '.workspace/automatic-zone-releases/old'
        args = [str(gui / 'runtime/electron'), '--ozone-platform=wayland', str(gui / 'electron'), '--observer', '/run/flowgate-api/daemon.sock.monitor', '--control', '/run/flowgate-api/daemon.sock']
        (proc / 'cmdline').write_bytes(('\0'.join(args) + '\0').encode())
        (proc / 'exe').symlink_to(gui / 'runtime/electron')
        (proc / 'stat').write_text('12345 (electron) ' + ' '.join(['S'] + ['0'] * 18 + ['99']))
        original = pathlib.Path.iterdir
        def listing(path):
            return iter([proc]) if str(path) == '/proc' else original(path)
        with patch.object(pathlib.Path, 'iterdir', listing), patch.object(m, 'target_desktop', return_value=(None, 'no verifiable Wayland session')), patch.object(m.signal, 'pidfd_send_signal') as sent, patch.object(m, 'supervise_gui') as launched:
            with self.assertRaises(m.GuiNotSwitched) as raised:
                m.Host().switch_gui(self.root, self.root / 'new-ui')
        sent.assert_not_called()
        launched.assert_not_called()
        self.assertIn('running GUI was left open', str(raised.exception))
    def test_gui_failure_is_reported_separately_after_verified_update(self):
        class NoDesktop(FakeHost):
            def switch_gui(self, root, bundle):
                self.calls.append('gui')
                raise m.GuiNotSwitched('no verifiable Wayland session; no GUI started')
        h = NoDesktop(status('old', 'both'))
        err, out = io.StringIO(), io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as code:
            m.main(['--root', str(self.root), '--revision', 'new'], host=h)
        self.assertEqual(code.exception.code, 3)
        self.assertEqual(h.calls[-1], 'gui')
        self.assertLess(h.calls.index('both'), h.calls.index('gui'))  # protection restored first
        self.assertIn('Update verified; protection mode: both', out.getvalue())
        self.assertIn('Backend update verified; GUI not switched', err.getvalue())
        self.assertNotIn('Update failed', err.getvalue())
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



class ReleasedGui(unittest.TestCase):
    """GUI selection from verifiable process evidence (fake /proc entries)."""
    MON, CTL = '/run/flowgate-api/daemon.sock.monitor', '/run/flowgate-api/daemon.sock'
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='g', dir=ROOT / '.workspace')
        self.addCleanup(self.tmp.cleanup)
        self.base = pathlib.Path(self.tmp.name)
        self.n = 0
    def proc(self, root, cmdline, exe=None):
        releases = root / '.workspace/automatic-zone-releases'
        gui = releases / 'old'
        self.n += 1
        p = self.base / ('proc' + str(self.n)); p.mkdir()
        p.joinpath('cmdline').write_bytes(cmdline(gui))
        p.joinpath('exe').symlink_to(exe(gui) if exe else gui / 'runtime/electron')
        return p, releases
    def argv(self, gui, args=None):
        # As launch-ui runs it (NUL-separated, original order).
        args = args if args is not None else ['--ozone-platform=wayland', str(gui / 'electron'), '--observer', self.MON, '--control', self.CTL]
        return ('\0'.join([str(gui / 'runtime/electron'), *args]) + '\0').encode()
    def rewritten(self, gui, switches=('--ozone-platform=wayland', '--observer', '--control'), values=None):
        values = values if values is not None else [str(gui / 'electron'), self.MON, self.CTL]
        return (' '.join([str(gui / 'runtime/electron'), *switches, *values]) + '\0').encode()
    def check(self, root, cmdline, **kw):
        p, releases = self.proc(root, cmdline, **kw)
        return m.released_gui(p, releases)
    def test_original_and_rewritten_command_lines_match(self):
        for root in (self.base / 'plain', self.base / 'with space'):
            self.assertTrue(self.check(root, self.argv), root)
            self.assertTrue(self.check(root, self.rewritten), root)
    def test_ambiguous_or_foreign_arguments_never_match(self):
        root = self.base / 'with space'
        app = lambda g: str(g / 'electron')
        cases = {
            'argv: socket strings as unrelated arguments': lambda g: self.argv(g, ['--ozone-platform=wayland', app(g), '--observer', '/x/mon', '--control', '/x/ctl', '--note', self.MON, self.CTL]),
            'argv: duplicate observer': lambda g: self.argv(g, ['--ozone-platform=wayland', app(g), '--observer', self.MON, '--observer', self.MON, '--control', self.CTL]),
            'argv: conflicting control': lambda g: self.argv(g, ['--ozone-platform=wayland', app(g), '--observer', self.MON, '--control', '/x/ctl']),
            'argv: swapped endpoints': lambda g: self.argv(g, ['--ozone-platform=wayland', app(g), '--observer', self.CTL, '--control', self.MON]),
            'argv: --type=zygote': lambda g: self.argv(g, ['--type=zygote', '--ozone-platform=wayland', app(g), '--observer', self.MON, '--control', self.CTL]),
            'argv: --type as its own argument': lambda g: self.argv(g, ['--type', 'renderer', '--ozone-platform=wayland', app(g), '--observer', self.MON, '--control', self.CTL]),
            'rewritten: --type= switch': lambda g: self.rewritten(g, switches=('--type=renderer', '--ozone-platform=wayland', '--observer', '--control')),
            'rewritten: --type as its own token': lambda g: self.rewritten(g, switches=('--type', '--ozone-platform=wayland', '--observer', '--control')),
            'rewritten: extra value with socket string': lambda g: self.rewritten(g, values=[app(g), '/x/mon', '/x/ctl', self.MON, self.CTL]),
            'rewritten: duplicate switch': lambda g: self.rewritten(g, switches=('--ozone-platform=wayland', '--observer', '--observer', '--control')),
            'rewritten: swapped values': lambda g: self.rewritten(g, values=[app(g), self.CTL, self.MON]),
            'rewritten: longer socket path': lambda g: self.rewritten(g, values=[app(g), self.MON + '2', self.CTL]),
            'another bundle app': lambda g: self.rewritten(g, values=[str(g.parent / 'other/electron'), self.MON, self.CTL]),
            'empty': lambda g: b'',
            'oversized': lambda g: self.argv(g)[:-1] + b'x' * (m.CMDLINE_LIMIT + 1),
        }
        for name, cmdline in cases.items():
            self.assertFalse(self.check(root, cmdline), name)
        for name, exe in {'outside releases': lambda g: pathlib.Path('/usr/lib/electron/electron'), 'nested layout': lambda g: g / 'nested/runtime/electron'}.items():
            self.assertFalse(self.check(root, self.rewritten, exe=exe), name)
    def test_other_user_and_deleted_executable(self):
        root = self.base / 'u'
        p, releases = self.proc(root, self.rewritten)
        self.assertFalse(m.released_gui(p, releases, uid=os.getuid() + 1))
        p, releases = self.proc(root, self.argv, exe=lambda g: pathlib.Path(str(g / 'runtime/electron') + ' (deleted)'))
        self.assertTrue(m.released_gui(p, releases))


class Desktop(unittest.TestCase):
    """Session discovery with real Unix sockets in private temporary runtime dirs."""
    def setUp(self):
        # Short path inside the workspace: AF_UNIX paths are limited to 108 bytes.
        self.tmp = tempfile.TemporaryDirectory(prefix='d', dir=ROOT / '.workspace')
        self.addCleanup(self.tmp.cleanup)
        self.base = pathlib.Path(self.tmp.name)
        self.servers = []
    def tearDown(self):
        for s in self.servers: s.close()
    def runtime(self, name, *displays, bus=False):
        d = self.base / name; d.mkdir(mode=0o700); d.chmod(0o700)
        for display in displays:
            s = m.socket.socket(m.socket.AF_UNIX); s.bind(str(d / display)); s.listen(4); self.servers.append(s)
            (d / (display + '.lock')).write_text('')
        if bus:
            s = m.socket.socket(m.socket.AF_UNIX); s.bind(str(d / 'bus')); s.listen(1); self.servers.append(s)
        return str(d)
    def test_socket_evidence_is_verified(self):
        r = self.runtime('a', 'wayland-0')
        self.assertTrue(m.wayland_socket(dict(XDG_RUNTIME_DIR=r, WAYLAND_DISPLAY='wayland-0')))
        self.assertTrue(m.wayland_socket(dict(XDG_RUNTIME_DIR=r, WAYLAND_DISPLAY=r + '/wayland-0')))
        for env in [dict(XDG_RUNTIME_DIR=r), dict(WAYLAND_DISPLAY='wayland-0'), dict(XDG_RUNTIME_DIR=r, WAYLAND_DISPLAY='wayland-9'),
                    dict(XDG_RUNTIME_DIR=r, WAYLAND_DISPLAY='wayland-0.lock'), dict(XDG_RUNTIME_DIR='relative', WAYLAND_DISPLAY='wayland-0')]:
            self.assertIsNone(m.wayland_socket(env), env)
        self.assertIsNone(m.wayland_socket(dict(XDG_RUNTIME_DIR=r, WAYLAND_DISPLAY='wayland-0'), uid=os.getuid() + 1))
        dead = self.runtime('dead'); s = m.socket.socket(m.socket.AF_UNIX); s.bind(dead + '/wayland-0'); s.close()
        self.assertIsNone(m.wayland_socket(dict(XDG_RUNTIME_DIR=dead, WAYLAND_DISPLAY='wayland-0')))
        shared = self.runtime('shared', 'wayland-0'); pathlib.Path(shared).chmod(0o755)
        self.assertIsNone(m.wayland_socket(dict(XDG_RUNTIME_DIR=shared, WAYLAND_DISPLAY='wayland-0')))
    def test_replaced_gui_session_wins_over_updater_environment(self):
        gui, own = self.runtime('gui', 'wayland-1'), self.runtime('own', 'wayland-0')
        env, reason = m.target_desktop([dict(XDG_RUNTIME_DIR=gui, WAYLAND_DISPLAY='wayland-1', DBUS_SESSION_BUS_ADDRESS='unix:path=x', SECRET='s')], dict(XDG_RUNTIME_DIR=own, WAYLAND_DISPLAY='wayland-0'))
        self.assertIsNone(reason)
        self.assertEqual(env, dict(XDG_RUNTIME_DIR=gui, WAYLAND_DISPLAY='wayland-1', DBUS_SESSION_BUS_ADDRESS='unix:path=x'))
    def test_conflicting_gui_sessions_are_ambiguous(self):
        a, b = self.runtime('a', 'wayland-0'), self.runtime('b', 'wayland-0')
        env, reason = m.target_desktop([dict(XDG_RUNTIME_DIR=a, WAYLAND_DISPLAY='wayland-0'), dict(XDG_RUNTIME_DIR=b, WAYLAND_DISPLAY='wayland-0')], {})
        self.assertIsNone(env); self.assertIn('different desktop sessions', reason)
    def test_updater_session_used_when_no_gui_runs(self):
        own = self.runtime('own', 'wayland-3')
        env, _ = m.target_desktop([], dict(XDG_RUNTIME_DIR=own, WAYLAND_DISPLAY='wayland-3'))
        self.assertEqual(env['WAYLAND_DISPLAY'], 'wayland-3')
    def test_agent_environment_without_display_finds_single_user_session(self):
        # The reported failure: XDG_RUNTIME_DIR known, WAYLAND_DISPLAY absent.
        r = self.runtime('agent', 'wayland-1', bus=True)
        env, reason = m.target_desktop([], dict(XDG_RUNTIME_DIR=r))
        self.assertIsNone(reason)
        self.assertEqual((env['WAYLAND_DISPLAY'], env['DBUS_SESSION_BUS_ADDRESS']), ('wayland-1', 'unix:path=' + r + '/bus'))
    def test_fallback_never_carries_another_sessions_bus(self):
        r = self.runtime('nobus', 'wayland-1')
        env, _ = m.target_desktop([], dict(XDG_RUNTIME_DIR=r, DBUS_SESSION_BUS_ADDRESS='unix:path=/elsewhere/bus'))
        self.assertNotIn('DBUS_SESSION_BUS_ADDRESS', env)
        (pathlib.Path(r) / 'bus').write_text('')  # not a socket
        env, _ = m.target_desktop([], dict(XDG_RUNTIME_DIR=r))
        self.assertNotIn('DBUS_SESSION_BUS_ADDRESS', env)
    def test_several_or_no_sessions_launch_nothing(self):
        r = self.runtime('two', 'wayland-0', 'wayland-1')
        env, reason = m.target_desktop([], dict(XDG_RUNTIME_DIR=r))
        self.assertIsNone(env); self.assertIn('several Wayland sessions', reason)
        empty = self.runtime('none')
        env, reason = m.target_desktop([], dict(XDG_RUNTIME_DIR=empty))
        self.assertIsNone(env); self.assertIn('no verifiable Wayland session', reason)
        # A stale display name in the updater environment is not trusted either.
        env, reason = m.target_desktop([dict(XDG_RUNTIME_DIR=empty, WAYLAND_DISPLAY='wayland-0')], dict(XDG_RUNTIME_DIR=empty, WAYLAND_DISPLAY='wayland-0'))
        self.assertIsNone(env)



class Launch(unittest.TestCase):
    """Supervised start with fake launchers: readiness, early exit, silence."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='l', dir=ROOT / '.workspace')
        self.addCleanup(self.tmp.cleanup)
        self.dir = pathlib.Path(self.tmp.name)
        self.pids = []
    def tearDown(self):
        for pid in self.pids:
            with contextlib.suppress(ProcessLookupError): os.killpg(pid, 15)
    def launcher(self, body):
        p = self.dir / 'launch-ui'
        p.write_text('#!/bin/sh\n' + body + '\n'); p.chmod(0o755)
        return [str(p), '--observer', 'x']
    def test_ready_line_returns_running_detached_gui(self):
        cmd = self.launcher('echo "[1:ERROR:display.cc] noise"; echo "FlowGate: main window rendered; sandbox enabled; native platform wayland"; exec sleep 30')
        pid = m.supervise_gui(cmd, dict(PATH=os.environ['PATH']), self.dir / '.workspace/gui-launch.log', timeout=5, poll=.05)
        self.pids.append(pid)
        self.assertEqual(os.getpgid(pid), pid)  # own session: survives the updater
    def test_early_exit_is_gui_failure_with_reason(self):
        cmd = self.launcher('echo "Failed to connect to Wayland display: No such file or directory (2)" >&2; exit 1')
        with self.assertRaises(m.GuiNotSwitched) as raised:
            m.supervise_gui(cmd, dict(PATH=os.environ['PATH']), self.dir / 'gui.log', timeout=5, poll=.05)
        self.assertIn('exited with status 1', str(raised.exception))
        self.assertIn('Failed to connect to Wayland display', str(raised.exception))
    def test_old_log_ready_line_does_not_count(self):
        log = self.dir / 'gui.log'
        log.write_bytes(b'FlowGate: main window rendered; earlier run\n')
        with self.assertRaises(m.GuiNotSwitched):
            m.supervise_gui(self.launcher('exit 1'), dict(PATH=os.environ['PATH']), log, timeout=5, poll=.05)
    def test_ready_line_then_exit_is_not_reported_started(self):
        # Deterministic: the child has already exited when readiness is first seen.
        cmd = self.launcher('echo "FlowGate: main window rendered; native platform wayland"; exit 1')
        with patch.object(m.subprocess.Popen, 'poll', lambda child: child.wait()), self.assertRaises(m.GuiNotSwitched) as raised:
            m.supervise_gui(cmd, dict(PATH=os.environ['PATH']), self.dir / 'gui.log', timeout=5, poll=.05)
        self.assertIn('exited with status 1 after reporting its main window loaded', str(raised.exception))
    def test_log_failures_are_gui_failures(self):
        blocked = self.dir / 'ro'; blocked.mkdir(); blocked.chmod(0o500)
        self.addCleanup(blocked.chmod, 0o700)
        with self.assertRaises(m.GuiNotSwitched) as raised:
            m.supervise_gui(self.launcher('exit 0'), dict(PATH=os.environ['PATH']), blocked / 'gui.log', timeout=1, poll=.05)
        self.assertIn('GUI launch failed', str(raised.exception))
        with self.assertRaises(m.GuiNotSwitched):
            m.supervise_gui(self.launcher('exit 0'), dict(PATH=os.environ['PATH']), self.dir / 'file' / 'sub' / 'gui.log', timeout=1, poll=.05) if (self.dir / 'file').write_text('') is not None else None
        # A log that becomes unreadable while waiting is reported, not raised as an update failure.
        real = open
        def failing(path, mode='r', *a, **k):
            if mode == 'rb': raise PermissionError('log unreadable')
            return real(path, mode, *a, **k)
        cmd = self.launcher('exec sleep 30')
        with patch('builtins.open', failing), self.assertRaises(m.GuiNotSwitched) as raised:
            m.supervise_gui(cmd, dict(PATH=os.environ['PATH']), self.dir / 'gui2.log', timeout=5, poll=.05)
        self.assertIn('could not be observed', str(raised.exception))
        self.pids.append(int(str(raised.exception).split('PID ')[1].split(',')[0]))
    def test_missing_readiness_is_reported_not_claimed(self):
        cmd = self.launcher('exec sleep 30')
        with self.assertRaises(m.GuiNotSwitched) as raised:
            m.supervise_gui(cmd, dict(PATH=os.environ['PATH']), self.dir / 'gui.log', timeout=.4, poll=.05)
        self.assertIn('did not report its main window loaded', str(raised.exception))
        self.pids.append(int(str(raised.exception).split('PID ')[1].split(')')[0]))


class StoredRuleSchemaGuard(unittest.TestCase):
    """Real SQLite and the real privileged script text, unprivileged: a temp rules DB
    replaces the fixed path and a fake candidate answers `version`. No host state."""
    FIXED = "RULES_DB = '/var/lib/flowgate/rules.db'"
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT / '.workspace')
        self.dir = pathlib.Path(self.tmp.name)
        self.count = 0
    def tearDown(self):
        self.tmp.cleanup()
    def db(self, *documents, table=True):
        self.count += 1
        path = self.dir / f'rules-{self.count}.db'
        with contextlib.closing(sqlite3.connect(path)) as c, c:
            if table:
                c.execute('CREATE TABLE rules (id TEXT PRIMARY KEY, document TEXT NOT NULL)')
            for i, d in enumerate(documents):
                c.execute('INSERT INTO rules VALUES (?,?)', (str(i), d if isinstance(d, str) else json.dumps(d)))
        return path
    def guard(self):
        self.assertEqual(m.SCHEMA_GUARD.count(self.FIXED), 1)
        ns = {}
        exec(m.SCHEMA_GUARD, ns)
        return ns
    def candidate(self, identity):
        body = '#!/usr/bin/python3\nimport sys\nif sys.argv[1:] != ["version"]: sys.exit(3)\n'
        if identity is None:
            body += 'sys.exit(2)\n'
        else:
            body += 'print(' + repr(identity if isinstance(identity, str) else json.dumps(identity)) + ')\n'
        return body.encode()
    def preflight(self, db, identity, manifest=None, profile='monitoring'):
        data = self.candidate(identity)
        script = m.STAGE_PREFLIGHT.replace(self.FIXED, 'RULES_DB = ' + repr(str(db)))
        payload = json.dumps({'binary': base64.b64encode(data).decode(), 'sha256': hashlib.sha256(data).hexdigest(), 'profile': profile, 'manifest': manifest or {}})
        return subprocess.run([sys.executable, '-I', '-B', '-c', script], input=payload, capture_output=True, text=True, timeout=30)

    def test_stored_schema_counts_and_refusals(self):
        g = self.guard()
        mixed = self.db({'id': 'legacy'}, *[{'schema': n} for n in range(1, 8)])
        self.assertEqual(g['stored_rule_schemas'](str(mixed)), {0: 1, **{n: 1 for n in range(1, 8)}})
        with self.assertRaisesRegex(RuntimeError, r'up to 6, but 1 rule\(s\) of schema 7 exist'):
            g['require_rule_schemas'](str(mixed), 6)
        g['require_rule_schemas'](str(mixed), 7)
        self.assertEqual(g['stored_rule_schemas'](str(self.dir / 'absent.db')), {})
        self.assertEqual(g['stored_rule_schemas'](str(self.db(table=False))), {})
        for bad in ['{not json', json.dumps({'schema': '7'}), json.dumps({'schema': -1}), json.dumps(['schema', 7]), json.dumps({'schema': 7.0})]:
            with self.subTest(bad=bad), self.assertRaisesRegex(RuntimeError, 'unreadable'):
                g['stored_rule_schemas'](str(self.db(bad)))

    def test_candidate_declaration_and_manifest_agreement(self):
        c = self.guard()['candidate_rule_schema']
        self.assertEqual(c(None, {}), 6)  # undeclared: prior ceiling only
        self.assertEqual(c(7, {}), 7)
        self.assertEqual(c(7, {'max_rule_schema': 7}), 7)
        for declared, manifest, message in [(6, {'max_rule_schema': 7}, 'differs'), (None, {'max_rule_schema': 7}, 'differs'),
                                            (7, {'max_rule_schema': 0}, 'invalid'), (7, {'max_rule_schema': 65}, 'invalid'), (7, {'max_rule_schema': '7'}, 'invalid')]:
            with self.subTest(declared=declared, manifest=manifest), self.assertRaisesRegex(RuntimeError, message):
                c(declared, manifest)

    def test_preflight_refuses_unsupported_schema_for_every_profile_before_firewall_checks(self):
        db = self.db({'schema': 6}, {'schema': 7})
        for profile in ('monitoring', 'incoming', 'both'):
            for identity in ({'source': 'old'}, None):  # no field, or a build without `version`
                with self.subTest(profile=profile, identity=identity):
                    r = self.preflight(db, identity, profile=profile)
                    self.assertNotEqual(r.returncode, 0)
                    self.assertIn('up to 6, but 1 rule(s) of schema 7 exist', r.stderr)
                    self.assertNotIn('Candidate preflight failed', r.stderr)

    def test_preflight_declaration_failures(self):
        db = self.db({'schema': 7})
        for identity, manifest, message in [({'max_rule_schema': 7}, {'max_rule_schema': 6}, 'differs'), ({'max_rule_schema': 0}, None, 'invalid'),
                                            ({'max_rule_schema': '7'}, None, 'invalid'), ('not json', None, 'output invalid'), ('[7]', None, 'output invalid')]:
            with self.subTest(identity=identity, manifest=manifest):
                r = self.preflight(db, identity, manifest)
                self.assertNotEqual(r.returncode, 0)
                self.assertIn(message, r.stderr)

    def test_preflight_supported_schema_monitoring_passes_and_others_still_run_firewall_checks(self):
        db = self.db({'schema': 7})
        ok = self.preflight(db, {'max_rule_schema': 7}, {'max_rule_schema': 7})
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertIn('firewall checks not needed for monitoring', ok.stdout)
        # The fake candidate refuses `doctor`: the guard passed and firewall checks still ran.
        both = self.preflight(db, {'max_rule_schema': 7}, profile='both')
        self.assertNotEqual(both.returncode, 0)
        self.assertIn('Candidate preflight failed', both.stderr)

    def test_stage_install_checks_staged_candidate_before_candidate_installer(self):
        s = m.STAGE_INSTALL
        self.assertTrue(s.startswith(m.SCHEMA_GUARD))
        hashed = s.index("raise RuntimeError('Staged bundle hash mismatch')")
        check = s.index('require_rule_schemas(RULES_DB, candidate_rule_schema(declared_rule_schema(fd), manifest))')
        staged = s.index("(stage / 'flowgate').read_bytes()")
        installer = s.index("str(stage / 'install-monitoring.py')")
        self.assertLess(hashed, staged)
        self.assertLess(staged, check)
        self.assertLess(check, installer)
        compile(s, 'STAGE_INSTALL', 'exec')

    def test_host_preflight_runs_for_monitoring_and_forwards_manifest_ceiling(self):
        for listed, expected in [({'max_rule_schema': 7}, {'max_rule_schema': 7}), ({}, {})]:
            manifest = dict(source='new', files={'flowgate': 'h'}, **listed)
            host = m.Host()
            host.install_payload = json.dumps({'files': {'flowgate': base64.b64encode(b'x').decode(), 'manifest.json': base64.b64encode(json.dumps(manifest).encode()).decode()}})
            with patch.object(m.Host, 'privileged') as privileged:
                host.preflight(None, 'monitoring')
            operation, source, payload = privileged.call_args.args
            self.assertEqual((operation, source), ('preflight', m.STAGE_PREFLIGHT))
            sent = json.loads(payload)
            self.assertEqual((sent['profile'], sent['manifest'], sent['sha256']), ('monitoring', expected, 'h'))

    def test_installer_copy_matches_shared_guard(self):
        spec = importlib.util.spec_from_file_location('installer_guard', ROOT / 'scripts/install-monitoring.py')
        installer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(installer)
        g = self.guard()
        fixtures = [self.db(), self.db({'id': 'x'}, {'schema': 4}), self.db({'schema': 7}), self.db({'schema': 9}, {'schema': 7}),
                    self.db('{bad'), self.db({'schema': True}), self.db(table=False), self.dir / 'absent.db']
        for db in fixtures:
            for ceiling in (6, 7, 8):
                with self.subTest(db=db.name, ceiling=ceiling):
                    outcomes = []
                    for check in (lambda: g['require_rule_schemas'](str(db), ceiling), lambda: installer.require_rule_schemas(db, ceiling)):
                        try:
                            check()
                            outcomes.append(None)
                        except RuntimeError as error:
                            outcomes.append(str(error))
                    self.assertEqual(outcomes[0], outcomes[1])
        for listed, ceiling in [({}, 6), ({'max_rule_schema': 7}, 7)]:
            self.assertEqual(installer.manifest_rule_schema(listed), ceiling)
            self.assertEqual(g['candidate_rule_schema'](None if not listed else 7, listed), ceiling)
        for bad in (0, 65, '7', True):
            with self.assertRaisesRegex(RuntimeError, 'invalid'):
                installer.manifest_rule_schema({'max_rule_schema': bad})


class LoginStartup(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT / '.workspace')
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.environment = patch.dict(os.environ, XDG_CONFIG_HOME=str(self.root / 'config'))
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.entry = m.login_entry_path()

    def test_opt_in_refresh_and_disabled_preference(self):
        m.configure_login_start(self.root / 'old')
        self.assertFalse(self.entry.exists())
        m.configure_login_start(self.root / 'old', enable=True)
        self.assertIn(str(self.root / 'old/launch-ui'), self.entry.read_text())
        self.entry.write_text(self.entry.read_text() + 'Hidden=true\n')
        m.configure_login_start(self.root / 'new')
        self.assertIn(str(self.root / 'new/launch-ui'), self.entry.read_text())
        self.assertIn('Hidden=true', self.entry.read_text())
        m.configure_login_start(self.root / 'new', enable=True)
        self.assertNotIn('Hidden=', self.entry.read_text())
        self.assertNotIn('WAYLAND_DISPLAY', self.entry.read_text())
        self.assertNotIn('host-start', self.entry.read_text())

    def test_unmanaged_and_symlink_left_unchanged(self):
        self.entry.parent.mkdir(parents=True)
        self.entry.write_text('[Desktop Entry]\nName=Custom\n')
        before = self.entry.read_bytes()
        m.configure_login_start(self.root)
        with self.assertRaisesRegex(ValueError, 'unmanaged'):
            m.configure_login_start(self.root, enable=True)
        self.assertEqual(self.entry.read_bytes(), before)
        self.entry.unlink()
        target = self.root / 'other'; target.write_text('untouched')
        self.entry.symlink_to(target)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            m.configure_login_start(self.root, enable=True)
        self.assertEqual(target.read_text(), 'untouched')

    def test_desktop_exec_reserved_characters(self):
        bundle = self.root / 'space $cash `tick` "quote" %field \\slash'
        content = m.login_entry(bundle)
        self.assertIn('%%field', content)
        self.assertIn('\\\\$cash', content)
        self.entry.parent.mkdir(parents=True)
        self.entry.write_text(content)
        subprocess.run(['desktop-file-validate', str(self.entry)], check=True)

    def test_root_and_invalid_configuration_refused(self):
        with patch.object(m.os, 'getuid', return_value=0), self.assertRaisesRegex(ValueError, 'desktop user'):
            m.configure_login_start(self.root, enable=True)
        with patch.dict(os.environ, XDG_CONFIG_HOME='relative'), self.assertRaisesRegex(ValueError, 'absolute'):
            m.configure_login_start(self.root, enable=True)


if __name__ == '__main__':
    unittest.main()
