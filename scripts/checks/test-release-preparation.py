#!/usr/bin/env python3
"""Exercise release CLI/manifest/failure behavior with a fake toolchain; no install."""
import ast
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
REVISION = 'a' * 40
TOOL = r'''#!/usr/bin/python3
import json,os,pathlib,sys
name=pathlib.Path(sys.argv[0]).name
args=sys.argv[1:]
with open(os.environ['TOOL_LOG'],'a') as log: log.write(json.dumps([name,*args])+'\n')
if name=='git':
 if args[:2]==['branch','--show-current']:print('master')
 elif args[:2]==['rev-parse','HEAD']:print('a'*40)
 elif args[:1]==['diff'] and os.environ.get('FAKE_DIRTY'):sys.exit(1)
elif name=='go' and args[:1]==['test']:
 if os.environ.get('FAKE_GO_FAIL'):sys.exit(93)
 print('fixture-only test result')
elif name in ('go','clang','cc') and '-o' in args:
 out=pathlib.Path(args[args.index('-o')+1]);out.parent.mkdir(parents=True,exist_ok=True)
 out.write_bytes(('fixture '+name+' '+' '.join(args)).encode());out.chmod(0o755)
elif name=='bpftool':print('/* fixture header */')
elif name in ('sudo','systemctl','nft'):raise RuntimeError('Forbidden host action')
'''

class Preparation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / '.workspace')
        self.root = Path(self.temp.name)
        names = ['scripts/prepare-release.sh', 'scripts/build.sh', 'scripts/go-env.sh',
                 'scripts/lib/update_and_start.py', 'scripts/lib/build_progress.py', 'scripts/install-monitoring.py', 'scripts/host-daily-acceptance.py',
                 'deployment/launch', 'deployment/control.py', 'deployment/recover.py', 'deployment/uninstall.py',
                 'deployment/systemd/flowgate.service', 'deployment/systemd/flowgate-guard.service',
                 'deployment/systemd/50-flowgate-guard.conf', 'docs/PROTON-LAUNCHER-REGRESSION.md',
                 'docs/AUTOMATIC-ZONES.md', 'electron/AUTOMATIC-ZONES.md', 'electron/PROMPT-PRESENTATION.md',
                 'electron/REMEMBER-REVALIDATION.md', 'electron/fontconfig_isolation.py', 'internal/identity/data/iana-special.json']
        for name in names:
            destination = self.root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, destination)
        lab = self.root / 'scripts/lab.sh'
        lab.write_text('#!/bin/sh\nexec "$@"\n'); lab.chmod(0o755)
        for name in ['electron/dist/index.html', 'electron/package.json', 'electron/node_modules/electron/dist/electron']:
            destination = self.root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text('fixture')
        tools = self.root / 'tools'; tools.mkdir()
        for name in ['git', 'go', 'clang', 'cc', 'bpftool', 'pkg-config', 'npm', 'node', 'file', 'sudo', 'systemctl', 'nft']:
            path = tools / name; path.write_text(TOOL); path.chmod(0o755)
        self.log = self.root / 'tool-log.jsonl'
        self.env = dict(os.environ, PATH=str(tools) + ':' + os.environ['PATH'], TOOL_LOG=str(self.log), PYTHONDONTWRITEBYTECODE='1')
        self.backend = self.root / '.workspace/daily-releases' / REVISION
        self.gui = self.root / '.workspace/automatic-zone-releases' / REVISION
    def tearDown(self): self.temp.cleanup()
    def prepare(self, *args, **env):
        return subprocess.run(['sh', 'scripts/prepare-release.sh', *args], cwd=self.root, env=dict(self.env, **env), text=True, capture_output=True)
    def calls(self): return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []
    def assert_manifest(self, directory, name):
        manifest = json.loads((directory / name).read_text())
        self.assertEqual(manifest['source'], REVISION)
        for filename, expected in manifest['files'].items():
            self.assertEqual(hashlib.sha256((directory / filename).read_bytes()).hexdigest(), expected, filename)
        return manifest
    def test_backend_only_prepares_without_gui_or_privileged_commands(self):
        self.backend.mkdir(parents=True)
        (self.backend / 'install.py').write_text('stray retired installer must not ship')
        result = self.prepare('--backend-only')
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest = self.assert_manifest(self.backend, 'manifest.json')
        self.assertIn('install-monitoring.py', manifest['files'])
        # Every produced/copied artifact belongs to the root transfer manifest;
        # only the manifest itself and deliberately injected junk are excluded.
        artifacts = {p.name for p in self.backend.iterdir() if p.is_file()} - {'manifest.json', 'install.py'}
        self.assertEqual(set(manifest['files']), artifacts)
        launch = ast.parse((ROOT / 'deployment/launch').read_text())
        helpers = {node.right.value for node in ast.walk(launch)
                   if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div)
                   and isinstance(node.left, ast.Name) and node.left.id == 'here'
                   and isinstance(node.right, ast.Constant) and isinstance(node.right.value, str)}
        self.assertTrue(helpers <= set(manifest['files']), helpers - set(manifest['files']))
        self.assertIn('wine-owner-observer.exe', helpers)
        self.assertNotIn('install.py', manifest['files'])
        self.assertFalse(self.gui.exists())
        self.assertFalse(any(call[0] in ('npm', 'sudo', 'systemctl', 'nft') for call in self.calls()))
    def test_full_bundle_can_be_reused_only_after_hash_verification(self):
        first = self.prepare()
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertIn('10/10 Package matched release — done', first.stdout)
        self.assertIn('1/10 Build daemon', first.stderr)
        self.assert_manifest(self.gui, 'matched-manifest.json')
        self.assert_manifest(self.gui / 'backend', 'manifest.json')
        # The GUI launcher's Fontconfig helper ships hashed with the bundle.
        matched = json.loads((self.gui / 'matched-manifest.json').read_text())
        self.assertIn('fontconfig_isolation.py', matched['files'])
        self.assertIn('fontconfig_isolation.py', (self.gui / 'launch-ui').read_text())
        before = self.calls()
        result = self.prepare()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any(call[0] in ('go','npm','clang','cc') for call in self.calls()[len(before):]))
        (self.backend / 'flowgate').write_bytes(b'tampered')
        result = self.prepare()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('hash mismatch', result.stderr)
    def test_individually_valid_bundles_must_also_match_each_other(self):
        result = self.prepare()
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest = json.loads((self.backend / 'manifest.json').read_text())
        (self.backend / 'flowgate').write_bytes(b'other valid build')
        manifest['files']['flowgate'] = hashlib.sha256(b'other valid build').hexdigest()
        (self.backend / 'manifest.json').write_text(json.dumps(manifest))
        result = self.prepare()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('bundles differ', result.stderr)

    def test_failed_check_never_publishes_a_manifest(self):
        result = self.prepare(FAKE_GO_FAIL='1')
        self.assertEqual(result.returncode, 93)
        self.assertIn('6/10 Isolated race and receiver checks', result.stderr)
        self.assertIn('FAILED', result.stderr)
        self.assertIn('Build log:', result.stderr)
        self.assertFalse((self.backend / 'manifest.json').exists())
        self.assertFalse((self.gui / 'matched-manifest.json').exists())
    def test_invalid_build_request_is_refused_before_any_target_runs(self):
        result = subprocess.run(['sh', 'scripts/build.sh', 'desktop', 'typo'], cwd=self.root, env=self.env, capture_output=True)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.calls(), [])
    def test_dirty_checkout_refused_before_build(self):
        result = self.prepare(FAKE_DIRTY='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call[0] == 'go' for call in self.calls()))

if __name__ == '__main__': unittest.main(verbosity=2)
