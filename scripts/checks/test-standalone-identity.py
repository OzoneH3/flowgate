"""Exercise Git-derived standalone identities without building or installing."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'deployment/standalone'))
from identity import archive_path, source_identity
from package import write_archive
from release import release_id


class IdentityChecks(unittest.TestCase):
    def setUp(self):
        workspace = ROOT / '.workspace'
        workspace.mkdir(exist_ok=True)
        temp = tempfile.TemporaryDirectory(dir=workspace)
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.git('init', '-q')
        self.git('config', 'user.name', 'FlowGate tests')
        self.git('config', 'user.email', 'fixture@example.invalid')
        self.git('config', 'commit.gpgsign', 'false')
        (self.root / 'electron').mkdir()
        (self.root / 'electron/package.json').write_text(json.dumps({'version': '0.1.0'}))
        self.git('add', 'electron/package.json')
        self.git('commit', '-qm', 'first')

    def git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.root, text=True).strip()

    def identity(self):
        return source_identity(self.root, require_clean=True)

    def test_tagged_release_and_untagged_successor_have_distinct_artifacts(self):
        self.git('tag', 'flowgate-v0.1.0-rc.8')
        tagged = self.identity()
        self.assertEqual(tagged['version'], '0.1.0-rc.8')
        self.assertEqual(tagged['release'], f"0.1.0-rc.8-{tagged['source'][:12]}")
        self.git('commit', '--allow-empty', '-qm', 'successor')
        dev = self.identity()
        self.assertEqual(dev['version'], f"0.1.0-rc.8.dev-{dev['source'][:12]}")
        self.assertEqual(dev['release'], dev['version'])
        self.assertNotEqual(archive_path(dev, self.root).name, archive_path(tagged, self.root).name)
        self.assertNotEqual(archive_path(dev, self.root).parent, archive_path(tagged, self.root).parent)
        self.git('tag', 'flowgate-v0.1.0')
        self.assertEqual(self.identity()['version'], '0.1.0')
        self.git('commit', '--allow-empty', '-qm', 'after stable')
        self.assertRegex(self.identity()['version'], r'^0\.1\.0-dev-[a-f0-9]{12}$')

    def test_no_release_tag_uses_development_identity_and_invalid_tags_fail(self):
        self.git('tag', 'v9.8.7')
        self.assertRegex(self.identity()['version'], r'^0\.1\.0-dev-[a-f0-9]{12}$')
        self.git('tag', 'flowgate-v0.1')
        with self.assertRaisesRegex(RuntimeError, 'Invalid FlowGate release tag'):
            self.identity()
        self.git('tag', 'flowgate-v0.1.0')
        with self.assertRaisesRegex(RuntimeError, 'Multiple FlowGate release tags'):
            self.identity()

    def test_source_archive_cannot_borrow_parent_git(self):
        archive = self.root / 'archive'
        archive.mkdir()
        with self.assertRaisesRegex(RuntimeError, 'no Git provenance.*clean Git clone'):
            source_identity(archive)
        (self.root / 'electron/package.json').write_text('{}')
        with self.assertRaisesRegex(RuntimeError, 'tracked changes'):
            self.identity()

    def test_development_version_is_bound_to_full_source_and_legacy_id_is_valid(self):
        self.assertEqual(release_id('0.1.0-rc.8', 'a' * 40), '0.1.0-rc.8-aaaaaaaaaaaa')
        with self.assertRaisesRegex(ValueError, 'development revision'):
            release_id('0.1.0-rc.8.dev-bbbbbbbbbbbb', 'a' * 40)

    def test_archive_headers_use_source_epoch_and_stable_metadata(self):
        epoch = 1_700_000_000
        archives = []
        for n in (1, 2):
            staging = self.root / f'staging-{n}'
            staging.mkdir()
            for path in ('backend', 'gui'):
                (staging / path).mkdir(mode=0o700 if n == 1 else 0o755)
            (staging / 'release.json').write_text('{}')
            helper = staging / 'backend/helper'
            helper.write_text('fixture')
            helper.chmod(0o755)
            for path in staging.rglob('*'):
                os.utime(path, (epoch + n, epoch + n + 0.5))
            archive = self.root / f'archive-{n}.tar.gz'
            write_archive(archive, staging, epoch)
            archives.append(archive)

        first, second = (archive.read_bytes() for archive in archives)
        self.assertEqual(first, second)
        self.assertFalse(first[3] & 0x08)  # gzip filename flag
        self.assertEqual(int.from_bytes(first[4:8], 'little'), epoch)
        with tarfile.open(archives[0]) as stream:
            self.assertEqual([m.name for m in stream], ['release.json', 'backend', 'backend/helper', 'gui'])
            for member in stream.getmembers():
                self.assertEqual((member.uid, member.gid, member.uname, member.gname), (0, 0, '', ''))
                self.assertEqual(member.mtime, epoch)
                self.assertNotIn('mtime', member.pax_headers)
            self.assertEqual(stream.getmember('backend').mode, 0o755)
            self.assertEqual(stream.getmember('backend/helper').mode, 0o755)


if __name__ == '__main__':
    unittest.main()
