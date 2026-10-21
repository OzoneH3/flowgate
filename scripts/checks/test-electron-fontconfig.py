#!/usr/bin/env python3
"""Private Fontconfig configuration for Electron: no host access, temp files only."""
import io
import pathlib
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'electron'))
import fontconfig_isolation as fc  # noqa: E402

SYSTEM = '''<?xml version="1.0"?>
<!DOCTYPE fontconfig SYSTEM "urn:fontconfig:fonts.dtd">
<fontconfig>
  <dir>/usr/share/fonts</dir>
  <dir prefix="xdg">fonts</dir>
  <dir>~/.fonts</dir>
  <match target="pattern"><edit name="hinting"><bool>true</bool></edit></match>
  <include ignore_missing="yes">conf.d</include>
  <cachedir>/var/cache/fontconfig</cachedir>
  <cachedir prefix="xdg">fontconfig</cachedir>
  <cachedir>~/.fontconfig</cachedir>
</fontconfig>
'''


class Isolation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT / '.workspace')
        self.addCleanup(self.tmp.cleanup)
        self.etc = pathlib.Path(self.tmp.name) / 'etc/fonts'
        (self.etc / 'conf.d').mkdir(parents=True)
        self.source = self.etc / 'fonts.conf'
        self.source.write_text(SYSTEM)
        self.cache = pathlib.Path(self.tmp.name) / 'cache'

    def test_replaces_every_cachedir_and_keeps_dirs_rules_and_absolute_includes(self):
        path = fc.private_config(self.cache, '44.9.0', self.source)
        root = ET.parse(path).getroot()
        cachedirs = [e.text for e in root.iter('cachedir')]
        self.assertEqual(cachedirs, [str(self.cache / 'flowgate-fontconfig/44.9.0/cache')])
        self.assertEqual([(e.get('prefix'), e.text) for e in root.iter('dir')],
                         [(None, '/usr/share/fonts'), ('xdg', 'fonts'), (None, '~/.fonts')])
        self.assertEqual([e.text for e in root.iter('include')], [str((self.etc / 'conf.d').resolve())])
        self.assertEqual(len(list(root.iter('match'))), 1)
        self.assertTrue((self.cache / 'flowgate-fontconfig/44.9.0/cache').is_dir())

    def test_cache_is_specific_to_runtime_version_and_generation_is_idempotent(self):
        first = fc.private_config(self.cache, '44.9.0', self.source)
        again = fc.private_config(self.cache, '44.9.0', self.source)
        other = fc.private_config(self.cache, '45.0.0', self.source)
        self.assertEqual(first, again)
        self.assertNotEqual(first.parent, other.parent)
        self.assertIn('45.0.0', str(ET.parse(other).getroot().find('cachedir').text))
        root = (self.cache / 'flowgate-fontconfig').resolve()
        for version in ['../../x y', '..', '.', '', '/etc']:
            unsafe = fc.private_config(self.cache, version, self.source)
            self.assertTrue(unsafe.resolve().is_relative_to(root), version)
            self.assertNotEqual(unsafe.parent.resolve(), root, version)

    def test_explicit_user_configuration_is_respected(self):
        for name in ('FONTCONFIG_FILE', 'FONTCONFIG_PATH'):
            env = {name: '/home/user/custom'}
            self.assertIsNone(fc.apply(env, self.cache, '44.9.0', log=io.StringIO()))
            self.assertEqual(env, {name: '/home/user/custom'})

    def test_missing_or_broken_system_configuration_leaves_environment_unchanged(self):
        self.source.unlink()
        self.assertIsNone(fc.private_config(self.cache, '44.9.0', self.source))
        self.source.write_text('<fontconfig>')
        original = fc.SYSTEM_CONFIG
        fc.SYSTEM_CONFIG = self.source
        try:
            env, log = {}, io.StringIO()
            self.assertIsNone(fc.apply(env, self.cache, '44.9.0', log=log))
            self.assertNotIn('FONTCONFIG_FILE', env)
            self.assertIn('unavailable', log.getvalue())
        finally:
            fc.SYSTEM_CONFIG = original

    def test_included_configuration_adding_cachedirs_is_reported(self):
        (self.etc / 'conf.d/90-extra.conf').write_text('<fontconfig><cachedir>/var/cache/other</cachedir></fontconfig>')
        (self.etc / 'conf.d/10-plain.conf').write_text('<fontconfig><dir>/opt/fonts</dir></fontconfig>')
        self.assertEqual(fc._included_cachedirs(self.source), [str(self.etc / 'conf.d/90-extra.conf')])
        original = fc.SYSTEM_CONFIG
        fc.SYSTEM_CONFIG = self.source
        try:
            env, log = {}, io.StringIO()
            target = fc.apply(env, self.cache, '44.9.0', log=log)
            self.assertEqual(env['FONTCONFIG_FILE'], str(target))
            self.assertIn('90-extra.conf', log.getvalue())
        finally:
            fc.SYSTEM_CONFIG = original

    def test_runtime_version_reads_electron_dist_version(self):
        dist = pathlib.Path(self.tmp.name) / 'dist'
        dist.mkdir()
        self.assertEqual(fc.runtime_version(dist), 'unknown')
        (dist / 'version').write_text('44.9.0\n')
        self.assertEqual(fc.runtime_version(dist), '44.9.0')


if __name__ == '__main__':
    if not __debug__:
        raise SystemExit('Optimized Python is unsupported: assertions would be disabled')
    unittest.main()
