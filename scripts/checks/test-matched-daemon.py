#!/usr/bin/env python3
import importlib.util
import pathlib
import hashlib
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('matched', ROOT / 'scripts/build-matched-daemon.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class Matched(unittest.TestCase):
    def setUp(self):
        (ROOT / '.workspace').mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT / '.workspace')
        self.addCleanup(self.tmp.cleanup)
        self.loader = pathlib.Path(self.tmp.name) / 'loader'
        self.loader.write_bytes(b'exact reviewed loader')
        self.out = self.loader.with_name('flowgate')
    def test_both_release_builds_pin_loader(self):
        for tags in ('', 'socketprototype'):
            with patch.object(m.subprocess, 'run') as run:
                digest = m.build(self.out, self.loader, 'a'*40, tags)
            args = run.call_args.args[0]
            self.assertEqual(digest, hashlib.sha256(self.loader.read_bytes()).hexdigest())
            self.assertIn('main.holderIteratorSHA256='+digest, args[args.index('-ldflags')+1])
            self.assertEqual('-tags' in args, bool(tags))
    def test_missing_or_empty_loader_refuses_before_build(self):
        for exists in (False, True):
            self.loader.unlink(missing_ok=True)
            if exists:self.loader.touch()
            with patch.object(m.subprocess, 'run') as run:
                with self.assertRaises((ValueError, FileNotFoundError)):
                    m.build(self.out,self.loader,'a'*40)
                run.assert_not_called()
    def test_changed_loader_discards_output(self):
        def mutate(*args, **kwargs):
            self.out.write_bytes(b'candidate');self.loader.write_bytes(b'changed')
        with patch.object(m.subprocess,'run',side_effect=mutate):
            with self.assertRaises(RuntimeError):m.build(self.out,self.loader,'a'*40)
        self.assertFalse(self.out.exists())
    def test_bad_revision_or_tags_refuse(self):
        for revision,tags in [('short',''),('a'*40,'unexpected')]:
            with patch.object(m.subprocess,'run') as run:
                with self.assertRaises(ValueError):m.build(self.out,self.loader,revision,tags)
                run.assert_not_called()

if __name__ == '__main__':unittest.main()
