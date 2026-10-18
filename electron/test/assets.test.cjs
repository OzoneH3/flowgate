const { test } = require('node:test');
const assert = require('node:assert/strict');
const { bundledAsset } = require('../dist/test/assets.cjs');
test('bundled Selawik faces have explicit font MIME types', () => {
  for (const name of ['selawk', 'selawksb', 'selawkb'])
    assert.equal(bundledAsset(`fonts/${name}.ttf`), 'font/ttf');
  assert.equal(bundledAsset('renderer.js'), 'text/javascript');
});
test('asset table rejects arbitrary files, traversal and inherited properties', () => {
  for (const name of [
    '../main.cjs',
    '/etc/passwd',
    'fonts/../main.cjs',
    'fonts/other.ttf',
    '__proto__',
    'toString',
  ])
    assert.equal(bundledAsset(name), undefined);
});
