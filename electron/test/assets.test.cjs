const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { bundledAsset, userStylesheet } = require('../dist/test/assets.cjs');
test('bundled Selawik faces have explicit font MIME types', () => {
  for (const name of ['selawk', 'selawksb', 'selawkb'])
    assert.equal(bundledAsset(`fonts/${name}.ttf`), 'font/ttf');
  assert.equal(bundledAsset('renderer.js'), 'text/javascript');
  assert.equal(bundledAsset('flowgate.png'), 'image/png');
  assert.equal(bundledAsset('flowgate-off.png'), 'image/png');
});

test('only the two user stylesheet routes read bounded regular config files', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'flowgate-css-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const desktop = path.join(dir, 'style.css');
  const popup = path.join(dir, 'permission-popup.css');
  assert.equal(userStylesheet('user-style.css', dir), '');
  assert.equal(userStylesheet('user-permission-popup.css', dir), '');
  fs.writeFileSync(desktop, ':root { color: blue; }');
  fs.writeFileSync(popup, ':root { color: red; }');
  assert.equal(userStylesheet('user-style.css', dir), ':root { color: blue; }');
  assert.equal(userStylesheet('user-permission-popup.css', dir), ':root { color: red; }');
  for (const name of ['style.css', 'permission-popup.css', '../user-style.css', '__proto__'])
    assert.equal(userStylesheet(name, dir), undefined);
  fs.writeFileSync(desktop, Buffer.alloc(1024 * 1024 + 1));
  assert.equal(userStylesheet('user-style.css', dir), '');
  fs.unlinkSync(desktop);
  fs.symlinkSync(popup, desktop);
  assert.equal(userStylesheet('user-style.css', dir), '');
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
