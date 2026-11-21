// About shows the GUI identity verified against its own bundle manifest;
// the daemon build is compared only. No package version or launch time is used.
const { test } = require('node:test'),
  assert = require('node:assert/strict'),
  fs = require('node:fs'),
  path = require('node:path'),
  crypto = require('node:crypto');
const { readGuiBuild } = require('../dist/test/gui-build.cjs');
const { headerVersion, parseDaemonBuild, formatBuildTime } = require('../dist/test/build-info.cjs');
const A = 'a'.repeat(40), B = 'b'.repeat(40);
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
function bundle(t, { manifest = true, builtAt = '2026-10-23T17:51:09Z', source = A, tamper = false, extra = {} } = {}) {
  // Entries hash with 64-hex digests; built_at null means 'not recorded'.
  const root = fs.mkdtempSync(path.resolve(__dirname, '../../.workspace/build-info-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const files = { 'electron/dist/main.cjs': 'main', 'electron/package.json': '{"version":"0.1.0"}', 'backend/flowgate': 'daemon' };
  for (const [n, c] of Object.entries(files)) { fs.mkdirSync(path.dirname(path.join(root, n)), { recursive: true }); fs.writeFileSync(path.join(root, n), c); }
  if (manifest) fs.writeFileSync(path.join(root, 'matched-manifest.json'), JSON.stringify({ source, ...(builtAt ? { built_at: builtAt } : {}), files: { ...Object.fromEntries(Object.entries(files).map(([n, c]) => [n, sha(c)])), ...extra } }));
  if (tamper) fs.writeFileSync(path.join(root, 'electron/dist/main.cjs'), 'changed');
  return path.join(root, 'electron');
}
test('a release bundle whose GUI files match is verified with its build time', (t) => {
  assert.deepEqual(readGuiBuild(bundle(t)), { state: 'verified', source: A, builtAt: '2026-10-23T17:51:09Z', reason: 'GUI files match the release manifest.' });
  const older = readGuiBuild(bundle(t, { builtAt: null })); // bundles prepared before built_at existed
  assert.equal(older.state, 'verified');
  assert.equal(older.builtAt, undefined);
  assert.equal(readGuiBuild(bundle(t, { builtAt: 'yesterday' })).builtAt, undefined);
});
test('changed, missing or unidentified GUI files are not shown as a release', (t) => {
  assert.equal(readGuiBuild(bundle(t, { tamper: true })).state, 'unverified');
  assert.equal(readGuiBuild(bundle(t, { source: 'not-a-revision' })).state, 'unverified');
  assert.equal(readGuiBuild(bundle(t, { extra: { 'electron/dist/missing.js': sha('x') } })).state, 'unverified');
  assert.equal(readGuiBuild(bundle(t, { extra: { 'electron/../../outside': sha('x') } })).state, 'unverified');
  assert.equal(readGuiBuild(bundle(t, { manifest: false })).state, 'unavailable'); // development run
});
test('malformed, unreadable or escaping manifests are unverified; only an absent one is unavailable', (t) => {
  const app = bundle(t), root = path.dirname(app), manifest = path.join(root, 'matched-manifest.json');
  for (const bad of ['null', '[]', '"text"', '{"source":"' + A + '","files":[]}', '{"source":"' + A + '","files":null}', '{not json']) {
    fs.writeFileSync(manifest, bad);
    assert.equal(readGuiBuild(app).state, 'unverified', bad);
  }
  fs.writeFileSync(manifest, '{"source":"' + A + '","files":{}}' + ' '.repeat(4 * 1024 * 1024));
  assert.match(readGuiBuild(app).reason, /size bound/);
  fs.rmSync(manifest);
  fs.mkdirSync(manifest); // exists but cannot be read as a file
  assert.equal(readGuiBuild(app).state, 'unverified');
});
test('a symlinked GUI entry pointing outside the application is unverified', (t) => {
  const app = bundle(t), root = path.dirname(app);
  const outside = path.join(root, 'backend/flowgate');
  fs.rmSync(path.join(app, 'dist/main.cjs'));
  fs.symlinkSync(outside, path.join(app, 'dist/main.cjs')); // same bytes as the listed hash would need
  const m = JSON.parse(fs.readFileSync(path.join(root, 'matched-manifest.json')));
  m.files['electron/dist/main.cjs'] = sha('daemon');
  fs.writeFileSync(path.join(root, 'matched-manifest.json'), JSON.stringify(m));
  assert.match(readGuiBuild(app).reason, /outside its application/);
});
test('daemon build parsing is fail-soft and accepts source or revision', () => {
  assert.deepEqual(parseDaemonBuild({ source: B, modified: false }), { source: B, modified: false });
  assert.deepEqual(parseDaemonBuild({ revision: B, modified: true }), { source: B, modified: true });
  for (const bad of [undefined, null, [], 'x', { source: 'short' }, {}]) assert.equal(parseDaemonBuild(bad), undefined);
});
test('About shows the GUI version, date, time and zone alongside the daemon revision', () => {
  const gui = { state: 'verified', source: A, version: '0.1.0-rc.7', builtAt: '2026-10-23T17:51:09Z', reason: 'ok' };
  // Explicit locales: no assumption about the system's 12/24-hour clock.
  const same = headerVersion(gui, { source: A, modified: false }, 'UTC', 'de-DE');
  assert.equal(same.text, 'aaaaaaa · built 23.10.2026, 17:51 UTC');
  assert.match(headerVersion(gui, undefined, 'UTC', 'en-US').text, /^aaaaaaa · built 10\/23\/2026, 05:51 PM UTC$/);
  // System locale: date, time and zone are all present, whatever the clock style.
  const parts = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', timeZone: 'UTC' }).formatToParts(new Date('2026-10-23T17:51:09Z'));
  const sys = headerVersion(gui, undefined, 'UTC').text;
  for (const p of parts.filter((p) => p.type === 'hour' || p.type === 'minute')) assert.ok(sys.includes(p.value), p.type + ' in ' + sys);
  assert.ok(sys.includes('2026') && sys.includes('UTC'), sys);
  assert.equal(same.mismatch, false);
  assert.match(same.title, /Version: 0\.1\.0-rc\.7/);
  assert.match(same.title, /GUI revision: a{40}/);
  assert.match(same.title, /Built: 23\.10\.2026, 17:51 UTC/);
  assert.match(same.title, /Daemon build: b{0}a{40}/);
  const other = headerVersion(gui, { source: B, modified: true }, 'UTC');
  assert.equal(other.mismatch, true);
  assert.match(other.text, /daemon bbbbbbb · daemon modified$/);
  assert.match(headerVersion({ ...gui, builtAt: undefined }, undefined, 'UTC').text, /^aaaaaaa · build time unavailable$/);
  assert.match(headerVersion(gui, undefined, 'UTC').title, /Daemon build: unavailable/);
});
test('unverified or unavailable GUI identity never shows a version or the package number', () => {
  for (const [g, text] of [[{ state: 'unverified', reason: 'x' }, 'unverified build'], [{ state: 'unavailable', reason: 'dev' }, 'version unavailable'], [undefined, 'version …']]) {
    const v = headerVersion(g, { source: B, modified: false }, 'UTC');
    assert.equal(v.text, text);
    assert.equal(v.mismatch, false); // a daemon build is never shown as the GUI's
    assert.doesNotMatch(v.text, /0\.1\.0|bbbbbbb/);
  }
});
test('About shows both package versions, including a development build of the same source', (t) => {
  const app = bundle(t), manifest = path.join(path.dirname(app), 'matched-manifest.json');
  const version = '0.1.0-rc.8.dev-' + A.slice(0, 12);
  fs.writeFileSync(manifest, JSON.stringify({ ...JSON.parse(fs.readFileSync(manifest)), version }));
  const gui = readGuiBuild(app);
  assert.equal(gui.version, version);
  const daemon = parseDaemonBuild({ source: A, modified: false, version: '0.1.0-rc.8' });
  assert.equal(headerVersion(gui, daemon).mismatch, true);
  assert.ok(headerVersion(gui, daemon).title.includes('Version: ' + version));
  assert.match(headerVersion(gui, daemon).title, /Daemon version: 0\.1\.0-rc\.8\n/);
  assert.equal(headerVersion(gui, { ...daemon, version }).mismatch, false);
});
