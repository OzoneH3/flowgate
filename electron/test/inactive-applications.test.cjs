// Not-running applications that stored rules name are listed after all running ones.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { activityTree, inactiveApplications, flatten, executableName } = require('../dist/test/model.cjs');

const rule = (id, application, revision, executable, extra = {}) => ({
  id, version: 1, schema: 2, action: 'allow', priority: 100, disabled: false, created: '', expires: '0001-01-01T00:00:00Z', executable,
  filter: { application, revision, uid: 1000, direction: 'outgoing', protocol: '*', ...extra },
});
const app = (key, revision, executable) => ({ key, revision, name: executable.split('/').pop(), executable, kind: 'native' });
const live = (id, pid, a) => ({ id, pid, start_ticks: String(pid), uid: 1000, executable: a.executable, application: a });
const sock = (id, owner, remote) => ({ id, owners: [owner], ownership_category: 'visible-holder', state: 'established', socket: { protocol: 'tcp', local: '10.0.0.2:1', remote, state: 1 }, traffic: { available: false } });

test('rules for programs that are not running produce inactive rows at the bottom', () => {
  const firefox = app('kf', 'rf', '/usr/lib/firefox/firefox');
  const activity = { processes: { p1: live('p1', 10, firefox) }, rows: [sock('s1', 'p1', '1.1.1.1:443')] };
  const rules = [
    rule('r1', 'kf', 'rf', '/usr/lib/firefox/firefox'), // running: no inactive row
    rule('r2', 'kc', 'rc', '/usr/bin/curl'),
    rule('r3', 'kc', 'rc', '/usr/bin/curl', { direction: 'incoming' }), // same app: one row, 2 rules
    rule('r4', 'kh', 'rh', '/usr/lib/heroic-games-launcher/app.asar'),
    rule('r5', 'kf', 'r-old', '/usr/lib/firefox/firefox'), // earlier version of a running program
    rule('r6', '', '', '', { all_programs: true, network_zone: 'local' }), // no application: never listed
  ];
  const roots = activityTree(activity, rules);
  const inactive = roots.filter((r) => r.inactive);
  assert.deepEqual(inactive.map((r) => r.label), ['curl', 'firefox', 'heroic-games-launcher']);
  assert.equal(inactive.find((r) => r.label === 'curl').inactive.rules, 2);
  assert.equal(inactive.find((r) => r.label === 'firefox').inactive.earlierVersion, true);
  assert.equal(inactive.find((r) => r.label === 'firefox').id, 'app:kf|r-old|uid:1000');
  for (const r of inactive) assert.deepEqual([r.rows.length, r.children.length, r.process], [0, 0, undefined]);
  // Bottom in every sort order and direction.
  for (const key of ['name', 'download_bps', 'count'])
    for (const desc of [false, true]) {
      const order = flatten(roots, new Set(), key, desc).map((x) => !!x.row.inactive);
      assert.deepEqual(order, [...order].sort((a, b) => a - b), `${key} ${desc}`);
    }
});

test('search and socket filters; a running application never doubles as inactive', () => {
  const rules = [rule('r2', 'kc', 'rc', '/usr/bin/curl'), rule('r7', 'kw', 'rw', '/usr/bin/wget')];
  const running = [{ id: 'app:kw|rw|uid:1000', kind: 'application', label: 'wget', rows: [], children: [] }];
  assert.deepEqual(inactiveApplications(rules, running).map((r) => r.label), ['curl']);
  assert.deepEqual(inactiveApplications(rules, [], 'wge').map((r) => r.label), ['wget']);
  assert.deepEqual(inactiveApplications(rules, [], '', 'active'), [], 'Active/Listening filters show sockets only');
  assert.deepEqual(inactiveApplications(undefined, []), []);
  assert.equal(executableName('/usr/lib/heroic-games-launcher/app.asar'), 'heroic-games-launcher');
  assert.equal(executableName('/usr/bin/curl (deleted)'), 'curl');
});

test('process rows show an inherited application rule muted and not interactive', () => {
  const fs = require('node:fs'), path = require('node:path');
  const src = fs.readFileSync(path.join(__dirname, '../src/renderer.ts'), 'utf8');
  assert.match(src, /if \(inherited\) \{\n\s*button\.classList\.add\('policy-inherited'\);\n\s*button\.disabled = true;/);
  assert.match(src, /button\.title = inherited\n\s*\? ''/, 'no tooltip on inherited cells');
  assert.match(src, /event\.stopPropagation\(\);\n\s*if \(inherited\) return;/, 'no click on inherited cells');
  // Not running: its own stored-rules popup, never the quick setter (that would create rules).
  assert.match(src, /if \(r\.inactive\) \{\n\s*const status = ruleStatus\(r, state\);\n\s*openInactiveRules\(button,[\s\S]*?\n\s*return;\n\s*\}/);
  const css = fs.readFileSync(path.join(__dirname, '../src/style.css'), 'utf8');
  assert.match(css, /\.policy-cell\.policy-inherited \{[^}]*pointer-events:none/);
});

test('same name, different programs show where they live; older revisions are marked', () => {
  const { inactiveApplications, shortLocation } = require('../dist/test/model.cjs');
  const r = (id, application, revision, executable, created) => ({ ...rule(id, application, revision, executable), created });
  const rows = inactiveApplications([
    r('a', 'k1', 'r1', '/home/u/.vscode-oss/extensions/openai.chatgpt-26.908.40401-linux-x64/bin/linux-x86_64/codex', '2026-10-19T23:41:00Z'),
    r('b', 'k2', 'r2', '/home/u/.codex/packages/standalone/releases/0.160.0-x86_64-unknown-linux-musl/bin/codex', '2026-10-20T11:17:00Z'),
    r('c', 'kh', 'old', '/home/u/.var/app/com.hypixel.HytaleLauncher/data/Hytale/hytale-launcher', '2026-10-19T10:00:00Z'),
    r('d', 'kh', 'new', '/home/u/.var/app/com.hypixel.HytaleLauncher/data/Hytale/hytale-launcher', '2026-10-19T23:35:00Z'),
  ], []);
  const codex = rows.filter((x) => x.label === 'codex');
  assert.equal(codex.length, 2);
  assert.ok(codex.every((x) => x.inactive.where && !x.inactive.earlierVersion), 'different programs: located, not "earlier"');
  assert.notEqual(codex[0].inactive.where, codex[1].inactive.where);
  const hy = rows.filter((x) => x.label === 'hytale-launcher');
  assert.deepEqual(hy.map((x) => [x.inactive.revision, x.inactive.earlierVersion]).sort(), [['new', false], ['old', true]]);
  assert.equal(shortLocation('/home/u/.codex/packages/standalone/releases/0.160.0-x86_64-unknown-linux-musl/bin/codex'), '~/…/0.160.0-x86_64-unknown-linux-musl/bin');
});

test('not-running rules popup: reviewed in-place edits only, delete via the confirmed path', () => {
  const fs = require('node:fs'), path = require('node:path');
  const src = fs.readFileSync(path.join(__dirname, '../src/inactive-rules.ts'), 'utf8');
  // Edits are pinned to the listed version and saved only when the backend reviewed exactly that change.
  assert.match(src, /draft\.rule\.version !== rule\.version/);
  assert.match(src, /v\.id !== rule\.id \|\| v\.action !== action \|\| v\.disabled !== disabled/);
  assert.match(src, /expiry: 'preserve'/);
  // Uncertain saves are never reported as success.
  assert.match(src, /result\.phase === 'unknown'\) return 'Save result unknown/);
  assert.match(src, /confirmRuleDelete\(rule, o\.generation\)/);
  // No creation path: no ruleDraft for a new source, only by id.
  assert.ok(!/ruleDraft\(\{ ?(kind|observed|process)/.test(src));
});
