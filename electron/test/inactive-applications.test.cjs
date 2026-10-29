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
  const group = roots.find(r => r.kind === 'inactive-group');
  const inactive = group.children;
  assert.equal(group.label, 'Not running (2)');
  assert.ok(inactive.every(r => r.parent === group.id));
  assert.equal(flatten(roots,new Set(),'name',false).some(x=>x.row.inactive),false);
  assert.equal(flatten(roots,new Set([group.id]),'name',false).filter(x=>x.row.inactive).length,2);
  assert.deepEqual(inactive.map((r) => r.label), ['curl', 'heroic-games-launcher']);
  assert.equal(inactive.find((r) => r.label === 'curl').inactive.rules, 2);
  // Earlier saved version of a running program: folded into its details, no child row.
  const running = roots.find(r => r.id === 'app:kf|rf|uid:1000');
  assert.equal(running.children.some(r => r.inactive), false);
  assert.deepEqual(running.foldedVersions.map(v => [v.revision, v.earlierVersion]), [['r-old', true]]);
  for (const r of inactive) assert.deepEqual([r.rows.length, r.children.length, r.process], [0, 0, undefined]);
  // Bottom in every sort order and direction.
  for (const key of ['name', 'download_bps', 'count'])
    for (const desc of [false, true]) {
      const order = flatten(roots, new Set(), key, desc).map((x) => x.row.kind === 'inactive-group');
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
  // Not running: stored identity popup, without a live observed target.
  assert.match(src, /if \(r\.inactive\) \{\n\s*showInactiveRules\(button, r, direction\);\n\s*return;\n\s*\}/);
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
  // The edit is built from the normalized draft and the reviewed scope must equal it (no widening).
  assert.match(src, /const d = draft\.rule;/);
  assert.match(src, /v\.action !== action \|\| v\.disabled !== disabled \|\| v\.schema !== editedSchema\(d\) \|\| scopeKey\(v\) !== scopeKey\(d\)/);
  assert.match(src, /expiry: 'preserve'/);
  // Uncertain saves are never reported as success.
  assert.match(src, /result\.phase === 'unknown'\) return 'Save result unknown/);
  assert.match(src, /confirmRuleDelete\(rule, o\.generation\)/);
  // No creation path: no ruleDraft for a new source, only by id.
  assert.ok(!/ruleDraft\(\{ ?(kind|observed|process)/.test(src));
});


test('script context survives inactive listing without changing interpreter identity', () => {
  const r = rule('script','python-key','rev','/usr/bin/python3');
  r.invocation = {mode:'file',name:'alpha.py',path:'/tools/alpha.py',revision:'script-rev'};
  const rows = inactiveApplications([r], []);
  assert.equal(rows[0].label, 'alpha.py via python3');
  assert.equal(rows[0].id, 'app:python-key|rev|uid:1000');
  assert.match(rows[0].identityNote, /Shared interpreter/);
  assert.equal(inactiveApplications([r], [], 'alpha').length, 1);
  const other = {...r,id:'other',invocation:{...r.invocation,name:'beta.py',path:'/tools/beta.py'}};
  assert.equal(inactiveApplications([r,other],[])[0].label,'python3', 'mixed script contexts must not look script-scoped');
  assert.equal(inactiveApplications([{...r,invocation:undefined}],[])[0].label,'python3', 'legacy rule has no invented script');
});

test('saved revisions share one program root; different identities remain visibly separate', () => {
  const old = {...rule('old','same','v1','/opt/tool'),created:'2025-01-01'};
  const next = {...rule('new','same','v2','/opt/tool'),created:'2026-01-01'};
  const tree = activityTree({processes:{},rows:[]},[old,next])[0].children;
  assert.equal(tree.length,1);
  assert.equal(tree[0].inactive.revision,'v2');
  assert.equal(tree[0].children.length,0,'no separate earlier-version row');
  assert.deepEqual(tree[0].foldedVersions.map(v=>v.revision),['v1']);
  const distinct = activityTree({processes:{},rows:[]},[old,rule('second','other','v1','/other/tool')])[0].children;
  assert.equal(distinct.length,2);
  const users = activityTree({processes:{},rows:[]},[old,rule('another-user','same','v1','/opt/tool',{uid:1001})])[0].children;
  assert.equal(users.length,1, 'accounts share a visual program');
  assert.equal(users[0].kind,'program');
  assert.deepEqual(users[0].children.map(r=>r.inactive.uid),[1000,1001]);
  assert.equal(users[0].inactive,undefined, 'wrapper has no rule target');
  assert.ok(distinct.every(r=>r.identityNote.includes('UID 1000') && r.identityNote.includes(r.inactive.executable)));
});


test('one executable across three accounts has one visual root and intact targets', () => {
  const rules = [1000,0,970].map(uid => rule(`r${uid}`,`key${uid}`,'v1','/usr/bin/tool',{uid}));
  const tree = activityTree({processes:{},rows:[]},rules)[0].children;
  assert.equal(tree.length,1);
  const group = tree[0];
  assert.equal(group.kind,'program');
  assert.equal(group.label,'tool');
  assert.equal(group.program.inactive,true);
  assert.equal(group.process,undefined);
  assert.equal(group.displayApplication,undefined);
  assert.equal(group.requestEvent,undefined);
  assert.deepEqual(group.children.map(r=>r.id).sort(),[1000,0,970].map(uid=>`app:key${uid}|v1|uid:${uid}`).sort());
  assert.equal(group.children.find(r=>r.inactive.uid===0).presentationLabel,'User UID 0');
  assert.ok(group.children.every(r=>r.parent===group.id));
  const different = activityTree({processes:{},rows:[]},[...rules,rule('else','else','v1','/other/tool')])[0].children;
  assert.equal(different.length,2,'same basename elsewhere is not the same program');
});

test('mixed running and saved accounts keep observed traffic on their original children', () => {
  const a = app('user-key','v1','/usr/bin/tool');
  const socket = sock('s','p','1.2.3.4:443');
  const tree = activityTree({processes:{p:live('p',10,a)},rows:[socket]},[rule('root','root-key','v1',a.executable,{uid:0})]);
  assert.equal(tree.length,1);
  assert.equal(tree[0].program.inactive,false);
  assert.deepEqual(tree[0].rows.map(r=>r.id),['s']);
  assert.equal(tree[0].children[0].process.application.key,'user-key');
  assert.equal(tree[0].children[1].inactive.key,'root-key');
});

test('computer, unidentified and inactive categories keep their order across table sorts', () => {
  const {overview}=require('../dist/test/model.cjs');
  const computer=overview({rows:[]},[],'user@host');
  assert.equal(computer.label,'user@host');
  const roots=[{id:'inactive-applications',kind:'inactive-group',label:'Not running',rows:[],children:[]},
    {id:'unidentified',kind:'unidentified',label:'Unidentified',rows:[],children:[]},computer];
  for(const key of ['name','download_bps','count']) for(const desc of [false,true])
    assert.deepEqual(flatten(roots,new Set(),key,desc).map(x=>x.row.id),['overview','unidentified','inactive-applications']);
});


// Daemon-reported follows_updates (never derived here). Two synthetic Windows
// programs in two prefixes plus a native one; versions fold per key+UID only.
test('rules following updates fold per program/user; no transfer across programs, prefixes or users', () => {
  const { inactiveRuleMatches } = require('../dist/test/model.cjs');
  const follow = (id, key, rev, exe, extra = {}, created = '2026-01-01') => ({ ...rule(id, key, rev, exe, extra), created, follows_updates: true });
  const pinned = (id, key, rev, exe, extra = {}, created = '2025-01-01') => ({ ...rule(id, key, rev, exe, extra), created });
  const rules = [
    follow('a-new', 'wine-a-prefix1', 'a2', '/games/p1/drive_c/AppA/a.exe'),
    pinned('a-old', 'wine-a-prefix1', 'a1', '/games/p1/drive_c/AppA/a.exe'),
    follow('a-p2', 'wine-a-prefix2', 'a2', '/games/p2/drive_c/AppA/a.exe'),
    follow('b', 'wine-b-prefix2', 'b1', '/games/p2/drive_c/AppB/b.exe'),
    follow('n', 'native-tool', 'n2', '/opt/tool/tool'),
    pinned('n-old', 'native-tool', 'n1', '/opt/tool/tool', {}, '2024-01-01'),
    follow('n-1001', 'native-tool-1001', 'n2', '/opt/tool/tool', { uid: 1001 }),
  ];
  const programs = inactiveApplications(rules, []);
  const ids = programs.map(r => r.id).sort();
  assert.deepEqual(ids, ['app:native-tool-1001|uid:1001', 'app:native-tool|n1|uid:1000', 'app:native-tool|uid:1000',
    'app:wine-a-prefix1|a1|uid:1000', 'app:wine-a-prefix1|uid:1000', 'app:wine-a-prefix2|uid:1000', 'app:wine-b-prefix2|uid:1000']);
  const tree = activityTree({ processes: {}, rows: [] }, rules)[0].children;
  const all = tree.flatMap(r => r.kind === 'program' ? r.children : [r]);
  // One row per verified identity; pinned other revision is folded, not a child row.
  const a1 = all.find(r => r.inactive.key === 'wine-a-prefix1');
  assert.equal(a1.inactive.followsUpdates, true);
  assert.deepEqual(a1.foldedVersions.map(v => [v.revision, !!v.followsUpdates]), [['a1', false]]);
  assert.equal(a1.children.length, 0);
  // Same program in another prefix, another program, another user: never folded together.
  for (const key of ['wine-a-prefix2', 'wine-b-prefix2', 'native-tool-1001'])
    assert.equal(all.filter(r => r.inactive.key === key).length, 1, key);
  assert.equal(all.length, 5);
  // Rule listing per row keeps exact scope: following rules vs the pinned revision.
  const ids2 = (i) => rules.filter(x => inactiveRuleMatches(i, x)).map(x => x.id);
  assert.deepEqual(ids2(a1.inactive), ['a-new']);
  assert.deepEqual(ids2(a1.foldedVersions[0]), ['a-old']);
  assert.deepEqual(ids2(all.find(r => r.inactive.key === 'wine-a-prefix2').inactive), ['a-p2']);
  // A running newer revision absorbs following rules; the pinned old rule is folded detail.
  const proc = live('p1', 10, { ...app('native-tool', 'n3', '/opt/tool/tool') });
  const roots = activityTree({ processes: { p1: proc }, rows: [sock('s1', 'p1', '1.1.1.1:443')] }, rules.filter(r => r.filter.application === 'native-tool'));
  assert.equal(roots.some(r => r.kind === 'inactive-group'), false);
  const runningRow = roots.find(r => r.id === 'app:native-tool|n3|uid:1000');
  assert.deepEqual(runningRow.foldedVersions.map(v => v.revision), ['n1']);
});

test('running processes of another revision of the same program fold under one row with exact identities', () => {
  const oldA = live('p1', 10, app('k', 'old', '/opt/tool/tool'));
  const newA = live('p2', 11, app('k', 'new', '/opt/tool/tool'));
  const other = live('p3', 12, app('k2', 'new', '/opt/other/tool'));
  const roots = activityTree({ processes: { p1: oldA, p2: newA, p3: other },
    rows: [sock('s1', 'p1', '1.1.1.1:443'), sock('s2', 'p2', '1.1.1.2:443'), sock('s3', 'p3', '1.1.1.3:443')] }, []);
  const apps = roots.filter(r => r.kind === 'application' || r.kind === 'program');
  const rowsFor = (k) => apps.flatMap(r => r.kind === 'program' ? r.children : [r]).filter(r => r.process?.application.key === k);
  assert.equal(rowsFor('k').length, 1, 'one program row');
  const row = rowsFor('k')[0];
  assert.deepEqual(row.revisions.sort(), ['new', 'old']);
  const procs = row.children.filter(c => c.kind === 'process');
  assert.deepEqual(procs.map(c => c.process.application.revision).sort(), ['new', 'old']);
  assert.ok(procs.every(c => c.parent === row.id));
  assert.equal(row.rows.length, 2);
  assert.equal(rowsFor('k2').length, 1, 'different identity stays separate');
});

test('follows_updates is daemon-reported, literal true only, never on process rules; rule status honours it', () => {
  const { parseRule, ruleCoversRevision } = require('../dist/test/protocol.cjs');
  const { ruleStatus } = require('../dist/test/rule-status.cjs');
  const base = { ...rule('f', 'k', 'v1', '/opt/tool/tool'), version: 1 };
  assert.equal(parseRule({ ...base, follows_updates: true }).follows_updates, true);
  assert.equal(parseRule({ ...base, follows_updates: 'true' }).follows_updates, undefined);
  assert.equal(parseRule(base).follows_updates, undefined);
  const following = parseRule({ ...base, follows_updates: true }), pinnedRule = parseRule({ ...base, id: 'p' });
  assert.equal(ruleCoversRevision(following, 'v2'), true);
  assert.equal(ruleCoversRevision(pinnedRule, 'v2'), false);
  assert.equal(ruleCoversRevision({ ...following, filter: { ...following.filter, process: { pid: 1 } } }, 'v2'), false);
  const state = (rules) => ({ control: { connected: true, serverNow: 1, rules }, observation: {} });
  const proc = (key, revision, uid = 1000) => ({ kind: 'process', process: live('p', 1, app(key, revision, '/opt/tool/tool')), rows: [], children: [], uid });
  const ids = (row, rules) => ruleStatus(row, state(rules)).outgoing.map(r => r.id);
  assert.deepEqual(ids(proc('k', 'v2'), [following, pinnedRule]), ['f'], 'pinned v1 rule does not list for v2');
  assert.deepEqual(ids(proc('other', 'v2'), [following]), [], 'never another program');
  const otherUser = { ...proc('k', 'v2'), process: { ...live('p', 1, app('k', 'v2', '/opt/tool/tool')), uid: 1001 } };
  assert.deepEqual(ids(otherUser, [following]), [], 'never another user');
});

test('adding a rule for a not-running program: same identity only; new-rule save check', () => {
  const { sameNewRule } = require('../dist/test/rules.cjs');
  const reviewed = { id: 'user:a', version: 1, created: '2026-10-23T10:00:00Z', schema: 2, action: 'block', disabled: false, priority: 100, executable: '/usr/bin/curl', expires: '0001-01-01T00:00:00Z',
    filter: { application: 'k', revision: 'r', uid: 1000, direction: 'incoming', protocol: '*', remote_address: '*' } };
  // The daemon assigns another id/creation time at save: still the same rule.
  assert.equal(sameNewRule({ ...reviewed, id: 'user:b', created: '2026-10-23T10:00:01Z' }, reviewed), true);
  assert.equal(sameNewRule({ ...reviewed, action: 'allow' }, reviewed), false);
  assert.equal(sameNewRule({ ...reviewed, filter: { ...reviewed.filter, revision: 'r2' } }, reviewed), false);
  assert.equal(sameNewRule({ ...reviewed, filter: { ...reviewed.filter, uid: 0 } }, reviewed), false);
  const fs = require('node:fs'), path = require('node:path');
  const src = fs.readFileSync(path.join(__dirname, '../src/inactive-rules.ts'), 'utf8');
  assert.match(src, /ruleDraft\(\{ basis: \{ rule: basisId, direction,/);
  assert.match(src, /v\.filter\.application !== f\.application \|\| v\.filter\.revision !== f\.revision \|\| v\.filter\.uid !== f\.uid/);
});
