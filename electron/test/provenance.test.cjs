// Launch provenance grouping and prompt permission-target text (display only).
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { hierarchy, flatten } = require('../dist/test/model.cjs');
const { parseProvenance, parsePermissionTarget } = require('../dist/test/protocol.cjs');
const { promptIdentity, targetLines, provenanceDetails, launchProcessLabel } = require('../dist/test/provenance.cjs');

const game = '/run/media/u/Games/Games/DEATH STRANDING 2 ON THE BEACH/DS2.exe';
function launch(group, launcherPid, prefix) {
  return {
    kind: 'umu',
    launcher_pid: launcherPid,
    launcher_start_ticks: '4936638',
    launcher_name: 'python3.14 umu-run',
    game: { name: 'DS2.exe', title: 'DEATH STRANDING 2: ON THE BEACH', executable: game, revision: '1:2:3:4:5', status: 'verified-file', source: 'proton waitforexitandrun argument' },
    prefix,
    prefix_id: '66:1234',
    prefix_source: 'owner Wine identity',
    runtime: 'dwproton-11.0-4',
    markers: ['wine', 'proton', 'pressure-vessel', 'umu-run'],
  };
}
const prov = (role, group = 'g-ds2', evidence = 'verified', l = launch(group, 1194845, '/home/u/Games/pfx/DS2/pfx')) =>
  parseProvenance({
    evidence,
    reason: 'unbroken parent chain (start times checked)',
    role,
    group,
    stop: 'init',
    ancestry: [
      { pid: 1197196, start_ticks: '4939000', uid: 1000, name: 'wine', executable: '/x/wine', marker: 'wine' },
      { pid: 1194845, start_ticks: '4936638', uid: 1000, name: 'python3.14 umu-run', executable: '/usr/bin/python3.14', marker: 'umu-run' },
    ],
    launch: evidence === 'verified' ? l : undefined,
  });
function proc(id, pid, name, exe, provenance, kind = 'wine') {
  return { id, pid, start_ticks: String(pid * 4), uid: 1000, executable: exe, application: { key: 'k-' + name + (provenance?.launch?.prefix || ''), revision: 'r', name, executable: exe, kind }, provenance };
}
function sock(id, owner, remote) {
  return { id, owners: [owner], ownership_category: 'visible-holder', state: 'Established', socket: { protocol: 'tcp', state: 1, local: '[::1]:46838', remote }, traffic: { available: false } };
}

test('verified helper and launcher rows sit beneath one game node; unrelated python stays separate', () => {
  const processes = {
    rundll: proc('rundll', 1195586, 'rundll32.exe', '/c/dwproton-11.0-4/files/lib/wine/x86_64-windows/rundll32.exe', prov('helper')),
    umu: proc('umu', 1194845, 'python3.14', '/usr/bin/python3.14', prov('launcher'), 'native'),
    ds2: proc('ds2', 1197196, 'DS2.exe', game, prov('game')),
    // Same interpreter, no launch provenance: never grouped by name/address.
    other: proc('other', 2000000, 'python3.14', '/usr/bin/python3.14', prov(undefined, undefined, 'none'), 'native'),
    // Chain broke (helper reparented): no group, ordinary application row.
    orphan: proc('orphan', 1195999, 'rundll32.exe', '/c/dwproton-11.0-4/files/lib/wine/x86_64-windows/rundll32.exe', prov(undefined, undefined, 'unavailable')),
  };
  const rows = [
    sock('s1', 'rundll', '[::1]:631'),
    sock('s2', 'umu', '34.126.228.17:443'),
    sock('s3', 'ds2', '34.126.228.17:443'),
    sock('s4', 'other', '34.126.228.17:443'),
    sock('s5', 'orphan', '[::1]:631'),
  ];
  const roots = hierarchy({ rows, processes });
  const launches = roots.filter((r) => r.kind === 'launch');
  assert.equal(launches.length, 1);
  const g = launches[0];
  assert.equal(g.label, 'DEATH STRANDING 2: ON THE BEACH · DS2.exe');
  assert.equal(g.process, undefined, 'a launch node is never a policy target');
  assert.equal(g.displayApplication, undefined);
  assert.deepEqual(
    g.children.map((c) => c.label).sort(),
    ['DS2.exe (game) · PID 1197196', 'python3.14 · umu-run launcher · PID 1194845', 'rundll32.exe (helper) · PID 1195586'],
  );
  assert.ok(g.children.every((c) => c.kind === 'process' && c.process && c.parent === g.id));
  assert.equal(g.rows.length, 3);
  const apps = roots.filter((r) => r.kind === 'application');
  assert.equal(apps.length, 2, 'unrelated python and the reparented helper stay separate');
  assert.ok(apps.some((a) => a.label === 'python3.14' && a.rows[0].id === 's4'));
  assert.ok(apps.some((a) => a.label === 'rundll32.exe' && a.rows[0].id === 's5'));
  // Search by game finds the helper rows.
  assert.equal(hierarchy({ rows, processes }, 'death stranding').flatMap((r) => r.rows).length, 3);
  const flat = flatten(roots, new Set([g.id]), 'name', false).map((x) => x.row.id);
  assert.ok(flat.indexOf(g.id) < flat.indexOf(g.children[0].id));
});

test('two launches of different games (different prefixes) form two groups; a relaunch is a new group', () => {
  const a = parseProvenance({ evidence: 'verified', reason: 'r', role: 'helper', group: 'A1', stop: 'init', ancestry: [], launch: { ...launch('A1', 10, '/w/pfx-a'), game: { ...launch().game, name: 'GameA.exe', title: '', executable: '/g/a/GameA.exe' } } });
  const b = parseProvenance({ evidence: 'verified', reason: 'r', role: 'helper', group: 'B1', stop: 'init', ancestry: [], launch: { ...launch('B1', 20, '/w/pfx-b'), game: { ...launch().game, name: 'GameB.exe', title: '', executable: '/g/b/GameB.exe' } } });
  const a2 = { ...a, group: 'A2', launch: { ...a.launch, launcher_pid: 30 } };
  const processes = {
    ha: proc('ha', 11, 'rundll32.exe', '/rt/rundll32.exe', a),
    hb: proc('hb', 21, 'rundll32.exe', '/rt/rundll32.exe', b),
    ha2: proc('ha2', 31, 'rundll32.exe', '/rt/rundll32.exe', a2),
  };
  const roots = hierarchy({ rows: [sock('1', 'ha', '10.0.0.1:1'), sock('2', 'hb', '10.0.0.1:1'), sock('3', 'ha2', '10.0.0.1:1')], processes });
  assert.deepEqual(roots.map((r) => r.label).sort(), ['GameA.exe', 'GameA.exe', 'GameB.exe']);
  assert.equal(new Set(roots.map((r) => r.id)).size, 3);
});

const helperTarget = parsePermissionTarget({
  kind: 'helper',
  label: 'rundll32.exe in prefix ~/Games/pfx/DS2/pfx (shared by every game using this prefix)',
  once: 'This connection request only; no rule is saved',
  for_a_while: 'This process instance only: rundll32.exe PID 1195586, same direction; a relaunch or another rundll32.exe process is not covered',
  remember: 'rundll32.exe (/c/rundll32.exe) in prefix ~/Games/pfx/DS2/pfx, UID 1000, this file revision',
  shared_with_note: 'Shared by every game using prefix ~/Games/pfx/DS2/pfx: any program there running this rundll32.exe file is covered, not only DEATH STRANDING 2: ON THE BEACH (DS2.exe)',
  key_basis: 'uid+wine+prefix+executable path; revision = file stamp',
  prefix: '/home/u/Games/pfx/DS2/pfx',
});

function event(owner, target) {
  return {
    id: 'e1', state: 'awaiting-decision', reason: 'no matching rule', deadline: new Date().toISOString(), first_seen: '', permission: '',
    flow: { direction: 'outgoing', protocol: 'tcp', local: '[::1]:46838', remote: '[::1]:631' },
    attribution: { status: 'corroborated', reason: 'one owner', visibility_complete: true, application: owner.application, owners: [owner], provenance: owner.provenance, permission_target: target },
    scope_previews: {},
  };
}

test('prompt names the verified game with a via-helper hint and states every scope before deciding', () => {
  const owner = proc('rundll', 1195586, 'rundll32.exe', '/c/rundll32.exe', prov('helper'));
  const e = event(owner, helperTarget);
  assert.deepEqual(promptIdentity(e), { title: 'DEATH STRANDING 2: ON THE BEACH · DS2.exe', via: 'via rundll32.exe' });
  const lines = targetLines(e.attribution.permission_target);
  assert.deepEqual(lines.map((l) => l.label), ['Once', 'For a while', 'Remember']);
  assert.match(lines[1].text, /process instance only: rundll32\.exe PID 1195586/);
  assert.match(lines[2].text, /^rundll32\.exe in prefix ~\/Games\/pfx\/DS2\/pfx \(shared by every game using this prefix\) — Shared by every game/);
  assert.ok(!/this game only/i.test(lines.map((l) => l.text).join(' ')));
  const details = Object.fromEntries(provenanceDetails(e));
  assert.match(details['Socket owner'], /^rundll32\.exe owns this socket\nPID 1195586 · start 4782344 · UID 1000/);
  assert.match(details.Prefix, /~\/Games\/pfx\/DS2\/pfx · inode 66:1234/);
  assert.match(details.Ancestry, /PID 1194845 · python3\.14 umu-run \[umu-run\]/);
  assert.match(details.Launch, /umu · launcher python3\.14 umu-run PID 1194845.*\nRuntime dwproton-11\.0-4/);
  // The launcher itself (case a): python3.14 · umu-run launcher.
  const launcher = proc('umu', 1194845, 'python3.14', '/usr/bin/python3.14', prov('launcher'), 'native');
  assert.deepEqual(promptIdentity(event(launcher, undefined)), { title: 'DEATH STRANDING 2: ON THE BEACH · DS2.exe', via: 'via python3.14 · umu-run launcher' });
  assert.equal(launchProcessLabel(launcher), 'python3.14 · umu-run launcher · PID 1194845');
});

test('without verified provenance the prompt keeps the owner identity (case b: ended helper, unknown game)', () => {
  for (const p of [undefined, prov(undefined, undefined, 'unavailable'), prov(undefined, undefined, 'none')]) {
    const owner = proc('x', 1195586, 'rundll32.exe', '/c/rundll32.exe', p);
    assert.deepEqual(promptIdentity(event(owner, helperTarget)), {});
  }
  const unverifiedGame = prov('helper');
  unverifiedGame.launch.game.status = 'not-found';
  assert.deepEqual(promptIdentity(event(proc('x', 1, 'rundll32.exe', '/c', unverifiedGame), helperTarget)), {});
  assert.deepEqual(targetLines(undefined), []);
});

test('parsers bound and reject malformed provenance', () => {
  assert.equal(parseProvenance({ evidence: 'trusted' }), undefined);
  assert.equal(parseProvenance(null), undefined);
  const p = parseProvenance({ evidence: 'verified', reason: 'x'.repeat(5000), stop: 'init', ancestry: [], launch: { kind: 'evil' } });
  assert.equal(p.reason.length, 1024);
  assert.equal(p.launch, undefined);
  assert.throws(() => parseProvenance({ evidence: 'none', ancestry: new Array(40).fill({}) }));
  assert.equal(parsePermissionTarget({ kind: 'everything' }), undefined);
});

class El {
  constructor(tag) {
    Object.assign(this, { tagName: tag.toUpperCase(), children: [], parent: null, text: '', className: '', id: '', dataset: {}, attrs: {}, hidden: false, title: '' });
  }
  set textContent(t) { this.children = []; this.text = String(t); }
  get textContent() { return this.text + this.children.map((c) => c.textContent).join(''); }
  append(...nodes) {
    for (let n of nodes) {
      if (typeof n === 'string') { const t = new El('#text'); t.text = n; n = t; }
      n.parent = this; this.children.push(n);
    }
  }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  *walk() { yield this; for (const c of this.children) yield* c.walk(); }
}
test('prompt card: game heading, via hint and explicit scopes precede Allow/Deny/Remember', () => {
  global.document = { createElement: (t) => new El(t) };
  global.Option = class extends El { constructor(l, v) { super('option'); this.text = l; this.value = v; } };
  global.window = { flowgate: { applicationMetadata: async () => ({}) } };
  const { buildRequestCard } = require('../dist/test/prompt-card.cjs');
  const owner = proc('rundll', 1195586, 'rundll32.exe', '/c/rundll32.exe', prov('helper'));
  const root = new El('div');
  root.append(...buildRequestCard(event(owner, helperTarget), { name: 'rundll32.exe', rememberMode: true, forAWhile: true, rememberOptions: [] }));
  const all = [...root.walk()], byId = (id) => all.find((n) => n.id === id);
  const heading = all.find((n) => n.className === 'compact-application');
  assert.match(heading.textContent, /DEATH STRANDING 2: ON THE BEACH · DS2\.exe/);
  assert.equal(byId('launchVia').textContent, 'via rundll32.exe');
  const scope = byId('permissionScope');
  assert.match(scope.textContent, /^Once: /, 'one line: the selected option (Once by default)');
  assert.match(scope.dataset.remember, /^Remember: .*shared by every game using this prefix/);
  assert.match(scope.dataset.forAWhile, /^For a while: /);
  const order = all.filter((n) => n.id === 'permissionScope' || n.id === 'allow' || n.id === 'rememberToggle');
  assert.deepEqual(order.map((n) => n.id), ['permissionScope', 'allow', 'rememberToggle']);
  const details = byId('requestMore').textContent;
  assert.match(details, /rundll32\.exe owns this socket/);
  assert.match(details, /uid\+wine\+prefix\+executable path/);
});
