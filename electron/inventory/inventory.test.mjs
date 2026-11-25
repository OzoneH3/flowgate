import assert from 'node:assert/strict';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import test from 'node:test';
import { bindDesktopAccount, matchesWindow, readProjectedControls } from './browser.mjs';
import { identities, recipeNames, startSeed } from './seeds.mjs';

const expected = JSON.parse(await readFile(new URL('./expected.json', import.meta.url), 'utf8'));

test('every source surface has at least one unique expected file', () => {
  const states = expected.journeys.flatMap(j => j.states);
  assert.deepEqual(new Set(states.map(s => s.window)), new Set(Object.keys(expected.windows)));
  assert.equal(new Set(states.map(s => s.window + '/' + s.id)).size, states.length);
  for (const journey of expected.journeys) assert(recipeNames.includes(journey.seed));
});

test('renderer selection requires the exact semantic window and request generation', () => {
  const expected = { document: 'prompt.html', query: { request: 'one', generation: 'a' } };
  const url = 'flowgate://app/prompt.html?request=one&generation=a';
  assert(matchesWindow(url, expected));
  assert(!matchesWindow(url.replace('one', 'two'), expected));
  assert(!matchesWindow(url.replace('generation=a', 'generation=b'), expected));
  assert(!matchesWindow(url.replace('app/', 'other/'), expected));
  assert(!matchesWindow(url.replace('prompt.html', 'index.html'), expected));
});

async function fixture(t, recipe, packageBuild) {
  const dir = await mkdtemp(path.resolve(import.meta.dirname, '../../.workspace/gui-test-'));
  const control = path.join(dir, 'c'), observer = path.join(dir, 'o');
  const seed = await startSeed(recipe, control, observer, packageBuild);
  t.after(async () => { await seed.close(); await rm(dir, { recursive: true, force: true }); });
  function request(fields) {
    return new Promise((resolve, reject) => {
      const c = net.createConnection(control);
      let input = '';
      c.on('connect', () => c.write(JSON.stringify({ version: 1, ...fields }) + '\n'));
      c.on('data', data => { input += data; });
      c.on('error', reject);
      c.on('end', () => {
        try { resolve(JSON.parse(input)); } catch (error) { reject(error); }
      });
    });
  }
  return { request, seed };
}

test('seed preserves the unrelated pending request and linked historical identity', async t => {
  const { request } = await fixture(t, 'requests');
  const before = await request({ operation: 'list' });
  assert.deepEqual(before.events.map(e => e.id), [identities.request, identities.incoming]);
  assert.equal((await request({ operation: 'decide', id: identities.request, scope: 'once', action: 'allow' })).decision.state, 'allowed');
  assert.deepEqual((await request({ operation: 'list' })).events.map(e => e.id), [identities.incoming]);
  const pending = await request({ operation: 'decision-log-get', decision_id: identities.logPending });
  const outcome = await request({ operation: 'decision-log-outcome', decision_id: identities.logPending });
  assert.equal(pending.decision_record.id, identities.logPending);
  assert.equal(outcome.decision_record.id, identities.logFinal);
  assert.equal(pending.decision_record.request_id, outcome.decision_record.request_id);
  assert.equal(pending.decision_record.flow.local, outcome.decision_record.flow.local);
});

test('seed exposes exact build identity, an older page and a separately arriving new record', async t => {
  const build = { source: 'a'.repeat(40), version: '1.2.3' };
  const { request, seed } = await fixture(t, 'logPages', build);
  assert.deepEqual((await request({ operation: 'list' })).build, { ...build, modified: false });
  const page = async query => (await request({ operation: 'decision-log', decision_query: query })).decision_log;
  const first = await page({});
  assert(first.next_before);
  assert(!first.records.some(record => record.id === 'inventory-log-older'));
  assert.deepEqual((await page({ before: first.next_before })).records.map(record => record.id), ['inventory-log-older']);
  assert.notEqual((await page({ limit: 1 })).records[0].id, 'inventory-log-new');
  seed.setStage('log-new');
  assert.equal((await page({ limit: 1 })).records[0].id, 'inventory-log-new');
});

test('binds all seven overview fields to the measured account only', () => {
  const local = 'local@desk.example', guest = 'lab@guest.example';
  const controls = account => [
    {id: 'group', text: 'Prefix ' + account + ' suffix'},
    {id: 'app', text: 'Prefix ' + account + ' suffix'},
    {id: 'rows/tr:overview', accessibleName: 'Collapse ' + [account, account, account].join(' ')},
    {id: 'rows/tr:overview/cell', accessibleName: 'Collapse ' + account + ' ' + account},
    ...['button', 'cell#4', 'group'].map(part => ({
      id: 'rows/tr:overview/' + part, accessibleName: account + ' rule status',
    })),
  ];
  const a = controls(local), b = controls(guest);
  assert.equal(bindDesktopAccount(a, local, true).length, 7);
  assert.equal(bindDesktopAccount(b, guest, true).length, 7);
  assert.deepEqual(a, b);
  for (const wrong of ['other@guest.example', 'lab@other.example']) {
    const original = controls(wrong);
    const before = structuredClone(original);
    assert.throws(() => bindDesktopAccount(original, guest, true), /all seven/);
    assert.deepEqual(original, before);
  }
  const changed = controls(guest);
  changed[0].text += ' changed';
  bindDesktopAccount(changed, guest, true);
  assert.notDeepEqual(a, changed);
  const wrongControl = controls(guest);
  wrongControl[0].id = 'other';
  assert.throws(() => bindDesktopAccount(wrongControl, guest, true), /all seven/);
});

test('a changed DOM order cannot assign another element’s accessible name or role', async () => {
  const calls = [];
  const ref = (name, objectId) => ({ name, value: { objectId } });
  const send = async (method, params) => {
    calls.push(method);
    switch (method) {
      case 'Runtime.evaluate': return { result: { objectId: 'snapshot' } };
      case 'Runtime.getProperties':
        return { result: params.objectId === 'snapshot'
          ? [ref('controls', 'controls'), ref('elements', 'elements')]
          : [ref('1', 'searchNode'), ref('0', 'pendingNode'), ref('2', 'expiredNode')] };
      case 'Runtime.callFunctionOn': return { result: { value: [
        { id: 'requestsTab', role: 'button', text: 'Pending requests 0', enabled: true },
        { id: 'search', role: 'textbox', text: '' },
        { id: 'allow', role: 'button', text: 'Allow always', enabled: false },
      ] } };
      case 'DOM.describeNode': return { node: {
        backendNodeId: { pendingNode: 32, searchNode: 14, expiredNode: 10 }[params.objectId],
      } };
      case 'Accessibility.getFullAXTree': return { nodes: [
        { backendDOMNodeId: 14, role: { value: 'searchbox' }, name: { value: 'Search Activity' } },
        { backendDOMNodeId: 400, role: { value: 'checkbox' }, name: { value: 'Other control' } },
        { backendDOMNodeId: 32, role: { value: 'button' }, name: { value: 'Pending requests 0' } },
      ] };
      case 'Runtime.releaseObjectGroup': return {};
      default: throw Error('Unexpected protocol call ' + method);
    }
  };
  assert.deepEqual(await readProjectedControls({ send }, 'body'), [
    { id: 'requestsTab', role: 'button', text: 'Pending requests 0', enabled: true },
    { id: 'search', role: 'searchbox', text: '', accessibleName: 'Search Activity' },
    { id: 'allow', role: 'button', text: 'Allow always', enabled: false },
  ]);
  assert.equal(calls.at(-1), 'Runtime.releaseObjectGroup');
});
