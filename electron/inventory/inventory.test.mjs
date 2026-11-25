import assert from 'node:assert/strict';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import test from 'node:test';
import { matchesWindow } from './browser.mjs';
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

test('seed preserves the unrelated pending request and linked historical identity', async t => {
  const dir = await mkdtemp(path.resolve(import.meta.dirname, '../../.workspace/gui-test-'));
  const control = path.join(dir, 'c'), observer = path.join(dir, 'o');
  const seed = await startSeed('requests', control, observer);
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
