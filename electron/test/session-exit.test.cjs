const { test } = require('node:test');
const assert = require('node:assert/strict');
const { SessionExit } = require('../dist/test/session-exit.cjs');

test('session shutdown bypasses tray and confirmation across simultaneous windows', async () => {
  let resolve, queries = 0, quits = 0, ordinary = 0;
  const exit = new SessionExit(() => { queries++; return new Promise(r => resolve = r); }, () => quits++);
  const a = exit.close(() => ordinary++), b = exit.close(() => ordinary++);
  resolve(true);
  await Promise.all([a, b]);
  assert.deepEqual({ queries, quits, ordinary }, { queries: 1, quits: 1, ordinary: 0 });
});

test('normal and unavailable session checks preserve ordinary closing; next close queries afresh', async () => {
  let queries = 0, ordinary = 0, quits = 0;
  const exit = new SessionExit(async () => {
    queries++;
    if (queries === 2) throw Error('session bus unavailable');
    return queries === 3;
  }, () => quits++);
  await exit.close(() => ordinary++);
  await exit.close(() => ordinary++);
  await exit.close(() => ordinary++);
  assert.deepEqual({ queries, ordinary, quits }, { queries: 3, ordinary: 2, quits: 1 });
});

test('system shutdown while a close check is pending never reopens a quit dialog', async () => {
  let resolve, quits = 0, ordinary = 0;
  const exit = new SessionExit(() => new Promise(r => resolve = r), () => quits++);
  const close = exit.close(() => ordinary++);
  exit.shutdown();
  exit.shutdown();
  resolve(false);
  await close;
  assert.equal(quits, 1);
  assert.equal(ordinary, 0);
});
