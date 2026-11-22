// Local desktop regression for a Decision Log permission change at the same socket and log.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { _electron } from 'playwright-core';

const root = path.resolve(import.meta.dirname, '../..');
const workspace = path.join(root, '.workspace');
const run = fs.mkdtempSync(path.join(workspace, 'scope-'));
const endpoint = path.join(run, 'api');
const generation = 'scope-fixture';
const logId = 'same-log';
const direct = process.argv.includes('--direct');
const record = (id, sequence, uid, name, kind = 'final') => ({
  id,
  sequence: String(sequence),
  kind,
  generation,
  request_id: 'request-' + uid,
  time: new Date().toISOString(),
  mode: 'daemon-monitor',
  principal_uid: uid,
  application: { name, key: id, kind: 'executable', executable: '/fixture/' + id, revision: '1' },
  flow: {
    direction: 'outgoing',
    protocol: 'tcp',
    family: 'ipv4',
    local: '192.0.2.10:1234',
    remote: '192.0.2.20:443',
  },
  ...(kind === 'final'
    ? {
        decision: {
          action: 'allow',
          source: 'user',
          scope: 'once',
          reason: 'Fixture allowed once',
        },
        verdict: { state: 'accept_submitted' },
      }
    : {}),
  delivery: 'not_observed',
});
const foreign = record('foreign', 91, 1001, 'Foreign application');
const foreignPending = record('foreign-pending', 89, 1001, 'Foreign pending', 'pending');
const olderForeign = record('foreign-older', 85, 1001, 'Foreign delayed page');
const ownPending = record('own-pending', 22, 1000, 'My application', 'pending');
const own = record('own-outcome', 23, 1000, 'My application');
const state = (scope) => ({
  version: 1,
  generation,
  read_only: false,
  mode: 'daemon-monitor',
  backend_mode: 'daemon-monitor',
  server_time: new Date().toISOString(),
  capabilities: ['explicit-administrator-v1', 'decision-log-v1', 'decision-log-outcome-v1'],
  permissions: {
    role: scope === 'machine' ? 'administrator' : 'user',
    observation_scope: scope,
    policy_scope: scope,
    can_manage_rules: false,
    can_decide: false,
  },
  enforcement: { state: 'stopped', profile: '' },
});
const page = (scope, records, next = '') => ({
  ...state(scope),
  decision_log: {
    scope,
    log_id: logId,
    records,
    newest: records[0]?.sequence || '',
    next_before: next,
    has_more: !!next,
    health: { state: 'ok', recording: true },
  },
});
function gate() {
  let resolve;
  const promise = new Promise((r) => {
    resolve = r;
  });
  return { promise, resolve };
}
const oldPage = gate(),
  oldDetail = gate(),
  oldCopy = gate(),
  newPage = gate();
const selfQueries = [];
let scope = 'machine';
let holdOldLookups = false;
let heldSelfPage = false;
const send = (socket, reply) => socket.end(JSON.stringify(reply) + '\n');
const server = net.createServer((socket) => {
  socket.on('error', () => {});
  socket.once('data', (buffer) => {
    const request = JSON.parse(buffer.toString());
    if (scope === 'offline') return socket.end();
    const base = state(scope);
    switch (request.operation) {
      case 'decision-log': {
        const query = request.decision_query;
        if (scope === 'machine') {
          if (query.before) return oldPage.resolve(socket);
          if (query.after) return send(socket, page(scope, []));
          return send(socket, page(scope, [foreign, foreignPending], '89'));
        }
        selfQueries.push(query);
        if (query.after || query.before) return send(socket, page(scope, []));
        if (!heldSelfPage) {
          heldSelfPage = true;
          return newPage.resolve(socket);
        }
        return send(socket, page(scope, [ownPending]));
      }
      case 'decision-log-get': {
        if (scope === 'machine' && holdOldLookups) return oldDetail.resolve(socket);
        const records = scope === 'machine' ? [foreign, foreignPending] : [ownPending, own];
        const decision_record = records.find((item) => item.id === request.decision_id);
        return send(socket, {
          ...base,
          decision_record,
          ...(!decision_record && { error_code: 'not_found' }),
        });
      }
      case 'decision-log-outcome':
        if (scope === 'machine' && holdOldLookups) return oldCopy.resolve(socket);
        if (scope === 'self' && request.decision_id === ownPending.id)
          return send(socket, { ...base, decision_record: own });
        return send(socket, { ...base, error_code: 'not_found' });
      default:
        return send(socket, base);
    }
  });
});
await new Promise((resolve) => server.listen(endpoint, resolve));

let app;
try {
  app = await _electron.launch({
    executablePath: process.env.FLOWGATE_TEST_ELECTRON,
    chromiumSandbox: true,
    args: [
      '--ozone-platform=wayland',
      path.join(root, 'electron'),
      '--observer',
      endpoint + '.absent',
      '--control',
      endpoint,
    ],
    env: { ...process.env, XDG_CACHE_HOME: path.join(run, 'cache') },
  });
  let ui = app.windows().find((window) => window.url() === 'flowgate://app/index.html');
  while (!ui) {
    const window = await app.waitForEvent('window', { timeout: 7000 });
    await window.waitForLoadState('domcontentloaded');
    if (window.url() === 'flowgate://app/index.html') ui = window;
  }
  ui.setDefaultTimeout(7000);
  await app.evaluate(({ BrowserWindow, clipboard }) => {
    BrowserWindow.getAllWindows()
      .find((window) => window.getTitle() === 'FlowGate')
      ?.maximize();
    clipboard.writeText('scope fixture clipboard marker');
  });
  assert.deepEqual(
    await ui.evaluate(() => [screen.width, screen.height, devicePixelRatio]),
    [1280, 800, 1],
  );
  await ui.getByRole('button', { name: 'Decision log', exact: true }).click();
  const rows = ui.locator('#logRows');
  const logDetails = ui.locator('#logDetails');
  const status = ui.locator('#logStatus');
  const loadOlder = ui.getByRole('button', { name: 'Load older' });
  const copy = ui.getByRole('button', { name: 'Copy record', exact: true });
  await status.getByText('All users', { exact: false }).waitFor();
  await rows.getByText('Foreign application', { exact: true }).click();
  await logDetails.getByText('foreign', { exact: true }).waitFor();
  await copy.waitFor();
  assert.equal(await rows.locator('tr[aria-selected="true"]').getAttribute('data-id'), foreign.id);
  await ui.screenshot({ path: path.join(run, 'before.png') });

  holdOldLookups = true;
  await loadOlder.click();
  const staleDetail = ui.evaluate((id) => window.flowgate.decisionLogDetail(id), foreign.id);
  const staleCopy = ui.evaluate(
    async ({ id, pending }) => {
      try {
        await window.flowgate.decisionLogCopy(id, undefined, pending);
        return 'copied';
      } catch {
        return 'refused';
      }
    },
    { id: foreign.id, pending: foreignPending.id },
  );
  const [olderSocket, detailSocket, copySocket] = await Promise.all([
    oldPage.promise,
    oldDetail.promise,
    oldCopy.promise,
  ]);

  scope = direct ? 'self' : 'offline';
  await logDetails.getByText('Select a record.', { exact: true }).waitFor();
  assert.equal(await rows.locator('tr').count(), 0);
  assert.equal(await ui.locator('#logTable').getAttribute('aria-activedescendant'), null);
  assert.equal(await copy.count(), 0);
  assert.equal(await loadOlder.count(), 0);
  scope = 'self';
  const freshSocket = await newPage.promise;
  assert.deepEqual(selfQueries[0], { limit: 100 });
  send(freshSocket, page('self', [ownPending]));
  await status.getByText('Your decisions only', { exact: false }).waitFor();
  await rows.getByText('My application', { exact: true }).waitFor();

  // Release all previous-access replies only after the authorized page is on screen.
  assert([olderSocket, detailSocket, copySocket].every((socket) => !socket.destroyed));
  send(olderSocket, page('machine', [olderForeign], '85'));
  send(detailSocket, { ...state('machine'), decision_record: foreign });
  send(copySocket, { ...state('machine'), decision_record: foreign });
  assert.equal((await staleDetail).record, undefined);
  assert.equal(await staleCopy, 'refused');
  assert.equal(
    await app.evaluate(({ clipboard }) => clipboard.readText()),
    'scope fixture clipboard marker',
  );
  const retained = await ui.evaluate(() => window.flowgate.decisionLog());
  assert.equal(retained.scope, 'self');
  assert.deepEqual(
    retained.records.map((item) => item.id),
    [ownPending.id],
  );
  assert.equal(retained.hasOlder, false);
  assert(!(await rows.getByText(/Foreign/).count()));
  assert.equal(await copy.count(), 0);
  assert.equal(await rows.locator('tr[aria-selected="true"]').count(), 0);
  await ui.screenshot({ path: path.join(run, 'self-cleared.png') });

  await rows.getByText('My application', { exact: true }).click();
  await ui.getByRole('button', { name: 'Open recorded outcome' }).click();
  await logDetails.getByText('own-outcome', { exact: true }).waitFor();
  await copy.click();
  await logDetails.getByRole('button', { name: 'Copied', exact: true }).waitFor();
  const copied = JSON.parse(await app.evaluate(({ clipboard }) => clipboard.readText()));
  assert.equal(copied.id, own.id);
  assert.equal(copied.principal_uid, 1000);
  assert.equal(copied.decision.scope, 'once');
  await ui.screenshot({ path: path.join(run, 'self-outcome.png') });
  console.log(
    `PASS same endpoint and log (${direct ? 'direct scope change' : 'reconnect'}): late machine page, detail and linked copy rejected after self page`,
  );
  console.log(
    'PASS visible selection and details reset; own linked outcome opened and copied at 1280x800, 100%',
  );
  console.log(run);
} finally {
  await app?.close();
  await new Promise((resolve) => server.close(resolve));
}
