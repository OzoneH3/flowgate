// Native prompt + receiver journey using process-rules-isolated.py --hold --hold-enforcement --zones.
// This test accepts only a ready file and sockets inside the supplied private workspace fixture.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import { _electron } from 'playwright-core';

const root = path.resolve(import.meta.dirname, '../..');
const workspace = await fs.realpath(process.env.FLOWGATE_TEST_WORKSPACE || root + '/.workspace');
assert(workspace.split(path.sep).includes('.workspace'));
const readyPath = await fs.realpath(process.env.FLOWGATE_TEST_READY);
const dir = path.dirname(readyPath);
assert(dir.startsWith(workspace + '/') && path.basename(readyPath) === 'ready.json');
const ready = JSON.parse(await fs.readFile(readyPath));
assert.equal(ready.profile, 'both');
for (const file of [ready.socket, ready.monitor_socket, ready.command]) {
  assert(path.resolve(file).startsWith(dir + '/'));
}
const { alpha, generation } = ready;
const wait = async (label, fn, ms = 12000) => {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const value = await fn();
    if (value) return value;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw Error('Timed out: ' + label);
};
const call = (operation, fields = {}) => new Promise((resolve, reject) => {
  const socket = net.createConnection(ready.socket);
  let data = '';
  socket.on('error', reject);
  socket.setTimeout(5000, () => socket.destroy(Error('fixture API timeout')));
  socket.on('connect', () => socket.write(JSON.stringify({ version: 1, operation, generation, ...fields }) + '\n'));
  socket.on('data', (chunk) => {
    data += chunk;
    if (!data.includes('\n')) return;
    socket.destroy();
    const result = JSON.parse(data);
    if (result.error) reject(Error(result.error));
    else resolve(result);
  });
});
const command = async (request) => {
  const result = path.join(dir, 'command-result.json');
  const draft = path.join(dir, '.next-command');
  await fs.rm(result, { force: true });
  await fs.writeFile(draft, JSON.stringify(request));
  await fs.rename(draft, ready.command);
  return wait('fixture command ' + request.op, async () => {
    try { return JSON.parse(await fs.readFile(result)); }
    catch (error) { if (error.code === 'ENOENT' || error instanceof SyntaxError) return; throw error; }
  });
};
const outgoing = { op: 'outgoing', name: 'alpha', protocol: 'tcp', host: '10.79.0.2', port: 43000 };
const count = async () => (await command({ op: 'peer-counts' })).lines.length;
const pending = async () => ((await call('list')).events || []).filter((e) =>
  e.state === 'awaiting-decision' && e.attribution.owners.some((p) => p.pid === alpha.pid));
const held = (n) => wait(n + ' held attempts', async () => {
  const rows = await pending();
  return rows.length === n && rows;
});
const run = await fs.mkdtemp(path.join(workspace, 'remember-ui-'));
const baseline = process.env.FLOWGATE_TEST_EXPECT_REPLACEMENT === '1';
let desktop;
try {
  const initial = await call('list');
  assert.equal(initial.enforcement.profile, 'both');
  assert.equal((initial.rules || []).length, 0, 'requires fresh disposable fixture');
  const draft = { target_scope: 'application', direction: 'outgoing', protocol: '*',
    action: 'ask', remote_address: '*', local_port: 0, remote_port: 0, disabled: false, application_policy: true, expires: '0001-01-01T00:00:00Z' };
  const { observed_preview } = await call('observed-rule-preview', { observed_target: ready.alpha_target, observed_draft: draft });
  const { saved_rule: ask } = await call('observed-rule-save', { preview_token: observed_preview.token, observed_draft: draft });
  desktop = await _electron.launch({
    chromiumSandbox: true,
    args: ['--ozone-platform=wayland', path.join(root, 'electron'),
      '--observer', ready.monitor_socket, '--control', ready.socket],
    env: { ...process.env, TMPDIR: path.join(workspace, 'tmp'), XDG_CACHE_HOME: path.join(run, 'cache') },
  });
  const main = await wait('main desktop', () => desktop.windows().find((w) => w.url().endsWith('/index.html')));
  const prompt = async (eventId) => {
    await wait('desktop received ' + eventId, () => main.evaluate(async (id) =>
      (await window.flowgate.snapshot()).control.events.some((event) => event.id === id), eventId));
    await main.evaluate((id) => window.flowgate.openPrompt(id), eventId);
    return wait('prompt ' + eventId, async () => {
    const w = desktop.windows().find((w) => new URL(w.url() || 'about:blank').searchParams.get('request') === eventId);
    return w && await w.locator('#allow').isVisible() && w;
    });
  };
  const answer = async (id, action) => (await prompt(id)).locator('#' + action).click();
  for (const action of ['allow', 'block']) {
    const before = await count();
    await command({ op: 'batch', items: [outgoing, outgoing] });
    const [first, second] = await held(2);
    await answer(first.id, action);
    assert.equal((await held(1))[0].id, second.id);
    if (action === 'allow') await wait('one receiver write', async () => await count() === before + 1);
    await command(outgoing);
    const subsequent = await held(2);
    assert(subsequent.some((r) => r.id !== second.id));
    for (const attempt of subsequent) await answer(attempt.id, 'block');
    await held(0);
    await command({ op: 'close', name: 'alpha' });
    assert.equal(await count(), before + Number(action === 'allow'));
    assert.equal((await call('list')).rules.length, 1);
    console.log('PASS ' + action + ' once settled one attempt; next prompted; receiver delta ' + Number(action === 'allow'));
  }
  const before = await count();
  await command({ op: 'batch', items: [outgoing, outgoing] });
  const [request] = await held(2);
  const window = await prompt(request.id);
  await window.locator('#rememberToggle').check();
  await window.locator('#rememberDuration').selectOption('60');
  const summary = await wait('60-second reviewed scope', async () => {
    const value = await window.locator('#rememberSummary').innerText();
    return /1m0s/.test(value) && value;
  });
  assert.equal(/replaces Ask rule/.test(summary), baseline, summary);
  await window.screenshot({ path: path.join(run, 'remember.png') });
  await window.locator('#allow').click();
  const list = await wait('remembered rule', async () => {
    const state = await call('list');
    return state.rules.some((r) => r.action === 'allow') && state;
  });
  const saved = list.rules.find((r) => r.action === 'allow');
  assert.equal(saved.id === ask.id, baseline);
  assert.equal(list.rules.some((r) => r.id === ask.id && r.action === 'ask'), !baseline);
  await wait('both receivers delivered', async () => await count() === before + 2);
  await held(0);
  await command(outgoing);
  await wait('fresh attempt delivered before expiry', async () => await count() === before + 3);
  await new Promise((resolve) => setTimeout(resolve, Math.max(0, Date.parse(saved.expires) - Date.now() + 500)));
  await command(outgoing);
  const [after] = await held(1);
  assert.equal(after.rule, baseline ? 'default-ask' : ask.id);
  const afterWindow = await prompt(after.id);
  const expectedSource = baseline ? 'default Ask' : ask.id;
  await wait('prompt source ' + expectedSource, async () =>
    (await afterWindow.locator('#askSource').textContent())?.includes(expectedSource));
  await afterWindow.screenshot({ path: path.join(run, 'after-expiry.png') });
  assert.equal(await count(), before + 3);
  const permanentAction = process.env.FLOWGATE_TEST_PERMANENT_ACTION;
  if (permanentAction) {
    assert(!baseline && ['allow', 'block'].includes(permanentAction));
    await afterWindow.locator('#rememberToggle').check();
    await afterWindow.locator('#rememberDuration').selectOption('0');
    await wait('permanent Ask replacement preview', async () => {
      const summary = await afterWindow.locator('#rememberSummary').innerText();
      return summary.includes('replaces Ask rule ' + ask.id);
    });
    await afterWindow.locator('#' + permanentAction).click();
    await wait('permanent choice on original Ask ID', async () =>
      (await call('list')).rules.some((rule) => rule.id === ask.id && rule.action === permanentAction));
    if (permanentAction === 'allow') await wait('held receiver write', async () => await count() === before + 4);
    await held(0);
    await command({ op: 'close', name: 'alpha' });
    const permanentBefore = await count();
    const since = new Date().toISOString();
    await command(outgoing);
    await wait('next matching decision', async () =>
      (await call('decision-log', { decision_query: { since, limit: 20 } })).decision_log.records.some((record) =>
        record.kind === 'final' && record.decision?.rule?.id === ask.id &&
        record.decision.action === permanentAction));
    if (permanentAction === 'allow') await wait('fresh receiver write', async () => await count() === permanentBefore + 1);
    else await new Promise((resolve) => setTimeout(resolve, 800));
    assert.equal(await count(), permanentBefore + Number(permanentAction === 'allow'));
    console.log('PASS permanent ' + permanentAction + ' reused original Ask ID ' + ask.id +
      '; next matching TCP receiver delta ' + Number(permanentAction === 'allow'));
  } else {
    await answer(after.id, 'block');
    await held(0);
  }
  console.log('PASS before expiry: two held plus one fresh attempt delivered; after expiry: ' +
    (baseline ? 'default Ask prompted' : 'original stored Ask prompted') + ', no additional delivery');
  console.log('Screenshots: ' + run);
} finally {
  if (desktop) {
    await desktop.evaluate(({ app }) => app.exit()).catch(() => {});
    await desktop.close().catch(() => {});
  }
  await fs.writeFile(ready.command, JSON.stringify({ op: 'quit' })).catch(() => {});
}
