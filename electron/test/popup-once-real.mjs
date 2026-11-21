// Actual Electron and TCP receiver against process-rules-isolated.py --hold --hold-enforcement.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import { _electron } from 'playwright-core';

const project = path.resolve(import.meta.dirname, '../..');
const workspace = await fs.realpath(process.env.FLOWGATE_TEST_WORKSPACE || path.join(project, '.workspace'));
assert(workspace.split(path.sep).includes('.workspace'));
const readyPath = await fs.realpath(process.env.FLOWGATE_TEST_READY);
const fixture = path.dirname(readyPath);
assert(fixture.startsWith(workspace + '/') && path.basename(readyPath) === 'ready.json');
const ready = JSON.parse(await fs.readFile(readyPath));
assert.equal(ready.profile, 'both');
for (const file of [ready.socket, ready.monitor_socket, ready.command])
  assert(path.resolve(file).startsWith(fixture + '/'));
const run = await fs.mkdtemp(path.join(workspace, 'once-'));
const evidence = { fixture: readyPath, generation: ready.generation, steps: [] };
const reproduce = process.env.FLOWGATE_TEST_REPRODUCE_DEFAULT === '1';
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function wait(label, check) {
  for (let until = Date.now() + 10000; Date.now() < until; await sleep(80)) {
    const value = await check();
    if (value) return value;
  }
  throw Error('Timed out waiting for ' + label);
}
function call(operation, fields = {}) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(ready.socket);
    let data = '';
    socket.on('error', reject);
    socket.setTimeout(5000, () => socket.destroy(Error('fixture API timeout')));
    socket.on('connect', () => socket.write(JSON.stringify({ version: 1, operation, generation: ready.generation, ...fields }) + '\n'));
    socket.on('data', (chunk) => {
      data += chunk;
      if (!data.includes('\n')) return;
      socket.destroy();
      const reply = JSON.parse(data);
      if (reply.error) reject(Error(reply.error));
      else resolve(reply);
    });
  });
}
async function command(op, fields = {}) {
  const result = path.join(fixture, 'command-result.json');
  const draft = path.join(fixture, '.once-command');
  await fs.rm(result, { force: true });
  await fs.writeFile(draft, JSON.stringify({ op, ...fields }));
  await fs.rename(draft, ready.command);
  return wait('fixture command ' + op, async () => {
    try { return JSON.parse(await fs.readFile(result)); }
    catch (error) { if (error.code === 'ENOENT' || error instanceof SyntaxError) return; throw error; }
  });
}
const count = async () => (await command('peer-counts')).lines.length;
const list = () => call('list');
const host = '10.79.0.2', port = 43000, remote = host + ':' + port;
const connect = (peer = host, timeout_ms = 5500) => command('outgoing', { name: 'alpha', protocol: 'tcp', host: peer, port, timeout_ms });
const records = async () => (await call('decision-log', { decision_query: { limit: 100 } })).decision_log.records;
let app;
try {
  assert.equal((await list()).rules?.length ?? 0, 0, 'fresh disposable fixture required');
  const observed_draft = {
    target_scope: 'application', direction: 'outgoing', protocol: '*', action: 'ask',
    remote_address: '*', local_port: 0, remote_port: 0, disabled: false, application_policy: true,
    expires: '0001-01-01T00:00:00Z',
  };
  const { observed_preview } = await call('observed-rule-preview', { observed_target: ready.alpha_target, observed_draft });
  const { saved_rule: ask } = await call('observed-rule-save', { preview_token: observed_preview.token, observed_draft });
  const seen = new Set();
  const client = path.join(run, 'electron');
  await fs.mkdir(client);
  await fs.cp(path.join(project, 'electron/dist'), path.join(client, 'dist'), { recursive: true });
  await fs.copyFile(path.join(project, 'electron/package.json'), path.join(client, 'package.json'));
  app = await _electron.launch({
    chromiumSandbox: true,
    args: ['--ozone-platform=wayland', client, '--observer', ready.monitor_socket, '--control', ready.socket],
    env: { ...process.env, XDG_CONFIG_HOME: path.join(run, 'config'), XDG_CACHE_HOME: path.join(run, 'cache'), FLOWGATE_INSTALLED: '0' },
  });
  const main = await wait('main window', () => app.windows().find((page) => page.url() === 'flowgate://app/index.html'));

  async function pending(peer = host) {
    const request = await wait('new outbound Ask', async () => (await list()).events?.find((event) =>
      !seen.has(event.id) && event.state === 'awaiting-decision' && event.ask_rule?.id === ask.id &&
      event.flow.direction === 'outgoing' && event.flow.protocol === 'tcp' && event.flow.remote === peer + ':' + port &&
      event.attribution.visibility_complete && event.attribution.owners.length === 1 &&
      event.attribution.owners[0].pid === ready.alpha.pid));
    seen.add(request.id);
    return request;
  }
  async function card(request) {
    const popup = await wait('automatic popup for ' + request.id, () => app.windows().find((page) =>
      new URL(page.url() || 'about:blank').searchParams.get('request') === request.id));
    popup.setDefaultTimeout(5000);
    const duration = popup.getByLabel('Rule duration:');
    await duration.waitFor();
    assert.equal(await popup.locator('#requestApplication strong').innerText(), request.attribution.application.name);
    assert.match(await popup.locator('#fieldProcess').innerText(), new RegExp('\\b' + ready.alpha.pid + '\\b'));
    assert.match(await popup.locator('#connectionHeader').innerText(), /Outgoing.*TCP/);
    const destination = await popup.locator('#fieldRemote').innerText();
    assert(destination.includes(request.flow.remote.split(':')[0]) && destination.includes(String(port)), destination);
    return { popup, duration };
  }
  function finalDecision(id, action) {
    return wait('linked final decision', async () => (await records()).find((record) =>
      record.kind === 'final' && record.request_id === id && record.decision?.action === action));
  }
  async function answer(name, action, durationValue) {
    const before = await count();
    await connect();
    const request = await pending();
    const { popup, duration } = await card(request);
    const durationBefore = await duration.inputValue();
    assert.equal(durationBefore, reproduce ? '0' : 'once');
    if (durationValue) await duration.selectOption(durationValue);
    const button = popup.locator('#' + action);
    await popup.waitForFunction((id) => document.getElementById(id)?.disabled === false, action);
    assert.equal(await count(), before, 'held request must deliver zero payloads');
    const screenshot = path.join(run, name + '.png');
    await popup.screenshot({ path: screenshot });
    await button.click();
    const final = await finalDecision(request.id, action);
    assert.equal(final.decision.scope, reproduce || durationValue === '0' ? 'persistent' : 'once');
    if (action === 'allow') await wait('one payload delivered', async () => await count() === before + 1);
    const clientResult = await command('settle', { name: 'alpha' });
    const delivered = (await count()) - before;
    assert.equal(delivered, Number(action === 'allow'));
    const rules = (await list()).rules;
    const step = { name, id: request.id, initialDuration: durationBefore, selectedDuration: durationValue || durationBefore,
      heldPayloads: 0, delivered, rules, final: final.decision, clientResult, screenshot };
    evidence.steps.push(step);
    console.log(JSON.stringify(step));
    return step;
  }

  if (reproduce) {
    const baseline = await answer('baseline-allow', 'allow');
    assert(baseline.rules.some((rule) => rule.action === 'allow' && rule.expires.startsWith('0001-')));
  } else {
    for (const [name, button] of [['allow-once', 'allow'], ['deny-once', 'block']]) {
      const step = await answer(name, button);
      assert.deepEqual(step.rules, [ask], 'Once must preserve the original Ask rule');
      assert.equal(step.clientResult.last_send?.status, button === 'allow' ? 'received' : 'dial-failed');
      assert.equal(step.clientResult.last_send?.remote, remote);
    }
    const queuedBefore = await count();
    await connect(host, 12000);
    const a = await pending();
    const aCard = await card(a);
    assert.equal(await aCard.duration.inputValue(), 'once');
    const alternate = '10.79.0.3';
    await connect(alternate, 12000);
    const b = await pending(alternate);
    await main.waitForFunction((id) => window.flowgate.snapshot().then((view) =>
      view.control.events.some((event) => event.id === id)), b.id);
    assert.equal(await count(), queuedBefore);
    await aCard.duration.selectOption('300');
    await aCard.popup.locator('#rememberPanel input[data-field="address"]').check();
    await aCard.popup.locator('#block').click();
    const savedA = (await finalDecision(a.id, 'block')).decision.rule;
    const bCard = await card(b);
    assert.equal(await bCard.duration.inputValue(), '300');
    assert(await bCard.popup.locator('#rememberPanel input[data-field="address"]').isChecked());
    assert.match(await bCard.popup.locator('#rememberPanel input[data-field="address"]').locator('..').innerText(), /10\.79\.0\.3/);
    assert.equal((await list()).events.find((event) => event.id === b.id)?.state, 'awaiting-decision');
    assert.equal(await count(), queuedBefore);
    const queuedScreenshot = path.join(run, 'queued-scope.png');
    await bCard.popup.screenshot({ path: queuedScreenshot });
    await bCard.duration.selectOption('once');
    await bCard.popup.locator('#allow').click();
    assert.equal((await finalDecision(b.id, 'allow')).decision.scope, 'once');
    await wait('queued B delivered once', async () => await count() === queuedBefore + 1);
    await command('close', { name: 'alpha' });
    await command('settle', { name: 'alpha' });
    const queuedRules = (await list()).rules;
    const ruleA = queuedRules.find((rule) => rule.id === savedA.id);
    assert.equal(ruleA.filter.remote_address, host);
    assert.equal(queuedRules.length, 2);
    await call('rule-delete', { id: ruleA.id, expected_version: ruleA.version });
    evidence.steps.push({ name: 'queued-handoff', a: a.id, b: b.id, savedA: ruleA.id,
      carriedDuration: '300', heldPayloads: 0, delivered: 1, screenshot: queuedScreenshot });
    const chosen = await answer('explicit-no-expiry', 'allow', '0');
    const saved = chosen.rules.find((rule) => rule.id !== ask.id && rule.action === 'allow' && rule.expires.startsWith('0001-'));
    assert(saved, 'explicit No expiry saved an Allow rule');
    const before = await count();
    await connect();
    await wait('fresh matching payload with no popup click', async () => await count() === before + 1);
    await command('settle', { name: 'alpha' });
    const final = await wait('saved rule wins', async () => (await records()).find((record) =>
      record.kind === 'final' && !seen.has(record.request_id) &&
      record.flow?.remote === remote && record.decision?.rule?.id === saved.id));
    assert.equal((await list()).events?.filter((event) => event.state === 'awaiting-decision').length ?? 0, 0);
    assert.equal(await count(), before + 1);
    evidence.steps.push({ name: 'matching-rule-wins', request: final.request_id, final: final.decision, delivered: 1 });
  }
  evidence.passed = true;
} finally {
  await fs.writeFile(path.join(run, 'result.json'), JSON.stringify(evidence, null, 2));
  console.log('Evidence', run);
  await app?.close();
}
