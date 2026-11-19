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
const { alpha } = ready;
let { generation } = ready;
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
const queueScope = process.env.FLOWGATE_TEST_QUEUE_SCOPE || 'address';
assert(['address', 'port', 'endpoint'].includes(queueScope));
const endpointScope = queueScope === 'endpoint';
const portScope = queueScope !== 'address';
const addressScope = queueScope !== 'port';
const differentPortAddress = queueScope === 'port' && process.env.FLOWGATE_TEST_QUEUE_DIFF_ADDRESS === '1';
const sharedEndpointField = process.env.FLOWGATE_TEST_QUEUE_SHARED || '';
assert(['', 'address', 'port'].includes(sharedEndpointField) && (!sharedEndpointField || endpointScope));
const alternateHost = '10.79.0.3';
const alternatePort = 44000;
const peerB = {
  ...outgoing, host: (addressScope || differentPortAddress) && sharedEndpointField !== 'address' ? alternateHost : outgoing.host,
  port: portScope && sharedEndpointField !== 'port' ? alternatePort : outgoing.port,
};
const crossPort = { ...peerB, host: outgoing.host };
const crossAddress = { ...outgoing, host: peerB.host };
const controlPort = { ...outgoing, port: 44002 };
const crossedEndpoints = sharedEndpointField === 'address' ? [{ ...peerB, host: alternateHost }] :
  sharedEndpointField === 'port' ? [{ ...peerB, port: alternatePort }] : [crossPort, crossAddress];
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
  const saveDraft = async (observed_draft) => {
    const { observed_preview } = await call('observed-rule-preview', {
      observed_target: ready.alpha_target, observed_draft,
    });
    const { saved_rule } = await call('observed-rule-save', {
      preview_token: observed_preview.token, observed_draft,
    });
    return saved_rule;
  };
  if (differentPortAddress || endpointScope) {
    const allow = await saveDraft({ ...draft, action: 'allow' });
    for (const target of endpointScope ? [outgoing, peerB, ...crossedEndpoints] : [crossPort]) {
      const before = await count();
      await command(target);
      await wait('Allow control delivered', async () => await count() === before + 1);
      const { lines } = await command({ op: 'peer-counts' });
      assert(lines.at(-1).includes(`('${target.host}', ${target.port})`));
      await command({ op: 'close', name: 'alpha' });
      await command({ op: 'settle', name: 'alpha' });
      console.log('PASS endpoint reachable under Allow: ' + target.host + ':' + target.port);
    }
    await call('rule-delete', { id: allow.id, expected_version: allow.version });
  }
  const ask = await saveDraft(draft);
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
  const closeAlpha = async () => {
    await command({ op: 'close', name: 'alpha' });
    await command({ op: 'settle', name: 'alpha' });
  };
  const ruleRow = (id) => main.locator(`#ruleRows tr[data-id="${id}"]`);
  const assertEnabledChoice = async (rule) => {
    await main.locator('#rulesTab').click();
    await wait('masked Ask and enabled saved choice', async () =>
      (await ruleRow(ask.id).locator('td').allTextContents()).at(-1) === 'Masked by newer rule' &&
      (await ruleRow(rule.id).locator('td').allTextContents()).at(-1) === 'Enabled');
  };
  const attemptWith = async (rule, request = outgoing) => {
    await closeAlpha();
    const received = await count();
    const since = new Date().toISOString();
    await command(request);
    const record = await wait('matching choice in Decision Log', async () =>
      (await call('decision-log', { decision_query: { since, limit: 20 } })).decision_log.records.find((r) =>
        r.generation === generation && r.kind === 'final' &&
        r.flow?.remote === request.host + ':' + request.port &&
        r.decision?.rule?.id === rule.id && r.decision.action === rule.action));
    if (rule.action === 'allow') await wait('fresh receiver write', async () => await count() === received + 1);
    else await new Promise((resolve) => setTimeout(resolve, 800));
    assert.equal(await count(), received + Number(rule.action === 'allow'));
    assert.equal((await pending()).length, 0);
    await main.locator('#decisionLogTab').click();
    await main.locator(`#logRows tr[data-id="${record.id}"]`).click();
    await wait('shown historical winner', async () =>
      (await main.locator('#logDetails').innerText()).includes(rule.id));
  };
  const mutate = async (id, button) => {
    await main.locator('#rulesTab').click();
    await ruleRow(id).click();
    await main.locator('#' + button).click();
    if (button === 'toggleRule') {
      await main.locator('#previewRule').click();
      await main.locator('#saveRule').click();
    } else {
      await main.locator('#confirmYes').click();
    }
  };
  if (!baseline) {
    const scopeFields = ['address', 'port'].filter((field) => field === 'address' ? addressScope : portScope);
    const fieldValue = (peer, field) => field === 'address' ? peer.host : String(peer.port);
    const scopeValues = (peer) => scopeFields.map((field) => fieldValue(peer, field));
    const scopeFilter = (peer) => ({
      ...(addressScope ? { remote_address: peer.host } : {}),
      ...(portScope ? { remote_port: peer.port } : {}),
    });
    const scopedFilter = (peer) => ({ ...ask.filter, ...scopeFilter(peer) });
    const queueDuration = process.env.FLOWGATE_TEST_QUEUE_DURATION || '0';
    assert(['0', '60', '300'].includes(queueDuration));
    const queueSeconds = Number(queueDuration);
    const queueSummary = queueSeconds ? `for ${queueSeconds / 60}m0s` : 'persistent';
    const checkRestoredAsk = async (peer) => {
      const received = await count();
      await command(peer);
      const [fresh] = await held(1);
      assert.equal(fresh.flow.remote, peer.host + ':' + peer.port);
      assert.equal(fresh.rule, ask.id);
      assert.equal(await count(), received);
      const freshWindow = await prompt(fresh.id);
      assert((await freshWindow.locator('#askSource').textContent()).includes(ask.id));
      assert.equal(await freshWindow.locator('#rememberToggle').isChecked(), false);
      await freshWindow.locator('#allow').click();
      await wait('restored Ask delivered after Allow Once', async () => await count() === received + 1);
      await held(0);
      await closeAlpha();
    };
    for (const scenario of queueSeconds ? ['refresh', 'keep', 'clear'] : ['keep', 'clear']) {
      const clearRemember = scenario === 'clear';
      await closeAlpha();
      let competingRule;
      if (scenario === 'refresh') {
        competingRule = await saveDraft({
          ...draft, ...scopeFilter(peerB), application_policy: false, action: 'block', disabled: true,
        });
      }
      const before = await count();
      await command(outgoing);
      const [a] = await held(1);
      const aWindow = await prompt(a.id);
      await command(peerB);
      const b = (await held(2)).find((request) => request.id !== a.id);
      assert.equal(b.flow.remote, peerB.host + ':' + peerB.port);
      assert.equal(b.rule, ask.id);
      await aWindow.locator('#rememberToggle').check();
      await aWindow.locator('#rememberDuration').selectOption(queueDuration);
      for (const field of scopeFields) await aWindow.locator(`input[data-field="${field}"]`).check();
      await wait('review scoped to A', async () => {
        const summary = await aWindow.locator('#rememberSummary').innerText();
        return scopeValues(outgoing).every((value) => summary.includes(value));
      });
      await aWindow.locator('#block').click();
      const bWindow = await wait('automatic handoff to B', async () => {
        const w = desktop.windows().find((w) => new URL(w.url() || 'about:blank').searchParams.get('request') === b.id);
        return w && await w.locator('#allow').isVisible() && w;
      });
      assert.equal((await held(1))[0].id, b.id);
      assert.equal(await count(), before);
      assert(await bWindow.locator('#rememberToggle').isChecked());
      assert.equal(await bWindow.locator('#rememberDuration').inputValue(), queueDuration);
      for (const field of ['protocol', 'address', 'port', 'process']) {
        const input = bWindow.locator(`input[data-field="${field}"]`);
        const selected = scopeFields.includes(field);
        assert.equal(await input.isChecked(), selected);
        if (selected) assert((await input.locator('..').innerText()).includes(fieldValue(peerB, field)));
      }
      const bSummary = await wait('fresh reviewed scope for B', async () => {
        const summary = await bWindow.locator('#rememberSummary').innerText();
        return scopeValues(peerB).every((value) => summary.includes(value)) &&
          scopeFields.every((field) => fieldValue(outgoing, field) === fieldValue(peerB, field) ||
            !summary.includes(fieldValue(outgoing, field))) &&
          summary.includes(queueSummary) && (!competingRule || summary.includes(competingRule.id)) && summary;
      });
      await bWindow.screenshot({ path: path.join(run, 'queued-b-' + scenario + '.png') });
      if (competingRule) {
        const versionBefore = competingRule.version;
        ({ saved_rule: competingRule } = await call('rule-save', {
          id: competingRule.id, expected_version: versionBefore, rule: { ...competingRule, action: 'allow' },
        }));
        assert.equal(competingRule.version, versionBefore + 1);
        await bWindow.locator('#allow').click();
        await wait('visible Refresh review', () => bWindow.locator('#refreshDecision').isVisible());
        assert.equal((await held(1))[0].id, b.id);
        assert.equal(await count(), before);
        assert.deepEqual((await call('list')).rules.find((rule) => rule.id === competingRule.id), competingRule);
        assert.equal(await bWindow.locator('#allow').isEnabled(), false);
        await bWindow.screenshot({ path: path.join(run, 'queued-b-review-refused.png') });
        await bWindow.locator('#refreshDecision').click();
        await wait('review names replacement rule', async () =>
          (await bWindow.locator('#rememberSummary').innerText()).includes(competingRule.id));
      }
      if (clearRemember) await bWindow.locator('#rememberToggle').uncheck();
      if (queueSeconds && scenario === 'keep') await new Promise((resolve) => setTimeout(resolve, 12000));
      const clickedBAt = Date.now();
      await bWindow.locator('#allow').click();
      await held(0);
      await wait('only B delivered after its answer', async () => await count() === before + 1);
      const { lines } = await command({ op: 'peer-counts' });
      assert(lines.at(-1).includes(`('${peerB.host}', ${peerB.port})`));
      const { rules } = await call('list');
      const denyA = rules.find((r) => r.action === 'block' &&
        (!portScope || r.filter.remote_port === outgoing.port) &&
        (!addressScope || r.filter.remote_address === outgoing.host));
      const allowB = rules.find((r) => r.action === 'allow');
      assert.deepEqual(rules.find((r) => r.id === ask.id), ask);
      assert.deepEqual(denyA.filter, scopedFilter(outgoing));
      if (queueSeconds) assert.equal(Date.parse(denyA.expires) - Date.parse(denyA.created), queueSeconds * 1000);
      else assert.equal(denyA.expires, ask.expires);
      assert.equal(rules.length, clearRemember ? 2 : 3);
      await attemptWith(denyA);
      if (endpointScope) {
        for (const crossed of crossedEndpoints) {
          await checkRestoredAsk(crossed);
          console.log(`PASS crossed ${crossed.host}:${crossed.port}: Ask ${ask.id}, receiver 0 held / 1 after Allow Once.`);
        }
      } else if (portScope) {
        await checkRestoredAsk(controlPort);
        console.log('PASS control port ' + controlPort.port + ': Ask ' + ask.id + ', receiver 0 held / 1 after Allow Once.');
      }
      if (clearRemember) {
        assert.equal(allowB, undefined);
        await checkRestoredAsk(peerB);
      } else {
        assert.deepEqual(allowB.filter, scopedFilter(peerB));
        if (differentPortAddress) {
          await attemptWith(allowB, crossPort);
          console.log('PASS saved rule ' + allowB.id + ' allowed ' + crossPort.host + ':' + crossPort.port +
            ' (B port at A address), receiver 1.');
        }
        if (competingRule) {
          assert.equal(allowB.id, competingRule.id);
          assert.equal(allowB.version, competingRule.version + 1);
          await attemptWith(allowB, peerB);
          console.log('PASS queued review conflict: no delivery or save on first click, visible Refresh review showed ' +
            competingRule.id + ' and the next click saved version ' + allowB.version + '; B delivered 1.');
        } else if (queueSeconds) {
          const deadlineA = Date.parse(denyA.expires), deadlineB = Date.parse(allowB.expires);
          assert.equal(deadlineB - Date.parse(allowB.created), queueSeconds * 1000);
          assert(deadlineB - deadlineA >= 10000, 'deadlines must track the gap between clicks');
          assert(deadlineB - clickedBAt >= queueSeconds * 1000 - 500, 'waiting on B must not shorten the saved duration');
          console.log('PASS timed queue: B preview ' + bSummary + '; click ' + new Date(clickedBAt).toISOString() +
            '; deadlines A ' + denyA.expires + ', B ' + allowB.expires +
            '; B lifetime from click ' + (deadlineB - clickedBAt) + ' ms.');
          if (queueSeconds === 60) {
            await wait('A deadline', () => Date.now() > deadlineA + 250, 70000);
            await checkRestoredAsk(outgoing);
            assert(Date.now() < deadlineB, 'B probe must start between the deadlines');
            await attemptWith(allowB, peerB);
            await wait('B deadline', () => Date.now() > deadlineB + 250, 25000);
            await checkRestoredAsk(peerB);
            console.log('PASS queued expiry: between deadlines A prompted under ' + ask.id +
              ' (0 held / 1 after Allow Once), B delivered 1; after B deadline the same Ask prompted.');
          } else {
            await attemptWith(allowB, peerB);
          }
        } else {
          assert.equal(allowB.expires, ask.expires);
          await attemptWith(allowB, peerB);
        }
      }
      if (allowB) await mutate(allowB.id, 'deleteRule');
      await mutate(denyA.id, 'deleteRule');
      await wait('only the explicit Ask remains', async () => {
        const { rules } = await call('list');
        return rules.length === 1 && rules[0].id === ask.id;
      });
      console.log('PASS queued Remember (' + queueScope + '): A saved ' + denyA.id + ' for ' + scopeValues(outgoing).join(' / ') +
        ' and fresh A delivered 0; original B ' + b.id + ' delivered 1; ' +
        (clearRemember ? 'cleared Remember saved no B rule, fresh B prompted under ' + ask.id
          : 'untouched Allow saved ' + allowB.id + ' for ' + scopeValues(peerB).join(' / ') + ', fresh B delivered 1'));
    }
    await closeAlpha();
  }
  const timedAction = process.env.FLOWGATE_TEST_TIMED_ACTION || 'allow';
  assert(['allow', 'block'].includes(timedAction));
  const timedDeliveries = Number(timedAction === 'allow');
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
  await window.locator('#' + timedAction).click();
  const list = await wait('remembered rule', async () => {
    const state = await call('list');
    return state.rules.some((r) => r.action === timedAction) && state;
  });
  const saved = list.rules.find((r) => r.action === timedAction);
  assert.equal(saved.id === ask.id, baseline);
  assert.equal(list.rules.some((r) => r.id === ask.id && r.action === 'ask'), !baseline);
  await held(0);
  if (timedDeliveries) await wait('both held attempts delivered', async () => await count() === before + 2);
  await closeAlpha();
  assert.equal(await count(), before + 2 * timedDeliveries);
  await attemptWith(saved);
  await closeAlpha();
  if (!baseline) {
    await mutate(saved.id, 'toggleRule');
    await wait('timed choice disabled and source Ask enabled', async () =>
      (await ruleRow(saved.id).locator('td').allTextContents()).at(-1) === 'Disabled' &&
      (await ruleRow(ask.id).locator('td').allTextContents()).at(-1) === 'Enabled');
    const disabled = (await call('list')).rules.find((rule) => rule.id === saved.id);
    assert.equal(disabled.expires, saved.expires);
    assert(Date.now() < Date.parse(saved.expires));
    const received = await count();
    const since = new Date().toISOString();
    await command(outgoing);
    const [request] = await held(1);
    assert.equal(request.rule, ask.id);
    const disabledWindow = await prompt(request.id);
    await wait('timed disable shows original Ask source', async () =>
      (await disabledWindow.locator('#askSource').textContent())?.includes(ask.id));
    await wait('timed disable Ask in Decision Log', async () =>
      (await call('decision-log', { decision_query: { since, limit: 20 } })).decision_log.records.some((record) =>
        record.kind === 'pending' && record.request_id === request.id && record.decision?.rule?.id === ask.id));
    await disabledWindow.screenshot({ path: path.join(run, 'timed-disabled-ask.png') });
    assert.equal(await count(), received);
    await disabledWindow.locator('#allow').click();
    await wait('disabled timed choice held until Allow Once', async () => await count() === received + 1);
    await held(0);
    await closeAlpha();
    await mutate(saved.id, 'toggleRule');
    await assertEnabledChoice(saved);
    const reenabled = (await call('list')).rules.find((rule) => rule.id === saved.id);
    assert.equal(reenabled.expires, saved.expires);
    assert.equal(reenabled.version, saved.version + 2);
    assert(Date.now() < Date.parse(saved.expires));
    await attemptWith(saved);
    await closeAlpha();
    console.log('PASS timed ' + timedAction + ', rule ' + saved.id + ' expires ' + saved.expires +
      '; enabled and re-enabled receiver +'+ timedDeliveries +
      '; disabled source ' + ask.id + ' receiver 0 held / 1 after Allow Once; deadline unchanged');
  }
  await new Promise((resolve) => setTimeout(resolve, Math.max(0, Date.parse(saved.expires) - Date.now() + 500)));
  const expiryCount = await count();
  const expirySince = new Date().toISOString();
  await command(outgoing);
  const [after] = await held(1);
  assert.equal(after.rule, baseline ? 'default-ask' : ask.id);
  const afterWindow = await prompt(after.id);
  const expectedSource = baseline ? 'default Ask' : ask.id;
  await wait('prompt source ' + expectedSource, async () =>
    (await afterWindow.locator('#askSource').textContent())?.includes(expectedSource));
  await afterWindow.screenshot({ path: path.join(run, 'after-expiry.png') });
  await wait('expired choice fallback in Decision Log', async () =>
    (await call('decision-log', { decision_query: { since: expirySince, limit: 20 } })).decision_log.records.some((record) =>
      record.kind === 'pending' && record.request_id === after.id &&
      (baseline ? record.decision?.source === 'default_ask' : record.decision?.rule?.id === ask.id)));
  assert.equal(await count(), expiryCount);
  await afterWindow.locator('#allow').click();
  await wait('expired choice held until Allow Once', async () => await count() === expiryCount + 1);
  await held(0);
  console.log('PASS timed expiry: ' + (baseline ? 'default Ask' : ask.id) +
    ' prompted, receiver 0 held / 1 after Allow Once');
  const permanentAction = process.env.FLOWGATE_TEST_PERMANENT_ACTION;
  if (permanentAction) {
    assert(!baseline && ['allow', 'block'].includes(permanentAction));
    await closeAlpha();
    const beforePermanent = await count();
    await command(outgoing);
    const [permanentRequest] = await held(1);
    assert.equal(permanentRequest.rule, ask.id);
    const permanentWindow = await prompt(permanentRequest.id);
    await permanentWindow.locator('#rememberToggle').check();
    await permanentWindow.locator('#rememberDuration').selectOption('0');
    await wait('permanent Ask retention preview', async () => {
      const summary = await permanentWindow.locator('#rememberSummary').innerText();
      return summary.includes('keeps Ask rule ' + ask.id) && summary.includes('saves a separate rule');
    });
    await permanentWindow.locator('#' + permanentAction).click();
    const remembered = await wait('separate permanent choice', async () => {
      const rules = (await call('list')).rules;
      const rule = rules.find((r) => r.action === permanentAction && r.expires.startsWith('0001-'));
      if (!rule) return false;
      assert.notEqual(rule.id, ask.id);
      assert.deepEqual(rules.find((r) => r.id === ask.id), ask);
      assert.deepEqual(rule.filter, ask.filter);
      return rule;
    });
    const deliveries = Number(permanentAction === 'allow');
    if (deliveries) await wait('held receiver write', async () => await count() === beforePermanent + 1);
    await held(0);

    const inventory = () => assertEnabledChoice(remembered);
    const attempt = () => attemptWith(remembered);
    await inventory();
    await attempt();

    await closeAlpha();
    const oldGeneration = generation;
    ({ generation } = await command({ op: 'restart' }));
    assert.notEqual(generation, oldGeneration);
    const reloaded = (await call('list')).rules;
    assert.deepEqual(reloaded.find((r) => r.id === ask.id), ask);
    assert.deepEqual(reloaded.find((r) => r.id === remembered.id), remembered);
    await wait('desktop reconnected to restarted daemon', () =>
      main.evaluate(async (g) => (await window.flowgate.snapshot()).control.generation === g, generation));
    await inventory();
    await attempt();

    // Retire the preceding blocked connect before allowing new requests to prompt.
    await closeAlpha();
    await mutate(remembered.id, 'toggleRule');
    await wait('disabled choice and Ask status', async () =>
      (await ruleRow(remembered.id).locator('td').allTextContents()).at(-1) === 'Disabled' &&
      (await ruleRow(ask.id).locator('td').allTextContents()).at(-1) === 'Enabled');
    await closeAlpha();
    const disabledCount = await count();
    await command(outgoing);
    const [disabledAsk] = await held(1);
    assert.equal(disabledAsk.rule, ask.id);
    const disabledWindow = await prompt(disabledAsk.id);
    await wait('disabled choice prompt source', async () =>
      (await disabledWindow.locator('#askSource').textContent())?.includes(ask.id));
    await disabledWindow.screenshot({ path: path.join(run, 'disabled-choice-ask.png') });
    assert.equal((await pending()).some((request) => request.id === disabledAsk.id), true);
    assert.equal(await count(), disabledCount);
    await disabledWindow.locator('#allow').click();
    await wait('disabled choice held until Allow Once', async () => await count() === disabledCount + 1);
    await held(0);
    await closeAlpha();

    await mutate(remembered.id, 'toggleRule');
    await inventory();
    await attempt();
    await closeAlpha();
    await mutate(remembered.id, 'deleteRule');
    await wait('delete reveals original Ask', async () =>
      (await ruleRow(remembered.id).count()) === 0 &&
      (await ruleRow(ask.id).locator('td').allTextContents()).at(-1) === 'Enabled');
    await closeAlpha();
    const deleteCount = await count();
    await command(outgoing);
    const [restored] = await held(1);
    assert.notEqual(restored.id, disabledAsk.id);

    const restoredWindow = await prompt(restored.id);
    await wait('restored explicit Ask source', async () =>
      (await restoredWindow.locator('#askSource').textContent())?.includes(ask.id));
    assert.equal(restored.rule, ask.id);
    await new Promise((resolve) => setTimeout(resolve, 800));
    assert.equal((await pending()).some((request) => request.id === restored.id), true);
    assert.equal(await count(), deleteCount);
    await restoredWindow.locator('#allow').click();
    await wait('restored Ask released only after answer', async () => await count() === deleteCount + 1);
    console.log('PASS permanent ' + permanentAction + ': Ask ' + ask.id + ' v' + ask.version +
      ', saved ' + remembered.id + ' v' + remembered.version + '; TCP receiver delta ' + deliveries +
      ' before and after restart and re-enable; disabled source ' + disabledAsk.rule +
      '; deleted restored explicit Ask, receiver 0 held / 1 after each answer');

  }
  console.log('Screenshots: ' + run);
} finally {
  if (desktop) {
    await desktop.evaluate(({ app }) => app.exit()).catch(() => {});
    await desktop.close().catch(() => {});
  }
  await fs.writeFile(ready.command, JSON.stringify({ op: 'quit' })).catch(() => {});
}
