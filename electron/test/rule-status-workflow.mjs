// Real Rule Status journey against an externally held, disposable process-rule fixture
// (scripts/process-rules-isolated.py --hold). Drives API mutations through the UI only.
// Never point this at the host daemon. Fixture owner quits/cleans after this run.
import { _electron } from 'playwright-core';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import assert from 'node:assert/strict';
const root = path.resolve(import.meta.dirname, '../..');
const readyPath = process.env.FLOWGATE_TEST_READY;
if (!readyPath?.startsWith('/home/flowgate-user/Apps/flowgate/.workspace/'))
  throw Error('Disposable workspace fixture ready.json required');
const ready = JSON.parse(fs.readFileSync(readyPath));
if (!ready.socket.startsWith(path.dirname(readyPath)))
  throw Error('Fixture socket outside fixture');
const run = fs.mkdtempSync(path.join(root, '.workspace/rule-status-real-'));
const prefs = path.join(root, '.workspace/electron-preferences.json'),
  old = fs.existsSync(prefs) ? fs.readFileSync(prefs) : undefined;
const log = [];
const step = (s) => {
  log.push(s);
  console.log('·', s);
};
const wait = async (fn, ms = 20000) => {
  for (let end = Date.now() + ms; Date.now() < end;) {
    if (await fn().catch(() => false)) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw Error('Timeout: ' + fn);
};
const list = () =>
  new Promise((resolve, reject) => {
    const s = net.createConnection(ready.socket);
    let b = '';
    s.on('connect', () => s.write('{"version":1,"operation":"list"}\n'));
    s.on('data', (c) => {
      b += c;
      if (b.includes('\n')) {
        s.destroy();
        resolve(JSON.parse(b));
      }
    });
    s.on('error', reject);
  });
let app;
try {
  fs.writeFileSync(prefs, '{}');
  app = await _electron.launch({
    chromiumSandbox: true,
    args: [
      '--ozone-platform=wayland',
      path.join(root, 'electron'),
      '--observer',
      ready.monitor_socket,
      '--control',
      ready.socket,
      '--width',
      '1280',
      '--height',
      '656',
    ],
    env: {
      ...process.env,
      WAYLAND_DISPLAY: process.env.WAYLAND_DISPLAY || 'wayland-0',
      XDG_CACHE_HOME: path.join(run, 'cache'),
      TMPDIR: path.join(root, '.workspace/tmp'),
    },
  });
  const p = await app.firstWindow();
  await p.setViewportSize({ width: 1280, height: 656 });
  const snapshot = () => p.evaluate(() => window.flowgate.snapshot());
  await wait(async () => {
    const s = await snapshot();
    return s.control.connected && s.control.policy?.processes?.length >= 2;
  });
  const alpha = ready.alpha_target.process_id,
    beta = ready.beta_target.process_id;
  const before = await list();
  assert(before.capabilities.includes('process-instance-rules-v1'));
  const rows = (pid) => p.locator(`#rows tr[data-id^="process:"][data-id$=":${pid}"]`);
  const cell = (tier, d) => p.locator(`[data-focus="cell:${tier}:${d}"]`);
  const ready2 = () =>
    wait(async () => !/Unavailable/.test(await cell('process', 'incoming').innerText()));
  const select = async (pid) => {
    await rows(pid).locator('.name').click();
    await ready2();
  };
  const saveReview = async () => {
    await wait(() => p.locator('.inline-review.phase-review').isVisible());
    assert.match(await p.locator('.inline-review .draft-badge').innerText(), /Draft · not saved/);
    await p.locator('[data-focus=review-save]').click();
    await wait(async () => !(await p.locator('.inline-review').count()));
  };
  const own = (s, pid) =>
    s.control.rules.filter(
      (r) => r.filter.process && `${r.filter.process.pid}` === pid.split(':')[0],
    );

  step('select application');
  await p.click('#expand');
  await p.locator('#rows tr[data-id^="app:"] .name').first().click();
  await wait(() => p.locator('[data-focus="cell:application:incoming"]').isVisible());
  assert.equal(await p.locator('[data-focus^="cell:process"]').count(), 0);
  await p.screenshot({ path: path.join(run, '01-application.png') });

  step('select alpha; open In via keyboard, Escape returns focus');
  await select(alpha);
  await cell('process', 'incoming').focus();
  await p.keyboard.press('Enter');
  await wait(() => p.locator('.activity-quick').isVisible());
  await p.waitForTimeout(800);
  assert.equal(await p.locator('.inline-review').count(), 0, 'Enter must not trigger an action');
  assert.equal(await p.evaluate(() => document.activeElement?.dataset.focus), 'quick');
  await p.keyboard.press('Escape');
  await wait(async () => !(await p.locator('.activity-quick').count()));
  assert.equal(
    await p.evaluate(() => document.activeElement?.dataset.focus),
    'cell:process:incoming',
  );

  const appRulesBefore = before.rules.filter((r) => !r.filter.process);
  let s = await snapshot();
  let target;
  if (own(s, alpha).length === 1) {
    step('alpha has one own rule: setter routes to that exact rule');
    target = own(s, alpha)[0];
    await cell('process', target.filter.direction).click();
    assert.match(await p.locator('.activity-quick').innerText(), /Change the existing rule/);
    await p.screenshot({ path: path.join(run, '02-setter-existing.png') });
    const previous = target.action;
    await p.locator(`.activity-quick [data-focus="setter:${target.id}:flip"]`).click();
    await wait(() => p.locator('.inline-review.phase-review').isVisible());
    step('review keeps focus through polling; Save reached by Tab, not pre-focused');
    assert.equal(await p.evaluate(() => document.activeElement?.dataset.focus), 'review');
    await p.keyboard.press('Tab');
    assert.equal(await p.evaluate(() => document.activeElement?.dataset.focus), 'review-save');
    await p.waitForTimeout(3500);
    assert.equal(await p.evaluate(() => document.activeElement?.dataset.focus), 'review-save');
    await p.screenshot({ path: path.join(run, '03-inline-review.png') });
    await saveReview();
    await wait(async () => {
      const r = (await snapshot()).control.rules.find((x) => x.id === target.id);
      return r && r.action !== previous;
    });
    const changed = (await snapshot()).control.rules.find((x) => x.id === target.id);
    assert.deepEqual(changed.filter, target.filter, 'binding/scope preserved');
    assert.equal(changed.expires, target.expires);
    target = changed;
  } else {
    step('alpha has no own rule: create process Allow UDP');
    await cell('process', 'incoming').click();
    await p.locator('[data-focus="quick-protocol:udp"]').click();
    await p.locator('.activity-quick .quick-allow').click();
    await p.screenshot({ path: path.join(run, '03-inline-review.png') });
    await saveReview();
    await wait(async () => own(await snapshot(), alpha).length === 1);
    target = own(await snapshot(), alpha)[0];
  }

  step('create a second, new process rule (Out Block TCP) via one-click setter');
  await cell('process', 'outgoing').click();
  if (await p.locator('.activity-quick [data-focus=quick-new]').count())
    await p.locator('.activity-quick [data-focus=quick-new]').click();
  await p.locator('[data-focus="quick-protocol:tcp"]').click();
  await p.locator('.activity-quick .quick-block').click();
  await wait(() => p.locator('.inline-review.phase-review').isVisible());
  assert.match(await p.locator('.inline-review-scope').innerText(), /This process · PID/);
  assert.match(await p.locator('.inline-review-scope').innerText(), /Block outgoing TCP/);
  await saveReview();
  await wait(async () => own(await snapshot(), alpha).length === 2);
  s = await snapshot();
  const outRule = own(s, alpha).find((r) => r.filter.direction === 'outgoing');
  assert(outRule && outRule.filter.process.pid === Number(alpha.split(':')[0]));
  await wait(async () =>
    /Block TCP|Block · TCP/.test(await cell('process', 'outgoing').innerText()),
  );
  await p.screenshot({ path: path.join(run, '04-alpha-two-own-rules.png') });

  step('beta unaffected: no own rules, fallback visible');
  await select(beta);
  assert.equal(own(await snapshot(), beta).length, 0);
  assert.match(await cell('process', 'incoming').innerText(), /Not set/);
  assert.match(await cell('process', 'outgoing').innerText(), /Not set/);
  assert.equal(await p.locator(`.activity-rule[data-rule-id="${outRule.id}"]`).count(), 0);
  assert.equal(await p.locator(`.activity-rule[data-rule-id="${target.id}"]`).count(), 0);
  const betaRow = await rows(beta).locator('.policy-cell').first().innerText();
  step('beta table In cell: ' + betaRow);
  await p.screenshot({ path: path.join(run, '05-beta-fallback.png') });
  assert.deepEqual(
    (await list()).rules.filter((r) => !r.filter.process).map((r) => [r.id, r.version]),
    appRulesBefore.map((r) => [r.id, r.version]),
    'application rules untouched',
  );

  step('beta draft: preview token expires, nothing saved, no silent refresh');
  const countBefore = (await list()).rules.length;
  await cell('process', 'incoming').click();
  await p.locator('[data-focus="quick-protocol:tcp"]').click();
  await p.locator('.activity-quick .quick-block').click();
  await wait(() => p.locator('.inline-review.phase-review').isVisible());
  assert.match(await p.locator('.review-timer').innerText(), /Review valid \d+ s/);
  await p.screenshot({ path: path.join(run, '05b-beta-draft.png') });
  await wait(() => p.locator('.inline-review.phase-expired').isVisible(), 45000);
  assert.equal(await p.locator('[data-focus=review-save]').count(), 0);
  await p.waitForTimeout(2500);
  assert(await p.locator('.inline-review.phase-expired').isVisible(), 'stays expired');
  assert.equal((await list()).rules.length, countBefore);
  await p.screenshot({ path: path.join(run, '05c-beta-expired.png') });
  await p.locator('[data-focus=review-discard]').click();
  await wait(async () => !(await p.locator('.inline-review').count()));
  step('stale review: let token expire, no silent refresh');
  await select(alpha);
  await p.locator(`.activity-rule[data-rule-id="${outRule.id}"] [data-focus$=":toggle"]`).click();
  await wait(() => p.locator('.inline-review.phase-review').isVisible());
  const expiryVisible = await p.locator('.review-timer').innerText();
  step('timer: ' + (expiryVisible || '(edit preview has no backend expiry)'));
  if (expiryVisible) {
    await wait(() => p.locator('.inline-review.phase-expired').isVisible(), 40000);
    assert.equal(await p.locator('[data-focus=review-save]').count(), 0);
    await p.locator('[data-focus=review-again]').click();
  }
  step('disable second rule');
  await saveReview();
  await wait(
    async () => (await snapshot()).control.rules.find((r) => r.id === outRule.id)?.disabled,
  );
  await wait(async () => /Disabled/.test(await cell('process', 'outgoing').innerText()));
  await p.screenshot({ path: path.join(run, '06-disabled.png') });

  step('delete second rule (conditional)');
  await p.locator(`.activity-rule[data-rule-id="${outRule.id}"] [data-focus$=":delete"]`).click();
  await p.click('#confirmYes');
  await wait(async () => !(await snapshot()).control.rules.some((r) => r.id === outRule.id));
  assert((await snapshot()).control.rules.some((r) => r.id === target.id));

  step('narrow 860×600 with setter open');
  await p.setViewportSize({ width: 860, height: 600 });
  await cell('process', 'incoming').click();
  await p.waitForTimeout(400);
  await p.screenshot({ path: path.join(run, '07-narrow-setter.png') });
  await p.keyboard.press('Escape');
  await p.setViewportSize({ width: 1280, height: 656 });

  let exited = false;
  if (process.env.FLOWGATE_EXIT_ALPHA === '1') {
    step('exit alpha via fixture owner command; session-bound rule becomes inactive');
    fs.writeFileSync(ready.command, JSON.stringify({ op: 'exit', name: 'alpha' }) + '\n');
    await wait(
      async () => (await snapshot()).control.rule_states?.[target.id]?.state === 'inactive',
      30000,
    );
    await wait(async () => /ended/i.test(await cell('process', 'incoming').innerText()));
    const card = p.locator(`.activity-rule[data-rule-id="${target.id}"]`);
    assert(await card.locator('[data-focus$=":flip"]').isDisabled());
    assert(await card.locator('[data-focus$=":delete"]').isEnabled());
    await p.screenshot({ path: path.join(run, '08-exited-inactive.png') });
    await p.setViewportSize({ width: 860, height: 600 });
    await p.screenshot({ path: path.join(run, '09-exited-narrow.png') });
    await p.setViewportSize({ width: 1280, height: 656 });
    step('delete inactive rule');
    await card.locator('[data-focus$=":delete"]').click();
    await p.click('#confirmYes');
    await wait(async () => !(await snapshot()).control.rules.some((r) => r.id === target.id));
    exited = true;
  }
  const g = (await list()).generation;
  await app.evaluate(({ app }) => app.exit());
  await app.close().catch(() => {});
  app = undefined;
  const after = await list();
  assert.equal(after.generation, g);
  assert.equal(after.enforcement.state, 'stopped');
  fs.writeFileSync(
    path.join(run, 'result.json'),
    JSON.stringify(
      {
        backend: process.env.FLOWGATE_TEST_BACKEND_SHA,
        generation: after.generation,
        alpha,
        beta,
        exited,
        steps: log,
        remaining: after.rules.map((r) => [r.id, r.action, r.filter.direction, !!r.filter.process]),
        enforcement: after.enforcement.state,
      },
      null,
      2,
    ),
  );
  console.log('PASS rule-status journey ' + run);
} catch (e) {
  if (app) {
    const p = await app.firstWindow();
    await p.screenshot({ path: path.join(run, 'failure.png') }).catch(() => {});
  }
  console.error('FAIL in', run);
  throw e;
} finally {
  if (app) {
    await app.evaluate(({ app }) => app.exit()).catch(() => {});
    await app.close().catch(() => {});
  }
  if (old) fs.writeFileSync(prefs, old);
  else if (fs.existsSync(prefs)) fs.unlinkSync(prefs);
}
