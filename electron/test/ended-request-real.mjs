// Real ended-request application-rule journey (request-application-rule-v1): sandboxed GUI against an
// externally held, disposable fixture (scripts/process-rules-isolated.py --hold --continuous --zones --other,
// fixture op "launch" relaunches the same executable). Never the host daemon. Receivers judge delivery.
import { _electron } from 'playwright-core';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import assert from 'node:assert/strict';
const project = path.resolve(import.meta.dirname, '../..'),
  readyPath = process.env.FLOWGATE_TEST_READY;
assert(
  readyPath?.startsWith('/home/flowgate-user/Apps/flowgate/.workspace/'),
  'disposable fixture required',
);
const ready = JSON.parse(fs.readFileSync(readyPath)),
  dir = path.dirname(readyPath);
assert(ready.socket.startsWith(dir + '/') && !ready.socket.startsWith('/run/'));
const run = fs.mkdtempSync(project + '/.workspace/ended-request-real-'),
  root = run + '/client';
fs.mkdirSync(root + '/electron', { recursive: true });
fs.cpSync(project + '/electron/dist', root + '/electron/dist', { recursive: true });
fs.copyFileSync(project + '/electron/package.json', root + '/electron/package.json');
fs.mkdirSync(root + '/.workspace/tmp', { recursive: true });
const evidence = {
  run,
  fixture: readyPath,
  generation: ready.generation,
  steps: [],
  findings: [],
  errors: [],
};
const step = (s) => {
  evidence.steps.push(s);
  console.log('PASS', s);
};
const finding = (s) => {
  evidence.findings.push(s);
  console.log('FINDING', s);
};
const call = (q) =>
  new Promise((resolve, reject) => {
    const s = net.createConnection(ready.socket);
    let text = '';
    s.on('error', reject);
    s.setTimeout(8000, () => s.destroy(Error('timeout')));
    s.on('connect', () => s.write(JSON.stringify({ version: 1, ...q }) + '\n'));
    s.on('data', (b) => {
      text += b;
      if (text.includes('\n')) {
        s.destroy();
        resolve(JSON.parse(text));
      }
    });
  });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const wait = async (fn, ms = 20000, label = '') => {
  for (let until = Date.now() + ms; Date.now() < until;) {
    const v = await fn().catch(() => undefined);
    if (v) return v;
    await sleep(80);
  }
  throw Error('timeout ' + (label || fn));
};
async function command(q) {
  const f = dir + '/command-result.json';
  fs.rmSync(f, { force: true });
  fs.writeFileSync(ready.command, JSON.stringify(q));
  await wait(async () => fs.existsSync(f), 20000, 'fixture command ' + q.op);
  return JSON.parse(fs.readFileSync(f));
}
const peerLines = async () => (await command({ op: 'peer-counts' })).lines.length;
const list = () =>
  call({ operation: 'list' }).then((l) => ({ ...l, rules: l.rules || [], events: l.events || [] }));
let app, main;
const prompts = () => app.windows().filter((w) => /[?&]request=/.test(w.url() || ''));
const promptWindow = () => prompts()[0];
const requestOf = (w) => new URL(w.url()).searchParams.get('request');
// Native window facts from the main process: bounds, focus and visibility of the prompt and main windows.
const windows = () =>
  app.evaluate(({ BrowserWindow }) =>
    BrowserWindow.getAllWindows().map((w) => ({
      url: w.webContents.getURL(),
      bounds: w.getBounds(),
      focused: w.isFocused(),
      visible: w.isVisible(),
    })),
  );
const promptFacts = async () => (await windows()).find((w) => /[?&]request=/.test(w.url));
const mainFacts = async () => (await windows()).find((w) => w.url.endsWith('/index.html'));
const shot = (w, name) => w.screenshot({ path: `${run}/${name}.png` }).catch(() => {});
try {
  const initial = await list();
  assert.equal(initial.generation, ready.generation);
  assert(
    initial.capabilities.includes('request-application-rule-v1'),
    'fixture lacks request-application-rule-v1',
  );
  for (const r of initial.rules) {
    // Disposable fixture only: start from zero rules through the real conditional delete API.
    const d = await call({ operation: 'rule-delete', generation: ready.generation, id: r.id, expected_version: r.version });
    assert(!d.error, 'fixture reset: ' + JSON.stringify(d));
  }
  evidence.backend = { capabilities: initial.capabilities, build: initial.build ?? null };
  app = await _electron.launch({
    chromiumSandbox: true,
    args: [
      '--ozone-platform=wayland',
      root + '/electron',
      '--observer',
      ready.monitor_socket,
      '--control',
      ready.socket,
    ],
    env: { ...process.env, TMPDIR: root + '/.workspace/tmp', XDG_CACHE_HOME: run + '/cache' },
  });
  // Main-process IPC refusals are invisible to the page; a stale transition
  // ("Permission presentation is transitioning") must never block a click.
  app.process().stderr?.on('data', (b) => {
    for (const line of String(b).split('\n'))
      if (/presentation is transitioning|Error occurred in handler for 'request-rule/.test(line))
        evidence.main_refusals = [...(evidence.main_refusals ?? []), line.slice(0, 300)];
  });
  main = await app.firstWindow();
  main.on('pageerror', (e) => evidence.errors.push(String(e)));
  app.on('window', (w) => w.on('pageerror', (e) => evidence.errors.push(String(e))));
  await main.setViewportSize({ width: 1280, height: 720 });
  await main.locator('#rows tr[data-id^="app:"]').first().waitFor();
  const menus = (open) =>
    main.evaluate((open) => {
      document.getElementById('toolsMenu').open = open;
      document.getElementById('controlMenu').open = open;
    }, open);
  evidence.alpha_start = await command({ op: 'launch', name: 'alpha' }); // fresh requester instance
  const prior = (await list()).protection;
  if (prior?.state === 'active')
    await call({
      operation: 'protection-stop',
      generation: ready.generation,
      protection_id: prior.id,
    });
  await wait(
    async () => (await list()).protection?.state !== 'active',
    30000,
    'fixture protection stopped before start',
  );
  await menus(true);
  await main.selectOption('#protectionProfile', 'both');
  await main.locator('#protectionCheck').click();
  await wait(() => main.evaluate(() => window.flowgate.protectionState()).then((s) => s.canStart));
  await main.locator('#protectionStart').click();
  await wait(
    async () => (await list()).protection?.state === 'active',
    30000,
    'fixture protection active',
  );
  await menus(false);
  step('fixture protection active (UI Start, profile both); host untouched');

  // 1. Real prompt from alpha; main window focused, prompt must not steal focus.
  await main.bringToFront();
  await main.locator('#search').focus();
  await command({
    op: 'outgoing',
    name: 'alpha',
    protocol: 'tcp',
    host: '10.79.0.2',
    port: 43000,
    timeout_ms: 30000,
  });
  const first = await wait(async () => promptWindow(), 20000, 'prompt');
  const requestId = requestOf(first);
  await first.locator('#rememberToggle').waitFor();
  await sleep(600);
  const compact = await promptFacts();
  evidence.compact_bounds = compact.bounds;
  evidence.focus_on_open = { prompt: compact.focused, main: (await mainFacts()).focused };
  if (compact.focused) finding('prompt window took focus on open (focus theft)');
  else step(`prompt opened ${compact.bounds.width}x${compact.bounds.height} without taking focus`);
  await shot(first, '01-prompt-compact');

  // Remember expansion + Process selection while the requester is alive.
  await first.locator('#rememberToggle').check();
  await first.locator('#rememberPanel').waitFor();
  await sleep(800);
  const expanded = await promptFacts();
  evidence.expanded_bounds = expanded.bounds;
  // Compact layout may already fit the Remember panel; then no growth is needed, but it must be fully visible.
  const panelFits = await first.evaluate(() =>
    ['rememberPanel', 'rememberDuration', 'allow', 'block'].every((id) => {
      const r = document.getElementById(id)?.getBoundingClientRect();
      return !!r && r.height > 0 && r.top >= 0 && r.bottom <= window.innerHeight;
    }),
  );
  if (expanded.bounds.height <= compact.bounds.height && !panelFits)
    finding('Remember panel neither fits nor enlarged the prompt window');
  else if (expanded.bounds.height <= compact.bounds.height)
    step(`Remember panel, duration and Allow/Deny fit the compact ${compact.bounds.height}px window`);
  else
    step(
      `Remember expansion enlarged prompt ${compact.bounds.height} -> ${expanded.bounds.height}px`,
    );
  const processBox = first.locator('#rememberPanel input[data-field="process"]');
  assert(await processBox.isEnabled(), 'Process selectable while requester alive');
  await processBox.check();
  await shot(first, '02-remember-process-selected');

  // 2. Requester exits; ended request stays accessible with selections preserved.
  await command({ op: 'exit', name: 'alpha' });
  // The API lists an event only until shortly after its deadline; the retained request (deadline + 10 min)
  // lives on in the card. Judge what the user sees: the card must show the ended state.
  const apiStates = [];
  await wait(
    async () => {
      const ev = (await list()).events.find((e) => e.id === requestId);
      apiStates.push(ev ? `${ev.state}/${ev.request_rule?.process_state}` : 'unlisted');
      return /instance has ended|has ended|ended request/i.test(
        await first.locator('#requestDetails').innerText(),
      );
    },
    40000,
    'card shows ended state',
  );
  evidence.api_states_after_exit = [...new Set(apiStates)];
  await sleep(1500);
  // The retained card may live in the idle window (URL request=__idle__); identify it by content.
  evidence.ended_window_url = promptWindow()?.url();
  assert(
    /10\.79\.0\.2:43000/.test(await first.locator('#requestDetails').innerText()),
    'ended request still on screen',
  );
  evidence.ended_field_states = await first
    .locator('#rememberPanel input[data-field]')
    .evaluateAll((xs) =>
      xs.map((x) => ({
        field: x.dataset.field,
        checked: x.checked,
        disabled: x.disabled,
        available: x.dataset.available,
      })),
    );
  const lockedOptional = evidence.ended_field_states.filter(
    (f) => f.field !== 'application' && f.field !== 'process' && f.disabled,
  );
  if (lockedOptional.length)
    finding(
      'ended request locks optional Remember fields: ' +
        lockedOptional.map((f) => f.field).join(', '),
    );
  assert(await first.locator('#rememberToggle').isChecked(), 'Remember survives');
  assert(await processBox.isChecked(), 'Process selection survives');
  await shot(first, '03-ended-process-still-checked');
  step(
    'requester exited; ended request remains on screen, Remember and Process selections preserved',
  );

  // 3. A checked Process restriction must remain uncheckable.
  const processState = {
    enabled: await processBox.isEnabled(),
    checked: await processBox.isChecked(),
  };
  evidence.process_checkbox_after_end = processState;
  if (!processState.enabled)
    finding('TRAP: ended request shows Process checked AND disabled; user cannot uncheck it');
  // Error visibility: with Process still checked the backend refuses the scope; the reason must be visible.
  evidence.ended_target_text = await first
    .locator('#permissionTarget')
    .innerText()
    .catch(() => '');
  // Remember + Allow is the save path; with the ended Process still checked it must not be offered.
  evidence.save_enabled_with_process = await first
    .locator('#allow')
    .isEnabled()
    .catch(() => false);
  if (evidence.save_enabled_with_process)
    finding('Allow enabled while the ended Process restriction is still checked');
  const bodyText = await first.locator('#requestDetails').innerText();
  evidence.ended_text_process_checked = bodyText.slice(0, 1500);
  assert(/Uncheck Process|instance has ended/i.test(bodyText), 'ended process reason visible');
  step('ended-process reason visible while Process is checked');
  if (!processState.enabled) throw Error('Process checkbox trap (see findings)');
  await processBox.uncheck();
  assert(!(await processBox.isChecked()), 'Process unchecked');
  step('Process restriction unchecked by the user');

  // 4. Application-only rule from the ordinary ended card: Remember checked, then Allow.
  for (const f of ['protocol', 'address', 'port'])
    if (await first.locator(`#rememberPanel input[data-field="${f}"]`).isChecked())
      await first.locator(`#rememberPanel input[data-field="${f}"]`).uncheck();
  // A one-time Allow is never converted into a rule: without Remember it is unavailable.
  await first.locator('#rememberToggle').uncheck();
  await sleep(300);
  evidence.plain_allow_enabled = await first.locator('#allow').isEnabled();
  evidence.plain_note = await first.locator('#decisionNote').innerText().catch(() => '');
  if (evidence.plain_allow_enabled) finding('plain Allow enabled on an ended request');
  assert(/check Remember to save a rule/i.test(evidence.plain_note), 'ended card explains Remember');
  if (await first.locator('#forAWhileToggle').count())
    evidence.for_a_while_disabled = await first.locator('#forAWhileToggle').isDisabled();
  if (evidence.for_a_while_disabled === false) finding('For a while enabled on an ended request');
  assert.equal((await list()).rules.length, 0, 'no rule from a plain click');
  await first.locator('#rememberToggle').check();
  assert(!(await processBox.isChecked()), 'Process stays unchecked after re-checking Remember');
  await wait(() => first.locator('#allow').isEnabled(), 15000, 'Remember + Allow enabled');
  evidence.rule_summary = await first.locator('#rememberSummary').innerText();
  assert(/future connections/i.test(evidence.rule_summary), 'summary names future connections');
  await shot(first, '04-ready-to-save');
  const beforeDelivered = await peerLines();
  await first.locator('#allow').click();
  const rule = await wait(
    async () => (await list()).rules.find((r) => r.action === 'allow'),
    15000,
    'rule saved',
  );
  assert.equal(rule.filter.protocol, '*');
  assert(
    ['*', ''].includes(rule.filter.remote_address) &&
      !rule.filter.remote_port &&
      !rule.filter.local_port,
  );
  assert(!rule.filter.process && !rule.filter.network_zone, 'application-wide, all zones');
  assert.equal((await list()).rules.length, 1);
  await wait(
    async () =>
      (await first.locator('#requestResult').innerText()) ===
      'Rule saved for future connections; this request has ended.',
    10000,
    'exact result text',
  );
  // A repeated click must not create a second rule.
  if (await first.locator('#allow').isEnabled()) {
    await first.locator('#allow').click();
    await sleep(800);
  }
  assert.equal((await list()).rules.length, 1, 'no duplicate rule');
  step(
    `Remember + Allow on the ended card stored ${rule.id}: application-wide Allow (TCP+UDP, any address/port, all zones)`,
  );
  if ((evidence.main_refusals ?? []).some((l) => /transitioning/.test(l)))
    finding('Save refused as transitioning by the main process: ' + evidence.main_refusals.join(' | '));

  // 6. Ended request still not approved.
  const ended = (await list()).events.find((e) => e.id === requestId);
  evidence.ended_event_state = ended?.state;
  assert.notEqual(ended?.state, 'allowed', 'ended request must not be approved');
  assert.equal(await peerLines(), beforeDelivered, 'ended request was not delivered');
  const afterText = await first.locator('#requestDetails').innerText();
  evidence.ended_text_after_save = afterText.slice(0, 1500);
  assert(/this request has ended/i.test(afterText), 'card says the request has ended');
  assert(!/Connection allowed|Allowed once/i.test(afterText), 'never reported as allowed');
  assert(
    !/Rule preview required before Allow\/Deny/.test(afterText),
    'ended card must not ask for an Allow/Deny preview',
  );
  await shot(first, '05-saved-ended-not-approved');
  // Settled geometry after the status line appears: it must sit inside the
  // framed shell and the native window must match the laid-out viewport.
  await first.waitForTimeout(900);
  const settled = await first.evaluate(() => {
    const r = (s) => document.querySelector(s)?.getBoundingClientRect();
    const shell = r('.prompt-shell'), feedback = r('#requestResult'), footer = r('.prompt-shell > footer');
    return { innerHeight, shellBottom: shell.bottom, feedbackTop: feedback.top, feedbackBottom: feedback.bottom,
      footerBottom: footer.bottom, feedbackText: document.querySelector('#requestResult').textContent,
      scrollHeight: document.documentElement.scrollHeight };
  });
  evidence.saved_settled_layout = settled;
  evidence.saved_settled_native = await promptFacts().catch(() => undefined);
  await shot(first, '05b-saved-settled');
  if (settled.feedbackText && (settled.feedbackBottom > settled.shellBottom + 1 || settled.scrollHeight > settled.innerHeight + 1))
    finding('status line renders outside the prompt frame after save: ' + JSON.stringify(settled));
  else step('settled after save: status line inside the frame, window ' + settled.innerHeight + 'px fits content');
  step(`ended request stays ${ended?.state}, not delivered, card says it was not approved`);

  // 8. Other pending requests behind the ended card: reachable from it.
  await command({
    op: 'outgoing',
    name: 'other',
    protocol: 'tcp',
    host: '10.79.0.3',
    port: 44000,
    timeout_ms: 30000,
  });
  await wait(
    async () => (await list()).events.some((e) => e.state === 'awaiting-decision'),
    15000,
    'other pending',
  );
  await sleep(800);
  const footer = await first.locator('#dismiss').innerText();
  evidence.footer_with_other_pending = footer;
  let next;
  if (!/10\.79\.0\.2:43000/.test(await promptWindow().locator('#requestDetails').innerText())) {
    next = promptWindow();
    step('next pending request replaced the settled ended card automatically');
  } else {
    await first.locator('#dismiss').click();
    next = await wait(
      async () => {
        const w = promptWindow();
        return w && /10\.79\.0\.3:44000/.test(await w.locator('#requestDetails').innerText())
          ? w
          : undefined;
      },
      15000,
      'moved to next request',
    );
    step(`moved past the ended request via "${footer}"`);
  }
  await next.locator('#allow').waitFor();
  await sleep(800);
  const nextFacts = await promptFacts();
  evidence.next_bounds = nextFacts.bounds;
  evidence.next_remember_checked = await next
    .locator('#rememberToggle')
    .isChecked()
    .catch(() => null);
  if (
    nextFacts.bounds.height !== compact.bounds.height ||
    nextFacts.bounds.width !== compact.bounds.width
  )
    finding(
      `next request not reset to compact size: ${JSON.stringify(nextFacts.bounds)} vs ${JSON.stringify(compact.bounds)}`,
    );
  else step('next request reset to compact size');
  if (evidence.next_remember_checked) finding('next request kept Remember expanded/checked');
  else step('next request starts with Remember collapsed');
  await shot(next, '06-next-request-compact');
  await next.click('#block');

  // 5. Relaunch the application: new PID, delivered without a prompt.
  const relaunch = await command({ op: 'launch', name: 'alpha' });
  evidence.relaunch = relaunch;
  const before = await peerLines();
  await command({
    op: 'outgoing',
    name: 'alpha',
    protocol: 'tcp',
    host: '10.79.0.2',
    port: 43000,
    timeout_ms: 8000,
  });
  await wait(async () => (await peerLines()) > before, 10000, 'relaunch delivered');
  const relaunchEvents = (await list()).events.filter((e) =>
    e.attribution?.owners?.some((o) => o.pid === relaunch.info.pid),
  );
  assert(!relaunchEvents.some((e) => e.state === 'awaiting-decision'), 'relaunch prompted');
  await sleep(1500);
  assert(
    !prompts().some((w) => relaunchEvents.some((e) => e.id === requestOf(w))),
    'no prompt window for relaunch',
  );
  step(`relaunched alpha PID ${relaunch.info.pid} delivered by ${rule.id} without a prompt`);
  assert.deepEqual(evidence.errors, []);
  await menus(true);
  await main.locator('#protectionStop').click();
  await wait(
    async () => (await list()).protection?.state !== 'active',
    30000,
    'fixture protection stopped',
  );
  evidence.pass = evidence.findings.length === 0;
} catch (e) {
  evidence.failure = String(e?.stack || e);
  if (main) await shot(main, 'failure-main');
  const w = app && promptWindow();
  if (w) await shot(w, 'failure-prompt');
} finally {
  fs.writeFileSync(run + '/evidence.json', JSON.stringify(evidence, null, 2));
  if (app) await app.close().catch(() => {});
  console.log(evidence.pass ? 'JOURNEY PASS' : 'JOURNEY FAIL', run);
  if (!evidence.pass) process.exitCode = 1;
}
