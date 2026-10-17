// Actual Wayland UI captures + narrow presentation smoke. Real TCP observer and isolated UDP controller.
import { _electron } from 'playwright-core';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
const { call } = createRequire(import.meta.url)('../dist/test/backend.cjs');
const root = path.resolve(import.meta.dirname, '../..'),
  stage = process.env.VISUAL_STAGE || 'after',
  run = fs.mkdtempSync(path.join(root, '.workspace/vis-'));
const evidence = path.join(root, '.workspace/visual-review', stage);
fs.mkdirSync(evidence, { recursive: true });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function wait(fn) {
  let error;
  for (let i = 0; i < 150; i++) {
    try {
      const v = await fn();
      if (v) return v;
    } catch (e) {
      error = e;
    }
    await sleep(100);
  }
  throw Error('Timeout ' + (error || fn));
}
function command(operation, fields = {}) {
  return new Promise((resolve, reject) => {
    const s = net.createConnection(path.join(run, 'demo.sock'));
    s.on('error', reject);
    s.on('connect', () => s.write(JSON.stringify({ operation, ...fields })));
    s.once('data', (b) => {
      s.destroy();
      resolve(JSON.parse(b));
    });
  });
}
const children = [];
let app, lab, burst;
function start(cmd, args = []) {
  const p = spawn(cmd, args, { cwd: root, stdio: ['pipe', 'pipe', 'pipe'] });
  children.push(p);
  let output = '';
  p.stdout.on('data', (b) => (output += b));
  p.stderr.on('data', (b) => (output += b));
  p.output = () => output;
  return p;
}
const pref = path.join(root, '.workspace/electron-preferences.json'),
  old = fs.existsSync(pref) ? fs.readFileSync(pref) : undefined;
try {
  fs.writeFileSync(pref, '{}');
  const harness = fs
    .readFileSync(path.join(root, 'scripts/host-lab.py'), 'utf8')
    .replace('ROOT=Path(__file__).resolve().parents[1]', `ROOT=Path(${JSON.stringify(root)})`)
    .replace("start('30s')", "start('120s')")
    .replace("'--timeout','8s'", "'--timeout','30s'");
  fs.writeFileSync(path.join(run, 'harness.py'), harness);
  const log = fs.openSync(path.join(run, 'lab.log'), 'w');
  lab = spawn(
    'scripts/lab.sh',
    ['python3', path.join(run, 'harness.py'), run, '--desktop-workflow'],
    {
      cwd: root,
      detached: true,
      stdio: ['ignore', log, log],
      env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' },
    },
  );
  fs.closeSync(log);
  await wait(() => fs.existsSync(path.join(run, 'ready')));
  const job = path.join(run, 'job');
  fs.mkdirSync(job);
  fs.writeFileSync(path.join(job, 'request.json'), '{"profile":"incoming"}');
  assert((await command('start', { job })).ok);
  const fixturePath = path.join(run, 'flowgate-visual-traffic');
  fs.copyFileSync(path.join(root, '.workspace/electron-traffic-fixture'), fixturePath);
  const fixture = start(fixturePath);
  await wait(() => fixture.output().includes('pid'));
  start(path.join(root, '.workspace/electron-observer'), [
    'observe',
    '--socket',
    path.join(run, 'host.sock'),
  ]);
  await wait(() => fs.existsSync(path.join(run, 'host.sock')));
  app = await _electron.launch({
    chromiumSandbox: true,
    args: [
      '--ozone-platform=wayland',
      path.join(root, 'electron'),
      '--observer',
      path.join(run, 'host.sock'),
      '--control',
      path.join(run, 'api/control.sock'),
    ],
    cwd: root,
    env: {
      ...process.env,
      WAYLAND_DISPLAY: 'wayland-0',
      XDG_CACHE_HOME: path.join(run, 'cache'),
      TMPDIR: path.join(root, '.workspace/tmp'),
    },
  });
  const pid = await app.evaluate(() => process.pid);
  assert(!fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').includes('--no-sandbox'));
  const page = await app.firstWindow();
  await page.setViewportSize({ width: 1280, height: 896 });
  const snap = () => page.evaluate(() => window.flowgate.snapshot());
  await wait(async () => (await snap()).control.connected && (await snap()).observation.connected);
  burst = setInterval(() => fixture.stdin.write('t\n'), 400);
  await sleep(2500);
  await page.locator('#rows tr').filter({ hasText: 'flowgate-visual-traffic' }).first().click();
  await sleep(3500);
  await page.screenshot({ path: path.join(evidence, 'main.png') });
  const metrics = await page.evaluate(() =>
    Object.fromEntries(
      ['.toolbar', '.tabs', '#tree thead', '#rows tr', 'aside', '#trafficGraph'].map((s) => {
        const r = document.querySelector(s).getBoundingClientRect();
        return [s, { x: r.x, y: r.y, width: r.width, height: r.height }];
      }),
    ),
  );
  metrics.presentation = await page.evaluate(() => {
    const row = document.querySelector('#rows tr'),
      cell = row.querySelector('td'),
      icon = row.querySelector('.application-icon');
    const c = getComputedStyle(cell),
      h = getComputedStyle(document.querySelector('#tree th'));
    const canvas = document.createElement('canvas'),
      ctx = canvas.getContext('2d');
    return {
      font: c.fontFamily,
      fontSize: c.fontSize,
      lineHeight: c.lineHeight,
      cellPadding: c.padding,
      rowPitch: row.getBoundingClientRect().height,
      header: document.querySelector('#tree thead').getBoundingClientRect().height,
      headerBackground: h.backgroundColor,
      iconRect: icon.getBoundingClientRect().toJSON(),
      fontWidths: Object.fromEntries(
        ['Noto Sans', 'Open Sans', 'Liberation Sans'].map((f) => {
          ctx.font = '12px ' + JSON.stringify(f);
          return [f, ctx.measureText('Windows Push Notifications System Service').width];
        }),
      ),
    };
  });
  if (stage.startsWith('target')) {
    const firefox = page.locator('#rows tr').filter({ hasText: 'firefox' }).first();
    await wait(() => firefox.locator('img').count());
    await firefox.click();
    await wait(() => page.locator('#selectedName img').count());
    await page.screenshot({ path: path.join(evidence, 'installed-icons.png') });
    const invalid = await page.evaluate(() => window.flowgate.applicationIcons(['/etc/passwd']));
    assert.equal(invalid['/etc/passwd'], null);
    assert(await page.locator('.col-incoming_policy').isVisible());
    console.log(
      'PASS installed desktop icons in real Activity and sidebar, arbitrary icon identity rejected',
    );
  }
  metrics.dpr = await page.evaluate(() => devicePixelRatio);
  fs.writeFileSync(path.join(evidence, 'metrics.json'), JSON.stringify(metrics, null, 2));
  if (stage !== 'before') {
    for (const id of ['controlMenu', 'optionsMenu']) {
      await page.click('#' + id + ' > summary');
      assert(await page.locator('#' + id + ' .menu-panel').isVisible());
      await page.keyboard.press('Escape');
      assert.equal(await page.locator('#' + id).getAttribute('open'), null);
    }
    for (const key of ['upload_bps', 'download_bps']) {
      await page.click('.col-' + key + ' button');
      assert.equal(await page.locator('.col-' + key).getAttribute('aria-sort'), 'descending');
      await page.click('.col-' + key + ' button');
      assert.equal(await page.locator('.col-' + key).getAttribute('aria-sort'), 'ascending');
    }
    await page.fill('#search', 'flowgate-visual-traffic');
    await page.click('#expand');
    assert((await page.locator('#rows tr').count()) > 2);
    await page.fill('#search', '');
    const grip = page.locator('#activityView .sidebar-grip');
    await grip.focus();
    await page.keyboard.press('ArrowLeft');
    const cg = page.locator('.col-name .column-grip'),
      b = await cg.boundingBox();
    await page.mouse.move(b.x + 2, b.y + 4);
    await page.mouse.down();
    await page.mouse.move(b.x + 22, b.y + 4);
    await page.mouse.up();
    assert(await page.locator('#trafficCanvas').isVisible());
    assert.match(await page.locator('#graphSource').innerText(), /UDP API/);
    await page.setViewportSize({ width: 860, height: 600 });
    await page.screenshot({ path: path.join(evidence, 'main-narrow.png') });
    await page.setViewportSize({ width: 1280, height: 896 });
    console.log(
      'PASS descending-first rate headers, toggle, search/expansion, keyboard sidebar and pointer column resizing, graph/source labels; narrow capture',
    );
  }
  const received = (port) =>
    (fs.readFileSync(path.join(run, `receiver-${port}.log`), 'utf8').match(/RECEIVED/g) || [])
      .length;
  async function pending(port) {
    await command('send', { port });
    return await wait(async () =>
      (await snap()).control.events.find(
        (e) => e.state === 'awaiting-decision' && e.flow.local.endsWith(':' + port),
      ),
    );
  }
  const e = await pending(44001);
  await page.click('#requestsTab');
  await page.locator('#requestRows tr').filter({ hasText: e.flow.remote }).click();
  await page.locator('.open-prompt').click();
  const prompt = await wait(() => app.windows().find((p) => p !== page));
  await prompt.waitForSelector('#allow');
  await prompt.setViewportSize({ width: 586, height: 714 });
  if (stage !== 'before') {
    assert.equal(e.flow.direction, 'incoming');
    assert.equal(await prompt.locator('.identity-route dd').first().innerText(), e.flow.remote);
  }
  await prompt.screenshot({ path: path.join(evidence, 'prompt.png') });
  await prompt.click('#allow');
  await wait(() => received(44001) === 1);
  await prompt.evaluate(() => window.flowgate.dismissPrompt());
  const block = await pending(44003);
  await page.locator('#requestRows tr').filter({ hasText: block.flow.remote }).click();
  await page.click('#block');
  await sleep(400);
  assert.equal(received(44003), 0);
  console.log('PASS real isolated Allow delivers retained UDP; Block prevents delivery');
  const edit = await pending(44005);
  await page.locator('#requestRows tr').filter({ hasText: edit.flow.remote }).click();
  await page.click('#createRule');
  await page.locator('#ruleEditor').screenshot({ path: path.join(evidence, 'editor.png') });
  if (stage !== 'before') {
    await page.fill('#editAddress', '2001:db8:1234:5678:abcd:ef01:2345:6789');
    await page.focus('#editAddress');
    await page.evaluate(() => {
      const i = document.querySelector('#editAddress');
      i.setSelectionRange(2, 12);
    });
    await sleep(1400);
    assert.equal(await page.inputValue('#editAddress'), '2001:db8:1234:5678:abcd:ef01:2345:6789');
    assert.equal(
      await page.evaluate(() => document.querySelector('#editAddress').selectionStart),
      2,
    );
    await page.click('#minimizeEditor');
    await page.click('#requestsTab');
    assert(await page.locator('#requestRows').isVisible());
    await page.click('#resumeEditor');
    assert.equal(await page.inputValue('#editAddress'), '2001:db8:1234:5678:abcd:ef01:2345:6789');
    await page.setViewportSize({ width: 860, height: 600 });
    await page.screenshot({ path: path.join(evidence, 'editor-narrow.png') });
    await page.setViewportSize({ width: 1280, height: 896 });
    console.log(
      'PASS IPv6 input, selection/focus across polling, draft minimize/resume and pending access',
    );
  }
  await page.fill('#editAddress', '10.79.0.2');
  await page.click('#previewRule');
  await wait(() => page.locator('#saveRule').isEnabled());
  await page.click('#saveRule');
  await wait(() => received(44005) === 1);
  console.log('PASS real isolated rule preview/save and receiver delivery');
  if (stage.startsWith('target')) {
    await app.evaluate(({ app }) => app.exit());
    await app.close();
    app = undefined;
    app = await _electron.launch({
      chromiumSandbox: true,
      args: [
        '--ozone-platform=wayland',
        path.join(root, 'electron'),
        '--observer',
        path.join(run, 'observer.sock'),
        '--control',
        path.join(run, 'api/control.sock'),
      ],
      cwd: root,
      env: {
        ...process.env,
        WAYLAND_DISPLAY: 'wayland-0',
        XDG_CACHE_HOME: path.join(run, 'cache'),
        TMPDIR: path.join(root, '.workspace/tmp'),
      },
    });
    const inventoryPage = await app.firstWindow();
    await inventoryPage.setViewportSize({ width: 1280, height: 896 });
    const read = () => inventoryPage.evaluate(() => window.flowgate.snapshot());
    await wait(
      async () =>
        (await read()).control.rules?.length && inventoryPage.locator('.policy-allow').count(),
    );
    const selected = inventoryPage
      .locator('#rows tr')
      .filter({ has: inventoryPage.locator('.policy-allow') })
      .first();
    await selected.click();
    await inventoryPage.screenshot({ path: path.join(evidence, 'rules-allow-real.png') });
    let current = (await read()).control.rules[0];
    const mutate = async (extra) => {
      const c = (await read()).control;
      const r = await call(path.join(run, 'api/control.sock'), {
        operation: 'rule-save',
        generation: c.generation,
        id: current.id,
        expected_version: current.version,
        rule: { ...current, ...extra },
      });
      assert.equal(r.error, '');
      current = r.saved_rule;
    };
    await mutate({ action: 'block' });
    await wait(() => inventoryPage.locator('.policy-block').count());
    await inventoryPage.screenshot({ path: path.join(evidence, 'rules-block-real.png') });
    await mutate({ disabled: true });
    await wait(() => inventoryPage.locator('.policy-disabled').count());
    await inventoryPage.screenshot({ path: path.join(evidence, 'rules-disabled-real.png') });
    console.log(
      'PASS real isolated rule inventory follows Allow, Block and disabled saved rule updates',
    );
  }

  clearInterval(burst);
  burst = undefined;
  fs.writeFileSync(
    path.join(evidence, 'run.txt'),
    run +
      '\nActual Wayland, real host TCP observer and disposable isolated UDP controller. DPR=' +
      metrics.dpr +
      '\n',
  );
  console.log('CAPTURES ' + evidence);
} finally {
  if (burst) clearInterval(burst);
  if (app) {
    await app.evaluate(({ app }) => app.exit()).catch(() => {});
    await app.close().catch(() => {});
  }
  for (const p of children) p.stdin.end();
  await sleep(150);
  for (const p of children) if (p.exitCode === null) p.kill('SIGTERM');
  if (lab) {
    await command('quit').catch(() => {});
    for (let i = 0; i < 40 && lab.exitCode === null; i++) await sleep(100);
    if (lab.exitCode === null)
      try {
        process.kill(-lab.pid, 'SIGTERM');
      } catch {}
  }
  if (old) fs.writeFileSync(pref, old);
  else fs.rmSync(pref, { force: true });
}
