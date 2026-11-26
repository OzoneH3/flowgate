// One real Activity window, with the renderer's animation frames held during
// startup. Use the packaged runtime and either a staged or rebuilt client.
import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { _electron as electron } from 'playwright-core';
import { readProjectedControls } from '../inventory/browser.mjs';
import { startSeed } from '../inventory/seeds.mjs';

const [runtime, client, output] = process.argv.slice(2).map((value) => path.resolve(value));
if (!runtime || !client || !output)
  throw Error('Pass the Electron executable, built client, and evidence path');
const run = await mkdtemp(path.resolve(import.meta.dirname, '../../.workspace/chart-'));
const display =
  process.env.WAYLAND_DISPLAY &&
  path.resolve(process.env.XDG_RUNTIME_DIR, process.env.WAYLAND_DISPLAY);
const [control, observer] = ['c', 'o'].map((name) => path.join(run, name));
const fixture = await startSeed('empty', control, observer);
const evidence = {};
let app;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

try {
  app = await electron.launch({
    executablePath: runtime,
    args: [
      `--ozone-platform=${display ? 'wayland' : 'x11'}`,
      client,
      '--show',
      '--control',
      control,
      '--observer',
      observer,
    ],
    cwd: run,
    env: {
      ...process.env,
      FLOWGATE_INSTALLED: '1',
      XDG_RUNTIME_DIR: run,
      XDG_CONFIG_HOME: path.join(run, 'config'),
      XDG_CACHE_HOME: path.join(run, 'cache'),
      TMPDIR: run,
      ...(display ? { WAYLAND_DISPLAY: display } : {}),
    },
  });
  let page;
  for (let i = 0; i < 100 && !page; i++) {
    page = app.windows().find((win) => win.url() === 'flowgate://app/index.html');
    if (!page) await sleep(50);
  }
  assert(page, 'Main renderer not found');
  // Model the stalled compositor schedule without changing the window, DOM,
  // chart response, or any app event handler. The harness can release frames
  // after observing the pre-paint DOM and Chromium accessibility tree.
  await page.addInitScript(() => {
    const schedule = window.requestAnimationFrame.bind(window);
    let next = 0,
      holding = true;
    const pending = new Map();
    window.chartTestFrames = {
      queued: () => pending.size,
      release: () => {
        holding = false;
        for (const callback of pending.values()) schedule(callback);
        pending.clear();
      },
    };
    window.requestAnimationFrame = (callback) => {
      if (!holding) return schedule(callback);
      pending.set(--next, callback);
      return next;
    };
  });
  await page.reload();
  const geometry = await page.evaluate(() => [screen.width, screen.height, devicePixelRatio]);
  assert.deepEqual(geometry, [1920, 1080, 1]);
  const tab = page.locator('#activityTab');
  await tab.press('Enter');
  assert.equal(await tab.getAttribute('aria-selected'), 'true');
  const download = page.locator('#graphValues [data-series=download]');
  const upload = page.locator('#graphValues [data-series=upload]');
  const selection = page.locator('.graph-selection');
  const canvas = page.locator('#trafficCanvas');
  const ready = () =>
    page.evaluate(
      () =>
        document.querySelector('#graphValues [data-series=download]')?.innerText ===
          'Download (—)' &&
        document.querySelector('#graphValues [data-series=upload]')?.innerText === 'Upload (—)' &&
        document.querySelector('.graph-selection')?.innerText === 'All applications',
    );
  const read = async () => ({
    framesQueued: await page.evaluate(() => window.chartTestFrames.queued()),
    download: (await download.count()) ? await download.innerText() : null,
    upload: (await upload.count()) ? await upload.innerText() : null,
    selection: await selection.innerText(),
    canvasName: await canvas.getAttribute('aria-label'),
    roles: (
      await readProjectedControls(await page.context().newCDPSession(page), '#trafficGraph')
    ).filter(
      (c) =>
        c.id === 'trafficCanvas' ||
        c.id.endsWith('button:download') ||
        c.id.endsWith('button:upload'),
    ),
  });

  for (let i = 0; i < 80 && !(await ready()); i++) await sleep(50);
  evidence.beforeFrame = await read();
  await page.evaluate(() => window.chartTestFrames.release());
  for (let i = 0; i < 100 && !(await ready()); i++) await sleep(50);
  evidence.afterFrame = await read();
  const checkpoint = evidence.beforeFrame;
  assert(checkpoint.framesQueued > 0, 'A paint had to be queued while frames were blocked');
  assert.deepEqual(
    [checkpoint.download, checkpoint.upload, checkpoint.selection],
    ['Download (—)', 'Upload (—)', 'All applications'],
  );
  for (const [id, name] of [
    ['button:download', 'Toggle download series'],
    ['button:upload', 'Toggle upload series'],
  ])
    assert(
      checkpoint.roles.some(
        (c) => c.id.endsWith(id) && c.role === 'button' && c.accessibleName === name,
      ),
    );
  assert(
    checkpoint.roles.some(
      (c) =>
        c.id === 'trafficCanvas' &&
        /All applications; Download \(—\); Upload \(—\)/.test(c.accessibleName),
    ),
  );
  assert.equal(evidence.afterFrame.canvasName, checkpoint.canvasName);
  await download.press('Space');
  assert.equal(await download.getAttribute('aria-pressed'), 'false');
  assert.equal(await upload.getAttribute('aria-pressed'), 'true');
  evidence.keyboard = { download: 'false', upload: 'true' };
  console.log(
    'PASS both series, selection and accessible names are readable before the first frame',
  );
} finally {
  await app?.close();
  await fixture.close();
  await writeFile(output, JSON.stringify(evidence, null, 2) + '\n');
}
