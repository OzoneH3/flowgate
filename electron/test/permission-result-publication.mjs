// Installed-mode Electron regression using isolated Unix sockets and keyboard input.
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, realpath, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { _electron as electron } from 'playwright-core';
import { identities, startSeed } from '../inventory/seeds.mjs';

const [runtime, client, output] = process.argv.slice(2).map((value) => path.resolve(value));
if (!runtime || !client || !output)
  throw Error('Pass the Electron executable, built client, and evidence path');
const workspace = path.resolve(import.meta.dirname, '../../.workspace');
await mkdir(workspace, { recursive: true });
const wayland = process.env.WAYLAND_DISPLAY;
const display = wayland && path.resolve(process.env.XDG_RUNTIME_DIR, wayland);
const findings = [];

for (const [recipe, expected, staleVisibility] of [
  ['requestUnknown', 'Result unknown · no retry sent', true],
  ['requests', 'Allowed once', true],
  ['requests', 'Allowed once', false],
]) {
  const run = await mkdtemp(path.join(workspace, 'perm-result-'));
  const env = {
    ...process.env,
    FLOWGATE_INSTALLED: '1',
    XDG_RUNTIME_DIR: run,
    XDG_CONFIG_HOME: path.join(run, 'config'),
    XDG_CACHE_HOME: path.join(run, 'cache'),
    TMPDIR: run,
    ...(display ? { WAYLAND_DISPLAY: display } : {}),
  };
  const control = path.join(run, 'c'),
    observer = path.join(run, 'o');
  const fixture = await startSeed(recipe, control, observer);
  const evidence = { recipe, expected, staleVisibility };
  findings.push(evidence);
  let app;
  try {
    app = await electron.launch({
      executablePath: await realpath(runtime),
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
      env,
    });
    let page;
    for (let i = 0; i < 100 && !page; i++) {
      page = app.windows().find((win) => win.url() === 'flowgate://app/index.html');
      if (!page) await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert(page, 'Main renderer not found');
    const row = page.locator(`#requestRows tr[data-id="${identities.request}"]`);
    const allow = page.locator('#allow');
    await page.locator('#requestsTab').press('Enter');
    await row.press('Enter');
    await page.waitForFunction(
      (id) =>
        document.querySelector('#requestDetails')?.dataset.eventId === id &&
        !document.querySelector('#allow')?.disabled,
      identities.request,
    );

    // Model the Kubuntu disagreement without hiding or minimizing the real
    // test window. If possible, confirm its native visibility before overriding
    // only the BrowserWindow getter that guards the state broadcast.
    for (let i = 0; i < 100; i++) {
      if (
        await app.evaluate(({ BrowserWindow }) =>
          BrowserWindow.getAllWindows().some(
            (w) =>
              w.webContents.getURL() === 'flowgate://app/index.html' &&
              w.isVisible() &&
              !w.isMinimized(),
          ),
        )
      )
        break;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    evidence.native = await app.evaluate(({ BrowserWindow }, staleVisibility) => {
      const win = BrowserWindow.getAllWindows().find(
        (w) => w.webContents.getURL() === 'flowgate://app/index.html',
      );
      const showing = win.isVisible(),
        minimized = win.isMinimized();
      const send = win.webContents.send.bind(win.webContents);
      win.resultSends = [];
      win.webContents.send = (channel, ...args) => {
        const outcome = args[0]?.control?.permissionResults;
        if (channel === 'state' && outcome?.length)
          win.resultSends.push({ publication: args[0].publication, outcomes: outcome });
        return send(channel, ...args);
      };
      if (staleVisibility) win.isVisible = () => false;
      return { showing, minimized, guardReportsVisible: win.isVisible() };
    }, staleVisibility);
    assert(
      evidence.native.showing && !evidence.native.minimized,
      'Real main window must be shown in the test',
    );
    await allow.press('Enter');
    // Read the main ledger without applying this read to the renderer. The
    // visible result still has to arrive through normal state IPC.
    evidence.ledger = await page
      .waitForFunction(async (id) => {
        const view = await window.flowgate.snapshot();
        const result = view.control.permissionResults.find((item) => item.eventId === id);
        return (
          result && {
            result,
            event: view.control.events.find((event) => event.id === id),
            publication: view.publication,
          }
        );
      }, identities.request)
      .then((handle) => handle.jsonValue());
    const resultRow = page.locator(`#permissionResultRows li[data-event="${identities.request}"]`);
    await resultRow.waitFor({ state: 'visible', timeout: 2500 }).catch(() => {});
    evidence.ipc = await app.evaluate(
      ({ BrowserWindow }) =>
        BrowserWindow.getAllWindows().find(
          (w) => w.webContents.getURL() === 'flowgate://app/index.html',
        ).resultSends,
    );
    evidence.rendered = {
      count: await resultRow.count(),
      visible: await resultRow.isVisible(),
      text: (await resultRow.count()) ? await resultRow.innerText() : '',
      pendingState: (await row.count()) ? await row.locator('td').last().innerText() : null,
      competingPending: await page
        .locator(`#requestRows tr[data-id="${identities.incoming}"]`)
        .count(),
    };
    // Let multiple read-only reconciliations run before checking for retries.
    const polls = fixture.calls.filter((call) => call.operation === 'list').length;
    for (
      let i = 0;
      i < 100 && fixture.calls.filter((call) => call.operation === 'list').length < polls + 3;
      i++
    )
      await new Promise((resolve) => setTimeout(resolve, 50));
    evidence.listPollsAfterOutcome =
      fixture.calls.filter((call) => call.operation === 'list').length - polls;
    assert(evidence.listPollsAfterOutcome >= 3, 'Expected three post-outcome read-only polls');
    evidence.decisions = fixture.calls.filter((call) => call.operation === 'decide');
    assert.equal(evidence.decisions.length, 1);
    assert.deepEqual(evidence.decisions[0].decision, {
      id: identities.request,
      generation: 'inventory-generation',
      action: 'allow',
      scope: 'once',
    });
    assert.equal(evidence.ledger.result.text, expected);
    if (recipe === 'requestUnknown') {
      assert.equal(evidence.decisions[0].error, 'fixture_lost_reply');
      assert.match(evidence.ledger.result.detail, /Backend closed without acknowledgement/);
      assert.equal(evidence.ledger.event.attempt.phase, 'unknown');
      assert.equal(evidence.rendered.pendingState, 'unknown');
    } else assert.equal(evidence.rendered.pendingState, null);
    assert.equal(evidence.rendered.competingPending, 1);
    assert.equal(evidence.rendered.count, 1);
    assert(evidence.rendered.visible && evidence.rendered.text.includes(expected));
    assert(
      evidence.ipc.some((frame) =>
        frame.outcomes.some(
          (outcome) => outcome.eventId === identities.request && outcome.text === expected,
        ),
      ),
    );
  } catch (error) {
    evidence.failure = error.message;
  } finally {
    await app?.close();
    await fixture.close();
    await writeFile(output, JSON.stringify(findings, null, 2) + '\n');
  }
}
for (const result of findings) assert(!result.failure, `${result.recipe}: ${result.failure}`);
console.log(
  'PASS lost and acknowledged Atlas decisions stay visible with one submission each',
  output,
);
