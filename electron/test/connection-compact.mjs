// Labelled synthetic presentation/state checks. Not native receiver/enforcement evidence.
import { _electron } from 'playwright-core';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import assert from 'node:assert/strict';
const root = path.resolve(import.meta.dirname, '../..');
const run = fs.mkdtempSync(path.join(root, '.workspace/connection-compact-'));
const endpoint = path.join(run, 'api');
let direction = 'incoming',
  disconnected = false,
  resolved = false,
  mutations = 0;
const appIdentity = {
  key: 'fixture',
  revision: 'r',
  name: 'SYNTHETIC dedicated app',
  executable: '/synthetic/fixture',
  display_name: 'SYNTHETIC dedicated app',
};
const deadline = new Date(Date.now() + 120000).toISOString();
const event = (id) => ({
  id,
  state: resolved ? 'expired' : 'awaiting-decision',
  reason: 'SYNTHETIC presentation fixture',
  deadline,
  first_seen: new Date().toISOString(),
  flow: {
    direction,
    protocol: 'udp',
    local: '[2001:db8::1]:44001',
    remote: '[2001:db8::2]:50000',
    network_scope: {
      state: 'known',
      zone: direction === 'incoming' ? 'local' : 'internet',
      revision: 'r',
      source: 'synthetic',
      reason: 'SYNTHETIC configured zone',
    },
  },
  attribution: {
    status: 'directly-associated',
    visibility_complete: true,
    application: appIdentity,
    owners: [],
  },
  scope_previews: {
    once: 'Only this held connection.',
    application: 'Backend preview: application and peer/service, any network, one hour.',
  },
});
const server = net.createServer((s) =>
  s.once('data', (raw) => {
    if (disconnected) {
      s.destroy();
      return;
    }
    const req = JSON.parse(raw);
    if (!['list', 'policy-view'].includes(req.operation)) mutations++;
    s.end(
      JSON.stringify({
        version: 1,
        generation: 'synthetic',
        mode: 'isolated-lab',
        read_only: false,
        server_time: new Date().toISOString(),
        permissions: {
          role: 'administrator',
          policy_scope: 'machine',
          observation_scope: 'machine',
          can_manage_rules: true,
          can_decide: true,
        },
        events: [event('first'), event('second')],
        rules: [],
        activity: {
          sequence: 1,
          collected: new Date().toISOString(),
          complete: true,
          processes: {},
          rows: [],
        },
      }) + '\n',
    );
  }),
);
await new Promise((r) => server.listen(endpoint, r));
const prefs = path.join(root, 'build/desktop-session/electron-preferences.json'),
  old = fs.existsSync(prefs) ? fs.readFileSync(prefs) : undefined;
let app, page;
try {
  fs.writeFileSync(prefs, '{}');
  app = await _electron.launch({
    chromiumSandbox: true,
    args: [
      '--ozone-platform=wayland',
      process.env.APP_PATH || path.join(root, 'electron'),
      '--observer',
      endpoint,
      '--control',
      endpoint,
    ],
    env: {
      ...process.env,
      TMPDIR: path.join(root, '.workspace/tmp'),
      XDG_CACHE_HOME: path.join(run, 'cache'),
    },
  });
  page = await app.firstWindow();
  await page.click('#requestsTab');
  await page.locator('#requestRows tr').first().waitFor();
  await page.locator('#requestRows tr').first().click();
  let prompt;
  if (process.env.BASELINE) {
    const opened = app.waitForEvent('window');
    await page.locator('.open-prompt').click();
    prompt = await opened;
  } else {
    for (let i = 0; i < 100 && !prompt; i++) {
      prompt = app.windows().find((w) => w.url().includes('?request='));
      if (!prompt) await new Promise((r) => setTimeout(r, 50));
    }
    assert(prompt, 'Automatic independent prompt appeared');
  }
  await prompt.locator('#allow').waitFor();
  await new Promise(r=>setTimeout(r,500));
  const placement=await app.evaluate(({BrowserWindow,screen})=>({workArea:screen.getPrimaryDisplay().workArea,prompt:BrowserWindow.getAllWindows().filter(w=>w.webContents.getURL().includes('?request=')).map(w=>({bounds:w.getBounds(),parent:!!w.getParentWindow()}))}));
  fs.writeFileSync(path.join(run,'placement.json'),JSON.stringify(placement,null,2));

  await prompt.screenshot({ path: path.join(run, 'incoming.png') });
  if (process.env.BASELINE) {
    console.log('BASELINE', run);
  } else {
    assert.match(await prompt.locator('#requestDetails').innerText(), /Local Network/);
    assert.equal(await prompt.locator('#block').innerText(), 'Deny');
    await prompt.locator('#requestDetails').focus();
    await prompt.keyboard.press('Enter');
    await prompt.keyboard.press('Enter');
    assert.equal(mutations, 0);
    await prompt.locator('#scope').selectOption('application');
    assert.match(await prompt.locator('#permissionTarget').innerText(), /Any network/);
    await prompt.locator('details').evaluate((n) => (n.open = true));
    await prompt.locator('#scope').focus();
    await new Promise((r) => setTimeout(r, 1100));
    assert.equal(
      await prompt.locator('#scope').evaluate((n) => document.activeElement === n),
      true,
    );
    assert.equal(await prompt.locator('details').evaluate((n) => n.open), true);
    resolved = true;
    await new Promise((r) => setTimeout(r, 1000));
    assert.equal(await prompt.locator('#allow').isDisabled(), true);
    assert.equal(await prompt.locator('details').evaluate((n) => n.open), true);
    resolved = false;
    direction = 'outgoing';
    await new Promise((r) => setTimeout(r, 1100));
    await prompt.screenshot({ path: path.join(run, 'outgoing.png') });
    assert.match(await prompt.locator('#requestDetails').textContent(), /This program → remote peer/);
    await prompt.setViewportSize({ width: 480, height: 500 });
    await prompt.screenshot({ path: path.join(run, 'narrow.png') });
    disconnected = true;
    await new Promise((r) => setTimeout(r, 1800));
    assert.equal(await prompt.locator('#allow').isDisabled(), true);
    assert.match(await prompt.locator('#requestDetails').innerText(), /SYNTHETIC dedicated app/);
    await prompt.keyboard.press('Escape').catch((error) => {
      if (!prompt.isClosed()) throw error;
    });
    await new Promise((r) => setTimeout(r, 250));
    assert.equal(mutations, 0);
    console.log('PASS synthetic focus/expiry/disconnect/no Enter decisions', run);
  }
} catch (error) {
  console.log('FAIL', run, await page?.evaluate(() => window.flowgate.snapshot()));
  if (page) await page.screenshot({ path: path.join(run, 'failure.png') });
  throw error;
} finally {
  if (app) await app.close();
  server.close();
  if (old) fs.writeFileSync(prefs, old);
  else fs.rmSync(prefs, { force: true });
}
