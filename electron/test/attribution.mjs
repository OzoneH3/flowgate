// Explicit synthetic presentation fixture; no ownership/kernel/enforcement evidence.
import { _electron } from 'playwright-core';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import assert from 'node:assert/strict';
const root = path.resolve(import.meta.dirname, '../..');
const run = fs.mkdtempSync(path.join(root, '.workspace/attribution-ui-'));
const socket = path.join(run, 'observer.sock');
const application = {
  key: 'native',
  revision: 'r',
  name: 'SYNTHETIC native application',
  executable: '/long/application/path/native',
};
const processes = {
  a: { id: 'a', pid: 11, uid: 1000, application },
  b: { id: 'b', pid: 12, thread_group_pid: 10, uid: 1000, application },
};
const row = (id, owners, category, remote) => ({
  id,
  owners,
  ownership_category: category,
  state: 'established',
  socket: { protocol: 'tcp', local: '[::1]:40000', remote, uid: 1001, state: 1 },
  traffic: {
    available: true,
    definition: 'tcp-transport',
    uploaded: 1024,
    downloaded: 2048,
    upload_bps: 16,
    download_bps: 32,
  },
});
const shared = row('shared', ['a', 'b'], 'shared', '[2001:db8::1]:443');
shared.display_application = application;
const rows = [
  shared,
  row('zero', [], 'no-userspace-inode', '[2001:db8::2]:443'),
  row('worker', ['b'], 'visible-holder', '[2001:db8::3]:443'),
];
const server = net.createServer((s) =>
  s.once('data', () =>
    s.end(
      JSON.stringify({
        version: 1,
        generation: 'synthetic-attribution',
        read_only: true,
        mode: 'host-monitor',
        server_time: new Date().toISOString(),
        activity: {
          sequence: Date.now(),
          collected: new Date().toISOString(),
          complete: true,
          issues: ['SYNTHETIC PRESENTATION FIXTURE'],
          rows,
          processes,
        },
      }) + '\n',
    ),
  ),
);
await new Promise((r) => server.listen(socket, r));
let app;
const pref = path.join(root, 'build/desktop-session/electron-preferences.json');
const old = fs.existsSync(pref) ? fs.readFileSync(pref) : undefined;
async function wait(fn) {
  for (let i = 0; i < 100; i++) {
    if (await fn()) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw Error('timeout');
}
try {
  app = await _electron.launch({
    chromiumSandbox: true,
    args: ['--ozone-platform=wayland', path.join(root, 'electron'), '--observer', socket],
    cwd: root,
    env: {
      ...process.env,
      WAYLAND_DISPLAY: 'wayland-0',
      XDG_CACHE_HOME: path.join(run, 'cache'),
      TMPDIR: path.join(root, '.workspace/tmp'),
    },
  });
  const p = await app.firstWindow();
  await wait(async () => (await p.locator('#rows').innerText()).includes('SYNTHETIC native'));
  await p.locator('#expand').click();
  const sharedRow = () => p.locator('#rows tr').filter({ hasText: '[2001:db8::1]:443' });
  await sharedRow().click();
  assert.match(await p.locator('#info').innerText(), /observation.only/i);
  delete shared.display_application;
  await wait(async () =>
    (await p.locator('#rows tr[aria-selected="true"]').innerText()).includes('[2001:db8::1]:443'),
  );
  await wait(async () => !(await p.locator('#info').innerText()).includes('Display association'));
  shared.display_application = application;
  await wait(async () => (await p.locator('#info').innerText()).includes('Display association'));
  assert.equal(await p.locator('#rows tr[aria-selected="true"]').count(), 1);
  assert.match(await p.locator('#rows').innerText(), /Worker TID 12 \(process 10\)/);
  await p.locator('#rows tr').filter({ hasText: '[2001:db8::2]:443' }).click();
  assert.match(await p.locator('#info').innerText(), /No userspace inode/);
  await p.screenshot({ path: path.join(run, 'synthetic-attribution.png') });
  console.log(
    'PASS synthetic display association regrouping retains selected socket and expands parent; worker TID; inode-zero explanation. ' +
      run,
  );
} finally {
  if (app) {
    await app.evaluate(({ app }) => app.exit());
    await app.close().catch(() => {});
  }
  server.close();
  if (old) fs.writeFileSync(pref, old);
  else fs.rmSync(pref, { force: true });
}
