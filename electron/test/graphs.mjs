// Real unprivileged TCP observer + sandboxed Wayland Electron; no controller/collector.
import { _electron } from 'playwright-core';
import { spawn, execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
const { hierarchy, allRows, sum } = createRequire(import.meta.url)('../dist/test/model.cjs');
const root = path.resolve(import.meta.dirname, '../..'),
  run = fs.mkdtempSync(path.join(root, '.workspace/gr-'));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function wait(fn) {
  let error;
  for (let i = 0; i < 160; i++) {
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
const children = [];
let app, burst;
function start(cmd, args = []) {
  const p = spawn(cmd, args, {
    cwd: root,
    stdio: ['pipe', 'pipe', 'pipe'],
    env: { ...process.env, TMPDIR: path.join(root, '.workspace/tmp') },
  });
  children.push(p);
  let output = '';
  p.stdout.on('data', (b) => (output += b));
  p.stderr.on('data', (b) => (output += b));
  p.output = () => output;
  return p;
}
const prefs = path.join(root, '.workspace/electron-preferences.json'),
  old = fs.existsSync(prefs) ? fs.readFileSync(prefs) : undefined;
try {
  const fixturePath = path.join(run, 'tcp-fixture');
  fs.copyFileSync(path.join(root, '.workspace/electron-traffic-fixture'), fixturePath);
  const fixture = start(fixturePath, ['shared']);
  const info = await wait(() => {
    const line = fixture.output().split('\n')[0];
    return line.startsWith('{') ? JSON.parse(line) : null;
  });
  const observer = start(path.join(root, '.workspace/electron-observer'), [
    'observe',
    '--socket',
    path.join(run, 'obs.sock'),
    '--interval',
    '1s',
  ]);
  await wait(() => fs.existsSync(path.join(run, 'obs.sock')));
  app = await _electron.launch({
    chromiumSandbox: true,
    args: [
      '--ozone-platform=wayland',
      path.join(root, 'electron'),
      '--observer',
      path.join(run, 'obs.sock'),
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
  const page = await app.firstWindow(),
    snap = () => page.evaluate(() => window.flowgate.snapshot()),
    graph = (id) => page.evaluate((id) => window.flowgate.graph({ id, seconds: 300 }), id);
  const socket = await wait(async () => {
    const s = await snap();
    return s.observation.activity?.rows.find(
      (r) =>
        r.socket.protocol === 'tcp' &&
        r.socket.local.endsWith(':' + info.client4) &&
        r.owners.length === 2,
    );
  });
  await wait(async () => (await graph(socket.id)).points.some((p) => p.up === 0));
  await page.fill('#search', fixturePath);
  await page.click('#expand');
  await page.locator('#rows tr').filter({ hasText: socket.socket.remote }).first().click();
  // Select exact stable ID (endpoints may appear for more than one socket).
  await page
    .locator('#rows tr')
    .evaluateAll((rows, id) => rows.find((r) => r.dataset.id === id)?.click(), socket.id);
  burst = setInterval(() => fixture.stdin.write('t\n'), 400);
  const measured = await wait(async () => {
    const s = await snap(),
      g = await graph(socket.id),
      r = s.observation.activity.rows.find((r) => r.id === socket.id),
      p = g.points.at(-1);
    return p?.up > 0 &&
      p.down > 0 &&
      p.up === r.traffic.upload_bps &&
      p.down === r.traffic.download_bps
      ? { s, g, r }
      : null;
  });
  assert(measured.r.traffic.upload_bps > measured.r.traffic.download_bps);
  console.log(
    'PASS real shared socket upload/download agree exactly with table backend rates; upload > download',
  );
  await sleep(3500);
  await page.screenshot({ path: path.join(run, 'real-tcp-socket.png') });
  const group = allRows(hierarchy(measured.s.observation.activity)).find(
    (r) => r.kind === 'application' && r.rows.some((s) => s.id === socket.id),
  );
  assert(group);
  await wait(async () => {
    const s = await snap(),
      rows = allRows(hierarchy(s.observation.activity))
        .find((r) => r.id === group.id)
        .rows.filter((r) => r.socket.protocol === 'tcp'),
      g = await graph(group.id),
      p = g.points.filter((p) => p.source === 'tcp').at(-1);
    return (
      p?.up > 0 &&
      p.up === sum(rows, 'upload_bps').value &&
      p.down === sum(rows, 'download_bps').value
    );
  });
  await page
    .locator('#rows tr')
    .evaluateAll((rows, id) => rows.find((r) => r.dataset.id === id)?.click(), group.id);
  await sleep(1100);
  await page.screenshot({ path: path.join(run, 'real-tcp-application.png') });
  console.log(
    'PASS application graph agrees with unique-socket table sums; shared holders counted once',
  );
  await page.setViewportSize({ width: 860, height: 600 });
  await page.screenshot({ path: path.join(run, 'real-tcp-narrow.png') });
  clearInterval(burst);
  burst = undefined;
  await wait(async () => {
    const p = (await graph(socket.id)).points.at(-1);
    return p?.up === 0 && p.down === 0;
  });
  console.log('PASS idle measured upload/download return to zero; history retains transfer');
  const before = await graph(socket.id);
  const main = await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].id);
  for (let i = 0; i < 3; i++) {
    await app.evaluate(({ BrowserWindow }, id) => BrowserWindow.fromId(id).hide(), main);
    fixture.stdin.write('t\n');
    await sleep(1200);
    await app.evaluate(({ BrowserWindow }, id) => BrowserWindow.fromId(id).show(), main);
  }
  const after = await graph(socket.id);
  assert(after.points.length > before.points.length);
  assert(after.points.some((p) => p.at === before.points[0].at));
  assert.equal(new Set(after.points.map((p) => p.at)).size, after.points.length);
  assert.equal(await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows().length), 1);
  console.log(
    'PASS three hide/reopen cycles retain sampling/history, no duplicate sample times or windows',
  );
  async function resources(label) {
    function sample() {
      const ps = new Map();
      for (const id of fs.readdirSync('/proc').filter((s) => /^\d+$/.test(s))) {
        try {
          const stat = fs.readFileSync(`/proc/${id}/stat`, 'utf8').split(') ').at(-1).split(' ');
          ps.set(Number(id), {
            parent: Number(stat[1]),
            ticks: Number(stat[11]) + Number(stat[12]),
            rssKiB: Number(stat[21]) * 4,
          });
        } catch {}
      }
      const ids = new Set([pid]);
      for (let i = 0; i < 10; i++) for (const [id, p] of ps) if (ids.has(p.parent)) ids.add(id);
      const result = { electron: [], observer: [] };
      for (const [kind, group] of [
        ['electron', ids],
        ['observer', new Set([observer.pid])],
      ])
        for (const id of group) {
          const p = ps.get(id);
          if (!p) continue;
          try {
            const smaps = fs.readFileSync(`/proc/${id}/smaps_rollup`, 'utf8');
            p.pssKiB = Number(/^Pss:\s+(\d+)/m.exec(smaps)[1]);
            p.privateKiB = [
              ...smaps.matchAll(/^Private_(?:Clean|Dirty|Hugetlb):\s+(\d+)/gm),
            ].reduce((n, m) => n + Number(m[1]), 0);
          } catch {}
          result[kind].push({ ...p, pid: id });
        }
      return result;
    }
    const a = sample();
    await sleep(5000);
    const b = sample(),
      hz = Number(execFileSync('getconf', ['CLK_TCK'], { encoding: 'utf8' }));
    const summary = {};
    for (const kind of ['electron', 'observer'])
      summary[kind] = {
        processes: b[kind].length,
        pssKiB: b[kind].reduce((n, p) => n + (p.pssKiB || 0), 0),
        privateKiB: b[kind].reduce((n, p) => n + (p.privateKiB || 0), 0),
        rssKiB: b[kind].reduce((n, p) => n + p.rssKiB, 0),
        cpuPercent:
          (b[kind].reduce(
            (n, p) => n + p.ticks - (a[kind].find((q) => q.pid === p.pid)?.ticks || p.ticks),
            0,
          ) /
            hz /
            5) *
          100,
      };
    fs.writeFileSync(
      path.join(run, label + '.json'),
      JSON.stringify({ summary, processes: b, debuggerAttached: true }, null, 2),
    );
    console.log(label + ' ' + JSON.stringify(summary));
  }
  await resources('visible');
  await app.evaluate(({ BrowserWindow }, id) => BrowserWindow.fromId(id).hide(), main);
  await resources('hidden');
  await app.evaluate(({ BrowserWindow }, id) => BrowserWindow.fromId(id).show(), main);
  const data = { socket: await graph(socket.id), application: await graph(group.id) };
  fs.writeFileSync(path.join(run, 'graphs.json'), JSON.stringify(data, null, 2));
  console.log('EVIDENCE ' + run);
} finally {
  if (burst) clearInterval(burst);
  if (app) {
    await app.evaluate(({ app }) => app.exit()).catch(() => {});
    await app.close().catch(() => {});
  }
  for (const p of children) p.stdin.end();
  await sleep(200);
  for (const p of children) if (p.exitCode === null) p.kill('SIGTERM');
  for (const p of children)
    await Promise.race([
      new Promise((r) => (p.exitCode !== null ? r() : p.once('exit', r))),
      sleep(2000),
    ]);
  if (old) fs.writeFileSync(prefs, old);
  else fs.rmSync(prefs, { force: true });
}
