// Synthetic Unix lifecycle replies; not BPF/kernel evidence. No privileged process invoked.
const { test } = require('node:test'),
  assert = require('node:assert/strict'),
  fs = require('node:fs'),
  path = require('node:path'),
  net = require('node:net');
const { Backend } = require('../dist/test/backend.cjs');
const { DaemonMonitoring } = require('../dist/test/daemon-monitoring.cjs');
const { ExtendedMonitoring } = require('../dist/test/extended.cjs');
async function fixture(t) {
  const dir = fs.mkdtempSync(path.resolve(__dirname, '../../.workspace/daemon-monitor-test-'));
  const f = {
    generation: 'daemon1',
    monitor: {
      state: 'disabled',
      available: true,
      reason_code: 'disabled',
      reason: 'No attachment',
      generation: '',
      netns: 'test',
      scope: 'machine',
      partial: false,
      missed_operations: 0,
      collected: new Date().toISOString(),
    },
    control: true,
    rules: true,
    cap: true,
    requests: [],
    drop: false,
    delay: 0,
    disconnected: false,
  };
  const response = (readonly = false) => ({
    version: 1,
    generation: f.generation,
    server_time: new Date().toISOString(),
    read_only: readonly,
    mode: readonly ? 'host-monitor' : 'daemon-monitor',
    backend_mode: 'daemon-monitor',
    capabilities: ['explicit-administrator-v1', ...(f.cap ? ['daemon-udp-monitor-v1'] : [])],
    permissions: {
      role: 'administrator',
      observation_scope: 'machine',
      policy_scope: 'machine',
      can_manage_rules: f.rules && !readonly,
      can_decide: false,
      can_view_measurements: true,
      can_control_traffic: f.control && !readonly,
    },
    traffic_monitor: f.monitor,
    activity: {
      sequence: 1,
      collected: new Date().toISOString(),
      complete: true,
      rows: [],
      processes: {},
      udp: { state: f.monitor.state, generation: f.monitor.generation, machine_scope: true },
    },
  });
  const servers = [];
  for (const readonly of [false, true]) {
    const server = net.createServer((s) =>
      s.once('data', async (b) => {
        const q = JSON.parse(b),
          mut = ['traffic-start', 'traffic-stop'].includes(q.operation);
        if (f.disconnected && !readonly) {
          s.end();
          return;
        }
        let r = response(readonly);
        if (!mut && f.listDelay) await new Promise((resolve) => setTimeout(resolve, f.listDelay));
        if (mut) {
          f.requests.push(q);
          if (readonly || !f.control) {
            r.error = 'denied';
            r.error_code = 'forbidden';
          } else if (
            q.generation !== f.generation ||
            q.collector_generation !== f.monitor.generation
          ) {
            r.error = 'changed';
            r.error_code = 'collector_conflict';
          } else {
            f.monitor = {
              ...f.monitor,
              state: q.operation === 'traffic-start' ? 'starting' : 'disabled',
              generation: q.operation === 'traffic-start' ? 'collector1' : f.monitor.generation,
            };
            r = response();
          }
          if (f.drop) {
            s.end();
            return;
          }
          if (f.delay) await new Promise((r) => setTimeout(r, f.delay));
        }
        s.end(JSON.stringify(r) + '\n');
      }),
    );
    await new Promise((r) => server.listen(path.join(dir, readonly ? 'monitor' : 'primary'), r));
    servers.push(server);
  }
  const b = new Backend(path.join(dir, 'monitor'), path.join(dir, 'primary'), () => {});
  await b.pollObserver();
  await b.pollControl();
  const e = new DaemonMonitoring(b);
  t.after(() => {
    b.stop();
    servers.forEach((s) => s.close());
    fs.rmSync(dir, { force: true, recursive: true });
  });
  return { ...f, f, b, e, dir };
}
test('explicit collector permission distinct from rules; frozen generations; duplicate and Stop safety', async (t) => {
  const { f, b, e } = await fixture(t);
  f.rules = false;
  await b.pollControl();
  assert(e.view().canEnable);
  f.delay = 30;
  const first = e.action('enable');
  await assert.rejects(() => e.action('enable'));
  await first;
  assert.equal(f.requests.length, 1);
  assert.equal(f.requests[0].collector_generation, '');
  assert.equal(e.view().state, 'starting');
  assert.equal(e.view().canEnable, false);
  assert(e.view().canStop);
  f.monitor.state = 'active';
  await b.pollControl();
  await e.action('stop');
  assert.equal(f.requests[1].collector_generation, 'collector1');
  assert.equal(e.view().state, 'disabled');
  f.control = false;
  f.rules = true;
  await b.pollControl();
  assert.equal(e.view().canEnable, false);
  await assert.rejects(() => e.action('enable'));
  assert.equal(f.requests.length, 2);
  b.controller = b.observer;
  await b.pollControl();
  assert.equal(e.view().canStop, false);
  assert.equal(e.view().canView, true);
});
test('lost response refreshes status without replay/fallback; disconnect keeps TCP observer usable', async (t) => {
  const { f, b, e, dir } = await fixture(t);
  f.drop = true;
  await e.action('enable');
  assert.match(e.view().message, /uncertain response/);
  assert.equal(f.requests.length, 1);
  f.monitor.state = 'active';
  await b.pollControl();
  assert.equal(e.view().state, 'active');
  f.disconnected = true;
  await b.pollControl();
  await b.pollObserver();
  assert(b.view().observation.connected);
  assert.equal(e.view().state, 'unknown');
  assert(!e.view().canEnable);
  const ext = new ExtendedMonitoring(dir, b);
  assert.equal(ext.view(false).mode, 'daemon');
  await assert.rejects(() => ext.action('enable'));
  assert.equal(f.requests.length, 1);
  f.disconnected = false;
  f.cap = false;
  await b.pollControl();
  assert.equal(ext.view(false).mode, 'daemon');
  assert(!ext.view(false).canEnable);
});
test('daemon generation change discards delayed lifecycle response; failed state never auto-restarts', async (t) => {
  const { f, b, e } = await fixture(t);
  f.delay = 40;
  const start = e.action('enable');
  await new Promise((r) => setTimeout(r, 10));
  f.generation = 'daemon2';
  f.monitor = {
    ...f.monitor,
    state: 'failed',
    generation: 'collector2',
    reason_code: 'load_failed',
  };
  await b.pollControl();
  await start;
  assert.match(e.view().message, /session changed/);
  assert.equal(e.view().state, 'failed');
  assert.equal(f.requests.length, 1);
  await b.pollObserver();
  assert(e.view().canEnable);
  await b.pollControl();
  assert.equal(f.requests.length, 1);
});
test('read-only companion discovery never routes to legacy launcher; wrong observer cannot start collection', async (t) => {
  const { f, b, e, dir } = await fixture(t);
  b.state.observation.generation = 'other';
  assert(!e.view().canEnable);
  b.controller = undefined;
  await b.pollObserver();
  const ext = new ExtendedMonitoring(dir, b);
  assert.equal(ext.view(false).mode, 'daemon');
  assert(!ext.view(false).canEnable);
  await assert.rejects(() => ext.action('enable'));
  assert.equal(f.requests.length, 0);
});
test('malformed collector status disables lifecycle without downgrading or losing ordinary API', async (t) => {
  const { f, b, e, dir } = await fixture(t);
  f.monitor.available = 'yes';
  await b.pollControl();
  await b.pollObserver();
  assert(b.view().control.connected);
  assert(b.view().observation.connected);
  assert.equal(e.view().state, 'unsupported');
  assert.equal(e.view().canEnable, false);
  const ext = new ExtendedMonitoring(dir, b);
  assert.equal(ext.view(false).mode, 'daemon');
  await assert.rejects(() => ext.action('enable'));
  assert.equal(f.requests.length, 0);
});
test('list begun before lost acknowledgement cannot unlock another Start', async (t) => {
  const { f, b, e } = await fixture(t);
  f.listDelay = 50;
  const old = b.pollControl();
  await new Promise((r) => setTimeout(r, 10));
  f.drop = true;
  await e.action('enable');
  assert(e.view().busy);
  await old;
  assert(e.view().busy);
  assert(!e.view().canEnable);
  await assert.rejects(() => e.action('enable'));
  f.listDelay = 0;
  await b.pollControl();
  assert.equal(e.view().state, 'starting');
  assert.equal(f.requests.length, 1);
});
