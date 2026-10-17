// Explicitly synthetic lifecycle/counter display fixture. Never loads BPF or invokes a daemon.
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
const root = path.resolve(import.meta.dirname, '../..'),
  dir = fs.mkdtempSync(path.join(root, '.workspace/synudp-'));
let state = 'disabled',
  generation = '',
  session = 0,
  sequence = 0,
  since = new Date().toISOString();
let transition;
const clock = setInterval(() => sequence++, 1000);
const application = {
  key: 'synthetic',
  revision: 'fixture',
  name: 'SYNTHETIC application',
  executable: '/synthetic/not-an-installed-application',
};
const processInfo = {
  id: '1:start',
  pid: 1,
  start_ticks: '1',
  uid: 1000,
  executable: application.executable,
  application,
};
const monitor = () => ({
  state,
  available: true,
  generation,
  reason_code: state,
  reason: 'SYNTHETIC UI fixture — not kernel measurements',
  netns: 'synthetic-netns',
  scope: 'machine',
  partial: true,
  missed_operations: 2,
  collected: new Date().toISOString(),
});
const row = (protocol) => ({
  id: protocol,
  owners: ['1:start'],
  ownership: 'Synthetic',
  ownership_category: 'visible-holder',
  state: 'Synthetic',
  direction: 'Unknown',
  evidence: 'Synthetic metadata, no kernel collector',
  socket: {
    protocol,
    local: '[::1]:4000',
    remote: '[::1]:4001',
    uid: 1000,
    cookie: protocol,
    netns: 'synthetic-netns',
    state: 1,
  },
  traffic: {
    state: protocol === 'tcp' || state === 'active' ? 'measured' : 'unavailable',
    available: protocol === 'tcp' || state === 'active',
    partial: protocol === 'udp',
    definition: protocol === 'tcp' ? 'tcp-transport-payload' : 'udp-api-reported',
    source: 'synthetic fixture',
    reason: 'SYNTHETIC rates',
    since: protocol === 'tcp' ? '2026-10-17T00:00:00Z' : since,
    uploaded: sequence * 4096,
    downloaded: sequence * 2048,
    upload_bps: 4096,
    download_bps: 2048,
  },
});
const reply = (readonly) => ({
  version: 1,
  generation: 'synthetic-daemon',
  read_only: readonly,
  mode: readonly ? 'host-monitor' : 'daemon-monitor',
  backend_mode: 'daemon-monitor',
  server_time: new Date().toISOString(),
  capabilities: ['explicit-administrator-v1', 'daemon-udp-monitor-v1'],
  permissions: {
    role: 'administrator',
    policy_scope: 'machine',
    observation_scope: 'machine',
    can_manage_rules: !readonly,
    can_decide: false,
    can_view_measurements: true,
    can_control_traffic: !readonly,
  },
  enforcement: { state: 'stopped', profile: '', detail: 'Synthetic fixture' },
  traffic_monitor: monitor(),
  activity: {
    sequence,
    collected: new Date().toISOString(),
    complete: true,
    rows: [row('udp'), row('tcp')],
    processes: { '1:start': processInfo },
    udp: {
      state: state === 'active' ? 'active' : 'unavailable',
      generation,
      machine_scope: true,
      reason: 'Synthetic fixture',
      missed_operations: 2,
    },
  },
});
const servers = [];
try {
  for (const readonly of [false, true]) {
    const server = net.createServer((s) =>
      s.once('data', (b) => {
        const q = JSON.parse(b);
        let r;
        if (['traffic-start', 'traffic-stop'].includes(q.operation)) {
          if (readonly)
            r = { ...reply(readonly), error: 'Read-only fixture', error_code: 'forbidden' };
          else if (q.generation !== 'synthetic-daemon' || q.collector_generation !== generation)
            r = {
              ...reply(readonly),
              error: 'Changed generation',
              error_code: 'collector_conflict',
            };
          else if (q.operation === 'traffic-start') {
            generation = 'synthetic-collector-' + ++session;
            since = new Date().toISOString();
            state = 'starting';
            transition = setTimeout(() => (state = 'active'), 150);
          } else {
            clearTimeout(transition);
            state = 'disabled';
          }
        }
        s.end(JSON.stringify(r || reply(readonly)) + '\n');
      }),
    );
    await new Promise((r) => server.listen(path.join(dir, 's') + (readonly ? '.monitor' : ''), r));
    servers.push(server);
  }
  const child = spawn(process.execPath, ['electron/test/daemon-udp-workflow.mjs'], {
    cwd: root,
    env: {
      ...process.env,
      FLOWGATE_UDP_UI_ENDPOINT: path.join(dir, 's'),
      FLOWGATE_UDP_UI_EXPECT: 'active',
      FLOWGATE_UDP_UI_SYNTHETIC: '1',
    },
    stdio: 'inherit',
  });
  const code = await new Promise((r) => child.on('exit', r));
  if (code) throw Error('Synthetic display workflow failed: ' + code);
} finally {
  clearInterval(clock);
  clearTimeout(transition);
  servers.forEach((s) => s.close());
}
