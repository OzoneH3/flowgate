// Sandboxed native Electron + synthetic Unix API. No daemon, TC, firewall or traffic.
// Run from the repository root inside the documented capped user scope after npm run build.
import { _electron } from 'playwright-core';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
fs.mkdirSync(path.join(root, '.workspace/account-names-ui'), { recursive: true });
const dir = fs.mkdtempSync(path.join(root, '.workspace/account-names-ui/native-'));
const client = path.join(dir, 'client');
fs.mkdirSync(client + '/electron', { recursive: true });
fs.cpSync(root + '/electron/dist', client + '/electron/dist', { recursive: true });
fs.copyFileSync(root + '/electron/package.json', client + '/electron/package.json');
fs.mkdirSync(client + '/.workspace/tmp', { recursive: true });
const appIdentity = {
  key: 'synthetic-native-alpha',
  revision: 'synthetic-revision',
  kind: 'native',
  name: 'Synthetic alpha',
  executable: '/synthetic/alpha',
};
const process = {
  id: '42:100',
  pid: 42,
  start_ticks: '100',
  uid: 1000,
  application: appIdentity,
  executable: appIdentity.executable,
};
const requests = [],
  sockets = new Set(),
  servers = [];
let version = 1,
  caps = [],
  sequence = 1,
  generation = 'synthetic-gen',
  readOnly = false,
  refuse = false,
  drop = false,
  holdStatus = false;
const pendingStatus = [];
function status() {
  return {
    version,
    applied_version: version,
    enabled: caps.length > 0,
    interface: 'synthetic0',
    status: caps.length ? 'Partial' : 'Disabled',
    configured_caps: caps,
    coverage_valid_for_ms: 10000,
    kernel: {
      bindings: caps.map((c) => ({
        app: c.uid + ':' + c.application,
        covered: true,
        download: !!c.download_bits_per_second,
      })),
      covered_bindings: caps.length,
    },
  };
}
function reply(q, monitor) {
  const now = new Date().toISOString(),
    r = { version: 1, generation, read_only: monitor || readOnly, server_time: now };
  if (q.operation === 'list')
    return {
      ...r,
      mode: monitor ? 'host-monitor' : 'daemon-monitor',
      events: [],
      rules: [],
      capabilities: [
        'explicit-administrator-v1',
        'experimental-native-upload-v1',
        'experimental-native-download-v1',
        'experimental-traffic-priority-v1',
        'experimental-zone-shaping-v1',
      ],
      permissions: {
        role: 'administrator',
        observation_scope: 'machine',
        policy_scope: 'machine',
        can_manage_rules: false,
        can_manage_machine_rules: false,
        can_decide: false,
      },
      activity: {
        sequence: ++sequence,
        collected: now,
        complete: true,
        issues: [],
        inaccessible_processes: 0,
        processes: Object.fromEntries([0,1000,970,4294967294].map((uid,i)=>[`${42+i}:100`, {...process,id:`${42+i}:100`,pid:42+i,uid,application:{...appIdentity,key:`synthetic-${uid}`}}])),
        rows: [0,1000,970,4294967294].map((uid,i)=>({
            id: `synthetic-socket-${uid}`,
            ownership: 'Visible descriptor holder',
            ownership_category: 'visible-holder',
            owners: [`${42+i}:100`],
            state: 'Established',
            direction: 'Outgoing',
            socket: {
              family: 2,
              protocol: 'tcp',
              local: '192.0.2.1:40001',
              remote: '198.51.100.1:443',
              state: 1,
              inode: 42+i,
              cookie: `synthetic-cookie-${uid}`,
              uid,
              netns: 'net:[synthetic]',
            },
            traffic: { available: false, state: 'unavailable', reason: 'Synthetic UI fixture' },
          })),
      },
    };
  if (q.operation === 'upload-status') return { ...r, upload_shaping: status() };
  if (q.operation === 'upload-configure') {
    if (monitor || readOnly)
      return { ...r, error_code: 'forbidden', error: 'Synthetic read-only controller' };
    if (refuse)
      return { ...r, error_code: 'synthetic_refusal', error: 'Synthetic configuration refusal' };
    if (q.generation !== generation || q.expected_version !== version)
      return { ...r, error_code: 'version_conflict', error: 'Configuration changed' };
    caps = structuredClone(q.upload_config.caps);
    version++;
    return drop ? null : { ...r, upload_shaping: status() };
  }
  return { ...r, error_code: 'unsupported', error: 'Synthetic operation unsupported' };
}
for (const [name, monitor] of [
  ['control.sock', false],
  ['monitor.sock', true],
]) {
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => {});
    let input = '';
    socket.on('data', async (b) => {
      input += b;
      if (!input.includes('\n')) return;
      const q = JSON.parse(input.split('\n')[0]);
      requests.push({ socket: name, q });
      if (q.operation === 'upload-status' && holdStatus)
        await new Promise((resolve) => pendingStatus.push(resolve));
      const response = reply(q, monitor);
      if (response === null) return socket.destroy();
      socket.end(JSON.stringify(response) + '\n');
    });
  });
  await new Promise((resolve) => server.listen(dir + '/' + name, resolve));
  fs.chmodSync(dir + '/' + name, 0o600);
  servers.push(server);
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const wait = async (fn, label = 'condition') => {
  for (let end = Date.now() + 15000; Date.now() < end;) {
    const value = await fn();
    if (value) return value;
    await sleep(100);
  }
  throw Error('Timeout: ' + label);
};

let app;
try {
 app=await _electron.launch({executablePath:root+'/electron/node_modules/electron/dist/electron',chromiumSandbox:true,args:['--ozone-platform=wayland',client+'/electron','--observer',dir+'/monitor.sock','--control',dir+'/control.sock'],env:{...globalThis.process.env,TMPDIR:client+'/.workspace/tmp',XDG_CACHE_HOME:dir+'/cache'}});
 await app.firstWindow();
 const page=await wait(()=>app.windows().find(w=>w.url()==='flowgate://app/index.html'),'main');
 const errors=[];page.on('pageerror',e=>errors.push(String(e)));
 await app.evaluate(({BrowserWindow})=>{const w=BrowserWindow.getAllWindows().find(w=>w.webContents.getURL()==='flowgate://app/index.html');w.show();w.restore();w.focus();});
 await page.setViewportSize({width:1280,height:720});
 await wait(async()=>await page.locator('#expand').isVisible(),'tree');
 await page.locator('#expand').click();
 const {execFileSync}=await import('node:child_process');
 const user=uid=>execFileSync('getent',['passwd',String(uid)],{encoding:'utf8'}).split(':')[0];
 for (const uid of [0,1000,970]) await wait(async()=>await page.getByText(`${user(uid)} (UID ${uid})`,{exact:false}).count(),'user '+uid);
 await wait(async()=>await page.getByText('User UID 4294967294',{exact:false}).count(),'unknown');
 assert.equal(await page.evaluate(async()=>{try{await window.flowgate.accountName('-1');return false}catch{return true}}),true);
 assert.equal(await page.evaluate(()=>window.flowgate.accountName(4294967294)),null);
 await page.screenshot({path:dir+'/account-tree.png'});
 assert.equal(errors.length,0,errors.join('\n'));
 assert.equal(requests.filter(x=>x.q.operation!=='list'&&x.q.operation!=='upload-status').length,0);
 fs.writeFileSync(dir+'/evidence.json',JSON.stringify({pass:true,scope:'sandboxed Electron, synthetic activity and real host NSS; no rule writes',names:[0,1000,970].map(uid=>({uid,name:user(uid)})),unknown:4294967294,errors},null,2));
 console.log(dir+' PASS');
} finally { if(app)await app.close(); for(const s of sockets)s.destroy(); await Promise.all(servers.map(s=>new Promise(r=>s.close(r)))); }
