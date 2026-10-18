// Synthetic process bridge boundary only; never invokes sudo or a collector.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const cp = require('node:child_process'),
  fs = require('node:fs'),
  path = require('node:path');
const { EventEmitter } = require('node:events');
const { ExtendedMonitoring } = require('../dist/test/extended.cjs');
test('extended bridge uses fixed operations; Stop acknowledgement and failure remain independent', async () => {
  const root = fs.mkdtempSync(path.resolve(__dirname, '../../.workspace/ext-unit-'));
  fs.mkdirSync(path.join(root, '.workspace'));
  fs.writeFileSync(path.join(root, '.workspace/udp-collector'), 'synthetic');
  const originalSpawn = cp.spawn,
    originalExec = cp.execFile;
  let calls = [];
  try {
    cp.spawn = (command, args, options) => {
      calls.push([command, args, options]);
      const child = new EventEmitter();
      child.unref = () => {};
      return child;
    };
    cp.execFile = (command, args, options, done) => {
      calls.push([command, args]);
      done(null, '{"version":1,"state":"stopped"}', '');
    };
    const ext = new ExtendedMonitoring(root);
    assert.equal(ext.view(false).busy, false);
    await assert.rejects(() => ext.action({ action: 'enable' }));
    await ext.action('enable');
    assert.deepEqual(calls[0][1], [
      '--separate',
      '--hold',
      '-e',
      'python3',
      path.join(root, 'scripts/traffic-control.py'),
      '--backend',
      'electron-backend',
    ]);
    assert(ext.view(false).busy);
    await assert.rejects(() => ext.action('enable'));
    ext.view(true);
    await ext.action('stop');
    assert.match(ext.state.message, /acknowledged Stop/);
    assert.equal(calls[1][0], path.join(root, '.workspace/electron-backend'));
    assert.deepEqual(calls[1][1], ['udp-stop']);
    cp.execFile = (c, a, o, done) => done(Error('lost acknowledgement'), '', 'disconnected');
    await ext.action('stop');
    assert.match(ext.state.message, /not confirmed/);
    assert.equal(calls.length, 2);
  } finally {
    cp.spawn = originalSpawn;
    cp.execFile = originalExec;
    fs.rmSync(root, { recursive: true, force: true });
  }
});
