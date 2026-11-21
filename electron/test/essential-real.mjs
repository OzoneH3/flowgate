// Real isolated API/storage/native identity; backend-owned simulated service configuration.
import { _electron } from 'playwright-core';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url),
  { parseRule } = require('../dist/test/protocol.cjs');
const resumePath = process.env.RESUME_ESSENTIAL_RESULT;
if (resumePath) assert(resumePath.startsWith('/home/flowgate-user/Apps/flowgate/'));
const prior = resumePath ? JSON.parse(fs.readFileSync(resumePath)) : undefined;
const project = path.resolve(import.meta.dirname, '../..'),
  readyPath = process.env.FLOWGATE_ESSENTIAL_READY;
assert(readyPath?.startsWith('/home/flowgate-user/Apps/flowgate/.workspace/'));
const ready = JSON.parse(fs.readFileSync(readyPath));
assert(ready.endpoint.startsWith(path.dirname(readyPath) + '/'));
const run = fs.mkdtempSync(project + '/.workspace/essential-real-'),
  root = run + '/client';
fs.mkdirSync(root + '/electron', { recursive: true });
fs.cpSync(project + '/electron/dist', root + '/electron/dist', { recursive: true });
fs.copyFileSync(project + '/electron/package.json', root + '/electron/package.json');
fs.mkdirSync(root + '/.workspace/tmp', { recursive: true });
const call = (q) =>
  new Promise((resolve, reject) => {
    const s = net.createConnection(ready.endpoint);
    let b = '';
    s.setTimeout(22000, () => s.destroy(Error('timeout')));
    s.on('error', reject);
    s.on('connect', () => s.write(JSON.stringify({ version: 1, ...q }) + '\n'));
    s.on('data', (x) => {
      b += x;
      if (b.includes('\n')) {
        s.destroy();
        resolve(JSON.parse(b.split('\n')[0]));
      }
    });
  });
const calls = [];
let drop = true;
const proxy = net.createServer((s) =>
  s.once('data', async (raw) => {
    try {
      const q = JSON.parse(raw);
      calls.push(q);
      const r = await call(q);
      if (drop && q.operation === 'essential-apply') {
        drop = false;
        s.end();
        return;
      }
      s.end(JSON.stringify(r) + '\n');
    } catch {
      s.destroy();
    }
  }),
);
await new Promise((r) => proxy.listen(run + '/api', r));
let app;
const result = { run, generation: ready.generation, label: ready.label, errors: [] };
const wait = async (fn) => {
  for (let end = Date.now() + 25000; Date.now() < end;) {
    const v = await fn();
    if (v) return v;
    await new Promise((r) => setTimeout(r, 75));
  }
  throw Error('timeout');
};
try {
  const initial = await call({ operation: 'list' });
  assert.equal(initial.generation, ready.generation);
  if (!prior) assert.equal((initial.rules || []).length, 0);
  else {
    assert.equal(prior.generation, ready.generation);
    assert.deepEqual(
      [...(initial.rules || []).map((r) => r.id)].sort(),
      [...prior.savedRuleIds].sort(),
    );
  }
  assert.equal(initial.enforcement.state, 'stopped');
  app = await _electron.launch({
    chromiumSandbox: true,
    args: [
      '--ozone-platform=wayland',
      root + '/electron',
      '--observer',
      ready.endpoint + '.monitor',
      '--control',
      run + '/api',
    ],
    env: { ...process.env, TMPDIR: root + '/.workspace/tmp' },
  });
  const page = await app.firstWindow();
  page.on('pageerror', (e) => result.errors.push(String(e)));
  await page.locator('#essentialOpen').waitFor({ state: 'attached' });
  await wait(async () => (await page.evaluate(() => window.flowgate.essentialState())).permitted);
  await page.evaluate(() => {
    document.getElementById('controlMenu').open = true;
  });
  await page.click('#essentialOpen');
  await wait(async () => !!(await page.evaluate(() => window.flowgate.essentialState())).status);
  if (!prior) {
    for (const key of ['tailscale', 'tailscale_incoming', 'tailscale_http', 'discovery'])
      assert.equal(await page.locator('#essential-' + key).isChecked(), false);
    await page.click('#essential-preview');
    let v = await wait(async () => {
      const x = await page.evaluate(() => window.flowgate.essentialState());
      return x.phase === 'review' && x.canApply ? x : false;
    });
    result.defaultPreview = v.preview;
    await page.screenshot({ path: run + '/default-review.png' });
    assert(v.preview.rules.length > 0);
    assert(v.preview.rules.every((r) => r.schema === 5));
    await page.locator('#essential-tailscale').check();
    assert(await page.locator('#essential-apply').isDisabled());
    await page.click('#essential-preview');
    v = await wait(async () => {
      const x = await page.evaluate(() => window.flowgate.essentialState());
      return x.phase === 'review' && x.canApply ? x : false;
    });
    result.optionalPreview = v.preview;
    assert.match(await page.locator('#essentialRules').innerText(), /Any destination/);
    await page.screenshot({ path: run + '/optional-review.png' });
    await page.click('#essential-apply');
    await wait(
      async () => (await page.evaluate(() => window.flowgate.essentialState())).phase === 'unknown',
    );
    assert.equal(calls.filter((q) => q.operation === 'essential-apply').length, 1);
    await page.click('#essential-reconcile');
    await wait(
      async () =>
        (await page.evaluate(() => window.flowgate.essentialState())).phase === 'confirmed',
    );
    const saved = await call({ operation: 'list' });
    assert.equal(saved.generation, ready.generation);
    assert.equal(saved.enforcement.state, 'stopped');
    const normalize = (rs) => rs.map(parseRule).sort((a, b) => a.id.localeCompare(b.id));
    assert.deepEqual(normalize(saved.rules), normalize(v.preview.rules));
    result.savedRuleIds = saved.rules.map((r) => r.id);
    await page.click('#essential-close');
    await page.click('#rulesTab');
    await page.locator('#ruleRows tr').first().waitFor();
    await page.locator('#ruleRows tr').first().click();
    await wait(async () => page.locator('#editRule').isDisabled());
    assert.match(await page.locator('#ruleInfo').innerText(), /essential-system-networking/);
    await page.evaluate(() => {
      document.getElementById('controlMenu').open = true;
    });
    await page.click('#essentialOpen');
  } else {
    result.savedRuleIds = prior.savedRuleIds;
    result.priorApplyEvidence = prior.run;
  }
  await page.click('#essential-removePreview');
  const removal = await wait(async () => {
    const x = await page.evaluate(() => window.flowgate.essentialState());
    return x.phase === 'review' && x.preview.operation === 'remove' && x.canApply ? x : false;
  });
  assert.deepEqual(
    [...removal.preview.rules.map((r) => r.id)].sort(),
    [...result.savedRuleIds].sort(),
  );
  await app.evaluate(({ BrowserWindow }) =>
    BrowserWindow.getAllWindows()[0].setContentSize(860, 600),
  );
  await page.waitForTimeout(200);
  await page.screenshot({ path: run + '/narrow-removal.png' });
  await page.click('#essential-remove');
  await wait(
    async () => (await page.evaluate(() => window.flowgate.essentialState())).phase === 'confirmed',
  );
  const final = await call({ operation: 'list' });
  assert.equal(final.generation, ready.generation);
  assert.equal((final.rules || []).length, 0);
  assert.equal(final.enforcement.state, 'stopped');
  assert.equal(calls.filter((q) => q.operation === 'essential-apply').length, prior ? 0 : 1);
  assert.equal(calls.filter((q) => q.operation === 'essential-remove').length, 1);
  assert(
    calls.every((q) =>
      [
        'list',
        'policy-view',
        'essential-status',
        'essential-preview',
        'essential-apply',
        'essential-remove-preview',
        'essential-remove',
      ].includes(q.operation),
    ),
  );
  assert.deepEqual(result.errors, []);
  result.final = {
    generation: final.generation,
    rules: (final.rules || []).length,
    enforcement: final.enforcement,
  };
  result.passed = true;
  console.log('PASS Essential isolated real UI', run, JSON.stringify(result.final));
} catch (e) {
  result.failure = String(e);
  throw e;
} finally {
  if (app) await app.close();
  proxy.close();
  result.operations = calls.map((q) => q.operation);
  fs.writeFileSync(run + '/result.json', JSON.stringify(result, null, 2));
}
