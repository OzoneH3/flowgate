// Labelled synthetic contract/layout journey; never host/enforcement evidence.
import { _electron } from 'playwright-core';
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
const project = path.resolve(import.meta.dirname, '../..'),
  run = fs.mkdtempSync(project + '/.workspace/essential-ui-'),
  root = run + '/client',
  endpoint = run + '/api';
fs.mkdirSync(root + '/electron', { recursive: true });
fs.cpSync(project + '/electron/dist', root + '/electron/dist', { recursive: true });
fs.copyFileSync(project + '/electron/package.json', root + '/electron/package.json');
fs.mkdirSync(root + '/.workspace/tmp', { recursive: true });
let rules = [],
  preview,
  receipt,
  drop = true,
  sequence = 0,
  calls = [],
  edited = '';
const options = {
  tailscale: false,
  tailscale_incoming: false,
  tailscale_http: false,
  discovery: false,
};
function makeRule(id, component, extra = {}) {
  return {
    schema: 5,
    id,
    version: 1,
    created: '2026-10-19T00:00:00Z',
    expires: '0001-01-01T00:00:00Z',
    disabled: false,
    priority: 100,
    executable: '/SYNTHETIC/resolver',
    action: 'allow',
    preset: {
      name: 'essential-system-networking',
      component,
      entry_id: id,
      revision: 'fixture-revision',
      digest: 'fixture-digest',
    },
    filter: {
      application: 'fixture-resolver',
      revision: 'fixture-executable',
      uid: 974,
      direction: 'outgoing',
      protocol: 'udp',
      remote_address: '192.0.2.53',
      remote_port: 53,
      local_port: 0,
      ...extra,
    },
  };
}
const components = () => [
  {
    id: 'dns',
    title: 'SYNTHETIC DNS resolver',
    state: 'ready',
    essential: true,
    revision: 'fixture-revision',
    details: ['Exact local stub client and configured upstream; no host permissions.'],
  },
  {
    id: 'tailscale',
    title: 'SYNTHETIC Tailscale',
    state: 'optional',
    essential: false,
    revision: 'fixture-revision',
    details: [
      'Optional outer transport to variable peers: Any destination. Not inner application permission.',
    ],
  },
  {
    id: 'discovery',
    title: 'LAN discovery',
    state: 'unavailable',
    essential: false,
    revision: 'fixture-revision',
    details: ['Trusted-interface configuration unavailable. No private-address trust inferred.'],
  },
];
const status = () => ({
  revision: 'fixture-revision',
  components: components(),
  rule_ids: rules.map((r) => r.id),
  issues: [],
});
const server = net.createServer((s) =>
  s.once('data', (raw) => {
    const q = JSON.parse(raw);
    calls.push(q);
    const reply = {
      version: 1,
      generation: 'essential-synthetic',
      mode: 'daemon-monitor',
      enforcement: { state: 'stopped', profile: 'both', detail: 'SYNTHETIC monitoring' },
      read_only: false,
      server_time: new Date().toISOString(),
      capabilities: [
        'essential-system-networking-v1',
        'explicit-administrator-v1',
        'conditional-rule-delete-v1',
      ],
      permissions: {
        role: 'administrator',
        policy_scope: 'machine',
        observation_scope: 'machine',
        can_manage_rules: true,
        can_decide: false,
      },
      rules,
      rule_states: Object.fromEntries(
        rules.map((r) => [
          r.id,
          { target_scope: 'system', state: 'active', reason: 'Synthetic preset' },
        ]),
      ),
      events: [],
      activity: {
        sequence: ++sequence,
        collected: new Date().toISOString(),
        complete: true,
        rows: [],
        processes: {},
      },
    };
    if (q.operation === 'essential-status') {
      reply.essential_status = status();
      if (q.preview_token) reply.essential_receipt = receipt;
    }
    if (q.operation === 'essential-preview') {
      const planned = [
        makeRule('stub', 'dns-stub-client', {
          application: '',
          revision: '',
          uid: 0,
          all_programs: true,
          all_uids: true,
          remote_address: '127.0.0.53',
          interface_name: 'lo',
          interface_index: 1,
          peer_service: {
            application: 'fixture-resolver',
            revision: 'fixture-executable',
            uid: 974,
          },
        }),
        makeRule('upstream', 'dns'),
      ];
      if (q.essential_options.tailscale)
        planned.push(
          makeRule('vpn', 'tailscale', {
            application: 'fixture-vpn',
            revision: 'fixture-vpn-exe',
            uid: 0,
            protocol: 'tcp',
            remote_address: '',
            remote_port: 443,
          }),
        );
      preview = {
        ...status(),
        token: 'apply-' + sequence,
        operation: 'apply',
        options: q.essential_options,
        rules: planned,
        preserved_rule_ids: [],
        expires_at: new Date(Date.now() + 30000).toISOString(),
      };
      reply.essential_preview = preview;
    }
    if (q.operation === 'essential-remove-preview') {
      preview = {
        ...status(),
        token: 'remove-' + sequence,
        operation: 'remove',
        options,
        rules: rules.filter((r) => r.id !== edited),
        preserved_rule_ids: edited ? [edited] : [],
        issues: edited ? ['User-edited/disabled record preserved: ' + edited] : [],
        expires_at: new Date(Date.now() + 30000).toISOString(),
      };
      reply.essential_preview = preview;
    }
    if (q.operation === 'essential-apply') {
      rules = preview.rules;
      receipt = {
        token: preview.token,
        operation: 'apply',
        rule_ids: rules.map((r) => r.id),
        rules,
        removed_rule_ids: [],
      };
      reply.essential_receipt = receipt;
      if (drop) {
        drop = false;
        s.end();
        return;
      }
    }
    if (q.operation === 'essential-remove') {
      const ids = preview.rules.map((r) => r.id);
      rules = rules.filter((r) => !ids.includes(r.id));
      reply.essential_receipt = {
        token: preview.token,
        operation: 'remove',
        rule_ids: [],
        rules: [],
        removed_rule_ids: ids,
      };
    }
    s.end(JSON.stringify(reply) + '\n');
  }),
);
await new Promise((r) => server.listen(endpoint, r));
let app;
const result = { run, synthetic: true };
try {
  app = await _electron.launch({
    chromiumSandbox: true,
    args: [
      '--ozone-platform=wayland',
      root + '/electron',
      '--observer',
      endpoint,
      '--control',
      endpoint,
    ],
    env: { ...process.env, TMPDIR: root + '/.workspace/tmp' },
  });
  const page = await app.firstWindow();
  await page.locator('#essentialOpen').waitFor({ state: 'attached' });
  await page.evaluate(() => {
    document.getElementById('toolsMenu').open = true;
    document.getElementById('controlMenu').open = true;
  });
  await page.click('#essentialOpen');
  await page.locator('#essentialComponents summary').first().waitFor();
  for (const key of Object.keys(options))
    assert.equal(await page.locator('#essential-' + key).isChecked(), false);
  await page.locator('#essentialDialog h2').focus();
  await page.keyboard.press('Enter');
  await page.keyboard.press('Enter');
  assert.equal(calls.filter((q) => q.operation === 'essential-apply').length, 0);
  await page.click('#essential-preview');
  await page.locator('#essential-apply').waitFor();
  await page.waitForFunction(() => !document.getElementById('essential-apply').disabled);
  assert.match(await page.locator('#essentialRules').innerText(), /All programs.*local service/);
  await page.locator('#essential-tailscale').check();
  assert(await page.locator('#essential-apply').isDisabled());
  await page.click('#essential-preview');
  await page.waitForFunction(() => !document.getElementById('essential-apply').disabled);
  assert.match(await page.locator('#essentialRules').innerText(), /Any destination/);
  await page.screenshot({ path: run + '/review.png' });
  await page.click('#essential-apply');
  await page.waitForFunction(() =>
    document.getElementById('essentialMessage').textContent.includes('Outcome unknown'),
  );
  assert.equal(calls.filter((q) => q.operation === 'essential-apply').length, 1);
  await page.click('#essential-reconcile');
  await page.waitForFunction(() =>
    document.getElementById('essentialMessage').textContent.includes('receipt confirmed'),
  );
  assert.equal(calls.filter((q) => q.operation === 'essential-apply').length, 1);
  edited = rules[0].id;
  rules[0] = { ...rules[0], disabled: true, version: 2 };
  await page.click('#essential-removePreview');
  await page.waitForFunction(() => !document.getElementById('essential-remove').disabled);
  assert.match(await page.locator('#essentialPreserved').innerText(), /stub/);
  await app.evaluate(({ BrowserWindow }) =>
    BrowserWindow.getAllWindows()[0].setContentSize(860, 600),
  );
  await page.waitForTimeout(300);
  const viewport = await page.evaluate(() => ({ w: innerWidth, h: innerHeight })),
    box = await page.locator('#essentialDialog').boundingBox();
  assert(
    box.x >= 0 &&
      box.y >= 0 &&
      box.x + box.width <= viewport.w + 1 &&
      box.y + box.height <= viewport.h + 1,
  );
  await page.screenshot({ path: run + '/narrow-removal.png' });
  await page.click('#essential-remove');
  await page.waitForFunction(() =>
    document.getElementById('essentialMessage').textContent.includes('records removed'),
  );
  assert.deepEqual(
    rules.map((r) => r.id),
    [edited],
  );
  await page.click('#essential-close');
  await page.click('#rulesTab');
  await page.locator('#ruleRows tr').first().click();
  await page.waitForFunction(() => document.getElementById('editRule').disabled);
  assert.match(await page.locator('#ruleInfo').innerText(), /essential-system-networking/);
  result.passed = true;
  result.operations = calls
    .filter((q) => q.operation.startsWith('essential-'))
    .map((q) => q.operation);
  assert(calls.every((q) => !q.operation.includes('protection-start')));
  console.log('PASS Essential synthetic UI', run);
} finally {
  if (app) await app.close();
  server.close();
  fs.writeFileSync(run + '/result.json', JSON.stringify(result, null, 2));
}
