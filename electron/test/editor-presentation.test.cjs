const { test } = require('node:test');
const assert = require('node:assert/strict');
const { reviewedScope, previewSeconds } = require('../dist/test/editor-presentation.cjs');
const { policyLabel } = require('../dist/test/policy.cjs');
test('reviewed structured scope preserves direction, protocol and any endpoints', () => {
  const rule = {
    action: 'allow',
    disabled: false,
    filter: {
      direction: 'incoming',
      protocol: 'tcp',
      remote_address: '*',
      local_port: 0,
      remote_port: 0,
    },
  };
  assert.equal(
    reviewedScope(rule),
    'Application · all instances · Allow incoming TCP connections · any remote address · any local port · any remote port.',
  );
  assert.equal(
    reviewedScope({
      ...rule,
      action: 'block',
      disabled: true,
      filter: {
        ...rule.filter,
        direction: 'outgoing',
        protocol: 'udp',
        remote_address: '2001:db8::/32',
        remote_port: 443,
      },
    }),
    'Application · all instances · Deny outgoing UDP connections · remote 2001:db8::/32 · any local port · remote port 443 · saved disabled.',
  );
});
test('preview validity clamps expiry and never renews it', () => {
  assert.equal(previewSeconds(30000, 1), 30);
  assert.equal(previewSeconds(30000, 29999), 1);
  assert.equal(previewSeconds(30000, 30000), 0);
  assert.equal(previewSeconds(30000, 31000), 0);
  assert.equal(previewSeconds(NaN, 0), 0);
});
test('concise configured labels do not infer default or enforcement', () => {
  for (const [configured, label] of [
    ['absent', 'No explicit rule'],
    ['inactive_only', 'Inactive rules'],
    ['scoped', 'Scoped · 2'],
    ['mixed', 'Mixed · 2'],
    ['uniform', 'Block'],
  ])
    assert.equal(policyLabel({ configured, action: 'block', rules: [{}, {}] }), label);
});
