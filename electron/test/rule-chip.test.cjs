const test = require('node:test');
const assert = require('node:assert/strict');
const { ruleChip } = require('../dist/test/rule-chip.cjs');
const ref = (action, o = {}) => ({
  id: action + Math.random(),
  version: '1',
  action,
  priority: 100,
  disabled: false,
  expired: false,
  active: true,
  expires: '0001-01-01T00:00:00Z',
  scope: {
    application: 'a',
    revision: 'r',
    uid: 1,
    direction: 'incoming',
    protocol: 'udp',
    remote_address: '*',
    local_port: 0,
    remote_port: 0,
  },
  ...o,
});
const dir = (configured, rules, action = '') => ({
  direction: 'incoming',
  configured,
  action,
  rules,
  reason: '',
});
test('rule chip shows action and scope, never Allow for absent', () => {
  assert.deepEqual(
    [ruleChip(dir('absent', [])).text, ruleChip(dir('absent', [])).tone],
    ['Not set', 'none'],
  );
  assert.equal(ruleChip(undefined).text, 'Unavailable');
  const one = ruleChip(dir('scoped', [ref('block')]));
  assert.equal(one.glyph, '✕');
  assert.equal(one.text, 'Deny · UDP');
  assert.equal(ruleChip(dir('scoped', [ref('block')]), false, true).text, 'Deny UDP');
  const narrow = ref('allow', {
    scope: { ...ref('allow').scope, protocol: 'tcp', remote_address: '10.0.0.0/8' },
  });
  assert.equal(ruleChip(dir('scoped', [narrow])).text, 'Allow · scoped');
  assert.equal(
    ruleChip(
      dir('uniform', [ref('allow', { scope: { ...ref('allow').scope, protocol: '*' } })], 'allow'),
    ).text,
    'Allow · all',
  );
});
test('rule chip keeps multiple scoped rules distinct and shows inactive', () => {
  const mixed = ruleChip(dir('mixed', [ref('allow'), ref('block')]));
  assert.equal(mixed.tone, 'mixed');
  assert.match(mixed.text, /1 allow, 1 deny/);
  assert.equal(mixed.detail.split('\n').length, 2);
  assert.equal(ruleChip(dir('scoped', [ref('block'), ref('block')])).text, 'Deny · 2 rules');
  const off = ref('allow', { disabled: true, active: false });
  assert.equal(ruleChip(dir('inactive_only', [off])).text, 'Disabled');
  assert.equal(ruleChip(dir('scoped', [ref('block'), off])).text, 'Deny · UDP +1 off');
  assert.equal(
    ruleChip(dir('inactive_only', [ref('allow', { expired: true, active: false })])).text,
    'Expired',
  );
  assert.equal(ruleChip(dir('scoped', [ref('block')]), true).text, 'Inactive · ended');
  assert.equal(ruleChip(dir('scoped', [ref('block')]), true).tone, 'off');
});
test('rule chip never presents a non-block action as Deny', () => {
  const ask = ref('ask');
  const one = ruleChip(dir('scoped', [ask]));
  assert.equal(one.tone, 'unavailable');
  assert.match(one.text, /^Ask/);
  assert.doesNotMatch(one.text, /Deny/);
  const mixed = ruleChip(dir('mixed', [ref('allow'), ask]));
  assert.match(mixed.text, /1 allow, 0 deny, 1 other/);
});
