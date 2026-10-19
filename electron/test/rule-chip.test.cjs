const test = require('node:test');
const assert = require('node:assert/strict');
const { ruleChip, ownRuleChip } = require('../dist/test/rule-chip.cjs');
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
test('rule chip never presents a non-block action as Deny; stored Ask has its own indicator', () => {
  const ask = ref('ask');
  const one = ruleChip(dir('scoped', [ask]));
  assert.equal(one.tone, 'ask');
  assert.equal(one.glyph, '?');
  assert.match(one.text, /^Ask/);
  assert.doesNotMatch(one.text, /Deny/);
  assert.match(one.detail, /Ask: prompt for each new connection/);
  const mixed = ruleChip(dir('mixed', [ref('allow'), ask]));
  assert.match(mixed.text, /1 allow, 0 deny, 1 ask/);
  const other = ruleChip(dir('scoped', [ref('limit')]));
  assert.equal(other.tone, 'unavailable');
  assert.match(other.text, /unsupported here/);
});
// NetLimiter Rule Status: the node's own rule (application_rule), scoped rules only as "+N scoped".
const own = (rules, application_rule, scoped_rules) => ({
  ...dir(rules.length ? 'scoped' : 'absent', rules),
  application_rule,
  scoped_rules: scoped_rules ?? rules.filter((r) => r !== application_rule).length,
});
const app = (action, o = {}) =>
  ref(action, { kind: 'application', scope: { ...ref(action).scope, protocol: '*' }, ...o });
const narrow = (action) =>
  ref(action, {
    kind: 'scoped',
    scope: { ...ref(action).scope, protocol: 'tcp', remote_address: '1.1.1.1' },
  });
test('own rule chip: Not set (+1 scoped) when only scoped rules exist, never their action', () => {
  for (const action of ['allow', 'block', 'ask']) {
    const chip = ownRuleChip(own([narrow(action)], null));
    assert.equal(chip.tone, 'none');
    assert.equal(chip.text, 'Not set · +1 scoped');
    assert.equal(chip.scoped, 1);
    assert.equal(ownRuleChip(own([narrow(action)], null), false, true).text, 'Not set +1 scoped');
  }
  assert.equal(ownRuleChip(own([], null)).text, 'Not set');
});
test('own rule chip: Allow, Deny, Ask, disabled, expired, ended from application_rule only', () => {
  const allow = app('allow');
  assert.deepEqual(
    [ownRuleChip(own([allow, narrow('block')], allow)).text, ownRuleChip(own([allow], allow)).tone],
    ['Allow · +1 scoped', 'allow'],
  );
  const deny = app('block');
  assert.deepEqual(
    [ownRuleChip(own([deny], deny)).glyph, ownRuleChip(own([deny], deny)).text],
    ['✕', 'Deny'],
  );
  const ask = app('ask');
  const chip = ownRuleChip(own([ask], ask));
  assert.deepEqual([chip.glyph, chip.text, chip.tone], ['?', 'Ask', 'ask']);
  assert.match(chip.detail, /^Ask: prompt for each new connection/);
  const disabled = app('allow', { disabled: true, active: false });
  assert.deepEqual(
    [ownRuleChip(own([disabled], disabled)).text, ownRuleChip(own([disabled], disabled)).tone],
    ['Disabled', 'off'],
  );
  const expired = app('block', { expired: true, active: false });
  assert.equal(ownRuleChip(own([expired], expired)).text, 'Expired');
  assert.equal(ownRuleChip(own([allow], allow), true).text, 'Inactive · ended');
  // The detailed (process-target) ref wins over the summary copy of the same rule.
  const summaryCopy = { ...allow, disabled: true, active: false };
  assert.equal(ownRuleChip(own([allow], summaryCopy)).tone, 'allow');
});
test('old daemon summary (no application_rule): a single scoped rule never masquerades as the application state', () => {
  const plainNarrow = ref('allow', {
    scope: { ...ref('allow').scope, protocol: 'tcp', remote_address: '10.0.0.0/8' },
  });
  const chip = ownRuleChip(dir('scoped', [plainNarrow]));
  assert.equal(chip.tone, 'none');
  assert.equal(chip.text, 'Not set · +1 scoped');
  const wide = ref('block');
  const both = ownRuleChip(dir('mixed', [wide, plainNarrow]));
  assert.equal(both.tone, 'block');
  assert.equal(both.text, 'Deny · UDP · +1 scoped');
});
test('compatibility inventory (no backend summary): narrow rules are "+N scoped", Ask keeps its tone', () => {
  const { ownConfigured } = require('../dist/test/rule-status.cjs');
  const rule = (action, filter = {}) => ({
    id: action,
    version: 1,
    action,
    disabled: false,
    expires: '0001-01-01T00:00:00Z',
    filter: {
      application: 'a',
      revision: 'r',
      uid: 1,
      direction: 'outgoing',
      protocol: 'tcp',
      ...filter,
    },
  });
  const now = Date.now();
  assert.deepEqual(ownConfigured([rule('allow', { remote_address: '1.1.1.1' })], now), {
    text: 'Not set +1 scoped',
    tone: 'none',
    scoped: 1,
  });
  assert.equal(
    ownConfigured([rule('block'), rule('allow', { remote_port: 443 })], now).tone,
    'block',
  );
  assert.equal(ownConfigured([rule('ask', { protocol: '*' })], now).tone, 'ask');
  assert.equal(ownConfigured([{ ...rule('allow'), disabled: true }], now).tone, 'off');
});
