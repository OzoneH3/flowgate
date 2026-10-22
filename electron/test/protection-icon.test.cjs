// Icon colour: blue shield only while protection is confirmed active; red when
// monitoring only, stopped, failed, starting or unknown (nothing is being blocked).
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { protectionActive } = require('../dist/test/protection-model.cjs');

test('blue only when protection is active and connected', () => {
  const { PROTECTION_CAPABILITY } = require('../dist/test/protection-model.cjs');
  const cap = PROTECTION_CAPABILITY;
  const s = (control) => ({ observation: { connected: true }, control: { capabilities: [cap], connected: true, ...control } });
  assert.equal(protectionActive(s({ protection: { state: 'active', profile: 'both' } })), true);
  assert.equal(protectionActive(s({ protection: { state: 'stopped', desired_mode: 'monitoring', cleanup: 'confirmed' } })), false, 'monitoring → red');
  assert.equal(protectionActive(s({ protection: { state: 'failed' } })), false);
  assert.equal(protectionActive(s({ protection: { state: 'starting' } })), false);
  assert.equal(protectionActive(s({ connected: false, protection: { state: 'active' } })), false, 'disconnected → unknown → red');
  assert.equal(protectionActive(s({})), false);
  // Legacy backend without the protection capability: enforcement state.
  assert.equal(protectionActive({ observation: {}, control: { capabilities: [], connected: true, enforcement: { state: 'active' } } }), true);
  assert.equal(protectionActive({ observation: {}, control: { capabilities: [], connected: true, enforcement: { state: 'stopped' } } }), false);
});
