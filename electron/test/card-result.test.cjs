// Which result a permission card shows for its own submission (renderer helper).
const { test } = require('node:test'),
  assert = require('node:assert/strict');
const { showsLocalResult, recordDecisionResult } = require('../dist/test/card-result.cjs');
const unknownLocal = { text: 'Result unknown · no retry sent. Use Check result.', detail: 'lost', phase: 'unknown', generation: 'g' };
const ackLocal = { text: 'Allowed · rule saved.', detail: 'ok', phase: 'acknowledged', generation: 'g' };
const ack = { phase: 'acknowledged', message: 'Backend confirmed allowed' };
const unknown = { phase: 'unknown', message: 'pending', reconcile: 't' };

test('a click-time unknown result yields to the same generation confirmed receipt', () => {
  assert.equal(showsLocalResult(unknownLocal, ack, 'g'), false);
});
test('a genuinely pending or invalid outcome stays shown from the unknown attempt', () => {
  assert.equal(showsLocalResult(unknownLocal, unknown, 'g'), false); // attempt text (unknown) is shown
  assert.equal(showsLocalResult(ackLocal, unknown, 'g'), false); // never hide an unresolved outcome
});
test('an older generation result is never shown', () => {
  assert.equal(showsLocalResult(ackLocal, undefined, 'g2'), false);
  assert.equal(showsLocalResult(ackLocal, ack, 'g2'), false);
});
test('ordinary results keep their local text', () => {
  assert.equal(showsLocalResult(ackLocal, ack, 'g'), true);
  assert.equal(showsLocalResult(ackLocal, undefined, 'g'), true); // settled and pruned from attempts
  assert.equal(showsLocalResult({ text: 'Rule saved for future connections.', detail: '' }, undefined, 'g'), true); // non-decision entries
  assert.equal(showsLocalResult(undefined, ack, 'g'), false);
});

// Seam: the renderer captures the generation before awaiting the reply and passes
// both the submitted and the then-current generation to recordDecisionResult.
test('a reply that returns after a daemon restart is not stored or relabelled', () => {
  const results = new Map();
  const reply = { text: 'Allowed · rule saved.', detail: 'ok', phase: 'acknowledged' };
  // Submitted under g; the daemon restarted (g2) while the request was in flight.
  assert.equal(recordDecisionResult(results, 'e', 'g', 'g2', reply), false);
  assert.equal(results.size, 0);
  assert.equal(showsLocalResult(results.get('e'), undefined, 'g2'), false);
});
test('a same-generation reply is stored with the submitted generation and later ignored after a restart', () => {
  const results = new Map();
  assert.equal(recordDecisionResult(results, 'e', 'g', 'g', { text: 'Result unknown · no retry sent. Use Check result.', detail: 'lost', phase: 'unknown' }), true);
  assert.equal(results.get('e').generation, 'g');
  // Same generation: the unknown click text yields once the receipt is confirmed.
  assert.equal(showsLocalResult(results.get('e'), { phase: 'acknowledged', message: 'ok' }, 'g'), false);
  // After a restart the old entry is never shown, even without an attempt.
  assert.equal(showsLocalResult(results.get('e'), undefined, 'g2'), false);
});
test('a delayed reply cannot overwrite an entry of the current generation', () => {
  const results = new Map();
  recordDecisionResult(results, 'e', 'g2', 'g2', { text: 'Allowed · rule saved.', detail: 'new', phase: 'acknowledged' });
  assert.equal(recordDecisionResult(results, 'e', 'g', 'g2', { text: 'Denied once.', detail: 'old', phase: 'acknowledged' }), false);
  assert.equal(results.get('e').detail, 'new');
});
