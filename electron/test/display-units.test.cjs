const { test } = require('node:test');
const assert = require('node:assert/strict');
const { displayAmount, isDisplayUnit, DISPLAY_UNITS } = require('../dist/test/display-units.cjs');
test('display unit conversion keeps rates/totals consistent; unknown is never zero', () => {
  assert.equal(displayAmount(125000, true, 'Mbit'), '1 Mbit/s');
  assert.equal(displayAmount(125000, false, 'Mbit'), '1 Mbit');
  assert.equal(displayAmount(1000, true, 'KB'), '1 KB/s');
  assert.equal(displayAmount(0, true, 'autoByte'), '0 B/s');
  assert.equal(displayAmount(0.5, true, 'B'), '0.5 B/s');
  assert.equal(displayAmount(undefined, true, 'B'), '—');
  assert.equal(displayAmount(NaN), '—');
  assert.equal(displayAmount(-1), '—');
  assert.equal(displayAmount(1500, true, 'autoByte'), '1.5 KB/s');
  assert.equal(displayAmount(1500, true, 'autoBit'), '12 Kbit/s');
});
test('only observed supported display choices accepted', () => {
  assert(DISPLAY_UNITS.every(isDisplayUnit));
  for (const v of ['tcp', 'udp', 'Ask', '', null, {}, 1]) assert.equal(isDisplayUnit(v), false);
});
