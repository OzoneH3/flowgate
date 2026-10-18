const { test } = require('node:test');
const assert = require('node:assert/strict');
const { popupPosition } = require('../dist/test/popup-position.cjs');
test('setter stays inside viewport at corners, offscreen anchors and narrow windows', () => {
  for (const viewport of [
    { width: 1280, height: 656 },
    { width: 330, height: 280 },
  ])
    for (const anchor of [
      { left: -80, top: -100, bottom: -80 },
      { left: 1270, top: 650, bottom: 670 },
      { left: 300, top: 50, bottom: 70 },
    ]) {
      const width = 241,
        height = 180,
        p = popupPosition(anchor, width, height, viewport);
      assert(p.left >= 6 && p.top >= 6);
      assert(p.left + width <= viewport.width - 6 && p.top + height <= viewport.height - 6);
    }
});
test('setter uses the actual anchor and flips above it near the lower edge', () => {
  assert.deepEqual(
    popupPosition({ left: 50, top: 20, bottom: 40 }, 241, 100, { width: 860, height: 600 }),
    { left: 50, top: 44 },
  );
  assert.deepEqual(
    popupPosition({ left: 50, top: 560, bottom: 580 }, 241, 100, { width: 860, height: 600 }),
    { left: 50, top: 456 },
  );
});
