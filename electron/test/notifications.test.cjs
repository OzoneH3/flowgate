const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { RequestNotifications, plain, pending } = require('../dist/test/notifications.cjs');
const event = (id) => ({
  id,
  state: 'awaiting-decision',
  remainingMs: 10000,
  attribution: { application: { name: '<img> App\nName' } },
  flow: { direction: 'incoming', protocol: 'udp', remote: '[2001:db8::1]:44001' },
});
const state = (ids, generation = 'g') => ({
  control: { connected: true, readOnly: false, generation, events: ids.map(event) },
});
function setup() {
  let time = 0,
    notices = [],
    clicked = [],
    supported = true;
  const manager = new RequestNotifications(
    () => supported,
    (c) => {
      const n = new EventEmitter();
      n.content = c;
      n.show = () => {};
      n.close = () => n.emit('close');
      notices.push(n);
      return n;
    },
    (r) => clicked.push(r),
    () => time,
  );
  return {
    manager,
    notices,
    clicked,
    advance: (n) => (time += n),
    unsupported: () => (supported = false),
  };
}
test('generation identities deduplicate polls/reconnect; expiry and external resolution close notices', () => {
  const t = setup(),
    s = state(['a']);
  t.manager.update(s, false);
  for (let i = 0; i < 20; i++) t.manager.update(s, false);
  assert.equal(t.notices.length, 1);
  t.manager.update({ ...s, control: { ...s.control, connected: false } }, false);
  assert.equal(t.manager.counts().live, 0);
  t.advance(5000);
  t.manager.update(s, false);
  assert.equal(t.notices.length, 1);
  t.manager.update(state(['a'], 'new'), false);
  assert.equal(t.notices.length, 2);
  t.notices[0].emit('click');
  assert.deepEqual(t.clicked[0], { generation: 'g', id: 'a', group: 'e:a' });
  t.manager.update(state([], 'new'), false);
  assert.equal(t.manager.counts().live, 0);
});
test('bursts summarized/rate-limited; active view no notification; all retention bounded', () => {
  const t = setup();
  t.manager.update(state(['active']), true);
  t.manager.update(state(['active']), false);
  assert.equal(t.notices.length, 0);
  t.manager.update(state(['1']), false);
  t.manager.update(state(['1', '2', '3']), false);
  assert.equal(t.notices.length, 1);
  t.advance(3000);
  t.manager.update(state(['1', '2', '3']), false);
  assert.match(t.notices[1].content.title, /3 pending/);
  t.notices[1].emit('click');
  assert.equal(t.clicked[0], undefined);
  for (let i = 0; i < 1000; i++) {
    t.advance(3000);
    t.manager.update(state([String(i)], String(i)), false);
  }
  assert(t.manager.counts().seen <= 512);
  assert(t.manager.counts().live <= 3);
  assert(t.manager.counts().queued <= 256);
});
test('suppression/failure keeps pending authoritative; metadata never carries markup', () => {
  const t = setup(),
    s = state(['a']);
  t.unsupported();
  t.manager.update(s, false);
  assert.equal(t.notices.length, 0);
  assert.equal(pending(s).length, 1);
  assert.match(t.manager.status, /unavailable/);
  assert.equal(plain('<b>name</b>\n'), ' b name /b ');
  const u = setup();
  u.manager.update(s, false);
  u.notices[0].emit('failed');
  assert.match(u.manager.status, /failed/);
  u.advance(10000);
  u.manager.update(s, false);
  assert.equal(u.notices.length, 1);
});

test('notices summarize by request group: 51 identical attempts are one notice', () => {
  const t = setup();
  const burst = (n) => ({
    control: {
      connected: true,
      readOnly: false,
      generation: 'g',
      events: Array.from({ length: n }, (_, i) => ({
        ...event('r' + i),
        request_group: 'same',
        first_seen: new Date(Date.UTC(2026, 0, 1, 0, 0, i)).toISOString(),
      })),
    },
  });
  for (let n = 1; n <= 51; n++) {
    t.advance(5000);
    t.manager.update(burst(n), false);
  }
  assert.equal(t.notices.length, 1);
  t.advance(5000);
  t.manager.update(burst(51), false);
  assert.equal(t.notices.length, 1);
  t.notices[0].emit('click');
  assert.deepEqual(t.clicked[0], { generation: 'g', id: 'r0', group: 'g:same' });
  const u = setup(),
    s = burst(51);
  s.control.events.push(event('x'), event('y'));
  u.manager.update(s, false);
  assert.match(u.notices[0].content.title, /3 pending requests/);
  assert.match(u.notices[0].content.body, /53 connection attempts/);
  const v = setup();
  v.manager.update(burst(51), false);
  assert.match(v.notices[0].content.body, /51 similar requests/);
  // Settled by policy re-evaluation: the group is gone and its notice closes.
  const settled = burst(51);
  for (const e of settled.control.events) e.state = 'allowed';
  v.manager.update(settled, false);
  assert.equal(v.manager.counts().live, 0);
});
