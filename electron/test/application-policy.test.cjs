// NetLimiter quick-setter parity (application-policy-v1, stored-ask-v1) through the real
// ActivityPolicy renderer code on a minimal synthetic DOM. No daemon; requests are recorded.
const { test } = require('node:test'),
  assert = require('node:assert/strict');
class El {
  constructor(tag) {
    this.tagName = tag.toUpperCase();
    this.children = [];
    this.parent = null;
    this.text = '';
    this.className = '';
    this.dataset = {};
    this.attrs = {};
    this.style = {};
  }
  get classList() {
    const names = () => this.className.split(/\s+/).filter(Boolean);
    return {
      add: (...c) => (this.className = [...new Set([...names(), ...c])].join(' ')),
      remove: (...c) =>
        (this.className = names()
          .filter((n) => !c.includes(n))
          .join(' ')),
      contains: (c) => names().includes(c),
      toggle: (c, on) =>
        (on ?? !names().includes(c)) ? this.classList.add(c) : this.classList.remove(c),
    };
  }
  set textContent(t) {
    this.children = [];
    this.text = String(t);
  }
  get textContent() {
    return this.text + this.children.map((c) => c.textContent).join('');
  }
  append(...nodes) {
    for (let n of nodes) {
      if (typeof n === 'string') {
        const t = new El('#text');
        t.text = n;
        n = t;
      }
      if (n.fragment) {
        this.append(...n.children.splice(0));
        continue;
      }
      n.remove();
      n.parent = this;
      this.children.push(n);
    }
  }
  prepend(...nodes) {
    const rest = this.children.splice(0);
    this.append(...nodes, ...rest);
  }
  replaceChildren(...nodes) {
    for (const c of this.children) c.parent = null;
    this.children = [];
    this.append(...nodes);
  }
  remove() {
    if (!this.parent) return;
    this.parent.children = this.parent.children.filter((c) => c !== this);
    this.parent = null;
  }
  setAttribute(k, v) {
    this.attrs[k] = String(v);
  }
  getAttribute(k) {
    return this.attrs[k];
  }
  addEventListener() {}
  focus() {
    document.activeElement = this;
  }
  getBoundingClientRect() {
    return { left: 0, top: 0, bottom: 10, right: 10, width: 10, height: 10 };
  }
  contains(n) {
    for (let x = n; x; x = x.parent) if (x === this) return true;
    return false;
  }
  get isConnected() {
    let x = this;
    while (x.parent) x = x.parent;
    return x === document.body;
  }
  closest(sel) {
    for (let x = this; x; x = x.parent) if (matches(x, sel)) return x;
    return null;
  }
  all() {
    return this.children.flatMap((c) => [c, ...c.all()]);
  }
  querySelector(sel) {
    return this.all().find((e) => matches(e, sel)) || null;
  }
  querySelectorAll(sel) {
    return this.all().filter((e) => matches(e, sel));
  }
}
function matches(e, sel) {
  return sel.split(',').some((s) => {
    s = s.trim();
    const focus = /^\[data-focus="(.*)"\]$/.exec(s);
    if (focus) return e.dataset.focus === focus[1];
    if (s.startsWith('.'))
      return s
        .slice(1)
        .split('.')
        .every((c) => e.classList.contains(c));
    return false;
  });
}
const feedback = new El('p');
global.document = {
  body: new El('body'),
  activeElement: null,
  createElement: (t) => new El(t),
  createElementNS: (ns, t) => Object.assign(new El(t), { namespaceURI: ns }),
  createDocumentFragment: () => Object.assign(new El('#fragment'), { fragment: true }),
  getElementById: (id) => (id === 'feedback' ? feedback : null),
  querySelector: () => null,
  addEventListener() {},
};
global.CSS = { escape: (s) => s };
global.requestAnimationFrame = (fn) => (fn(), 0);
global.innerWidth = 1200;
global.innerHeight = 900;
const calls = [];
let state;
global.window = {
  addEventListener() {},
  flowgate: {
    applicationMetadata: async () => ({}),
    ruleContext: async () => state,
    ruleDraft: async (source) => {
      calls.push(['draft', source]);
      const rule = state.control.rules.find(r => r.id === (source.id || source.basis?.rule));
      return { token: 'draft-' + calls.length, generation: 'g', source: 'test', rule: rule || {} };
    },
    rulePreview: async (edit) => {
      calls.push(['preview', edit]);
      return {
        receipt: 'receipt-1',
        preview: 'Synthetic',
        expiresAt: new Date(Date.now() + 30000).toISOString(),
        verifiedRule: saved(edit),
      };
    },
    ruleSave: async (receipt) => {
      calls.push(['save', receipt]);
      const edit = calls.findLast((c) => c[0] === 'preview')[1];
      return { phase: 'acknowledged', rule: saved(edit), message: 'Saved by backend.' };
    },
  },
};
const { parsePolicyView } = require('../dist/test/policy.cjs');
const { ActivityPolicy } = require('../dist/test/activity-policy.cjs');
const process = {
  id: '9:start',
  pid: 9,
  start_ticks: '10',
  uid: 1000,
  application: { key: 'app', revision: 'rev', executable: '/native/app', name: 'app' },
};
const filter = (o = {}) => ({
  application: 'app',
  revision: 'rev',
  uid: 1000,
  direction: 'outgoing',
  protocol: '*',
  remote_address: '*',
  local_port: 0,
  remote_port: 0,
  ...o,
});
function saved(edit) {
  const source = calls.findLast((c) => c[0] === 'draft')?.[1];
  const existing = state.control.rules.find(r => r.id === (source?.id || source?.basis?.rule));
  if (existing)
    return {
      ...existing, id: source.id || 'new', version: 2, priority: edit.priority,
      action: edit.action, disabled: edit.disabled,
      filter: { ...existing.filter, direction: source.basis?.direction || existing.filter.direction,
        protocol: edit.protocol, remote_address: edit.remote_address,
        remote_port: edit.remote_port, local_port: edit.local_port },
    };
  return {
    id: 'own',
    version: 2,
    schema: 2,
    created: '2026-01-01T00:00:00Z',
    executable: '/native/app',
    action: edit.action,
    disabled: edit.disabled,
    priority: 100,
    expires: '0001-01-01T00:00:00Z',
    filter: filter({ protocol: edit.protocol, remote_address: edit.remote_address }),
  };
}
const ref = (id, action, kind, o = {}) => ({
  id,
  version: '1',
  action,
  priority: 100,
  scope: filter(kind === 'scoped' ? { protocol: 'tcp', remote_address: '1.1.1.1' } : {}),
  disabled: false,
  expired: false,
  active: true,
  expires: '0001-01-01T00:00:00Z',
  ...(kind ? { kind } : {}),
  ...o,
});
const stored = (r) => ({
  id: r.id,
  version: 1,
  schema: 2,
  created: '2026-01-01T00:00:00Z',
  executable: '/native/app',
  action: r.action,
  disabled: r.disabled,
  priority: 100,
  expires: r.expires,
  filter: r.scope,
});
const direction = (d, rules, own) => ({
  direction: d,
  configured: rules.length ? 'scoped' : 'absent',
  reason: 'Backend classification',
  rules,
  active_rules: rules.length,
  disabled_rules: 0,
  expired_rules: 0,
  potential_overlapping_actions: false,
  configured_default: { known: false, reason: 'Unknown' },
  runtime_default: { known: false, reason: 'Stopped' },
  enforcement: { state: 'active', covered: true, reason: 'Covered' },
  ...(own === undefined
    ? {}
    : { application_rule: own, scoped_rules: rules.filter((r) => r !== own).length }),
});
// rules: outgoing refs; own: the application_rule ref (null = none, undefined = old daemon).
function setup(rules, own, capabilities = ['application-policy-v1'], inactive = false) {
  calls.length = 0;
  feedback.textContent = '';
  const now = new Date().toISOString();
  state = {
    control: {
      connected: true,
      readOnly: false,
      generation: 'g',
      serverNow: Date.now(),
      permissions: { can_manage_rules: true },
      enforcement: { state: 'active' },
      capabilities: [
        'policy-explanations-v1',
        'observed-rule-create-v1',
        'observed-rule-any-protocol-v1',
        'conditional-rule-delete-v1',
        ...capabilities,
      ],
      rules: rules.map(stored),
      policy: parsePolicyView({
        snapshot: { generation: 'g', token: 't', sequence: '1', evaluated_at: now, meaning: 'Now' },
        activity_sequence: '1',
        activity_collected: now,
        activity_available: true,
        complete: true,
        applications: [
          {
            ref: 'appref',
            identity: { key: 'app', revision: 'rev', uid: 1000 },
            process_ids: [process.id],
            incoming: direction('incoming', [], own === undefined ? undefined : null),
            outgoing: direction('outgoing', rules, own),
          },
        ],
        rows: [],
      }),
    },
    observation: {
      connected: true,
      generation: 'g',
      activity: { sequence: 1, collected: now, processes: { [process.id]: process }, rows: [] },
    },
  };
  if (inactive) state.observation.activity.processes = {};
  const row = {
    id: 'application:app',
    kind: 'application',
    label: 'app',
    ...(inactive
      ? { inactive: { key: 'app', revision: 'rev', uid: 1000 }, rows: [] }
      : { process, rows: [{ id: 'socket-1', owners: [process.id], ownership_category: 'visible-holder' }] }),
  };
  const host = new El('section');
  document.body.replaceChildren(host);
  const policy = new ActivityPolicy(host);
  policy.update(row, state);
  const cell = host.querySelector('[data-focus="cell:application:outgoing"]');
  const open = async () => {
    policy.activate('outgoing', 'application', cell);
    await settle(); // popup refreshes the bounded policy batch before enabling actions
  };
  return { host, policy, cell, row, open };
}
const find = (host, focus) => host.querySelector(`[data-focus="${focus}"]`);
const settle = async () => {
  for (let i = 0; i < 10; i++) await new Promise((r) => setImmediate(r));
};
test('narrow remembered rule + application Allow: one-click canonical application_policy, scoped rule never edited', async () => {
  const narrow = ref('narrow', 'block', 'scoped');
  const f = setup([narrow], null);
  assert.match(f.cell.textContent, /^Not set/);
  assert.match(f.cell.textContent, /\+1 scoped/);
  assert(f.cell.classList.contains('tone-none'));
  await f.open();
  const popup = f.host.querySelector('.quick-popup');
  assert.match(popup.textContent, /Scoped rules \(1\)/);
  assert.equal(find(f.host, 'qs:narrow:allow').disabled, false);
  const allow = find(f.host, 'qs:new:allow');
  assert.equal(allow.disabled, false);
  allow.onclick();
  await settle();
  assert.deepEqual(
    calls.map((c) => c[0]),
    ['draft', 'preview', 'save'],
    'no manual review step',
  );
  assert.deepEqual(calls[0][1], {
    observed: {
      generation: 'g',
      row_id: 'socket-1',
      process_id: process.id,
      direction: 'outgoing',
    },
  });
  assert(!calls.some((c) => c[0] === 'draft' && c[1].id), 'never drafts an existing rule');
  assert.deepEqual(calls[1][1], {
    token: 'draft-1',
    action: 'allow',
    protocol: '*',
    remote_address: '*',
    local_port: 0,
    remote_port: 0,
    priority: 100,
    disabled: false,
    expiry: 'permanent',
    creation_scope: 'policy',
  });
  assert.equal(f.host.querySelector('.quick-popup'), null);
  assert.match(feedback.textContent, /^Allow · .* own v2/);
});
test('cell shows the own application rule: Allow, Deny, Disabled; scoped hint separate', () => {
  const narrow = ref('narrow', 'block', 'scoped');
  let own = ref('own', 'allow', 'application');
  let f = setup([own, narrow], own);
  assert.match(f.cell.textContent, /Allow/);
  assert.match(f.cell.textContent, /\+1 scoped/);
  assert(f.cell.classList.contains('tone-allow'));
  own = ref('own', 'block', 'application');
  f = setup([own], own);
  assert.equal(f.cell.textContent.replace(/\s/g, ''), '✕Deny');
  assert(f.cell.classList.contains('tone-block'));
  own = ref('own', 'allow', 'application', { disabled: true, active: false });
  f = setup([own], own);
  assert.match(f.cell.textContent, /Disabled/);
  assert(f.cell.classList.contains('tone-off'));
  assert(!f.cell.classList.contains('tone-allow'));
});
test('existing own rule: Deny sets it through application_policy; enabled and Delete act on the own rule only', async () => {
  const own = ref('own', 'allow', 'application'),
    narrow = ref('narrow', 'allow', 'scoped');
  const f = setup([own, narrow], own);
  await f.open();
  assert.equal(find(f.host, 'qs:own:allow').disabled, true, 'current active action');
  assert.equal(find(f.host, 'qs-delete').disabled, false);
  assert.equal(find(f.host, 'qs:narrow:block').disabled, false);
  find(f.host, 'qs:own:block').onclick();
  await settle();
  assert.equal(calls[0][1].observed.direction, 'outgoing');
  assert.equal(calls[1][1].creation_scope, 'policy');
  assert.equal(calls[1][1].action, 'block');
  await f.open();
  const enabled = find(f.host, 'qs:own:enabled');
  enabled.checked = false;
  enabled.onchange();
  await settle();
  assert.deepEqual(calls[3], ['draft', { id: 'own' }], 'enabled toggles the own rule');
});
test('without application-policy-v1 an app Allow creates a new app-wide rule, never routed into a scoped rule', async () => {
  const narrow = ref('narrow', 'block');
  narrow.scope = filter({ protocol: 'tcp', remote_address: '1.1.1.1' });
  const f = setup([narrow], undefined, []);
  assert.match(f.cell.textContent, /Not set/);
  assert(!f.cell.classList.contains('tone-block'));
  await f.open();
  assert.equal(find(f.host, 'qs:narrow:allow').disabled, false);
  find(f.host, 'qs:new:allow').onclick();
  await settle();
  assert(calls[0][1].observed);
  assert.equal(calls[1][1].creation_scope, 'application');
  assert.equal(calls[1][1].remote_address, '*');
});
test('stored Ask: NetLimiter order Ask | Allow | Deny and one-click ask policy; Ask indicator', async () => {
  const f = setup([], null, ['application-policy-v1', 'stored-ask-v1']);
  await f.open();
  const order = f.host.querySelectorAll('.qs-action').map((b) => b.dataset.focus.split(':').pop());
  assert.deepEqual(order, ['ask', 'allow', 'block']);
  find(f.host, 'qs:new:ask').onclick();
  await settle();
  assert.equal(calls[1][1].action, 'ask');
  assert.equal(calls[1][1].creation_scope, 'policy');
  const own = ref('own', 'ask', 'application');
  const g = setup([own], own, ['application-policy-v1', 'stored-ask-v1']);
  assert.equal(g.cell.textContent.replace(/\s/g, ''), '?Ask');
  assert(g.cell.classList.contains('tone-ask'));
  assert.match(g.cell.title, /Ask: prompt for each new connection/);
});
test('without stored-ask-v1 an Ask rule is read-only and Ask is never offered', async () => {
  const own = ref('own', 'ask', 'application');
  const f = setup([own], own);
  assert(f.cell.classList.contains('tone-ask'));
  await f.open();
  assert.equal(find(f.host, 'qs:own:ask'), null);
  assert.equal(find(f.host, 'qs:own:allow').disabled, true);
  assert.equal(find(f.host, 'qs:own:block').disabled, true);
  assert.equal(find(f.host, 'qs:own:enabled').disabled, true);
});

for (const inactive of [false, true]) {
  test(`shared Blocker popup edits each scoped rule by ID (${inactive ? 'not running' : 'running'})`, async () => {
    const first = ref('first', 'block', 'scoped');
    const second = ref('second', 'allow', 'scoped', {
      scope: filter({ protocol: 'udp', remote_port: 53 }),
    });
    const f = setup([first, second], null, ['application-policy-v1', 'rule-from-basis-v1'], inactive);
    await f.open();
    const popup = f.host.querySelector('.quick-popup');
    assert.match(popup.textContent, /Outgoing rules/);
    assert.match(popup.textContent, /Scoped rules \(2\)/);
    assert.equal(find(popup, 'qs:second:block').disabled, false);
    assert.equal(find(popup, 'qs:first:block').disabled, true);
    find(popup, 'qs:first:allow').onclick();
    await settle();
    assert.deepEqual(calls.map(([op]) => op), ['draft', 'preview', 'save']);
    assert.deepEqual(calls[0], ['draft', { id: 'first' }]);
    assert.deepEqual(
      [calls[1][1].action, calls[1][1].protocol, calls[1][1].remote_address, calls[1][1].expiry],
      ['allow', 'tcp', '1.1.1.1', 'preserve'],
    );
    await f.open();
    find(f.host, 'qs:second:block').onclick();
    await settle();
    assert.deepEqual(calls[3], ['draft', { id: 'second' }]);
    assert.deepEqual([calls[4][1].action, calls[4][1].protocol, calls[4][1].remote_port], ['block', 'udp', 53]);
  });
}

test('a stopped app can add an incoming rule from its saved outgoing identity', async () => {
  const f = setup([ref('basis', 'block', 'scoped')], null, ['rule-from-basis-v1'], true);
  f.policy.activate('incoming', 'application', find(f.host, 'cell:application:incoming'));
  await settle();
  const popup = f.host.querySelector('.quick-popup');
  assert.match(popup.textContent, /Incoming rules/);
  const allow = find(popup, 'qs:new:allow');
  assert.equal(allow.disabled, false);
  allow.onclick();
  await settle();
  assert.deepEqual(calls.map(([op]) => op), ['draft', 'preview', 'save']);
  assert.deepEqual(calls[0], ['draft', { basis: { rule: 'basis', direction: 'incoming' } }]);
});

test('clicking a different row after a policy refresh uses the clicked identity', async () => {
  const f = setup([ref('first', 'block', 'scoped')], null, ['application-policy-v1'], true);
  const previous = { ...state, publication: 5 };
  state = { ...state, publication: 6 };
  f.policy.update(f.row, state);
  await f.open();
  const other = { ...f.row, id: 'other', label: 'Other stopped app',
    inactive: { ...f.row.inactive, key: 'different' } };
  f.policy.activateForRow(other, previous, 'outgoing', f.cell);
  await settle();
  assert.match(f.host.querySelector('.quick-popup').textContent, /Other stopped app/);
  assert.equal(find(f.host, 'qs:first:allow'), null);
});
