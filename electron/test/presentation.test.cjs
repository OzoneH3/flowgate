const { test } = require('node:test');
const assert = require('node:assert/strict');
const { ruleStatus, ruleState } = require('../dist/test/rule-status.cjs');
const {
  desktopEntry,
  execToken,
  safeIcon,
  ApplicationIcons,
  iconKey,
} = require('../dist/test/icons.cjs');
const p = {
  application: { key: 'key', revision: 'rev', executable: '/usr/bin/firefox' },
  uid: 1000,
};
function rule(id, action = 'allow', extra = {}) {
  return {
    id,
    action,
    filter: {
      application: 'key',
      revision: 'rev',
      uid: 1000,
      direction: 'incoming',
      protocol: 'tcp',
      remote_address: '192.0.2.1',
    },
    expires: '',
    disabled: false,
    ...extra,
  };
}
const state = (rules) => ({
  observation: { activity: { processes: { p }, rows: [] } },
  control: { connected: true, serverNow: 10000, rules, events: [] },
});
test('scoped inventory keeps action, direction, revision and UID distinct; no flow verdict', () => {
  const rules = [
    rule('a'),
    rule('b', 'block'),
    rule('c', 'allow', { disabled: true }),
    rule('d', 'block', { expires: new Date(9000).toISOString() }),
    rule('out', 'allow', { filter: { ...rule('').filter, direction: 'outgoing' } }),
    rule('foreign', 'block', { filter: { ...rule('').filter, uid: 0 } }),
    rule('old', 'allow', { filter: { ...rule('').filter, revision: 'old' } }),
  ];
  const got = ruleStatus({ process: p }, state(rules));
  assert.deepEqual(
    got.incoming.map((r) => r.id),
    ['a', 'b', 'c', 'd'],
  );
  assert.deepEqual(
    got.outgoing.map((r) => r.id),
    ['out'],
  );
  assert.deepEqual(
    got.incoming.map((r) => ruleState(r, got.now)),
    ['allow', 'block', 'disabled', 'expired'],
  );
  assert.match(got.reason, /not a verdict/);
});
test('disconnected, missing identity, shared display association are unavailable', () => {
  const s = state([rule('a')]);
  assert.equal(ruleStatus({ displayApplication: p.application, process: p }, s).available, false);
  assert.equal(ruleStatus({ kind: 'unidentified' }, s).available, false);
  s.control.connected = false;
  assert.equal(ruleStatus({ process: p }, s).available, false);
});
test('desktop association parses only main entry, does not execute wrapper commands', () => {
  assert.deepEqual(
    {
      ...desktopEntry(
        '[Desktop Entry]\nType=Application\nExec=/usr/bin/firefox %u\nIcon=firefox\n[Desktop Action new]\nIcon=other',
      ),
    },
    { Type: 'Application', Exec: '/usr/bin/firefox %u', Icon: 'firefox' },
  );
  assert.equal(execToken('"/opt/My App/bin" %U'), '/opt/My App/bin');
  for (const text of [
    'env WRAP=1 firefox',
    'sh -c firefox',
    'wine game.exe',
    '$HOME/bin/app',
    'flatpak run app',
  ])
    assert.equal(execToken(text), undefined);
});
test('icon serving only accepts bounded static image formats', () => {
  assert(
    safeIcon(Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0"/></svg>'), '.svg'),
  );
  for (const text of [
    '<svg><script>x</script></svg>',
    '<svg><image href="file:///secret"/></svg>',
    '<svg onload="x"/>',
    '<svg><use href="https://bad"/></svg>',
    '<svg><style>@import "x"</style></svg>',
  ])
    assert.equal(safeIcon(Buffer.from(text), '.svg'), false);
});
test('actual installed Firefox desktop entry resolves; arbitrary identities do not', async () => {
  const icons = new ApplicationIcons();
  const app = { key: 'observed', revision: 'rev', executable: '/usr/lib/firefox/firefox' };
  const s = state([]);
  s.observation.activity.processes = { p: { application: app } };
  icons.observe(s);
  const key = iconKey(app),
    got = await icons.request([key, '/etc/passwd']);
  assert.match(got[key], /^flowgate:\/\/app\/icons\/[a-f0-9]{64}\.(png|svg)$/);
  assert.equal(got['/etc/passwd'], null);
  assert.deepEqual({ ...(await icons.request([key])) }, { [key]: got[key] });
  await assert.rejects(icons.request({ path: '/etc/passwd' }));
});

test('Go zero-time expiry remains permanent', () =>
  assert.equal(
    ruleState(rule('permanent', 'allow', { expires: '0001-01-01T00:00:00Z' }), 10000),
    'allow',
  ));
test('configured labels separate broad constraints, scoped, mixed and absent without effective inference', () => {
  const { configuredPolicy } = require('../dist/test/rule-status.cjs');
  assert.equal(configuredPolicy([], 10000), 'No rule');
  assert.equal(
    configuredPolicy(
      [
        rule('wide', 'allow', {
          filter: { ...rule('').filter, protocol: '*', remote_address: '' },
        }),
      ],
      10000,
    ),
    'Allow · app-wide',
  );
  assert.equal(
    configuredPolicy(
      [rule('tcp', 'allow', { filter: { ...rule('').filter, remote_address: '' } })],
      10000,
    ),
    'Allow · TCP',
  );
  assert.equal(configuredPolicy([rule('one')], 10000), 'Allow · scoped');
  assert.equal(configuredPolicy([rule('one'), rule('two', 'block')], 10000), 'Mixed · 2');
  assert.equal(configuredPolicy([rule('one'), rule('two')], 10000), 'Scoped · 2');
});
