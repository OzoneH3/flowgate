const { test } = require('node:test');
const assert = require('node:assert/strict');
const {
  compactUDPOnce,
  connectionPresentation,
  permissionTarget,
  parseConnectionZone,
  scopeZoneText,
} = require('../dist/test/connection-presentation.cjs');
const { parseReply } = require('../dist/test/protocol.cjs');
test('whole-application UDP Once explains Allow and Deny separately using the daemon preview', () => {
  const event = (direction, once) => ({
    flow: { direction, protocol: 'udp' },
    ask_rule: { id: 'ask', version: 1 },
    scope_previews: { once },
  });
  const outgoing = event('outgoing', 'Allow Once permits later datagrams on this UDP tuple for 30 seconds. Already queued datagrams will be discarded.');
  const incoming = event('incoming', 'Once: incoming udp, local 10.0.0.1:4300, remote 10.0.0.2:4400. Block Once drops queued datagrams. The next datagram can open a new request.');
  assert.deepEqual(compactUDPOnce(outgoing), {
    summary: 'Allow drops waiting datagrams and permits later sends for 30 seconds. Deny drops both.',
    allow: 'Allow Once permits later datagrams on this UDP tuple for 30 seconds. Already queued datagrams will be discarded. No rule is saved.',
    block: 'Deny drops waiting datagrams and blocks later sends on this UDP tuple for 30 seconds. No rule is saved.',
  });
  assert.deepEqual(compactUDPOnce(incoming), {
    summary: 'Allow permits waiting datagrams and later sends for 30 seconds. Deny drops waiting datagrams. The next send can prompt again.',
    allow: 'Allow permits waiting datagrams and later sends on this UDP tuple for 30 seconds. No rule is saved.',
    block: 'Deny drops waiting datagrams. The next send can prompt again. No rule is saved.',
  });
  assert.equal(compactUDPOnce({ ...outgoing, flow: { ...outgoing.flow, protocol: 'tcp' } }), undefined);
  assert.equal(compactUDPOnce({ ...incoming, ask_rule: undefined }), undefined);
  assert.equal(compactUDPOnce(event('outgoing', 'Once: ordinary scoped UDP request')), undefined);
  assert.equal(compactUDPOnce({ ...outgoing, flow: { ...outgoing.flow, direction: 'incoming' } }), undefined);
});

test('direction is evidence, independent of endpoints and byte flow', () => {
  const flow = {
    direction: 'incoming',
    local: '[::1]:2',
    remote: '[2001:db8::1]:80',
    protocol: 'tcp',
  };
  assert.equal(connectionPresentation(flow).direction, 'Incoming');
  assert.match(
    connectionPresentation({ ...flow, direction: 'outgoing' }).relation,
    /This program → remote/,
  );
  assert.equal(
    connectionPresentation({ ...flow, direction: 'Unknown' }).direction,
    'Unknown direction',
  );
});
test('classification is not the scope of a remembered decision', () => {
  const zone = parseConnectionZone({
    state: 'known',
    zone: 'local',
    revision: 'r',
    source: 'configured-prefix',
    reason: 'Explicit',
  });
  assert.equal(
    connectionPresentation({ direction: 'incoming', network_scope: zone }).zone,
    'Local Network',
  );
  assert.match(permissionTarget('application', 'udp'), /Application.*Any network.*1 hour/);
  assert.match(permissionTarget('once', 'tcp'), /TCP connection/);
  assert.match(permissionTarget('once', 'udp'), /UDP tuple.*30 seconds/);
  assert.equal(connectionPresentation({ direction: 'incoming' }).zone, 'Zone unavailable');
  assert.throws(() => parseConnectionZone({ state: 'known', zone: 'private' }));
});
test('pending event parser preserves authoritative classification, no guessed zone', () => {
  const reply = {
    version: 1,
    generation: 'g',
    mode: 'enforce',
    read_only: false,
    server_time: new Date().toISOString(),
    events: [
      {
        id: 'e',
        deadline: new Date(Date.now() + 10000).toISOString(),
        flow: {
          direction: 'incoming',
          protocol: 'udp',
          local: '127.0.0.1:1',
          remote: '10.0.0.1:2',
          network_scope: { state: 'unavailable', reason: 'Not configured' },
        },
        attribution: {},
        scope_previews: { once: 'Backend text' },
      },
    ],
  };
  const event = parseReply(reply).events[0];
  assert.equal(event.flow.network_scope.state, 'unavailable');
  assert.equal(event.flow.network_scope.zone, undefined);
  assert.equal(event.scope_previews.once, 'Backend text');
});
test('custom prefix classification is shown separately from automatic scope', () => {
  const scope = (basis, zone = 'local') =>
    parseConnectionZone({ state: 'known', zone, revision: 'r', source: 'automatic-peer-v1', reason: 'x', basis });
  assert.equal(scopeZoneText(scope('custom')), 'Local Network · custom classification');
  assert.equal(scopeZoneText(scope('automatic', 'internet')), 'Internet · automatic');
  assert.equal(scopeZoneText(scope(undefined)), 'Local Network · configured policy zone');
  assert.equal(scope('bogus').basis, undefined);
  assert.equal(
    scopeZoneText(parseConnectionZone({ state: 'unavailable', revision: 'r', source: 's', reason: 'no route' })),
    'no route',
  );
  const flow = { direction: 'outgoing', network_scope: scope('custom') };
  assert.equal(connectionPresentation(flow).zone, 'Local Network (custom)');
  assert.equal(connectionPresentation({ ...flow, network_scope: scope('automatic') }).zone, 'Local Network');
});
