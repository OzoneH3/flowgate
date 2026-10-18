const { test } = require('node:test');
const assert = require('node:assert/strict');
const {
  connectionPresentation,
  permissionTarget,
  parseConnectionZone,
} = require('../dist/test/connection-presentation.cjs');
const { parseReply } = require('../dist/test/protocol.cjs');
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
