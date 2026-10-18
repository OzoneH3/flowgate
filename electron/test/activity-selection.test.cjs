const { test } = require('node:test');
const assert = require('node:assert/strict');
const { initiationPresentation } = require('../dist/test/initiation.cjs');
global.window = { addEventListener() {} };
const { scopeLabel } = require('../dist/test/activity-policy.cjs');
const socket = { protocol: 'tcp', state: 1, local: '[::1]:50000', remote: '[::1]:80' };
const row = { socket, direction: 'Unknown', traffic: { upload_bps: 1000000, download_bps: 0 } };
test('known direction follows backend initiation and keeps evidence; byte rates and ports confer no direction', () => {
  assert.equal(initiationPresentation(row).state, 'unknown');
  for (const direction of ['incoming', 'outgoing']) {
    const r = initiationPresentation({
      ...row,
      initiation: {
        state: 'known',
        direction,
        source: 'sampled-handshake',
        reason: 'real backend observation',
      },
    });
    assert.equal(r.direction, direction);
    assert.match(r.title, /sampled-handshake/);
    assert.match(r.title, /not a firewall verdict/);
  }
  for (const state of ['listening', 'unconnected', 'ambiguous', 'unknown']) {
    const r = initiationPresentation({
      ...row,
      initiation: { state, direction: 'outgoing', source: 'backend', reason: 'not established' },
    });
    assert.equal(r.direction, '');
    assert.equal(r.state, state);
  }
});
test('scope formatting is descriptive and retains exact protocol/address/port distinctions', () => {
  const ref = {
    scope: {
      protocol: 'tcp',
      direction: 'incoming',
      remote_address: '*',
      local_port: 0,
      remote_port: 443,
    },
  };
  assert.match(scopeLabel(ref), /TCP · remote any address · local port any · remote port 443/);
  assert.match(
    scopeLabel({ scope: { ...ref.scope, remote_address: '2001:db8::/32', protocol: 'udp' } }),
    /UDP.*2001:db8::\/32/,
  );
});

test('bridge projects initiation evidence and rejects malformed known direction', () => {
  const { parseReply } = require('../dist/test/protocol.cjs');
  const raw = {
    version: 1,
    generation: 'g',
    read_only: true,
    server_time: new Date().toISOString(),
    activity: {
      sequence: 1,
      collected: new Date().toISOString(),
      processes: {},
      rows: [
        {
          id: 's',
          owners: [],
          socket,
          initiation: {
            state: 'known',
            direction: 'incoming',
            source: 'kernel-cookie',
            reason: 'sampled request',
            observed_at: '2026-10-18T00:00:00Z',
          },
        },
      ],
    },
  };
  const projected = parseReply(raw).activity.rows[0].initiation;
  assert.equal(projected.direction, 'incoming');
  assert.equal(projected.source, 'kernel-cookie');
  raw.activity.rows[0].initiation.direction = 'download';
  assert.throws(() => parseReply(raw), /initiation direction/);
});
