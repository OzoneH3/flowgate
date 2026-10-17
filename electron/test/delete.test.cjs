// Synthetic transport/protocol cases; real Electron/controller evidence is delete.mjs.
const { test } = require('node:test'),
  assert = require('node:assert/strict'),
  net = require('node:net'),
  fs = require('node:fs'),
  path = require('node:path');
const { Rules } = require('../dist/test/rules.cjs');
const { call } = require('../dist/test/backend.cjs');
test('conditional delete: exact zero tokens, capabilities, errors, acknowledgements, response loss and uint64 refusal', async () => {
  const dir = fs.mkdtempSync(path.resolve(__dirname, '../../.workspace/delete-unit-')),
    socket = path.join(dir, 's');
  let mode = 'success',
    sent = [],
    polls = 0;
  const base = () => ({
    version: 1,
    generation: 'g',
    read_only: false,
    mode: 'host-enforcement',
    server_time: new Date().toISOString(),
  });
  const server = net.createServer((s) =>
    s.once('data', (b) => {
      const q = JSON.parse(b);
      sent.push(q);
      if (mode === 'lost') {
        s.destroy();
        return;
      }
      let r = { ...base(), deleted_rule: { id: q.id, version: q.expected_version } };
      if (mode.startsWith('error:'))
        r = { ...base(), error_code: mode.slice(6), error: 'Actual backend failure' };
      if (mode === 'wrong-id') r.deleted_rule.id = 'other';
      if (mode === 'wrong-version') r.deleted_rule.version = 1;
      if (mode === 'wrong-generation') r.generation = 'new';
      if (mode === 'missing-version') delete r.deleted_rule.version;
      if (mode === 'unsafe') {
        s.end(
          '{"version":1,"generation":"g","read_only":false,"server_time":"2026-10-17T12:00:00Z","rules":[{"version":18446744073709551615}]}\n',
        );
        return;
      }
      if (mode === 'legacy-zero') r = { ...base(), rules: [{ id: 'old' }] };
      s.end(JSON.stringify(r) + '\n');
    }),
  );
  await new Promise((r) => server.listen(socket, r));
  let control = {
    connected: true,
    readOnly: false,
    generation: 'g',
    capabilities: ['conditional-rule-delete-v1'],
  };
  const rules = new Rules({
      controller: socket,
      view: () => ({ control }),
      pollControl: async () => {
        polls++;
      },
    }),
    tokens = { generation: 'g', id: 'old', version: 0 };
  try {
    assert.equal((await rules.delete(tokens)).phase, 'acknowledged');
    assert.deepEqual(sent[0], {
      version: 1,
      operation: 'rule-delete',
      generation: 'g',
      id: 'old',
      expected_version: 0,
    });
    control.capabilities = [];
    await assert.rejects(() => rules.delete(tokens), /conditional-rule-delete/);
    assert.equal(sent.length, 1);
    control.capabilities = ['conditional-rule-delete-v1'];
    for (const code of [
      'version_conflict',
      'generation_conflict',
      'not_found',
      'forbidden',
      'read_only',
      'unavailable',
      'persistence_failed',
    ]) {
      mode = 'error:' + code;
      const r = await rules.delete(tokens);
      assert.equal(r.phase, 'rejected');
      assert.match(r.message, new RegExp(code));
      assert.match(r.message, /Actual backend failure/);
    }
    for (mode of ['wrong-id', 'wrong-version', 'wrong-generation', 'missing-version', 'lost']) {
      assert.equal((await rules.delete(tokens)).phase, 'unknown');
    }
    const count = sent.length;
    await new Promise((r) => setTimeout(r, 20));
    assert.equal(sent.length, count);
    assert.equal(polls, count);
    await assert.rejects(
      () => rules.delete({ ...tokens, version: 9007199254740992 }),
      /Invalid deletion/,
    );
    assert.equal(sent.length, count);
    mode = 'unsafe';
    await assert.rejects(() => call(socket, { operation: 'list' }), /losslessly/);
    mode = 'legacy-zero';
    assert.equal((await call(socket, { operation: 'list' })).rules[0].version, 0);
  } finally {
    await new Promise((r) => server.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
