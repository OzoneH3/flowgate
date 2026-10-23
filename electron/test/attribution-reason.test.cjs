// Synthetic API metadata only: no kernel attribution or delivery claim.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { parseAttributionReasonCode, attributionReasonLabel } = require('../dist/test/attribution-reason.cjs');
const { parseReply } = require('../dist/test/protocol.cjs');
const { parseRecord, outcomeLabel, reasonSummary } = require('../dist/test/decision-log.cjs');
const { addRequestApplications } = require('../dist/test/model.cjs');
const { awaiting } = require('../dist/test/automatic-prompts.cjs');
const { requestRuleAvailable } = require('../dist/test/request-rule.cjs');

const now = '2026-10-23T20:00:00Z';
const attribution = (code) => ({ status: 'unidentified', reason: 'no visible matching socket', reason_code: code,
  visibility_complete: false, owners: [], sockets: [], fingerprint: '' });
const request = (code) => parseReply({ version: 1, generation: 'g', read_only: false, server_time: now,
  events: [{ id: 'request', deadline: now, state: 'blocked', reason: 'attribution unavailable',
    permission: 'none', first_seen: now, flow: { direction: 'outgoing', protocol: 'tcp', local: '127.0.0.1:41001', remote: '127.0.0.1:41002' },
    attribution: attribution(code), scope_previews: {} }] }).events[0];
const record = (code) => parseRecord({ id: 'record', sequence: '1', time: now, generation: 'g', mode: 'isolated-lab',
  kind: 'final', request_id: 'request', application: null, principal_uid: null,
  flow: { direction: 'outgoing', protocol: 'tcp', family: 'ipv4', local: '127.0.0.1:41001', remote: '127.0.0.1:41002' },
  attribution: attribution(code), decision: { action: 'block', source: 'attribution', reason: 'attribution unavailable', scope: null, rule: null, matching_rules: [] },
  verdict: { state: 'drop_submitted', detail: '' }, delivery: 'not_observed' });
function withoutCode(value) {
  const copy = structuredClone(value);
  delete copy.attribution.reason_code;
  return copy;
}

test('new and future categories survive both API parsers without altering recorded decisions or identity', () => {
  const oldRequest = request(undefined), oldRecord = record(undefined);
  for (const code of ['no_socket_observed', 'native_owner_observed', 'runtime_owner_ambiguous', 'localhost_exempt', 'future_category', 'a'.repeat(64)]) {
    assert.equal(parseAttributionReasonCode(code), code);
    const event = request(code), log = record(code);
    assert.equal(event.attribution.reason_code, code);
    assert.equal(log.attribution.reason_code, code);
    assert.deepEqual(withoutCode(event), withoutCode(oldRequest));
    assert.deepEqual(withoutCode(log), withoutCode(oldRecord));
    assert.equal(outcomeLabel(log), outcomeLabel(oldRecord));
    assert.equal(reasonSummary(log), reasonSummary(oldRecord));
    // Even a success-looking diagnostic code cannot turn this refusal into identity.
    assert.equal(event.attribution.application, undefined);
    assert.equal(log.application, null);
    assert.equal(log.decision.action, 'block');
    assert.equal(log.delivery, 'not_observed');
  }
});

test('legacy and malformed categories retain the complete event and evidence without prose inference', () => {
  for (const code of [undefined, null, '', 0, true, {}, [], 'UPPER', 'has space', 'a'.repeat(65), 'no_socket_observed\n', '<img src=x onerror=alert(1)>']) {
    assert.equal(parseAttributionReasonCode(code), undefined);
    const event = request(code), log = record(code);
    assert.equal(event.attribution.reason_code, undefined);
    assert.equal(log.attribution.reason_code, undefined);
    assert.equal(event.attribution.reason, 'no visible matching socket');
    assert.equal(log.attribution.reason, 'no visible matching socket');
    assert.deepEqual(withoutCode(event), withoutCode(request(undefined)));
    assert.deepEqual(withoutCode(log), withoutCode(record(undefined)));
  }
});

test('category labels retain absence, ambiguity and exemption limits; future codes are not guessed', () => {
  assert.equal(attributionReasonLabel('no_socket_observed'), 'No matching socket observed');
  assert.equal(attributionReasonLabel('multiple_candidates'), 'Ambiguous owner candidates');
  assert.equal(attributionReasonLabel('localhost_exempt'), 'Localhost exemption (not owner identification)');
  for (const code of ['future_category', 'constructor', 'native_owner_observed_future', ''])
    assert.equal(attributionReasonLabel(code), 'Unrecognized attribution category');
});

test('a runtime refusal with a retained success-looking status cannot create an application or actionable request', () => {
  for (const status of ['directly-associated', 'corroborated']) {
    const event = request('runtime_observer_unavailable');
    event.attribution.status = status;
    event.attribution.owners = [{ id: 'owner', pid: 123, uid: 1000,
      application: { key: 'linux-holder', revision: 'r', name: 'Synthetic holder', executable: '/synthetic/holder' } }];
    event.remainingMs = 60000;
    assert.equal(event.attribution.application, undefined);
    const roots = [];
    addRequestApplications(roots, [event]);
    assert.deepEqual(roots, []); // Owner metadata/status must not substitute for the refused application.
    assert.equal(awaiting(event), false);
    assert.equal(requestRuleAvailable(event, ['request-application-rule-v1']), false);
    const log = record('runtime_observer_unavailable');
    log.attribution.status = status;
    assert.equal(log.application, null);
    assert.equal(outcomeLabel(log), 'Blocked');
  }
});
