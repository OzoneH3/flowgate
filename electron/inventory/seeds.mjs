// Local Unix-socket daemon simulation. It never opens a host control socket.
import net from 'node:net';
import { unlink } from 'node:fs/promises';

export const identities = Object.freeze({
  app: 'inventory-atlas', otherApp: 'inventory-beacon', process: '4281:101',
  rule: 'inventory-rule-enabled', disabled: 'inventory-rule-disabled', legacy: 'inventory-rule-legacy',
  request: 'inventory-request-atlas', incoming: 'inventory-request-beacon',
  logPending: 'inventory-log-pending', logFinal: 'inventory-log-final',
  logOther: 'inventory-log-other', logGap: 'inventory-log-gap', logAggregate: 'inventory-log-aggregate',
});
const id = identities;
const never = '0001-01-01T00:00:00Z';
const fixed = '2025-01-15T12:00:00.000Z';
// Use a fixture principal that has no login name on either the host or guest.
const fixtureUid = 424242;
const generation = 'inventory-generation';
const zone = { state: 'known', zone: 'internet', revision: 'inventory-zones', source: 'manual', reason: 'Fixture network' };
const application = (key, name) => ({ name, key, kind: 'native', revision: 'rev-1', executable: '/fixture/' + key });
const atlas = application(id.app, 'Atlas Sync');
const beacon = application(id.otherApp, 'Beacon Relay');
const owner = (app, pid) => ({ id: pid + ':101', pid, uid: fixtureUid, start_ticks: '101', executable: app.executable, application: app });
const firstOwner = owner(atlas, 4281), secondOwner = owner(beacon, 4282);
const connection = (direction, local, remote, protocol = 'tcp') =>
  ({ direction, family: 'ipv4', protocol, local, remote, network_scope: zone, interface_index: 2 });
const firstFlow = connection('outgoing', '192.0.2.1:50123', '198.51.100.2:443');
const secondFlow = connection('incoming', '192.0.2.1:50124', '198.51.100.2:443');
const filter = (app, direction = 'outgoing', protocol = 'tcp') => ({
  application: app.key, revision: app.revision, direction, uid: fixtureUid, protocol,
  remote_address: '198.51.100.2', remote_port: 443,
});
const rule = (identifier, app, disabled, version = 1) => ({
  schema: 2, id: identifier, version, executable: app.executable, action: 'block', disabled,
  created: fixed, expires: never, priority: 10, filter: filter(app),
});
const baseRules = [rule(id.rule, atlas, false), rule(id.disabled, beacon, true, 2),
  { ...rule(id.legacy, atlas, false), schema: 4, filter: { ...filter(atlas), network_zone: 'local', zone_state: 'legacy' } }];

function event(identifier, app, process, flow, deadline, first) {
  return {
    id: identifier, state: 'awaiting-decision', deadline, first_seen: first, flow,
    attribution: {
      status: 'directly-associated', visibility_complete: true, application: app, owners: [process],
      permission_target: { kind: 'application', label: app.name, once: 'This held connection.',
        remember: 'This application.', key_basis: 'verified executable' },
    },
    remembered_filter: filter(app, flow.direction, flow.protocol),
    scope_previews: {
      once: 'This held connection.', persistent: 'This application.',
      'for-a-while': 'This process instance.',
    },
    request_group: identifier,
    request_rule: { available: true, reason: 'Verified executable' },
  };
}
const capabilities = [
  'explicit-administrator-v1', 'request-list-snapshot-v1', 'conditional-rule-delete-v1',
  'conditional-rule-mutation-v1', 'observed-rule-create-v1', 'process-instance-rules-v1',
  'local-pair-v1', 'decision-remember-fields-v1', 'request-application-rule-v1', 'decision-for-a-while-v1',
  'decision-for-a-while-durations-v1', 'decision-timeout-settings-v1', 'stored-ask-v1',
  'decision-log-v1', 'decision-log-outcome-v1', 'observed-usage-v1', 'continuous-firewall-v1',
  'experimental-native-upload-v1', 'experimental-native-download-v1',
  'experimental-traffic-priority-v1', 'saved-shaping-settings-v1',
  'daemon-udp-monitor-v1', 'network-zone-policy-v1', 'automatic-network-zones-v1',
  'network-endpoint-policy-v1', 'zone-migration-v1', 'daemon-evaluation-v1', 'connection-check-settings-v1', 'activity-connection-analysis-v1',
];
const record = (identifier, kind, request_id, flow, app, sequence) => ({
  id: identifier, kind, request_id, flow, application: app, generation, mode: 'isolated-lab',
  sequence, time: fixed, principal_uid: fixtureUid, attribution: { status: 'directly-associated' },
});
const pending = record(id.logPending, 'pending', id.request, firstFlow, atlas, '20');
const final = { ...record(id.logFinal, 'final', id.request, firstFlow, atlas, '22'),
  decision: { action: 'allow', source: 'user', scope: 'once', reason: 'Explicit user decision', decided_by_uid: fixtureUid },
  verdict: { state: 'deferred', detail: 'Applies at the next queue flush' },
};
const records = [
  { id: id.logGap, kind: 'gap', generation, sequence: '23', time: fixed,
    mode: 'isolated-lab', gap: { reason: 'Fixture retention gap' } },
  { ...record(id.logAggregate, 'final', id.incoming, secondFlow, beacon, '24'),
    decision: { action: 'block', source: 'rule', scope: 'persistent', reason: 'Matched stored rule' },
    related_request_id: id.incoming,
    aggregation: { observations: 2, window_ms: 1000, first_seen: '2025-01-15T12:00:00.012Z', last_seen: '2025-01-15T12:00:00.123Z' },
  },
  final, record(id.logOther, 'pending', id.incoming, secondFlow, beacon, '21'), pending,
].sort((a, b) => Number(b.sequence) - Number(a.sequence));

const recipes = {
  empty: {},
  logPages: { populated: true, logPages: true },
  populated: { populated: true },
  readonly: { populated: true, readOnly: true },
  requests: { populated: true, requests: 'both' },
  requestUdp: { populated: true, requests: 'udp' },
  requestShort: { populated: true, requests: 'udp', short: true },
  requestUnknown: { populated: true, requests: 'both', loseDecision: true },
  processLease: { populated: true, requests: 'both', activeLease: true },
  requestPair: { populated: true, requests: 'pair' },
  requestFault: { populated: true, requests: 'both', rejectPreview: true },
  unhealthy: { populated: true, unhealthy: true },
  offline: { offline: true },
  trafficCleanup: { populated: true, cleanup: true },
  trafficActive: { populated: true, trafficActive: true },
};
export const recipeNames = Object.keys(recipes);

function inventory(recipe, packageBuild) {
  const started = Date.now();
  const now = () => new Date().toISOString();
  const later = seconds => new Date(started + seconds * 1000).toISOString();
  const calls = [];
  const stored = recipe.populated ? structuredClone(baseRules) : [];
  let stage = recipe.requests;
  const answered = new Set();
  let revision = 0;
  let timeout = { seconds: 30, revision: '1' };
  let migratedPreview;
  let evaluation = { id: '', request_id: '', state: 'stopped', profile: 'incoming', duration_seconds: 300,
    cleanup: 'not_needed', review: 'Review the isolated incoming evaluation fixture.',
    reason_code: 'stopped', reason: 'Fixture evaluation stopped',
    readiness: { state: 'ready', checked_at: fixed, checks: [] } };
  const olderRecord = record('inventory-log-older', 'pending', 'inventory-request-older', firstFlow, atlas, '19');
  const newerRecord = record('inventory-log-new', 'pending', 'inventory-request-new', secondFlow, beacon, '25');
  const pendingEvents = () => {
    const primary = event(id.request, atlas, firstOwner,
      recipe.requests === 'udp' ? { ...firstFlow, protocol: 'udp' } : firstFlow, later(recipe.short ? 10 : 900), later(-2));
    const incoming = event(id.incoming, beacon, secondOwner, secondFlow, later(900), later(-1));
    if (stage === 'pair') {
      const outgoing = { ...primary, flow: connection('outgoing', '127.0.0.1:50123', '127.0.0.1:443') };
      const reverse = { ...incoming, flow: connection('incoming', '127.0.0.1:443', '127.0.0.1:50123') };
      const pair = (original, other, peer, role) => ({
        ...original, local_peer: { state: 'verified', role, owner: peer, reason: 'Exact reversed fixture socket tuple',
          correlated_event_id: other.id, socket: { kind: role === 'client' ? 'client' : 'listener',
            protocol: 'tcp', local: other.flow.local, remote: other.flow.remote, state: 'Established',
            cookie: 'fixture-peer', inode: 6000 + peer.pid } },
      });
      return [pair(outgoing, reverse, secondOwner, 'server'), pair(reverse, outgoing, firstOwner, 'client')];
    }
    if (recipe.short && Date.parse(primary.deadline) <= Date.now()) return [{
      ...primary, state: 'expired',
      revalidation: { code: 'connection_ended', reason: 'Original connection ended', checked_at: now() },
      request_rule: { ...primary.request_rule, process_state: 'ended', until: later(900) },
    }];
    if (stage === 'both') return [primary, incoming].filter(e => !answered.has(e.id));
    if (stage === 'udp') return [primary].filter(e => !answered.has(e.id));
    return [];
  };
  const activityRows = [
    { id: 'inventory-socket-atlas', owners: [id.process], ownership_category: 'visible-holder', state: 'Established',
      socket: { protocol: 'tcp', family: 2, local: firstFlow.local, remote: firstFlow.remote, uid: fixtureUid, inode: 6001, state: 1 },
      traffic: { available: false, reason: 'Waiting for a sample' } },
    { id: 'inventory-socket-unidentified', owners: [], ownership_category: 'unidentified', state: 'Established',
      socket: { protocol: 'tcp', family: 2, local: '192.0.2.1:50125', remote: firstFlow.remote, uid: fixtureUid, inode: 6002, state: 1 },
      traffic: { available: false, reason: 'Socket owner unknown' } },
  ];
  const response = (q, observer) => {
    if (recipe.offline) return { version: 1, generation, server_time: now(), mode: 'unavailable', read_only: true,
      error: 'Fixture endpoint unavailable', error_code: 'disconnected' };
    const common = {
      version: 1, generation, read_only: observer || !!recipe.readOnly,
      mode: observer ? 'host-monitor' : 'isolated-lab', backend_mode: 'host-enforcement',
      server_time: now(), snapshot_at: now(), snapshot_revision: String(++revision),
      ...(packageBuild ? { build: { source: packageBuild.source, version: packageBuild.version, modified: false } } : {}),
      capabilities, for_a_while_durations: [15, 60, 3600],
      permissions: { role: 'administrator', policy_scope: 'machine', observation_scope: 'machine',
        can_manage_rules: !observer && !recipe.readOnly, can_manage_machine_rules: !observer && !recipe.readOnly,
        can_decide: !observer && !recipe.readOnly, can_view_measurements: true,
        can_control_traffic: !observer && !recipe.readOnly, can_control_protection: !observer && !recipe.readOnly, can_control_evaluation: !observer && !recipe.readOnly },
      traffic_monitor: { state: recipe.trafficActive ? 'active' : 'disabled', available: true,
        generation, scope: 'machine', partial: false, reason_code: 'fixture', reason: 'Fixture UDP measurement status', collected: now() },
      queue_health: recipe.unhealthy ? { state: 'pressure', sampled_at: fixed } : { state: 'inactive', sampled_at: fixed },
      protection: { id: '', request_id: '', state: 'stopped', desired_mode: 'monitoring', profile: 'both',
        cleanup: 'not_needed', reason_code: 'monitoring', reason: 'Fixture protection stopped',
        gui_required: false, readiness: { state: 'ready', checked_at: fixed, checks: [] } },
      evaluation,
      process_leases: recipe.activeLease ? [{ id: 'inventory-process-lease', action: 'allow', direction: 'outgoing',
        application_name: atlas.name, executable: atlas.executable, uid: fixtureUid, pid: firstOwner.pid,
        start: firstOwner.start_ticks, until: later(900), seconds: 900, event_id: id.request }] : [],
      enforcement: { state: 'stopped', profile: 'both', detail: 'Fixture enforcement' },
      network_zones: { revision: zone.revision, model: 'automatic-peer-v1', local_prefixes: [],
        internet_prefixes: [], reason: 'Fixture networks' },
    };
    const events = pendingEvents();
    const found = events.find(e => e.id === q.id);
    const storedRule = stored.find(r => r.id === q.id);
    const failure = (message, code = 'unsupported') => ({ ...common, error: message, error_code: code });
    switch (q.operation) {
      case 'list':
        return { ...common, events, rules: stored, activity: { sequence: 1, collected: now(), complete: true,
          processes: recipe.populated ? { [id.process]: firstOwner } : {},
          rows: recipe.populated ? activityRows : [] } };
      case 'upload-status':
        return { ...common, upload_shaping: { version: 1, applied_version: 1,
          enabled: recipe.populated && !recipe.cleanup, status: recipe.cleanup ? 'Unsupported' : recipe.populated ? 'Partial' : 'Disabled',
          cleanup_pending: !!recipe.cleanup, coverage_valid_for_ms: 10000, interface: 'fixture0',
          configured_caps: !recipe.populated || recipe.cleanup ? [] : [
            { uid: fixtureUid, application: atlas.key, bits_per_second: 8000000,
              download_bits_per_second: 5000000, traffic_priority: 'high' },
          ], kernel: { bindings: [], covered_bindings: 0 } } };
      case 'connection-analyze': {
        const tracked = { protocol: 'tcp', local: '192.0.2.1:50125', remote: firstFlow.remote };
        return { ...common, connection_analysis: { observation_scope: 'machine', finished_at: fixed,
          baseline_unidentified: 1, baseline_complete: true, truncated: false, samples: [{ complete: true }],
          connections: [{ socket: tracked, from_activity: true, observations: [{
            category: 'shared', reason: 'More than one descriptor holder', observed_at: fixed,
            local: tracked.local, remote: tracked.remote, holders: [
              { pid: firstOwner.pid, executable: atlas.executable },
              { pid: secondOwner.pid, executable: beacon.executable, windows_image_reason: 'Process exited during inspection' },
            ],
          }] }] } };
      }
      case 'observed-usage':
        return { ...common, observed_usage: { version: 1, partial: true, attribution: 'sampled-owner',
          scope: 'machine', capacity_limited: false, saturated: false, epoch: 'inventory-usage',
          sequence: '1', started_at: fixed, sampled_at: fixed,
          entries: recipe.populated ? [{ id: 'inventory-usage-atlas', application: atlas, uid: fixtureUid,
            source: 'tcp-transport-payload', partial: true, first_observed_at: fixed, last_observed_at: fixed,
            uploaded: '2048', downloaded: '1024' }] : [],
          sources: [{ source: 'tcp-transport-payload', state: 'active', reason: 'Fixture interval' },
            { source: 'udp-api-reported', state: 'unavailable', reason: 'Collector inactive' }],
        } };
      case 'decision-timeout-status':
        return { ...common, decision_timeout: timeout };
      case 'decision-timeout-configure':
        if (q.decision_timeout?.expected_revision !== timeout.revision) return failure('Timeout revision changed');
        timeout = { seconds: q.decision_timeout.seconds, revision: String(Number(timeout.revision) + 1) };
        return { ...common, decision_timeout: timeout };
      case 'evaluation-start':
        evaluation = { ...evaluation, id: 'inventory-evaluation', request_id: q.request_id,
          state: 'starting', cleanup: 'pending', reason_code: 'starting', reason: 'Fixture evaluation starting',
          started_at: now(), stops_at: later(300) };
        return { ...common, evaluation };
      case 'evaluation-stop':
        if (q.evaluation_id !== evaluation.id) return failure('Evaluation identity changed');
        evaluation = { ...evaluation, state: 'stopped', cleanup: 'confirmed', reason_code: 'stopped',
          reason: 'Fixture evaluation stopped' };
        return { ...common, evaluation };
      case 'request-rule-preview':
      case 'decision-preview': {
        if (recipe.rejectPreview || !found) return failure('Fixture review unavailable', 'review_unavailable');
        const remembered = q.remember || {};
        const preview = { ...rule('preview-rule', found.attribution.application, false), action: q.action,
          created: now(), filter: { ...found.remembered_filter,
            protocol: remembered.protocol ? found.flow.protocol : '*',
            remote_address: remembered.address ? found.remembered_filter.remote_address : '*',
            remote_port: remembered.port && found.flow.direction === 'outgoing' ? 443 : 0,
            local_port: remembered.port && found.flow.direction === 'incoming' ? 50124 : 0 } };
        if (q.operation === 'request-rule-preview') return { ...common, request_rule_preview: {
          event_id: q.id, action: q.action, token: 'future-rule-' + q.id + '-' + q.action,
          expires_at: later(900), scope_preview: 'Future connections from this application only.',
          summary: 'Review a rule for future connections.', rule: preview, replaces: null,
        } };
        return { ...common, decision_preview: { ...q, event_id: q.id, token: 'decision-preview-' + q.id + '-' + q.action,
          expires_at: later(900), connection_network: zone, scope_preview: found.scope_previews[q.scope],
          summary: q.action + ' this application.', rule: preview } };
      }
      case 'rule-preview': {
        if (!storedRule || storedRule.version !== q.expected_version) return failure('Rule version changed', 'version_conflict');
        const proposed = { ...storedRule, ...q.rule, version: storedRule.version, id: storedRule.id };
        const token = 'edit-' + storedRule.id;
        return { ...common, saved_rule: proposed, scope_preview: 'Review stored rule scope.', preview_token: token };
      }
      case 'rule-save': {
        if (!storedRule || storedRule.version !== q.expected_version || recipe.readOnly)
          return failure('Preview unavailable', 'stale_preview');
        const saved = { ...storedRule, ...q.rule, id: storedRule.id, version: storedRule.version + 1 };
        stored.splice(stored.findIndex(r => r.id === saved.id), 1, saved);
        if (stage === 'lose-save') return null;
        return { ...common, saved_rule: saved, scope_preview: 'Saved stored rule scope.' };
      }
      case 'zone-migration-preview':
        if (!storedRule || storedRule.schema !== 4) return failure('Expected legacy rule');
        migratedPreview = { token: 'zone-migration-preview',
          rule_id: storedRule.id, old_version: storedRule.version, zone_revision: zone.revision,
          old_model: 'configured-prefix-v1', new_model: 'automatic-peer-v1',
          expires_at: new Date(Date.now() + 29000).toISOString(),
          old_prefixes: ['192.0.2.0/25'], new_prefixes: ['192.0.2.0/24'],
          added_prefixes: ['192.0.2.128/25'], removed_prefixes: [], samples: [],
          scope_preview: 'Automatic network scope reviewed.',
          rule: { ...storedRule, schema: 6, version: storedRule.version + 1,
            filter: { ...storedRule.filter, zone_model: 'automatic-peer-v1' } },
        };
        return { ...common, zone_migration: migratedPreview };
      case 'zone-migration-save':
        if (q.preview_token !== migratedPreview?.token || q.id !== migratedPreview.rule_id)
          return failure('Migration review changed');
        stored.splice(stored.findIndex(r => r.id === q.id), 1, migratedPreview.rule);
        return null; // Accepted write, lost acknowledgement. Reconcile with list.
      case 'endpoint-rule-preview': {
        const draft = q.endpoint_draft;
        return { ...common, endpoint_preview: {
          token: 'endpoint-preview', expires_at: new Date(Date.now() + 29000).toISOString(),
          rule: { schema: 7, network_endpoint: true, id: 'endpoint:inventory', version: 1, created: fixed,
            priority: 100, disabled: false, action: draft.action, expires: draft.expires,
            filter: { application: '', revision: '', uid: 0, all_programs: true, all_uids: true,
              direction: 'outgoing', protocol: 'tcp', remote_address: draft.remote_address,
              remote_port: draft.remote_port } },
          scope_preview: 'All matching users and programs · exact outgoing TCP endpoint.',
          evaluation,
      process_leases: recipe.activeLease ? [{ id: 'inventory-process-lease', action: 'allow', direction: 'outgoing',
        application_name: atlas.name, executable: atlas.executable, uid: fixtureUid, pid: firstOwner.pid,
        start: firstOwner.start_ticks, until: later(900), seconds: 900, event_id: id.request }] : [],
      enforcement: { state: 'stopped', covered: false, reason: 'Fixture protection stopped' },
        } };
      }
      case 'decision-log': {
        const f = q.decision_query || {};
        if (recipe.logPages) {
          const newest = stage === 'log-new' ? [newerRecord, ...records] : records;
          const selected = f.before ? [olderRecord] : f.after
            ? newest.filter(r => Number(r.sequence) > Number(f.after)) : newest.slice(0, f.limit || 100);
          return { ...common, decision_log: { records: selected, log_id: 'inventory-log-pages', scope: 'machine',
            order: 'newest_first', has_more: !f.before && !f.after && f.limit !== 1,
            next_before: !f.before && !f.after && f.limit !== 1 ? '20' : '', next_after: selected[0]?.sequence || '',
            health: { state: 'recording', retention_days: 30, retention_records: 20000 }, limitations: [] } };
        }
        const selected = !recipe.populated || f.after ? []
          : records.filter(row => !f.direction || row.flow?.direction === f.direction)
            .filter(row => !f.action || (f.action === 'pending' ? row.kind === 'pending' : row.decision?.action === f.action));
        return { ...common, decision_log: { records: selected, scope: 'machine', order: 'newest_first',
          has_more: false, next_before: '', next_after: selected[0]?.sequence || '',
          health: { state: recipe.unhealthy ? 'degraded' : 'recording', retention_days: 30, retention_records: 20000 },
          limitations: [] } };
      }
      case 'decision-log-get':
      case 'decision-log-outcome': {
        const hit = q.operation === 'decision-log-get' ? records.find(r => r.id === q.decision_id)
          : q.decision_id === id.logPending ? final : undefined;
        return hit ? { ...common, decision_record: hit } : failure('Record not found', 'not_found');
      }
      case 'decide':
        if (!found || recipe.readOnly) return failure('Request unavailable', 'stale_request');
        if (recipe.loseDecision) return null;
        answered.add(found.id);
        return { ...common, decision: { ...found, state: q.action === 'allow' ? 'allowed' : 'blocked' } };
      default:
        return failure('No fixture response for ' + q.operation);
    }
  };
  function listen(filename, observer) {
    const server = net.createServer(socket => {
      let buffer = '';
      socket.setTimeout(5000, () => socket.end());
      socket.on('error', () => {});
      socket.setEncoding('utf8').on('data', chunk => {
        buffer += chunk;
        if (!buffer.includes('\n')) return;
        if (buffer.length > 1024 * 1024) return socket.end();
        try {
          const request = JSON.parse(buffer.split('\n')[0]);
          const reply = response(request, observer);
          calls.push({ operation: request.operation,
            ...(request.operation === 'decide' ? { decision: { id: request.id, generation: request.generation,
              action: request.action, scope: request.scope } } : {}),
            error: reply ? reply.error_code || undefined : 'fixture_lost_reply' });
          const send = () => socket.end(reply ? JSON.stringify(reply) + '\n' : undefined);
          if (request.operation === 'connection-analyze' && request.connection_analysis?.watch_ms) setTimeout(send, 1600);
          else send();
        } catch { socket.end(); }
      });
    });
    return new Promise((resolve, reject) =>
      server.once('error', reject).listen(filename, () => resolve(server)));
  }
  return { listen, calls, setStage: value => { stage = value; } };
}

export async function startSeed(name, control, observer, packageBuild) {
  const recipe = recipes[name];
  if (!recipe) throw Error('Unknown seed recipe ' + name);
  const fixture = inventory(recipe, packageBuild);
  const servers = [];
  try {
    servers.push(await fixture.listen(control, false), await fixture.listen(observer, true));
    return { calls: fixture.calls, setStage: fixture.setStage, close: async () => {
      await Promise.all(servers.map(s => new Promise(resolve => s.close(resolve))));
      await Promise.all([control, observer].map(file => unlink(file).catch(() => {})));
    } };
  } catch (error) {
    for (const server of servers) server.close();
    throw error;
  }
}
