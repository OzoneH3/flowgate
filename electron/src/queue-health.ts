// Queue diagnostics never grant permission or alter protection state.
export interface QueueHealth {
  state: 'inactive' | 'ready' | 'pressure' | 'unavailable';
  malformed?: true;
  sampled_at?: string;
  sessions?: { generation: string; direction: string; queue: number; started_at: string; stopped_at?: string; last_issue_at?: string; counters: Record<string, string>; saturated: boolean; gauges: Record<string, number | string> }[];
  counter_units?: Record<string, string>;
}
const object = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const stamp = (v: unknown): v is string => typeof v === 'string' && v.length <= 64 && Number.isFinite(Date.parse(v));
const decimal = (v: unknown): v is string => typeof v === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(v) && BigInt(v) <= 18446744073709551615n;
const unavailable: QueueHealth = { state: 'unavailable', malformed: true };
// These cumulative first-proof totals are uint64 decimal strings on the wire.
const decimalGauges = new Set([
  'first_proof_admissions', 'first_proof_denied_tails_reclaimed',
  'first_proof_history_evictions', 'first_proof_history_full_observations',
]);
const counterLabels: Record<string, string> = {
  attribution_capacity_rejections: 'Owner lookup queue full',
  census_capacity_rejections: 'Ownership census queue full',
  fairness_displacement_rejections: 'Older work displaced to make room',
  deadline_rejections: 'Packet decision deadline elapsed',
  shutdown_rejections: 'Packets rejected during shutdown',
  retention_capacity_rejections: 'Held-packet queue full',
  retained_deadline_rejections: 'Held-packet deadline elapsed',
  retained_shutdown_rejections: 'Held packets rejected during shutdown',
  parse_rejections: 'Packets that could not be parsed',
  missing_payload_rejections: 'Queue messages missing packet data',
  netlink_overflow_notifications: 'Kernel queue overflow notifications',
  receive_failures: 'Queue receive failures',
  verdict_failures: 'Failures submitting a packet verdict',
  self_tracking_failures: 'Local connection tracking failures',
  verdict_write_retries: 'Retries submitting a packet verdict',
  verdict_target_gone: 'Packet gone before verdict submission',
};
export function parseQueueHealth(raw: unknown): QueueHealth | undefined {
  if (raw === undefined) return undefined;
  if (!object(raw) || typeof raw.state !== 'string' || !['inactive', 'ready', 'pressure', 'unavailable'].includes(raw.state) || !stamp(raw.sampled_at)) return unavailable;
  const out: QueueHealth = { state: raw.state as QueueHealth['state'], sampled_at: raw.sampled_at };
  if (raw.sessions === undefined) return out; // ordinary peers: no machine counters
  if (!Array.isArray(raw.sessions) || raw.sessions.length > 8 || !object(raw.counter_units) || Object.keys(raw.counter_units).length > 32) return unavailable;
  const units: Record<string, string> = {};
  for (const [key, value] of Object.entries(raw.counter_units)) {
    if (!/^[a-z][a-z0-9_]{0,63}$/.test(key) || typeof value !== 'string' || !['packets', 'notifications', 'operations'].includes(value)) return unavailable;
    units[key] = value as string;
  }
  out.counter_units = units;
  out.sessions = [];
  for (const s of raw.sessions) {
    if (!object(s) || typeof s.generation !== 'string' || !/^[a-f0-9]{32}$/.test(s.generation) || typeof s.direction !== 'string' || !['incoming', 'outgoing', 'both'].includes(s.direction) || !Number.isInteger(s.queue) || Number(s.queue) < 0 || Number(s.queue) > 65535 || !stamp(s.started_at) || (s.stopped_at !== undefined && !stamp(s.stopped_at)) || (s.last_issue_at !== undefined && !stamp(s.last_issue_at)) || !object(s.counters) || Object.keys(s.counters).length > 32 || typeof s.saturated !== 'boolean' || !object(s.gauges) || Object.keys(s.gauges).length > 16) return unavailable;
    const counters: Record<string,string> = {}, gauges: Record<string,number | string> = {};
    for (const [key, value] of Object.entries(s.counters)) { if (!Object.hasOwn(units, key) || !decimal(value)) return unavailable; counters[key] = value; }
    for (const [key, value] of Object.entries(s.gauges)) {
      if (!/^[a-z][a-z0-9_]{0,63}$/.test(key)) return unavailable;
      if (decimalGauges.has(key)) {
        if (!decimal(value)) return unavailable;
        gauges[key] = value;
      } else {
        if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0 || value > 1073741824) return unavailable;
        gauges[key] = value;
      }
    }
    out.sessions.push({ generation: s.generation, direction: String(s.direction), queue: Number(s.queue), started_at: s.started_at, stopped_at: s.stopped_at as string | undefined, last_issue_at: s.last_issue_at as string | undefined, counters, gauges, saturated: s.saturated });
  }
  return out;
}
export function queueHealthWarning(connected: boolean, health?: QueueHealth): { text: string; title: string } | undefined {
  if (!connected || !health || health.state === 'ready' || health.state === 'inactive') return undefined;
  const lines = [health.state === 'pressure' ? 'Recent queue rejections or I/O failures (last 30 seconds).'
    : health.malformed ? 'The GUI could not read the queue diagnostics returned by the daemon.'
    : 'The daemon reports that queue diagnostics are unavailable.', 'Protection state is shown separately. Rejection counters count packet attempts, not confirmed kernel drops. Netlink overflow notifications do not give a lost-packet count. Accounting coverage gaps are separate.'];
  if (health.sampled_at) lines.push('Sample taken: ' + new Date(health.sampled_at).toLocaleString());
  if (!health.sessions?.length) lines.push('This response did not include per-queue counters.');
  for (const s of health.sessions || []) {
    lines.push('');
    lines.push(`Queue ${s.queue} · ${s.direction} · generation ${s.generation} · started ${s.started_at}${s.stopped_at ? ' · stopped ' + s.stopped_at : ''}${s.saturated ? ' · counters saturated' : ''}`);
    if (s.last_issue_at) lines.push('Last issue: ' + new Date(s.last_issue_at).toLocaleString());
    const nonzero = Object.entries(s.counters).filter(([, value]) => value !== '0');
    if (nonzero.length) {
      lines.push('Recorded totals since this queue started:');
      for (const [key, value] of nonzero) {
        const label = Object.hasOwn(counterLabels, key) ? counterLabels[key] : key.replaceAll('_', ' ');
        lines.push(`${label}: ${value} ${health.counter_units?.[key] || ''}`);
      }
    }
    if (Object.keys(s.gauges).length)
      lines.push('Queue measurements: ' + Object.entries(s.gauges).map(([key, value]) => `${key.replaceAll('_', ' ')}: ${value}`).join(' · '));
  }
  return { text: health.state === 'pressure' ? 'Queue pressure / errors' : 'Queue health unavailable', title: lines.join('\n') };
}
