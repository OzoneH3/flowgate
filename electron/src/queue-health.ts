// Queue diagnostics never grant permission or alter protection state.
export interface QueueHealth {
  state: 'inactive' | 'ready' | 'pressure' | 'unavailable';
  malformed?: true;
  sampled_at?: string;
  sessions?: {
    generation: string; direction: string; queue: number; started_at: string; stopped_at?: string;
    last_issue_at?: string; counters: Record<string, string>; recent_counters?: Record<string, string>;
    last_admission_mask?: number; saturated: boolean; gauges: Record<string, number | string>;
  }[];
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
  attribution_capacity_rejections: 'Owner lookup capacity reached before a rule decision',
  census_capacity_rejections: 'Ownership census queue full',
  fairness_displacement_rejections: 'Older work displaced to make room',
  deadline_rejections: 'Packet decision deadline elapsed',
  shutdown_rejections: 'Packets rejected during shutdown',
  retention_capacity_rejections: 'Could not hold packets pending a decision',
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
    let recent: Record<string, string> | undefined;
    if (s.recent_counters !== undefined) {
      if (!object(s.recent_counters) || Object.keys(s.recent_counters).length > 32) return unavailable;
      recent = {};
      for (const [key, value] of Object.entries(s.recent_counters)) {
        if (!Object.hasOwn(counters, key) || !decimal(value) || BigInt(value) > BigInt(counters[key])) return unavailable;
        recent[key] = value;
      }
    }
    const mask = s.last_admission_mask;
    if (mask !== undefined && (typeof mask !== 'number' || !Number.isInteger(mask) || mask < 0 || mask > 31)) return unavailable;
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
    out.sessions.push({ generation: s.generation, direction: String(s.direction), queue: Number(s.queue), started_at: s.started_at, stopped_at: s.stopped_at as string | undefined, last_issue_at: s.last_issue_at as string | undefined, counters, recent_counters: recent, last_admission_mask: mask, gauges, saturated: s.saturated });
  }
  return out;
}
function localTime(stamp: string): string {
  return new Date(stamp).toLocaleString();
}

function backlog(gauges: Record<string, number | string>): string | undefined {
  const lookup = gauges.attribution_packets;
  const held = gauges.retained_packets;
  if (typeof lookup !== 'number' || typeof held !== 'number') return undefined;
  if (lookup === 0 && held === 0) return 'No packets in owner lookup or held for a decision.';
  return `${lookup} in owner lookup, ${held} held for a decision.`;
}

export function queueHealthNow(connected: boolean, health?: QueueHealth): string {
  if (!connected) return 'Controller disconnected. Live queue status unavailable.';
  if (!health || health.state === 'unavailable') return 'Live queue status unavailable.';
  if (health.state === 'inactive') return 'No active queue.';
  const state = health.state === 'ready' ? 'No queue rejections or I/O issues in the last 30 seconds.'
    : 'The queue recorded an issue in the last 30 seconds.';
  const active = (health.sessions ?? []).filter((s) => !s.stopped_at);
  const work = active.map((s) => backlog(s.gauges));
  const details = work.length === 1 && work[0] ? ' ' + work[0] : '';
  return state + details;
}

export function queueHealthWarning(connected: boolean, health?: QueueHealth): { text: string; title: string } | undefined {
  if (!connected || !health || health.state === 'ready' || health.state === 'inactive') return undefined;
  const lines = [health.state === 'pressure' ? 'Queue snapshot'
    : health.malformed ? 'The GUI could not read the queue diagnostics returned by the daemon.'
    : 'The daemon reports that queue diagnostics are unavailable.'];
  if (health.sampled_at) lines.push('Sample taken: ' + localTime(health.sampled_at));
  if (!health.sessions?.length) lines.push('This response did not include per-queue counters.');
  const counterLines = (counters: Record<string, string>) => Object.entries(counters).filter(([, value]) => value !== '0').map(([key, value]) => {
    const label = Object.hasOwn(counterLabels, key) ? counterLabels[key] : key.replaceAll('_', ' ');
    const unit = health.counter_units?.[key] ?? '';
    return `${label}: ${BigInt(value).toLocaleString()} ${value === '1' ? unit.slice(0, -1) : unit}`.trimEnd();
  });
  const sessions = health.sessions ?? [];
  for (const s of [...sessions].reverse().sort((a, b) => Number(!!a.stopped_at) - Number(!!b.stopped_at))) {
    lines.push('');
    lines.push(`Queue ${s.queue} · ${s.direction}${s.stopped_at ? ' · ended ' + localTime(s.stopped_at) : ''}`);
    if (s.last_issue_at) lines.push('Last issue: ' + localTime(s.last_issue_at));
    const work = backlog(s.gauges);
    if (work && !s.stopped_at) lines.push('At sample: ' + work);
    if (s.recent_counters) {
      const recent = counterLines(s.recent_counters);
      lines.push('', 'About the last 30 seconds', ...(recent.length ? recent : ['No recent issues in this queue.']));
      const mask = s.last_admission_mask;
      if (mask !== undefined) {
        const limits = ['per-endpoint limit', 'shared queue limit', 'census queue limit', 'queue stopping', 'reserved capacity for other flows'];
        const hit = limits.filter((_, i) => (mask & (1 << i)) !== 0);
        lines.push('Latest owner lookup rejection: ' + (hit.join(', ') || 'specific limit unavailable'));
      }
    } else {
      lines.push('This daemon supplies session totals only. The recent count by cause is unavailable.');
    }
    const totals = counterLines(s.counters);
    if (totals.length) lines.push('', 'Recorded totals since this queue started (' + localTime(s.started_at) + ')', ...totals);
    if (s.saturated) lines.push('At least one session total has reached its reporting limit.');
  }
  lines.push('', 'Rejections count packet attempts, not confirmed kernel drops. Netlink overflow notifications do not give a lost-packet count. Accounting coverage gaps are separate.');
  return { text: health.state === 'pressure' ? 'Queue pressure / errors' : 'Queue health unavailable', title: lines.join('\n') };
}
