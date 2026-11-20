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
  for (const s of health.sessions || []) {
    lines.push(`Queue ${s.queue} · ${s.direction} · generation ${s.generation} · started ${s.started_at}${s.stopped_at ? ' · stopped ' + s.stopped_at : ''}${s.saturated ? ' · counters saturated' : ''}`);
    for (const [key, value] of Object.entries(s.counters)) if (value !== '0') lines.push(`${key}: ${value} ${health.counter_units?.[key] || ''}`);
    lines.push('Current userspace gauges: ' + Object.entries(s.gauges).map(([key,value]) => `${key}=${value}`).join(', '));
  }
  return { text: health.state === 'pressure' ? 'Queue pressure / errors' : 'Queue health unavailable', title: lines.join('\n') };
}
