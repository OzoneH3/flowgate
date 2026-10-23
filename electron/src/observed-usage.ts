import type { DisplayUnit } from './display-units';

export const USAGE_CAPABILITY = 'observed-usage-v1';
/** Presentation records, deliberately separate from live Activity and policy identities. */
export interface UsageEntry {
  id: string;
  application: string;
  uid?: number;
  name: string;
  executable: string;
  source: 'tcp' | 'udp';
  uploaded: string;
  downloaded: string;
  coverage: string;
}
export interface UsageSnapshot {
  epoch: string;
  sequence: string;
  startedAt: string;
  observedAt?: string;
  scope: 'self' | 'machine';
  entries: UsageEntry[];
  coverage: string;
}

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw Error('Invalid observed-usage record');
  return value as Record<string, unknown>;
}
function text(value: unknown, limit = 256): string {
  if (typeof value !== 'string' || value.length > limit) throw Error('Invalid observed-usage text');
  return value;
}
function date(value: unknown): string {
  const result = text(value, 64);
  if (!/^\d{4}-\d{2}-\d{2}T/.test(result) || !Number.isFinite(Date.parse(result)))
    throw Error('Invalid observed-usage timestamp');
  return result;
}
function source(value: unknown): 'tcp' | 'udp' {
  if (value === 'tcp-transport-payload') return 'tcp';
  if (value === 'udp-api-reported') return 'udp';
  throw Error('Unknown observed-usage source');
}
function list(value: unknown, limit: number): unknown[] {
  if (!Array.isArray(value) || value.length > limit) throw Error('Invalid observed-usage list');
  return value;
}

/** Validate the server's bounded wire record before exposing it to the renderer. */
export function parseUsageSnapshot(raw: unknown): UsageSnapshot {
  const value = object(raw);
  if (value.version !== 1 || value.partial !== true || value.attribution !== 'sampled-owner' ||
      !['user', 'machine'].includes(String(value.scope)) ||
      typeof value.capacity_limited !== 'boolean' || typeof value.saturated !== 'boolean')
    throw Error('Invalid observed-usage coverage metadata');
  if (value.scope === 'user' && (value.unattributed !== undefined || value.gaps !== undefined))
    throw Error('Unexpected machine accounting in a user response');
  const epoch = text(value.epoch);
  if (!epoch) throw Error('Missing observation interval');
  const seen = new Set<string>();
  const entries: UsageEntry[] = list(value.entries, 1024).map((rawEntry) => {
    const entry = object(rawEntry), app = object(entry.application);
    const id = text(entry.id);
    if (!id || seen.has(id) || entry.partial !== true || !Number.isSafeInteger(entry.uid) ||
        Number(entry.uid) < 0 || Number(entry.uid) > 4294967295)
      throw Error('Invalid observed-usage identity');
    seen.add(id);
    const key = text(app.key), revision = text(app.revision), kind = text(app.kind);
    if (!key || !revision || !kind) throw Error('Missing observed-usage identity');
    const first = date(entry.first_observed_at), last = date(entry.last_observed_at);
    if (Date.parse(last) < Date.parse(first)) throw Error('Reversed observation interval');
    return { id, application: key, uid: Number(entry.uid), name: text(app.name),
      executable: '', source: source(entry.source), uploaded: usageCounter(entry.uploaded),
      downloaded: usageCounter(entry.downloaded), coverage: `Sampled ownership · last observed ${new Date(last).toLocaleString()}` };
  });
  const sources = new Set<string>();
  const coverage = list(value.sources, 2).map((rawSource) => {
    const entry = object(rawSource), kind = source(entry.source);
    if (sources.has(kind) || !['active', 'unavailable'].includes(String(entry.state)))
      throw Error('Invalid observed-usage source status');
    sources.add(kind);
    return `${kind === 'tcp' ? 'TCP payload' : 'UDP API bytes'}: ${entry.state}. ${text(entry.reason, 2048)}`;
  });
  if (sources.size !== 2) throw Error('Missing observed-usage source status');
  const unattributed = new Set<string>();
  if (value.unattributed !== undefined) for (const rawEntry of list(value.unattributed, 2)) {
    const entry = object(rawEntry), kind = source(entry.source);
    if (unattributed.has(kind)) throw Error('Duplicate unattributed source');
    unattributed.add(kind);
    entries.push({ id: `unattributed:${kind}`, application: '', name: 'Unattributed / shared intervals',
      executable: '', source: kind, uploaded: usageCounter(entry.uploaded), downloaded: usageCounter(entry.downloaded),
      coverage: 'Administrator view · no exclusive application attribution' });
  }
  if (value.gaps !== undefined) coverage.push(`Coverage breaks (including ended socket baselines): ${usageCounter(value.gaps)}. This is not an error or lost-byte count; unseen traffic and closure tails remain unmeasured.`);
  if (value.capacity_limited) coverage.push('Capacity reached: accumulation is frozen until restart. Previously recorded totals are retained.');
  if (value.saturated) coverage.push('Counter limit reached: affected totals are capped and cannot measure further growth.');
  entries.sort((a, b) => a.name.localeCompare(b.name) || (a.uid ?? -1) - (b.uid ?? -1) ||
    a.source.localeCompare(b.source) || a.id.localeCompare(b.id));
  return { epoch, sequence: usageCounter(value.sequence), startedAt: date(value.started_at),
    observedAt: value.sampled_at === undefined ? undefined : date(value.sampled_at),
    scope: value.scope === 'machine' ? 'machine' : 'self', entries, coverage: coverage.join('\n') };
}

/** Byte counters stay exact across the wire and while formatting/sorting. */
export function usageCounter(value: unknown): string {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(value) ||
      BigInt(value) > 18446744073709551615n)
    throw Error('Invalid observed-usage counter');
  return value;
}

export function formatUsage(value: string, unit: DisplayUnit = 'autoByte'): string {
  let count = BigInt(usageCounter(value));
  const bits = unit === 'autoBit' || unit.toLowerCase().endsWith('bit');
  if (bits) count *= 8n;
  const labels = bits ? ['bit', 'Kbit', 'Mbit', 'Gbit', 'Tbit', 'Pbit', 'Ebit'] : ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB'];
  let power = 0;
  if (unit.startsWith('auto')) {
    while (power < labels.length - 1 && count >= 1000n ** BigInt(power + 1)) power++;
  } else power = Math.max(0, labels.indexOf(unit));
  const divisor = 1000n ** BigInt(power);
  if (power === 0) return `${count} ${labels[power]}`;
  // Round entirely in integers; the exact backend byte string is available in the cell title.
  const hundredths = (count * 100n + divisor / 2n) / divisor;
  if (count > 0n && hundredths === 0n) return `<0.01 ${labels[power]}`;
  const fraction = String(hundredths % 100n).padStart(2, '0').replace(/0+$/, '');
  return `${hundredths / 100n}${fraction ? '.' + fraction : ''} ${labels[power]}`;
}
