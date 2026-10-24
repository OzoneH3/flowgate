import { usageCounter } from './observed-usage';
export const HISTORY_CAPABILITY = 'usage-history-v1';
export type HistorySource = 'tcp-transport-payload' | 'udp-api-reported';
export interface HistoryQuery {
  range: '1h' | '24h' | '7d' | '30d';
  source: HistorySource;
  entry_id?: string;
  unattributed?: boolean;
}
export interface HistorySettings {
  enabled: boolean;
  retention_days: 1 | 7 | 30;
  revision: string;
}
export interface HistoryEntry {
  id: string;
  uid: number;
  name: string;
  key: string;
  revision: string;
  kind: string;
  uploaded: string;
  downloaded: string;
}
export interface HistoryPoint {
  at: string;
  uploaded: string;
  downloaded: string;
  observed_buckets: number;
  epoch_count: number;
  flags: number;
  partial: true;
}
export interface HistorySnapshot {
  scope: 'user' | 'machine';
  state: 'disabled' | 'starting' | 'recording' | 'capacity_limited' | 'unavailable';
  settings: HistorySettings;
  source: HistorySource;
  from: string;
  until: string;
  resolution_seconds: number;
  entries: HistoryEntry[];
  points: HistoryPoint[];
  epochs: { epoch: string; daemon_generation: string; started_at: string }[];
  last_commit_at?: string;
  error?: string;
}
const obj = (v: unknown): Record<string, unknown> => {
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw Error('Invalid history object');
  return v as Record<string, unknown>;
};
const text = (v: unknown, max = 256): string => {
  if (typeof v !== 'string' || v.length > max) throw Error('Invalid history text');
  return v;
};
const stamp = (v: unknown): string => {
  const s = text(v, 64);
  if (!/^\d{4}-\d\d-\d\dT/.test(s) || !Number.isFinite(Date.parse(s)))
    throw Error('Invalid history timestamp');
  return s;
};
const list = (v: unknown, max: number): unknown[] => {
  if (!Array.isArray(v) || v.length > max) throw Error('History response exceeds bounds');
  return v;
};
const int = (v: unknown, max: number) => {
  if (!Number.isSafeInteger(v) || Number(v) < 0 || Number(v) > max)
    throw Error('Invalid history integer');
  return Number(v);
};
const hex = (v: unknown, n: number) => {
  const s = text(v, n);
  if (!new RegExp(`^[a-f0-9]{${n}}$`).test(s)) throw Error('Invalid history identity');
  return s;
};
export function parseHistorySettings(raw: unknown): HistorySettings {
  const v = obj(raw);
  if (
    typeof v.enabled !== 'boolean' ||
    ![1, 7, 30].includes(Number(v.retention_days)) ||
    typeof v.retention_days !== 'number'
  )
    throw Error('Invalid history settings');
  return {
    enabled: v.enabled,
    retention_days: v.retention_days as 1 | 7 | 30,
    revision: usageCounter(v.revision),
  };
}
export function parseHistoryQuery(raw: unknown): HistoryQuery {
  const v = obj(raw);
  if (
    typeof v.range !== 'string' ||
    !['1h', '24h', '7d', '30d'].includes(v.range) ||
    typeof v.source !== 'string' ||
    !['tcp-transport-payload', 'udp-api-reported'].includes(v.source) ||
    (v.unattributed !== undefined && typeof v.unattributed !== 'boolean')
  )
    throw Error('Invalid history query');
  return {
    range: v.range as HistoryQuery['range'],
    source: v.source as HistorySource,
    ...(v.entry_id ? { entry_id: hex(v.entry_id, 64) } : {}),
    ...(v.unattributed ? { unattributed: true } : {}),
  };
}
export function parseHistory(raw: unknown): HistorySnapshot {
  const v = obj(raw);
  if (
    v.version !== 1 ||
    v.partial !== true ||
    typeof v.scope !== 'string' ||
    !['user', 'machine'].includes(v.scope) ||
    typeof v.state !== 'string' ||
    !['disabled', 'starting', 'recording', 'capacity_limited', 'unavailable'].includes(v.state) ||
    typeof v.source !== 'string' ||
    !['tcp-transport-payload', 'udp-api-reported'].includes(v.source) ||
    ![300, 1800, 7200].includes(Number(v.resolution_seconds)) ||
    typeof v.resolution_seconds !== 'number'
  )
    throw Error('Invalid history coverage');
  if (v.scope === 'user' && (v.last_commit_at !== undefined || v.error !== undefined))
    throw Error('Machine history diagnostics in user response');
  const from = stamp(v.from),
    until = stamp(v.until);
  if (Date.parse(until) < Date.parse(from)) throw Error('Reversed history range');
  const ids = new Set<string>();
  const entries = list(v.entries, 1024).map((raw) => {
    const e = obj(raw),
      a = obj(e.application);
    const id = hex(e.id, 64);
    if (ids.has(id) || e.source !== v.source || e.partial !== true)
      throw Error('Invalid history entry');
    ids.add(id);
    const key = text(a.key),
      revision = text(a.revision),
      kind = text(a.kind);
    if (!key || !revision || !kind) throw Error('Missing historical identity metadata');
    return {
      id,
      uid: int(e.uid, 4294967295),
      name: text(a.name),
      key,
      revision,
      kind,
      uploaded: usageCounter(e.uploaded),
      downloaded: usageCounter(e.downloaded),
    };
  });
  const epochs = new Set<string>();
  const epochRows = list(v.epochs, 128).map((raw) => {
    const e = obj(raw),
      epoch = hex(e.epoch, 32);
    if (epochs.has(epoch)) throw Error('Duplicate history interval');
    epochs.add(epoch);
    return {
      epoch,
      daemon_generation: text(e.daemon_generation, 128),
      started_at: stamp(e.started_at),
    };
  });
  let last = -Infinity;
  const points = list(v.points, 512).map((raw) => {
    const p = obj(raw),
      at = stamp(p.at),
      time = Date.parse(at);
    if (
      p.partial !== true ||
      time <= last ||
      time > Date.parse(until) ||
      time <
        Math.floor(Date.parse(from) / (Number(v.resolution_seconds) * 1000)) *
          Number(v.resolution_seconds) *
          1000
    )
      throw Error('Invalid history graph ordering');
    last = time;
    const count = int(p.epoch_count, 128),
      buckets = int(p.observed_buckets, Number(v.resolution_seconds) / 300);
    if (count < 1 || count > epochs.size || buckets < 1)
      throw Error('Invalid history coverage counts');
    return {
      at,
      uploaded: usageCounter(p.uploaded),
      downloaded: usageCounter(p.downloaded),
      observed_buckets: buckets,
      epoch_count: count,
      flags: int(p.flags, 7),
      partial: true as const,
    };
  });
  return {
    scope: v.scope as HistorySnapshot['scope'],
    state: v.state as HistorySnapshot['state'],
    settings: parseHistorySettings(v.settings),
    source: v.source as HistorySource,
    from,
    until,
    resolution_seconds: Number(v.resolution_seconds),
    entries,
    points,
    epochs: epochRows,
    ...(v.last_commit_at !== undefined ? { last_commit_at: stamp(v.last_commit_at) } : {}),
    ...(v.error !== undefined ? { error: text(v.error, 2048) } : {}),
  };
}
