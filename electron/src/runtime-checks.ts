// Read-only runtime capability snapshot (daemon `runtime_checks`, readiness.Check).
// Advisory display only: it never changes actions; malformed data is rejected.

export interface RuntimeCheck {
  id: string;
  // Unknown future statuses are kept as 'unrecognized' and shown as degraded.
  status: 'ready' | 'blocked' | 'optional_unavailable' | 'not_checked' | 'unrecognized';
  code: string;
  detail: string;
  next?: string;
}

const STATUSES = ['ready', 'blocked', 'optional_unavailable', 'not_checked'];
const MAX = 64;
const text = (v: unknown, max = 1024) => (typeof v === 'string' ? v.slice(0, max) : '');
const unavailable: RuntimeCheck = {
  id: 'runtime.health',
  status: 'unrecognized',
  code: 'runtime_checks_unrecognized',
  detail: 'Runtime health unavailable (unrecognized data)',
};

// Never throws: the field is advisory, so malformed data degrades to a visible
// "unavailable" entry instead of rejecting the whole response (no reconnect loop).
export function parseRuntimeChecks(raw: unknown): RuntimeCheck[] | undefined {
  if (raw === undefined || raw === null) return undefined;
  if (!Array.isArray(raw)) return [unavailable];
  const out: RuntimeCheck[] = [];
  let malformed = raw.length > MAX;
  for (const v of raw.slice(0, MAX)) {
    const c = v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined;
    if (!c || typeof c.id !== 'string' || !c.id || typeof c.status !== 'string' || typeof c.detail !== 'string') {
      malformed = true;
      continue;
    }
    out.push({
      id: text(c.id, 128),
      status: STATUSES.includes(c.status) ? (c.status as RuntimeCheck['status']) : 'unrecognized',
      code: text(c.code, 128),
      detail: text(c.detail),
      next: typeof c.next === 'string' ? text(c.next) : undefined,
    });
  }
  if (malformed) out.push(unavailable);
  return out;
}

/** Degraded (not ready) checks as a short status suffix plus full detail lines. */
export function runtimeDegradation(checks: RuntimeCheck[] | undefined): { text: string; lines: string[] } | undefined {
  const degraded = (checks || []).filter((c) => c.status !== 'ready');
  if (!degraded.length) return undefined;
  const first = degraded[0].detail.split(/[.:]/)[0].trim() || degraded[0].id;
  return {
    text: `Degraded: ${first}${degraded.length > 1 ? ` (+${degraded.length - 1} more)` : ''}`,
    lines: degraded.map((c) => `${c.id}: ${c.status} · ${c.detail}${c.next ? ' · Next: ' + c.next : ''}`),
  };
}
