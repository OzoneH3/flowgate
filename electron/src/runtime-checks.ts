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

const LABEL_MAX = 60;
// First clause of a detail: a dot inside a version ("7.3.0-3") is not a boundary.
function shortReason(c: RuntimeCheck) {
  const cut = c.detail.search(/[;:.](\s|$)/);
  const s = (cut >= 0 ? c.detail.slice(0, cut) : c.detail).trim() || c.id;
  return s.length > LABEL_MAX ? s.slice(0, LABEL_MAX - 1).trimEnd() + '…' : s;
}

/** Degraded (not ready) checks as a short status suffix plus full detail lines. */
export function runtimeDegradation(checks: RuntimeCheck[] | undefined): { text: string; lines: string[] } | undefined {
  const degraded = (checks || []).filter((c) => c.status !== 'ready');
  if (!degraded.length) return undefined;
  const first = shortReason(degraded[0]);
  return {
    text: `Degraded: ${first}${degraded.length > 1 ? ` (+${degraded.length - 1} more)` : ''}`,
    lines: degraded.map((c) => `${c.id}: ${c.status} · ${c.detail}${c.next ? ' · Next: ' + c.next : ''}`),
  };
}

/** Toolbar badge, separate from protection state: shown only for a connected controller's degraded checks. */
export function runtimeBadge(connected: boolean, checks: RuntimeCheck[] | undefined): { text: string; title: string } | undefined {
  const d = connected ? runtimeDegradation(checks) : undefined;
  return d && { text: d.text, title: ['Runtime health (advisory; protection state is shown separately)', ...d.lines].join('\n') };
}
