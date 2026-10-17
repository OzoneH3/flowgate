// Pure projection of daemon-evaluation-v1. No readiness or policy inference here.
export const EVALUATION_CAPABILITY = 'daemon-evaluation-v1';
export interface DaemonEvaluationStatus {
  review: string;
  unsupported_outgoing: string;
  id: string;
  request_id: string;
  state: 'stopped' | 'starting' | 'active' | 'stopping' | 'failed' | 'degraded';
  profile: 'incoming';
  stops_at: string;
  duration_seconds: 300;
  cleanup: 'not_needed' | 'pending' | 'confirmed' | 'unconfirmed';
  reason_code: string;
  reason: string;
  readiness: {
    state: 'not_checked' | 'checking' | 'ready' | 'blocked';
    checked_at: string;
    checks: {
      id: string;
      status: string;
      code: string;
      detail: string;
      next: string;
    }[];
  };
}
export interface EvaluationTokens {
  generation: string;
  evaluationId: string;
}
const object = (v: unknown): Record<string, any> =>
  v && typeof v === 'object' && !Array.isArray(v) ? v : {};
const text = (v: unknown, limit = 4096) => (typeof v === 'string' ? v.slice(0, limit) : '');
export function parseEvaluation(raw: unknown): DaemonEvaluationStatus | undefined {
  const e = object(raw),
    r = object(e.readiness);
  if (
    !['stopped', 'starting', 'active', 'stopping', 'failed', 'degraded'].includes(e.state) ||
    e.profile !== 'incoming' ||
    e.duration_seconds !== 300 ||
    !['not_needed', 'pending', 'confirmed', 'unconfirmed'].includes(e.cleanup) ||
    !['not_checked', 'checking', 'ready', 'blocked'].includes(r.state) ||
    (r.checks != null && !Array.isArray(r.checks)) ||
    (r.checks?.length || 0) > 128 ||
    typeof e.id !== 'string' ||
    typeof e.request_id !== 'string'
  )
    return undefined;
  return {
    review: typeof e.review === 'string' && e.review.length <= 8192 ? e.review : '',
    unsupported_outgoing: text(e.unsupported_outgoing),
    id: text(e.id, 128),
    request_id: text(e.request_id, 128),
    state: e.state,
    profile: 'incoming',
    stops_at: text(e.stops_at, 64),
    duration_seconds: 300,
    cleanup: e.cleanup,
    reason_code: text(e.reason_code, 128),
    reason: text(e.reason),
    readiness: {
      state: r.state,
      checked_at: text(r.checked_at, 64),
      checks: (r.checks || []).map((v: unknown) => {
        const c = object(v);
        return {
          id: text(c.id, 128),
          status: text(c.status, 64),
          code: text(c.code, 128),
          detail: text(c.detail),
          next: text(c.next),
        };
      }),
    },
  };
}
export function evaluationTokens(raw: unknown): EvaluationTokens {
  const r = object(raw);
  if (
    Object.keys(r).sort().join(',') !== 'evaluationId,generation' ||
    typeof r.generation !== 'string' ||
    !r.generation ||
    r.generation.length > 128 ||
    typeof r.evaluationId !== 'string' ||
    r.evaluationId.length > 128
  )
    throw Error('Invalid evaluation session tokens');
  return { generation: r.generation, evaluationId: r.evaluationId };
}
export function evaluationLabel(e: DaemonEvaluationStatus | undefined, remainingMs: number) {
  if (!e) return 'Firewall · unknown';
  if (e.state === 'active') {
    if (!Number.isFinite(remainingMs) || remainingMs <= 0)
      return 'Incoming firewall · awaiting expiry confirmation';
    const s = Math.ceil(remainingMs / 1000);
    return `Incoming firewall · ${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')} remaining`;
  }
  if (e.state === 'stopped' && ['confirmed', 'not_needed'].includes(e.cleanup)) {
    if (e.readiness.state === 'checking') return 'Firewall · checking readiness';
    if (e.readiness.state === 'blocked') return 'Firewall · blocked (monitoring only)';
    return 'Monitoring only · firewall stopped';
  }
  return `Firewall · ${e.state === 'stopped' ? 'cleanup unconfirmed' : e.state}`;
}
