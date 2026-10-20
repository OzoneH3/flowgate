import type { PairResult } from './local-pair';
import type { Attempt, RequestEvent } from './protocol';

// Outcomes of permission submissions. The permission window hides on a valid
// Allow/Deny click and the submission continues asynchronously, so its result
// (including refusals, uncertain acknowledgements and conflicts with existing
// rules) is kept here for review in Pending requests. Never a false success.

export type ResultSeverity = 'ok' | 'warning' | 'error' | 'unknown';
export interface PermissionResult {
  id: string;
  at: number;
  generation: string;
  eventId: string;
  application: string;
  destination: string;
  severity: ResultSeverity;
  text: string;
  detail: string;
}
export const MAX_RESULTS = 50;

export function eventLabel(e?: Pick<RequestEvent, 'attribution' | 'flow'>) {
  const a = e?.attribution.application;
  return {
    application:
      a?.display_name || (a?.name || '').replace(/ \(deleted\)$/, '') || (a?.executable || '').split('/').pop() || 'Unknown application',
    destination: e ? `${e.flow.direction === 'incoming' ? 'from' : 'to'} ${e.flow.remote} · ${e.flow.protocol.toUpperCase()}` : '',
  };
}

const clean = (error: unknown) =>
  String((error as Error)?.message ?? error)
    .replace(/^Error invoking remote method '[^']*': /, '')
    .replace(/^Error: /, '');

/** A thrown submission: unknown when the acknowledgement was lost, else refused. */
export function failureResult(error: unknown): Pick<PermissionResult, 'severity' | 'text' | 'detail'> {
  const detail = clean(error);
  return /acknowledgement|outcome unknown|unconfirmed/i.test(detail)
    ? { severity: 'unknown', text: 'Result unknown · no retry sent', detail }
    : { severity: 'error', text: 'Not decided: ' + (detail.length > 120 ? detail.slice(0, 117) + '…' : detail), detail };
}

/** Single-request decision (Once, For a while, Remember). */
export function attemptResult(a: Attempt, action: 'allow' | 'block'): Pick<PermissionResult, 'severity' | 'text' | 'detail'> {
  const verb = action === 'allow' ? 'Allowed' : 'Denied';
  if (a.phase === 'unknown') return { severity: 'unknown', text: 'Result unknown · no retry sent', detail: a.message };
  if (a.phase === 'rejected') return { severity: 'error', text: 'Not decided: ' + a.message.replace(/^Backend rejected: /, ''), detail: a.message };
  if (a.phase === 'submitting') return { severity: 'unknown', text: 'Submitting…', detail: a.message };
  return {
    severity: 'ok',
    text: a.scope === 'for-a-while' ? `${verb} for a while` : a.rule ? `${verb} · rule saved` : `${verb} once`,
    detail: a.message,
  };
}

/** Pair decision: both verdicts; an existing rule deciding the other hook differently is a warning. */
export function pairOutcome(r: PairResult, action: 'allow' | 'block', text: string): Pick<PermissionResult, 'severity' | 'text' | 'detail'> {
  const a = r.incoming_admission;
  const conflict = !!a && a.outcome === 'rule' && a.configured_action !== action;
  return { severity: conflict ? 'warning' : 'ok', text, detail: [r.sentence, a?.sentence].filter(Boolean).join('\n') };
}

export function pushResult(list: PermissionResult[], entry: PermissionResult) {
  list.unshift(entry);
  if (list.length > MAX_RESULTS) list.length = MAX_RESULTS;
}

/** Results that still need the user's attention (not ok). */
export function needsReview(list: PermissionResult[] = []) {
  return list.filter((r) => r.severity !== 'ok').length;
}
