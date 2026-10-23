import { rememberDecision, reviewFailureOf, type RememberFields } from './decision-remember';
import type { Decision } from './protocol';
import type { PairChoice } from './local-pair';
import {
  processInstanceEnded,
  requestRuleAvailable,
  requestRuleChoice,
  requestRuleKey,
  type RequestRuleChoice,
  type RequestRulePreview,
} from './request-rule';
import { durationLabel, forAWhileSupported, validForAWhileSeconds, type ProcessLease } from './process-lease';
import type { ViewEvent } from './protocol';

// What an Allow/Deny click does on the request card. Pure; the renderer only
// executes the returned plan. An ended request is never decided: with Remember
// it saves a rule for future connections, otherwise nothing is sent.
export const ENDED_RULE_RESULT = 'Rule saved for future connections; this request has ended.';
export const ENDED_NEEDS_REMEMBER = 'Check Remember to save a rule for future connections.';
// Ended request whose process still runs: For a while is offered too.
export const ENDED_NEEDS_CHOICE = 'Check Remember to save a rule, or For a while for the running process.';
export const ENDED_FOR_A_WHILE = 'Unavailable: this request has ended.';
export const ENDED_PROCESS =
  'This process has ended; uncheck Process to save a rule for the application.';
// Short connection outcome shown under Details → Status, alongside the
// backend's field-level reasons.
export const ENDED_MESSAGE = 'This connection has ended.';
// The first view's one status line for an ended request (the countdown's slot): the most
// specific action-level reason, then the outcome, then the generic ended message.
export function endedStatusLine(note?: string | null, result?: string | null): string {
  return note || result || ENDED_MESSAGE;
}
export const ENDED_PROCESS_EXITED = 'The process has exited; For a while has nothing to cover.';
// queue-reconcile-v1: an enabled rule exists for an earlier revision of this
// application (same key, user, direction). Display only; never applied.
export const PREVIOUS_REVISION_NOTICE =
  'A rule exists for an earlier version of this application (updated executable).';
export function previousRevisionTitle(rules: { id: string; action: string; revision: string }[]) {
  return rules
    .map((r) => `${r.id} (${r.action === 'block' ? 'Deny' : r.action === 'allow' ? 'Allow' : r.action}) · revision ${r.revision}`)
    .concat('Not applied to this request: the executable changed since that rule was saved.')
    .join('\n');
}
// request-for-a-while-v1: For a while from an ended request whose exact process
// instance is still running creates only the process lease.
export const REQUEST_FOR_A_WHILE_CAPABILITY = 'request-for-a-while-v1';
export interface EndedLeaseChoice {
  generation: string;
  id: string;
  action: 'allow' | 'block';
  duration_seconds?: number;
}
export function validateEndedLease(v: unknown): EndedLeaseChoice {
  const d = (v && typeof v === 'object' ? v : {}) as Record<string, unknown>;
  if (
    Object.keys(d).some((k) => !['generation', 'id', 'action', 'duration_seconds'].includes(k)) ||
    typeof d.generation !== 'string' || !d.generation || d.generation.length > 256 ||
    typeof d.id !== 'string' || !d.id || d.id.length > 64 ||
    !['allow', 'block'].includes(d.action as string) ||
    (d.duration_seconds !== undefined && !validForAWhileSeconds(d.duration_seconds))
  )
    throw Error('Invalid For a while request');
  return d as unknown as EndedLeaseChoice;
}
export function endedLeaseAvailable(e: ViewEvent | undefined, capabilities?: string[]) {
  return (
    endedRequest(e) &&
    !!capabilities?.includes(REQUEST_FOR_A_WHILE_CAPABILITY) &&
    !!e!.request_rule?.process_lease_available &&
    e!.request_rule.process_state === 'running'
  );
}
// Why For a while is unavailable on an ended card ('' when available).
export function endedLeaseReason(e: ViewEvent | undefined, capabilities?: string[]) {
  if (!endedRequest(e) || endedLeaseAvailable(e, capabilities)) return '';
  if (!capabilities?.includes(REQUEST_FOR_A_WHILE_CAPABILITY)) return ENDED_FOR_A_WHILE;
  if (e!.request_rule?.process_state === 'ended') return ENDED_PROCESS_EXITED;
  return 'For a while is unavailable for this ended request.';
}
// The single main-card line for an ended request (details stay in Details).
export function endedSummary(failure: { code: string; message: string }) {
  return ['connection_ended', 'request_ended'].includes(failure.code)
    ? ENDED_MESSAGE
    : failure.code === 'process_exited'
      ? 'The requesting process exited. No decision was submitted.'
      : failure.code === 'stale_decision'
        ? 'Request no longer pending. No decision was submitted.'
        : 'This request can no longer be verified. No decision was submitted.';
}
export function endedLeaseResult(lease: Pick<ProcessLease, 'action' | 'pid' | 'seconds'>) {
  return `For a while: ${lease.action === 'allow' ? 'Allow' : 'Deny'} for process ${lease.pid} (${durationLabel(lease.seconds)}). This ended request was not delivered.`;
}
export interface PromptChoice {
  generation: string;
  zoneRevision: string;
  capabilities?: string[];
  forAWhile: boolean;
  // Selected For a while duration (decision-for-a-while-durations-v1); 15 when absent.
  forAWhileSeconds?: number;
  remember: boolean;
  fields: RememberFields;
  duration: number;
  // local-pair-v1: the backend-verified pair of this connection (outgoing id
  // first; the incoming id when it exists). Plain Allow/Deny answers exactly it.
  pairIds?: string[];
}
export type PromptPlan =
  | { kind: 'decide'; decision: Decision; review: boolean }
  | { kind: 'pair'; choice: PairChoice }
  | { kind: 'request-rule'; choice: RequestRuleChoice }
  | { kind: 'ended-lease'; choice: EndedLeaseChoice }
  | { kind: 'unavailable'; note: string };
const leaseSeconds = (c: PromptChoice) =>
  c.forAWhileSeconds && c.forAWhileSeconds !== 15 ? { duration_seconds: c.forAWhileSeconds } : {};
export function endedRequest(e: ViewEvent | undefined) {
  return !!e && !!reviewFailureOf(e);
}
export function promptPlan(
  e: ViewEvent,
  action: 'allow' | 'block',
  c: PromptChoice,
): PromptPlan {
  if (endedRequest(e)) {
    // For a while on an ended request: a process lease only, never a decision.
    if (c.forAWhile && !c.remember) {
      if (!endedLeaseAvailable(e, c.capabilities))
        return { kind: 'unavailable', note: endedLeaseReason(e, c.capabilities) || ENDED_FOR_A_WHILE };
      return { kind: 'ended-lease', choice: { generation: c.generation, id: e.id, action, ...leaseSeconds(c) } };
    }
    if (!requestRuleAvailable(e, c.capabilities))
      return { kind: 'unavailable', note: 'This request has ended. No decision was submitted.' };
    if (!c.remember)
      return { kind: 'unavailable', note: endedLeaseAvailable(e, c.capabilities) ? ENDED_NEEDS_CHOICE : ENDED_NEEDS_REMEMBER };
    if (c.fields.process && processInstanceEnded(e)) return { kind: 'unavailable', note: ENDED_PROCESS };
    return {
      kind: 'request-rule',
      choice: requestRuleChoice(
        { generation: c.generation, id: e.id, action },
        c.fields,
        c.duration,
        c.zoneRevision,
      ),
    };
  }
  const base = { generation: c.generation, id: e.id, action };
  // Remember wins if the options are ever made non-exclusive.
  if (c.remember)
    return {
      kind: 'decide',
      decision: rememberDecision(base, { fields: c.fields, duration: c.duration }, c.zoneRevision),
      review: true,
    };
  if (c.forAWhile) {
    if (!forAWhileSupported(c.capabilities))
      return { kind: 'unavailable', note: 'For a while needs a newer FlowGate backend.' };
    return { kind: 'decide', decision: { ...base, scope: 'for-a-while', ...leaseSeconds(c) }, review: false };
  }
  // Once on a verified local pair: one click answers both firewall hooks of this
  // exact connection only (never a rule, never another client or prefix).
  if (c.pairIds?.length)
    return { kind: 'pair', choice: { generation: c.generation, ids: [...c.pairIds], action, scope: 'once' } };
  return { kind: 'decide', decision: { ...base, scope: 'once' }, review: false };
}
// Backend refusal codes surfaced as "<code>: <backend text>".
export function errorCode(message: string) {
  return /^([a-z_]{3,64}): /.exec(message)?.[1] ?? '';
}
export function shortError(message: string) {
  switch (errorCode(message)) {
    case 'process_scope_unavailable':
      return 'For a while needs one verified running process. Uncheck it to decide once.';
    case 'stale_decision':
      return 'This request has ended. No decision was submitted.';
    case 'connection_ended':
    case 'request_ended':
      return ENDED_MESSAGE;
    case 'process_ended':
      return ENDED_PROCESS_EXITED;
    case 'request_decided':
      return 'This request was already decided.';
    case 'identity_unverifiable':
      return 'No rule can be saved from this ended request: the sandboxed program exited and FlowGate can no longer verify its file. Choose Remember while its next request is still open.';
  }
  return message.length > 140 ? message.slice(0, 137) + '…' : message;
}

// request-application-rule-v1 from an ended request, Allow/Deny with Remember.
// Each action is reviewed first; once a save was sent, every retry reuses that
// exact reviewed choice and token, so a lost acknowledgement can never create a
// second rule.
export interface RequestRuleBridge {
  requestRulePreview(c: RequestRuleChoice): Promise<RequestRulePreview>;
  requestRuleSave(c: RequestRuleChoice): Promise<{ message: string; replayed: boolean }>;
}
export type SaveOutcome =
  | { phase: 'saved'; text: string; detail: string }
  | { phase: 'unknown' | 'rejected' | 'refused'; text: string; detail: string };
export class EndedRuleFlow {
  reviews: Partial<Record<'allow' | 'block', RequestRulePreview>> = {};
  reviewKeys: Partial<Record<'allow' | 'block', string>> = {};
  pinned = new Map<string, { action: 'allow' | 'block'; choice: RequestRuleChoice }>();
  saved = new Map<string, string>();
  constructor(private bridge: RequestRuleBridge) {}
  fresh(choice: RequestRuleChoice, now: number) {
    const a = choice.action as 'allow' | 'block',
      p = this.reviews[a];
    return !!p && this.reviewKeys[a] === requestRuleKey(choice) && Date.parse(p.expires_at) > now;
  }
  clearReviews() {
    this.reviews = {};
    this.reviewKeys = {};
  }
  async review(choice: RequestRuleChoice) {
    const a = choice.action as 'allow' | 'block',
      key = requestRuleKey(choice),
      preview = await this.bridge.requestRulePreview(choice);
    this.reviews[a] = preview;
    this.reviewKeys[a] = key;
    return preview;
  }
  async save(choice: RequestRuleChoice, now: number): Promise<SaveOutcome> {
    const id = choice.id;
    if (this.saved.has(id)) return { phase: 'saved', text: ENDED_RULE_RESULT, detail: this.saved.get(id)! };
    const held = this.pinned.get(id);
    if (held && held.action !== choice.action)
      return {
        phase: 'refused',
        text: `The earlier ${held.action === 'allow' ? 'Allow' : 'Deny'} rule is unconfirmed; click it again to check (no duplicate).`,
        detail: '',
      };
    let sent = held?.choice;
    if (!sent) {
      const a = choice.action as 'allow' | 'block',
        p = this.reviews[a];
      if (!p || !this.fresh(choice, now))
        return { phase: 'refused', text: 'Review required; checking the rule…', detail: '' };
      sent = { ...choice, preview_token: p.token };
      this.pinned.set(id, { action: a, choice: sent });
    }
    try {
      const r = await this.bridge.requestRuleSave(sent);
      this.pinned.delete(id);
      this.saved.set(id, r.message);
      return { phase: 'saved', text: ENDED_RULE_RESULT, detail: r.message };
    } catch (error) {
      const detail = String((error as Error)?.message ?? error)
        .replace(/^Error invoking remote method '[^']*': /, '')
        .replace(/^Error: /, '');
      // Only a definitive refusal releases the reviewed choice; an unknown
      // outcome keeps it so the next click asks about the same receipt.
      if (/acknowledgement|waiting for backend/i.test(detail))
        return { phase: 'unknown', text: 'Save unconfirmed · click again to check (no duplicate).', detail };
      this.pinned.delete(id);
      return { phase: 'rejected', text: shortError(detail) + ' · Selections kept.', detail };
    }
  }
}
