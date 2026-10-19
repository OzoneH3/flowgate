import { rememberDecision, reviewFailureOf, type RememberFields } from './decision-remember';
import type { Decision } from './protocol';
import {
  processInstanceEnded,
  requestRuleAvailable,
  requestRuleChoice,
  requestRuleKey,
  type RequestRuleChoice,
  type RequestRulePreview,
} from './request-rule';
import { forAWhileSupported } from './process-lease';
import type { ViewEvent } from './protocol';

// What an Allow/Deny click does on the request card. Pure; the renderer only
// executes the returned plan. An ended request is never decided: with Remember
// it saves a rule for future connections, otherwise nothing is sent.
export const ENDED_RULE_RESULT = 'Rule saved for future connections; this request has ended.';
export const ENDED_NEEDS_REMEMBER =
  'This request has ended; check Remember to save a rule for future connections';
export const ENDED_FOR_A_WHILE = 'Unavailable: this request has ended.';
export const ENDED_PROCESS =
  'This process has ended; uncheck Process to save a rule for the application.';
export interface PromptChoice {
  generation: string;
  zoneRevision: string;
  capabilities?: string[];
  forAWhile: boolean;
  remember: boolean;
  fields: RememberFields;
  duration: number;
}
export type PromptPlan =
  | { kind: 'decide'; decision: Decision; review: boolean }
  | { kind: 'request-rule'; choice: RequestRuleChoice }
  | { kind: 'unavailable'; note: string };
export function endedRequest(e: ViewEvent | undefined) {
  return !!e && !!reviewFailureOf(e);
}
export function promptPlan(
  e: ViewEvent,
  action: 'allow' | 'block',
  c: PromptChoice,
): PromptPlan {
  if (endedRequest(e)) {
    if (!requestRuleAvailable(e, c.capabilities))
      return { kind: 'unavailable', note: 'This request has ended. No decision was submitted.' };
    if (!c.remember) return { kind: 'unavailable', note: ENDED_NEEDS_REMEMBER };
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
    return { kind: 'decide', decision: { ...base, scope: 'for-a-while' }, review: false };
  }
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
