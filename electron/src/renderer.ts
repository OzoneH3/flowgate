import { updateConnectionStatus } from './status-slot';
import { fastPathIndicator, appFastPathDetails } from './fast-path';
import { accountLabel } from './accounts';
import {uploadButton, priorityButton, refreshUpload, openUploadLimits} from "./upload-shaping-view";
import { setupObservedUsage, showObservedUsage, updateObservedUsage } from './observed-usage-view';
import { matchesApplicationZone } from './application-zones';
import { ApplicationCallers } from './application-callers';
import { replaceKeyedRow } from './keyed-rows';
import { rowStructure } from './row-structure';
import { acceptsPublication } from './publication';
import { PROTECTION_CAPABILITY, stateProtection } from './protection-model';
import { advanceClock } from './state-clock';
import {
  REMEMBER_ZONE_CAPABILITY,
  DEFAULT_REMEMBER,
  rememberDecision,
  rememberFieldsSupported,
  reviewFailureOf,
  rememberKey,
  rememberOptions,
  rememberReviewText,
  rememberScope,
  type DecisionPreview,
  type RememberFields,
} from './decision-remember';
import { askSource, awaiting, groupKey, requestGroups } from './automatic-prompts';
import { permissionTarget, scopeZoneText } from './connection-presentation';
import {
  IDENTITY_UNVERIFIABLE_TEXT,
  identityUnverifiable,
  processInstanceEnded,
  requestRuleAvailable,
  requestRuleChoice,
  requestRuleKey,
} from './request-rule';
import {
  activeLeases,
  forAWhileSupported,
  leaseDetails,
  leaseHolds,
  leaseLine,
  leasesForRequest,
  toggleDecisionOption,
  FOR_A_WHILE_TOOLTIP,
  defaultForAWhile,
  DEFAULT_FOR_A_WHILE_SECONDS,
  expiryPreview,
  forAWhileDurations,
  forAWhileNote,
  type ProcessLease,
} from './process-lease';
import {
  EndedRuleFlow,
  ENDED_NEEDS_REMEMBER,
  ENDED_PROCESS,
  ENDED_RULE_RESULT,
  ENDED_NEEDS_CHOICE,
  endedStatusLine,
  endedLeaseAvailable,
  liveLeaseReason,
  endedLeaseReason,
  endedLeaseResult,
  endedRequest,
  endedSummary,
  promptPlan,
  shortError,
} from './prompt-decision';
import { buildRequestCard } from './prompt-card';
import { localPairView, pairSignature } from './local-pair';
import { splitPreview } from './prompt-summary';
import { ZONE_CAPABILITY, zoneLabel } from './network-zones';
import type { Presentation, PaneFrame } from './pane-model';
import { DISPLAY_UNITS, displayAmount, isDisplayUnit, type DisplayUnit } from './display-units';
import { initiationPresentation } from './initiation';
import { ActivityPolicy, STATUS_SLOTS, blockerGlyph } from './activity-policy';
import { ruleChip, ownRuleChip, type RuleChip } from './rule-chip';
import {
  POLICY_CAPABILITY,
  authoritativePolicy,
  authoritativeZonePolicy,
  authoritativeProcessPolicy,
} from './policy';
import { ruleStatus, ruleState, ruleDescription, ownConfigured, zoneConfigured } from './rule-status';
import { canDecide, canManageRules } from './protocol';
import type { Application } from './protocol';
import { verifiedLaunch } from './provenance';
import { openInactiveRules } from './inactive-rules';
import { TrafficGraph } from './graph';
import { setupWorkflows, updateWorkflows, openRule, resumeRuleEditor } from './workflows';
import { setupDecisionLog, showDecisionLog, updateDecisionLog } from './decision-log-view';
import { runtimeBadge, runtimeDegradation } from './runtime-checks';
import { queueHealthWarning } from './queue-health';
import { headerVersion, type GuiBuild } from './build-info';
import type { Attempt, ClientState, ViewEvent, Scope } from './protocol';
import { recordDecisionResult, showsLocalResult, type CardResult } from './card-result';
import { attributionReasonLabel } from './attribution-reason';
import {
  hasObservedConnection,
  isKernelTimeWait,
  KERNEL_LIFECYCLE_EXPLANATION,
  activityRowCounts,
  overview,
  networkOverviews,
  NETWORK_UNAVAILABLE,
  flatten,
  allRows,
  activityTree,
  sum,
  endpoint,
  trafficDetails,
  ownershipExplanation,
  inactiveRuleMatches,
  type Row,
  type Metric,
} from './model';
const root = document.querySelector<HTMLDivElement>('#app')!;
const promptGeneration = new URL(location.href).searchParams.get('generation');
const promptID = new URL(location.href).searchParams.get('request');
const applicationCallers = new ApplicationCallers();
let state: ClientState;
let selected = 'overview';
let presentation: Presentation | undefined;
let selectionPending = '';
function syncSelection() {
  if (
    !state ||
    selectionPending === selected ||
    (presentation?.selection === selected &&
      presentation.generation === state.observation.generation)
  )
    return;
  selectionPending = selected;
  const pending = selected;
  void window.flowgate
    .paneUpdate({ selection: selected, generation: state.observation.generation })
    .catch(() => {})
    .finally(() => {
      if (selectionPending === pending) selectionPending = '';
    });
}
// Declared before the init code below: esbuild hoists top-level lets, so order matters.
let displayUnit: DisplayUnit = 'autoByte';
let rateMode: 'rate' | 'total' = 'rate';
// Retain only the selected context, not a second inventory. Never rebind by PID/name.
let retainedSelection: { generation: string; row: Row } | undefined;
let measurementSource: 'tcp' | 'udp' = 'tcp';
let graph: TrafficGraph | undefined;
let activityPolicy: ActivityPolicy | undefined;
let selectedRequest = promptID ?? '';
let chosenScope: Scope = 'once';
let decisionZone: 'any' | 'local' | 'internet' = 'any';
let decisionReviews: Partial<Record<'allow' | 'block', DecisionPreview>> = {};
let reviewSequence = 0,
  reviewChecking = false,
  reviewMessage = '',
  reviewFor = '';
// decision-remember-fields-v1 (NetLimiter 5.3.28): Remember unchecked = Once.
let rememberOn = false,
  rememberFields: RememberFields = { ...DEFAULT_REMEMBER },
  rememberDuration = 0,
  reviewTimer: ReturnType<typeof setTimeout> | undefined;
// decision-for-a-while-v1: For a while checkbox (exclusive with Remember, see process-lease).
let forAWhileOn = false;
// decision-for-a-while-durations-v1 (FlowGate extension): the selected lease
// duration; defaults to the user's last choice when the backend allows it.
let forAWhileSeconds = DEFAULT_FOR_A_WHILE_SECONDS,
  savedForAWhile: number | undefined;
void window.flowgate
  .preferences()
  .then((p) => {
    savedForAWhile = p.forAWhileSeconds;
    if (state && !forAWhileOn) forAWhileSeconds = defaultForAWhile(savedForAWhile, forAWhileDurations(state.control));
  })
  .catch(() => {});
// request-for-a-while-v1: ended requests whose lease was created / is in flight.
const endedLeaseBusy = new Set<string>(),
  endedLeaseDone = new Set<string>();function rememberMode() {
  return rememberFieldsSupported(state?.control.capabilities);
}
function forAWhileMode() {
  return forAWhileSupported(state?.control.capabilities);
}
function setOption(option: 'forAWhile' | 'remember', checked: boolean) {
  const next = toggleDecisionOption({ forAWhile: forAWhileOn, remember: rememberOn }, option, checked);
  forAWhileOn = next.forAWhile && forAWhileMode();
  rememberOn = next.remember;
  const r = $<HTMLInputElement>('rememberToggle'),
    f = $<HTMLInputElement>('forAWhileToggle');
  if (r) r.checked = rememberOn;
  if (f) f.checked = forAWhileOn;
  cardNote = undefined;
  syncRememberScope();
  invalidateReview(0);
}
// Short inline text for one request card; technical detail lives in Details.
let cardNote: { id: string; text: string; detail?: string } | undefined;
const cardResults = new Map<string, CardResult>();
function note(e: ViewEvent, text: string, detail = '') {
  cardNote = { id: e.id, text, detail };
  updateDecisions();
}
// request-application-rule-v1: Allow/Deny with Remember on an ended request saves a
// rule for future connections (never decides it). Same token on every retry.
const endedFlow = new EndedRuleFlow({
  requestRulePreview: (c) => window.flowgate.requestRulePreview(c),
  requestRuleSave: (c) => window.flowgate.requestRuleSave(c),
});
let ruleChecking = false,
  ruleReviewedAt = -Infinity,
  ruleMessage = '',
  ruleMessageFor = '',
  ruleSequence = 0,
  ruleTimer: ReturnType<typeof setTimeout> | undefined;
// Ended requests whose sandboxed process left no reusable identity
// (identity_unverifiable): permanent, so never re-reviewed; full text in Details.
const ruleUnverifiable = new Map<string, string>();
function ruleChoice(e: ViewEvent, action: 'allow' | 'block') {
  return requestRuleChoice(
    { generation: state.control.generation, id: e.id, action },
    rememberFields,
    rememberDuration,
    state.control.networkZones?.revision || '',
  );
}
function ruleKey(e: ViewEvent | undefined) {
  if (!e) return '';
  try {
    return requestRuleKey(ruleChoice(e, 'allow'));
  } catch {
    return '';
  }
}
function endedRuleMode(e: ViewEvent | undefined) {
  return requestRuleAvailable(e, state.control.capabilities);
}
function scheduleRequestRule(delay = 250) {
  ++ruleSequence;
  endedFlow.clearReviews();
  ruleMessage = '';
  ruleMessageFor = '';
  clearTimeout(ruleTimer);
  ruleTimer = setTimeout(() => void prepareRequestRule(), delay);
}
async function prepareRequestRule() {
  clearTimeout(ruleTimer);
  const e = currentEvent();
  if (!e || !endedRuleMode(e) || !rememberOn || endedFlow.saved.has(e.id) || endedFlow.pinned.has(e.id) || ruleUnverifiable.has(e.id)) return;
  if (rememberFields.process && processInstanceEnded(e)) return;
  const seq = ++ruleSequence,
    key = ruleKey(e);
  ruleChecking = true;
  ruleMessageFor = key;
  updateDecisions();
  try {
    for (const action of ['allow', 'block'] as const) {
      if (seq !== ruleSequence || key !== ruleKey(currentEvent())) break;
      await endedFlow.review(ruleChoice(e, action));
    }
    if (seq === ruleSequence) ruleMessage = '';
  } catch (error) {
    // Exact backend reason in Details; the selections (draft) stay unchanged.
    if (seq === ruleSequence) ruleMessage = errorText(error);
    if (identityUnverifiable(errorText(error))) {
      if (ruleUnverifiable.size >= 64) ruleUnverifiable.delete(ruleUnverifiable.keys().next().value!);
      ruleUnverifiable.set(e.id, errorText(error));
    }
  } finally {
    if (seq === ruleSequence) ruleChecking = false;
    updateDecisions();
  }
}
function resetRemember() {
  rememberOn = false;
  forAWhileOn = false;
  forAWhileSeconds = defaultForAWhile(savedForAWhile, state ? forAWhileDurations(state.control) : [15]);
  rememberFields = { ...DEFAULT_REMEMBER };
  rememberDuration = 0;
}
function syncRememberScope() {
  if (rememberMode()) chosenScope = rememberOn ? rememberScope(rememberDuration) : 'once';
}
function needsDecisionReview() {
  return rememberMode()
    ? rememberOn
    : chosenScope !== 'once' && !!state.control.capabilities?.includes(REMEMBER_ZONE_CAPABILITY);
}
function reviewKey() {
  return JSON.stringify([
    state.control.generation,
    selectedRequest,
    chosenScope,
    decisionZone,
    state.control.networkZones?.revision,
    rememberMode() && rememberOn
      ? rememberKey({ fields: rememberFields, duration: rememberDuration })
      : '',
  ]);
}
// Backend text verbatim (e.g. policy_conflict "… still wins"), without IPC wrapping.
function errorText(error: unknown) {
  return String((error as Error)?.message ?? error)
    .replace(/^Error invoking remote method '[^']*': /, '')
    .replace(/^Error: /, '');
}
function decisionFor(action: 'allow' | 'block', e: ViewEvent, preview?: DecisionPreview) {
  const base = { generation: state.control.generation, id: e.id, action };
  const zoneRevision = preview?.zone_revision ?? (state.control.networkZones?.revision || '');
  if (rememberMode() && rememberOn)
    return {
      ...rememberDecision(
        base,
        { fields: rememberFields, duration: rememberDuration },
        zoneRevision,
      ),
      ...(preview ? { preview_token: preview.token } : {}),
    };
  if (forAWhileOn && forAWhileMode())
    return {
      ...base,
      scope: 'for-a-while' as const,
      // 15 s is the backend default and stays implicit (older backends).
      ...(forAWhileSeconds !== 15 && forAWhileDurations(state.control).includes(forAWhileSeconds)
        ? { duration_seconds: forAWhileSeconds }
        : {}),
    };
  return {
    ...base,
    scope: chosenScope,
    ...(needsDecisionReview()
      ? {
          network_zone: decisionZone,
          zone_revision: zoneRevision,
          ...(preview ? { preview_token: preview.token } : {}),
        }
      : {}),
  };
}
// Any change invalidates the shown preview immediately; the fresh review follows
// shortly so rapid checkbox changes do not exhaust the backend's preview capacity.
function invalidateReview(delay = 250) {
  ++reviewSequence;
  decisionReviews = {};
  reviewFor = '';
  reviewMessage = '';
  clearTimeout(reviewTimer);
  if (requestRuleAvailable(currentEvent(), state.control.capabilities)) scheduleRequestRule(delay);
  updateDecisions();
  reviewTimer = setTimeout(() => void prepareDecisions(), delay);
}
let autoReviewAt = -Infinity;
/**
 * Why Allow/Deny are unavailable with Remember on a live request ('' when the
 * reviewed rule is ready). Never leaves disabled buttons unexplained.
 */
function rememberBlockReason(e: ViewEvent | undefined, now: number): string {
  if (!e || !needsDecisionReview() || reviewFailureOf(e)) return '';
  if (!state.control.connected) return 'Disconnected · decisions unavailable.';
  if (!canDecide(state.control)) return 'This connection to FlowGate may not decide requests (read-only).';
  if (e.state !== 'awaiting-decision' || e.remainingMs <= 0) return 'This request has ended.';
  if (e.attempt || localSubmitted.has(state.control.generation + ':' + e.id)) return 'Already submitted.';
  if (!e.scope_previews[chosenScope])
    return chosenScope === 'persistent'
      ? 'A permanent rule is not offered for this request; choose an expiry duration.'
      : 'This expiry duration is not offered for this request.';
  if (reviewMessage) return 'Rule not available: ' + shortError(reviewMessage);
  if (reviewChecking || reviewFor !== reviewKey() || !decisionReviews.allow) return 'Checking rule…';
  if (Date.parse(decisionReviews.allow.expires_at) <= now) return 'Rule review expired · checking again…';
  return '';
}
async function prepareDecisions() {
  clearTimeout(reviewTimer);
  syncRememberScope();
  const e = currentEvent();
  const seq = ++reviewSequence,
    key = reviewKey();
  decisionReviews = {};
  reviewMessage = '';
  reviewChecking = false;
  if (!e || !needsDecisionReview() || !actionable(e)) {
    updateDecisions();
    return;
  }
  reviewChecking = true;
  updateDecisions();
  try {
    const entries = await Promise.all(
      (['allow', 'block'] as const).map(
        async (action) =>
          [action, await window.flowgate.decisionPreview(decisionFor(action, e))] as const,
      ),
    );
    if (seq === reviewSequence && key === reviewKey()) {
      decisionReviews = Object.fromEntries(entries);
      reviewFor = key;
    }
  } catch (error) {
    if (seq === reviewSequence && key === reviewKey()) reviewMessage = errorText(error);
  } finally {
    if (seq === reviewSequence) {
      reviewChecking = false;
      updateDecisions();
    }
  }
}
let tab = 'activity';
let sequence = '';
let eventSignature = '';
let detailSignature = '';
let roots: Row[] = [];
let visible: { row: Row; depth: number }[] = [];
let sort = 'name',
  descending = false;
const expanded = new Set<string>(['overview']);
const localSubmitted = new Set<string>();
let ruleSignature = '';
let lastGeneration = '';
const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
function element<K extends keyof HTMLElementTagNameMap>(tag: K, text = '', className = '') {
  const e = document.createElement(tag);
  e.textContent = text;
  e.className = className;
  return e;
}
function rowIcon(kind: Row['kind'] | 'service' | 'terminal') {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 16 16');
  svg.setAttribute('class', 'row-icon');
  svg.setAttribute('aria-hidden', 'true');
  const path = document.createElementNS(svg.namespaceURI, 'path');
  path.setAttribute(
    'd',
    kind === 'network'
      ? 'M1 2h14L10 8v6l-4-2V8z'
      : kind === 'service'
        ? 'M6.5 1h3l.5 2 1.5 1 2-.5 1.5 2.5-1.5 1v2l1.5 1-1.5 2.5-2-.5-1.5 1-.5 2h-3l-.5-2-1.5-1-2 .5L.5 10l1.5-1V7L.5 6 2 3.5l2 .5 1.5-1z M10.5 8a2.5 2.5 0 1 0-5 0 2.5 2.5 0 1 0 5 0'
        : kind === 'terminal'
          ? 'M1 2h14v12H1zM1 5h14M4 7l3 2-3 2M9 11h3'
          : kind === 'overview'
      ? 'M1 2h14v9H1zM8 11v3M4 14h8'
      : kind === 'inactive-group'
        ? 'M2 3h12v3H2zM3 6v8h10V6M6 9h4'
        : kind === 'application' || kind === 'program' || kind === 'launch'
      ? 'M2 2h12v9H2zM5 14h6M8 11v3M2 5h12'
      : kind === 'process'
        ? 'M5 3h6v10H5zM2 5h3m6 0h3M2 8h3m6 0h3M2 11h3m6 0h3'
        : kind === 'socket'
          ? 'M2 5h4v6H2zM10 5h4v6h-4zM6 8h4'
          : 'M3 3h10v10H3zM6 6a2 2 0 1 1 3 2l-1 1M8 11v1',
  );
  if (kind === 'network') svg.classList.add('network-filter-icon');
  svg.append(path);
  return svg;
}

const appNames = new Map<string, string>();
const iconFallbacks = new Map<string, 'service' | 'terminal'>();
const iconCache = new Map<string, string | null>();
const iconPending = new Set<string>();
const iconRetryAfter = new Map<string, number>();
function rememberIcon(key: string, url: string | null) {
  if (iconCache.size >= 2048 && !iconCache.has(key)) {
    const oldest = iconCache.keys().next().value!;
    iconCache.delete(oldest);
    iconRetryAfter.delete(oldest);
  }
  iconCache.set(key, url);
  if (url) iconRetryAfter.delete(key);
  else iconRetryAfter.set(key, Date.now() + 30_000);
}
let iconScheduled = false;
function installedIcon(app: Application | undefined, kind: Row['kind']) {
  const span = element('span', '', 'application-icon');
  const key = app?.key ? JSON.stringify([app.key, app.revision, app.executable]) : undefined;
  span.append(rowIcon((key && iconFallbacks.get(key)) || kind));
  if (!key) return span;
  span.dataset.iconKey = key;
  const paint = (node: HTMLElement, url: string) => {
    const img = element('img');
    img.src = url;
    img.alt = '';
    img.width = img.height = 16;
    img.onerror = () => {
      if (node.dataset.iconKey) rememberIcon(node.dataset.iconKey, null);
      node.replaceChildren(rowIcon(iconFallbacks.get(node.dataset.iconKey || '') || 'application'));
    };
    node.replaceChildren(img);
  };
  if ((iconRetryAfter.get(key) ?? Infinity) <= Date.now()) {
    iconCache.delete(key);
    iconRetryAfter.delete(key);
  }
  const url = iconCache.get(key);
  if (url) paint(span, url);
  else if (!iconCache.has(key)) {
    if (iconPending.size < 2048) iconPending.add(key);
    if (!iconScheduled) {
      iconScheduled = true;
      queueMicrotask(async () => {
        const keys = [...iconPending].slice(0, 128);
        keys.forEach((k) => iconPending.delete(k));
        try {
          const result = await window.flowgate.applicationMetadata(keys);
          for (const [key, metadata] of Object.entries(result)) {
            const url = metadata.icon;
            if (metadata.fallback) {
              if (iconFallbacks.size >= 2048) iconFallbacks.delete(iconFallbacks.keys().next().value!);
              iconFallbacks.set(key, metadata.fallback);
              for (const node of document.querySelectorAll<HTMLElement>('[data-icon-key]'))
                if (node.dataset.iconKey === key && !url) {
                  node.replaceChildren(rowIcon(metadata.fallback));
                  node.title = metadata.fallback === 'service' ? 'Service executable (installed system service metadata)' : 'Command-line program (terminal or executable-location metadata)';
                }
            }
            if (metadata.name) {
              if (appNames.size >= 2048) appNames.delete(appNames.keys().next().value!);
              appNames.set(key, metadata.name);
              for (const label of document.querySelectorAll<HTMLElement>('[data-display-key]'))
                if (label.dataset.displayKey === key) label.textContent = metadata.name;
            }
            rememberIcon(key, url);
            if (url)
              for (const node of document.querySelectorAll<HTMLElement>('[data-icon-key]'))
                if (node.dataset.iconKey === key) paint(node, url);
          }
        } catch {
          for (const key of keys) rememberIcon(key, null);
        } finally {
          iconScheduled = false;
        }
      });
    }
  }
  return span;
}
function rowApplication(r: Row) {
  if (r.displayApplication || (r.socket && r.socket.owners.length > 1)) return undefined;
  return (
    r.runtimeApplication?.application || r.process?.application ||
    r.displayApplication ||
    (r.socket?.owners.length === 1
      ? state.observation.activity?.processes[r.socket.owners[0]]?.application
      : r.socket?.display_application)
  );
}

// Seven-slot Rule Status strip. Slots 4/5 are the In/Out Blocker state for the
// row's own target (a process without its own rule shows Not set, like NetLimiter). The
// other slots are explicitly unavailable rule families, never controls.
function showFloatingRuleStatus() {
  let floating = $('floatingRuleStatus');
  if (!floating) {
    floating = element('section', '', 'floating-rule-status');
    floating.id = 'floatingRuleStatus';
    floating.setAttribute('aria-label', 'Activity rule status');
    const title = element('header', 'Rule Status · actions reviewed in Activity');
    const close = element('button', '✕');
    close.setAttribute('aria-label', 'Close floating rule status');
    title.append(close);
    floating.append(title);
    document.body.append(floating);
    const anchor = document.createComment('Info rule host');
    $('infoRules').before(anchor);
    close.onclick = () => {
      anchor.after($('infoRules'));
      floating.remove();
      anchor.remove();
    };
  }
  floating.append($('infoRules'));
}
function statusFamilyGlyph(key: string) {
  const span = element('span', '', 'slot-icon family-' + key);
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 16 16');
  svg.setAttribute('aria-hidden', 'true');
  const path = document.createElementNS(svg.namespaceURI, 'path');
  path.setAttribute(
    'd',
    key === 'in-blocker'
      ? 'M10 2h3v12h-3M2 8h8M7 5l3 3-3 3'
      : key === 'out-blocker'
        ? 'M6 2H3v12h3M6 8h8M11 5l3 3-3 3'
      : key.includes('quota')
        ? 'M8 1l6 3v8l-6 3-6-3V4zM8 1v14M2 4l6 4 6-4'
        : key === 'dl-limit'
          ? 'M8 3v10M4 9l4 4 4-4'
          : 'M8 13V3M4 7l4-4 4 4',
  );
  path.setAttribute('fill', 'none');
  path.setAttribute('stroke', 'currentColor');
  path.setAttribute('stroke-width', key === 'in-blocker' || key === 'out-blocker' ? '1.5' : '1.3');
  path.setAttribute('stroke-linecap', 'round');
  path.setAttribute('stroke-linejoin', 'round');
  svg.append(path);
  span.append(svg);
  return span;
}
function statusStrip(r: Row) {
  const cell = element('td', '', 'rule-status');
  const strip = element('span', '', 'status-strip');
  strip.setAttribute('role', 'group');
  strip.setAttribute('aria-label', r.label + ' rule status');
  const status = ruleStatus(r, state);
  const authoritative = state.control.capabilities?.includes(POLICY_CAPABILITY);
  const result = authoritative ? authoritativePolicy(r, state) : undefined;
  const processPolicy = authoritativeProcessPolicy(r, state);
  for (const slot of STATUS_SLOTS) {
    if (slot.key === "ul-limit" || slot.key === "dl-limit") { strip.append(uploadButton(r,state,slot.key === "dl-limit" ? "download" : "upload")); continue; }
    if (slot.key === "priority") { strip.append(priorityButton(r,state)); continue; }
    if (!slot.direction) {
      const empty = element('span', '', 'status-slot');
      empty.setAttribute('aria-hidden', 'true');
      strip.append(empty);
      continue;
    }
    const direction = slot.direction;
    const button = element('button', '', 'policy-cell status-slot');
    button.dataset.direction = direction;
    button.disabled =
      r.kind === 'inactive-group' ||
      r.kind === 'overview' ||
      r.kind === 'program' ||
      r.kind === 'launch' ||
      r.kind === 'socket' ||
      (r.kind === 'network' && !state.control.capabilities?.includes(ZONE_CAPABILITY));
    let chip: RuleChip = { glyph: '', text: 'Not set', tone: 'none', detail: '' };
    let fallbackShown = false;
    // A process row without its own rule shows its application's rule as inherited:
    // a different colour, not editable here (no hover, no click).
    let inherited = false;
    let title = '';
    if (r.kind === 'network' && state.control.capabilities?.includes(ZONE_CAPABILITY)) {
      const zone = authoritativeZonePolicy(r, state);
      chip = ruleChip(zone?.[direction], false, true);
      title = `${r.label} · all programs · ${direction}\n${zone?.[direction].reason || 'Policy unavailable'}`;
    } else if (r.kind === 'overview' || r.kind === 'network') {
      chip = { glyph: '', text: '', tone: 'none', detail: '' };
      title = r.kind === 'network' ? NETWORK_UNAVAILABLE : 'Machine: no rules at this level.';
    } else if (r.kind === 'socket') {
      chip = { glyph: '', text: '', tone: 'none', detail: '' };
      title = `${slot.label}: connections carry no rules; see the holder process.`;
    } else if (r.kind === 'inactive-group') {
      chip = { glyph: '', text: '', tone: 'none', detail: '' };
      title = 'Expand to view saved programs and edit their individual rules.';
    } else if (r.kind === 'program') {
      chip = { glyph: '', text: '', tone: 'none', detail: '' };
      title = 'Expand this program to edit each account’s permissions.';
    } else if (r.kind === 'launch') {
      chip = { glyph: '', text: '', tone: 'none', detail: '' };
      title = `${slot.label}: launch group (display only); rules apply to each process below.`;
    } else if (r.applicationZone) {
      const rules=status.available?status[direction]:[];
      const own=zoneConfigured(rules,status.now);
      chip={glyph:'',text:own.text,tone:status.available?own.tone:'unavailable',detail:rules.map(rule=>ruleDescription(rule,status.now)).join('\n')};
      title=`${r.label} · ${direction} · exact application/zone stored rules\n${chip.detail}\nConfigured policy, not a connection verdict. Parent application rule and global zone policies remain separate.`;
    } else if (r.inactive) {
      // Not running: the backend summarizes live processes only; list its stored rules.
      const rules = status.available ? status[direction] : [],
        own = ownConfigured(rules, status.now);
      chip = {
        glyph: '',
        text: own.text,
        tone: own.tone,
        detail: rules.map((rule) => ruleDescription(rule, status.now)).join('\n'),
        scoped: own.scoped,
      };
      title = `${slot.label} (not running · stored rules): ${chip.text}\n${chip.detail}`;
    } else if (authoritative) {
      // NetLimiter Rule Status: the node's OWN rule; scoped rules only add a "+N scoped" hint.
      const summary = processPolicy?.[direction] || result?.application?.[direction];
      const fallback =
        processPolicy && !processPolicy[direction].rules.length
          ? ownRuleChip(
              processPolicy[
                direction === 'incoming' ? 'application_incoming' : 'application_outgoing'
              ],
              false,
              true,
            )
          : undefined;
      // NetLimiter shows only the node's own rule; an inherited application rule is named in the tooltip.
      chip = ownRuleChip(summary, processPolicy?.state === 'inactive', true);
      if (r.kind === 'process' && !processPolicy?.[direction].rules.length) {
        const app = ownRuleChip(
          processPolicy?.[direction === 'incoming' ? 'application_incoming' : 'application_outgoing'] ||
            result?.application?.[direction],
          false,
          true,
        );
        if (['allow', 'block', 'ask', 'mixed', 'off'].includes(app.tone)) {
          chip = app;
          inherited = true;
        }
      }
      const appNote =
        fallback && fallback.tone !== 'none' ? `\nApplication rule applies: ${fallback.text}` : '';
      title = summary
        ? `${slot.label}: ${chip.text}${appNote}\n${chip.detail}\n${summary.reason}\nEnforcement: ${summary.enforcement.state} · ${summary.enforcement.reason}`
        : `${slot.label}: ${result?.reason || 'unavailable'}`;
      if (!summary) chip = { glyph: '', text: 'Unavailable', tone: 'unavailable', detail: '' };
    } else if (status.available) {
      const rules = status[direction],
        own = ownConfigured(rules, status.now);
      chip = {
        glyph: '',
        text: own.text,
        tone: own.tone,
        detail: rules.map((rule) => ruleDescription(rule, status.now)).join('\n'),
        scoped: own.scoped,
      };
      title = `${slot.label} (compatibility inventory): ${chip.text}\n${chip.detail}`;
    } else title = `${slot.label}: ${status.reason}`;
    if (['allow', 'block', 'ask', 'mixed', 'off'].includes(chip.tone))
      button.append(blockerGlyph(chip));
    else button.append(element('span', '·', 'slot-dot'), statusFamilyGlyph(slot.key));
    if (chip.scoped && !fallbackShown)
      button.append(element('span', '+' + chip.scoped, 'scoped-hint'));
    button.classList.add('tone-' + chip.tone);
    if (fallbackShown) button.classList.add('policy-fallback');
    if (inherited) {
      button.classList.add('policy-inherited');
      button.disabled = true;
    }
    if (button.disabled) {
      const empty = element('span', '', 'status-slot');
      empty.setAttribute('aria-hidden', 'true');
      strip.append(empty);
      continue;
    }
    button.title = inherited
      ? ''
      : title + (state.control.enforcement?.state === 'stopped' ? '\nStored only; enforcement stopped.' : '');
    button.setAttribute('aria-label', `${r.label} · ${slot.label} · ${chip.text || 'none'}${inherited ? ' · inherited from the application rule' : ''}`);
    button.onclick = (event) => {
      event.stopPropagation();
      if (inherited) return;
      selected = r.id;
      void window.flowgate.paneUpdate({
        selection: selected,
        generation: state.observation.generation,
      });
      for (const tr of document.querySelectorAll<HTMLElement>('#rows tr'))
        tr.setAttribute('aria-selected', String(tr.dataset.id === selected));
      renderInfo();
      if (r.inactive) {
        showInactiveRules(button, r, direction);
        return;
      }
      if (presentation?.panes.info !== 'docked') showFloatingRuleStatus();
      activityPolicy?.activate(direction, undefined, button);
    };
    strip.append(button);
  }
  cell.append(strip);
  return cell;
}
function showInactiveRules(anchor: HTMLElement, r: Row, direction: 'incoming' | 'outgoing') {
  if (!r.inactive || !state) return;
  const status = ruleStatus(r, state);
  const allStatus = ruleStatus({...r, applicationZone: undefined}, state);
  openInactiveRules(anchor, {
    label: r.applicationZone ? r.label : r.presentationLabel || appNames.get(JSON.stringify([r.inactive.key, r.inactive.revision, r.inactive.executable])) || r.label,
    direction,
    rules: status.available ? status[direction] : [],
    generation: state.control.generation,
    now: status.now,
    canManage: state.control.connected && canManageRules(state.control),
    canDelete: !!state.control.capabilities?.includes('conditional-rule-delete-v1'),
    askWritable: !!state.control.capabilities?.includes('stored-ask-v1'),
    message,
    // New rules reuse the identity of one of this program's own stored rules.
    networkZone: r.applicationZone?.zone,
    basisRuleId: (!r.applicationZone || r.applicationZone.model === state.control.networkZones?.model) && state.control.capabilities?.includes('rule-from-basis-v1')
      ? [...(allStatus.available ? [...allStatus.incoming, ...allStatus.outgoing] : [])].find(
          (x) => !x.preset && !x.filter.process && !x.filter.all_programs && !x.filter.all_uids,
        )?.id
      : undefined,
  });
}
function field(container: HTMLElement, label: string, value: string) {
  container.append(element('dt', label), element('dd', value || 'Unknown'));
}
function message(text: string) {
  $('feedback').textContent = text;
}
const scopeLabels: Record<Scope, string> = {
  once: 'Once',
  application: 'Remember · 1 hour',
  persistent: 'Remember · persistent',
};
let promptStableAt = performance.now() + 650;
let pointerDown = false;
const promptKeysDown = new Set<string>();
let promptLayoutReady = false;
let layoutFrame = 0;
let lastPromptLayout = '';
function measurePrompt() {
  if (!promptID || layoutFrame) return;
  layoutFrame = requestAnimationFrame(() => {
    layoutFrame = 0;
    const shell = document.querySelector<HTMLElement>('.prompt-shell');
    const body = $('promptBody');
    if (!shell || !body) return;
    // Natural rendered content, independent of the constrained scrolling viewport.
    const height =
      shell.offsetHeight -
      body.offsetHeight +
      $('requestDetails').getBoundingClientRect().height +
      16;
    const keysDown = [...promptKeysDown].sort();
    const signature = Math.ceil(height) + ':' + pointerDown + ':' + keysDown.join(',') + ':' + rememberOn;
    if (signature === lastPromptLayout) return;
    lastPromptLayout = signature;
    void window.flowgate.promptLayout({ height, pointerDown, keysDown, remember: rememberOn }).then(() => {
      if (!promptLayoutReady) {
        promptLayoutReady = true;
        promptStableAt = performance.now() + 650;
        setTimeout(() => {
          if (state) updateDecisions();
        }, 670);
      }
    });
  });
}
if (promptID) {
  document.addEventListener(
    'keyup',
    (event) => {
      promptKeysDown.delete(event.key);
      measurePrompt();
    },
    true,
  );
  // Repeated keys and the second click of a double-click never activate a new card.
  document.addEventListener(
    'keydown',
    (event) => {
      if (['Enter', ' ', 'Escape'].includes(event.key)) {
        promptKeysDown.add(event.key);
        measurePrompt();
      }
      if (
        ['Enter', ' '].includes(event.key) &&
        (event.repeat || performance.now() < promptStableAt)
      ) {
        event.preventDefault();
        event.stopImmediatePropagation();
      }
    },
    true,
  );
  document.addEventListener(
    'click',
    (event) => {
      if (event.detail > 1 || performance.now() < promptStableAt) {
        event.preventDefault();
        event.stopImmediatePropagation();
      }
    },
    true,
  );
  document.addEventListener(
    'pointerdown',
    () => {
      pointerDown = true;
      measurePrompt();
    },
    true,
  );
  for (const type of ['pointerup', 'pointercancel'])
    document.addEventListener(
      type,
      () => {
        pointerDown = false;
        measurePrompt();
      },
      true,
    );
  root.innerHTML = `<section class="prompt-shell"><header class="prompt-heading"><strong>FlowGate Blocker</strong><span id="promptPending">Connection permission</span><button id="closePrompt" aria-label="Dismiss permission window">×</button></header><div id="promptBody"><div id="requestDetails"></div></div><footer><span id="controlStatus"></span><button id="dismiss">Decide later</button></footer><div id="feedback" role="status" aria-live="polite"></div></section>`;
  new ResizeObserver(measurePrompt).observe($('requestDetails'));
  new ResizeObserver(measurePrompt).observe($('feedback'));
  document.addEventListener('toggle', measurePrompt, true);
  setTimeout(() => {
    if (state) updateDecisions();
  }, 670);
  $('dismiss').onclick = () => void window.flowgate.dismissPrompt();
  $('closePrompt').onclick = () => void window.flowgate.dismissPrompt();
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      event.preventDefault();
      void window.flowgate.dismissPrompt();
    }
  });
} else {
  root.innerHTML = `<header class="toolbar"><strong class="brand">FLOWGATE</strong><span id="buildVersion" class="build-version"></span><span id="toolbarUnits" class="toolbar-units"><label for="displayUnits">Units</label><select id="displayUnits" aria-label="Display units" title="Display only: bytes or bits, decimal SI prefixes (1 KB = 1000 B). Accounting sources stay separate."></select></span><span id="observerStatus" class="toolbar-status"></span><span id="controlStatus" class="toolbar-status"></span><span class="toolbar-layout"><select id="layoutPreset" aria-label="Window layout"><option value="chart">Default with Chart</option><option value="plain">Default</option><option value="activity">Activity only</option></select></span><input id="search" type="search" aria-label="Search Activity" placeholder="Search"></header><nav class="tabs" aria-label="Views"><button id="activityTab" aria-selected="true">Activity</button><button id="requestsTab" aria-selected="false">Pending requests <span id="pendingCount">0</span></button><span id="tabsPaneControls" class="pane-controls"></span></nav><main id="activityView"><section class="activity-main"><div class="filterbar"><select id="activitySource" aria-label="Activity measurement source"><option value="tcp">TCP</option><option value="udp">UDP</option></select><button id="uploadLimits">Upload limits</button><button id="rateMode" aria-pressed="false" title="Switch the two traffic columns between current rate and total transferred">Rate</button><select id="columnPreset" aria-label="Column preset"><option value="status">Status</option><option value="details">Details</option></select><select id="filter" aria-label="Socket filter"><option value="all">All sockets</option><option value="active">Active TCP / connected UDP</option><option value="listening">Listening TCP / bound UDP</option></select><span class="filterbar-icons"><button id="expand" class="icon-button" title="Expand all" aria-label="Expand all">⊞</button><button id="collapse" class="icon-button" title="Collapse all" aria-label="Collapse all">⊟</button><button id="refreshNow" class="icon-button" title="Refresh now" aria-label="Refresh now">↻</button></span></div><div class="table-scroll"><table id="tree" role="treegrid" tabindex="0" aria-label="Application process socket activity"><thead><tr id="headers"></tr></thead><tbody id="rows"></tbody></table></div><div id="activitySummary" class="summary"></div></section><aside><h2>Info View<span id="infoPaneControls" class="pane-controls"></span></h2><h3 id="selectedName">FlowGate Activity</h3><div id="selectedExecutable"></div><div class="info-scroll"><h3 id="infoProperties" class="info-section-title">Overview</h3><dl id="info"></dl><section id="infoRules"></section><section class="info-tools"><h3 class="info-section-title">Tools</h3><button id="infoOpenRules">Rule list</button><button id="infoOpenLog">Decision log</button><button id="infoOpenPending">Pending requests</button></section></div><section id="trafficGraph"></section></aside></main><main id="requestsView" hidden><section class="request-list"><h2>Pending requests</h2><p class="hint">One row per group of identical requests; a decision answers its oldest request. Dismissal grants nothing. Closing FlowGate leaves an independent controller running.</p><div class="table-scroll"><table id="requests"><thead><tr><th>Application</th><th>Direction</th><th>Protocol</th><th>Remote endpoint</th><th>Requests</th><th>State</th></tr></thead><tbody id="requestRows"></tbody></table></div><section id="temporaryDecisions" class="temporary-decisions" hidden><h3 title="For a while decisions: in memory only, never saved as rules">Temporary decisions</h3><div id="leaseRows"></div></section><section id="permissionResultsView" class="permission-results" hidden><h3 title="Outcomes of Allow/Deny submissions; the permission window hides on the click">Results</h3><ol id="permissionResultRows"></ol></section></section><aside class="request-sidebar"><h2>Connection permission</h2><div id="requestDetails"></div></aside></main><footer><span id="footerSummary"></span><button id="resultsAttention" class="link-button results-attention" hidden></button><span id="feedback" role="status" aria-live="polite"></span></footer>`;
  // The GUI's own release identity (verified against its bundle manifest).
  void window.flowgate
    .guiBuild()
    .catch(() => ({ state: 'unavailable', reason: 'GUI build identity could not be read.' }) as GuiBuild)
    .then((b) => {
      guiBuild = b;
      renderBuildVersion();

    });
  const columns = [
    ['name', 'Name'],
    ['download_bps', 'DL Rate'],
    ['upload_bps', 'UL Rate'],
    ['rule_status', 'Rule Status'],
    ['count', 'Sockets'],
    ['pid', 'PID'],
    ['downloaded', 'Downloaded'],
    ['uploaded', 'Uploaded'],
    ['protocol', 'Protocol'],
    ['local', 'Local endpoint'],
    ['remote', 'Remote endpoint'],
    ['state', 'State'],
    ['filler', ''],
  ];
  for (const [key, title] of columns) {
    const th = element('th');
    th.className = 'col-' + key;
    const b = element('button', title);
    if (key === 'download_bps' || key === 'upload_bps') {
      b.classList.add('rate-header');
      b.append(element('small', 'autoByte (def)'));
    }
    b.disabled = key === 'rule_status';
    b.onclick = () => {
      const actual =
        key === 'download_bps' ? rateKeys()[0] : key === 'upload_bps' ? rateKeys()[1] : key;
      descending = sort === actual ? !descending : /bps|loaded/.test(actual);
      sort = actual;
      renderTree();
    };
    th.append(b);
    $('headers').append(th);
  }
  const chooseTab = (next: string) => {
    tab = next;
    showObservedUsage(next === 'usage');
    if ($('rulesView')) {
      $('rulesView').hidden = next !== 'rules';
      $('rulesTab').setAttribute('aria-selected', String(next === 'rules'));
    }
    if ($('decisionLogView')) {
      $('decisionLogView').hidden = next !== 'log';
      $('decisionLogTab').setAttribute('aria-selected', String(next === 'log'));
      void showDecisionLog(next === 'log');
    }
    $('activityView').hidden = next !== 'activity';
    $('requestsView').hidden = next !== 'requests';
    if (next === 'activity') void graph?.update(selected, sequence + ':shown');
    $('activityTab').setAttribute('aria-selected', String(next === 'activity'));
    $('requestsTab').setAttribute('aria-selected', String(next === 'requests'));
  };
  setupWorkflows(chooseTab);
  $('infoOpenRules').onclick = () => chooseTab('rules');
  $('infoOpenLog').onclick = () => chooseTab('log');
  $('infoOpenPending').onclick = () => chooseTab('requests');
  setupDecisionLog(
    chooseTab,
    (app) => installedIcon(app, 'application'),
    (id) => {
      chooseTab('rules');
      void openRule({ id });
    },
  );
  setupObservedUsage(chooseTab);
  graph = new TrafficGraph($('trafficGraph'), {
    change: (chart) => void window.flowgate.paneUpdate({ chart }).catch(message),
    source: (source) => void window.flowgate.paneUpdate({ source }).catch(message),
  });
  setupPaneControls();
  activityPolicy = new ActivityPolicy($('infoRules'));
  $('uploadLimits').onclick=()=>void openUploadLimits().catch(e=>message(String(e)));
  window.flowgate.onFutureApplicationRule((source) => {
    if (source.generation !== state?.control.generation || source.target_scope !== 'application') return;
    chooseTab('activity');
    void openRule({ observed: source }, { activity: true, applicationScope: true, protocol: '*', action: 'allow', futureOnly: true });
  });
  window.flowgate.onNavigate((v) => {
    chooseTab('requests');
    message(v.message);
  });
  document.addEventListener('keydown', (e) => {
    if (e.ctrlKey && ['1', '2', '3', '4'].includes(e.key)) {
      e.preventDefault();
      chooseTab({ '1': 'activity', '2': 'requests', '3': 'rules', '4': 'log' }[e.key]!);
    }
    if (e.ctrlKey && e.key.toLowerCase() === 'p') {
      e.preventDefault();
      const event = currentEvent();
      if (event) void window.flowgate.openPrompt(event.id);
    }
  });
  $('activityTab').onclick = () => chooseTab('activity');
  $('requestsTab').onclick = () => chooseTab('requests');
  $('search').oninput = () => buildTree();
  $('activitySource').onchange = () => {
    measurementSource = ($('activitySource') as HTMLSelectElement).value as 'tcp' | 'udp';
    graph?.setSource(measurementSource);
    void window.flowgate.paneUpdate({ source: measurementSource }).catch(message);
    renderTree();
    renderInfo();
  };
  $('filter').onchange = () => {
    syncFilterGroup();
    buildTree();
  };
  // Reference-style All / Active / Listening toggle strip; the select stays as the accessible model.
  const filterGroup = element('div', '', 'filter-group');
  filterGroup.setAttribute('role', 'radiogroup');
  filterGroup.setAttribute('aria-label', 'Socket filter');
  for (const [value, label] of [
    ['all', 'All'],
    ['active', 'Active'],
    ['listening', 'Listening'],
  ]) {
    const b = element('button', label);
    b.dataset.value = value;
    b.setAttribute('role', 'radio');
    b.onclick = () => {
      $<HTMLSelectElement>('filter').value = value;
      syncFilterGroup();
      buildTree();
    };
    filterGroup.append(b);
  }
  $('filter').after(filterGroup);
  $('filter').classList.add('visually-hidden');
  function syncFilterGroup() {
    for (const b of filterGroup.querySelectorAll<HTMLElement>('button'))
      b.setAttribute(
        'aria-checked',
        String(b.dataset.value === $<HTMLSelectElement>('filter').value),
      );
  }
  syncFilterGroup();
  $('expand').onclick = () => {
    for (const r of allRows(roots)) if (r.children.length) expanded.add(r.id);
    renderTree();
  };
  $('collapse').onclick = () => {
    expanded.clear();
    selected = 'overview';
    expanded.add('overview');
    renderTree();
    renderInfo();
  };
  $('tree').onkeydown = (e) => {
    if (['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight'].includes(e.key)) e.preventDefault();
    let index = visible.findIndex((v) => v.row.id === selected);
    const row = visible[index]?.row;
    if (e.key === 'ArrowDown') index = Math.min(index + 1, visible.length - 1);
    else if (e.key === 'ArrowUp') index = Math.max(0, index - 1);
    else if (e.key === 'ArrowRight' && row?.children.length) {
      expanded.add(row.id);
      renderTree();
      return;
    } else if (e.key === 'ArrowLeft' && row) {
      if (expanded.has(row.id)) {
        expanded.delete(row.id);
        renderTree();
        return;
      }
      index = visible.findIndex((v) => v.row.id === row.parent);
    } else return;
    e.preventDefault();
    if (index >= 0) {
      selected = visible[index].row.id;
      renderTree();
      renderInfo();
      document
        .querySelector('tr[aria-selected="true"]')
        ?.scrollIntoView({ block: 'nearest', inline: 'nearest' });
    }
  };
}
let hostLabel = 'This computer';
function buildTree() {
  const a = state?.observation.activity;
  roots = a
    ? activityTree(a, state.control.rules, $<HTMLInputElement>('search').value, $<HTMLSelectElement>('filter').value, undefined, state.control.capabilities?.includes(ZONE_CAPABILITY)?state.control.networkZones:undefined, state.control.events)
    : [];
  if (a) {
    const inactive = roots.filter(r => r.kind === 'inactive-group');
    const observationGroups = roots.filter(r => r.kind === 'unidentified' || r.kind === 'kernel-lifecycle');
    const children = [...networkOverviews(), ...roots.filter(r => r.kind !== 'inactive-group' && r.kind !== 'unidentified' && r.kind !== 'kernel-lifecycle')];
    for (const child of children) child.parent = 'overview';
    roots = [overview(a, children, hostLabel), ...observationGroups, ...inactive];
  }
  const all = allRows(roots);
  const r = all.find((r) => r.id === selected);
  if (r) {
    let parent = r.parent;
    while (parent) {
      expanded.add(parent);
      parent = all.find((r) => r.id === parent)?.parent;
    }
  }
  if (expanded.size > 8192) {
    const ids = new Set(all.map((r) => r.id));
    for (const id of expanded) if (id !== 'unidentified' && id !== 'kernel-lifecycle' && !ids.has(id)) expanded.delete(id);
  }
  renderTree();
  renderInfo();
  const counts = activityRowCounts(roots);
  const detailedSummary = a ? `${counts.displayed} displayed / ${a.rows.length} observed sockets · ${counts.lifecycle} kernel TIME_WAIT · ${counts.unresolved} unresolved/shared · ${a.complete ? 'Complete census' : 'Partial visibility'}` : state.observation.message;
  $('footerSummary').textContent = $('activitySummary').textContent = a
    ? `${counts.displayed}/${a.rows.length} sockets · ${counts.lifecycle} TIME_WAIT · ${counts.unresolved} unresolved · ${a.complete ? 'Complete' : 'Partial'}`
    : state.observation.message;
  $('activitySummary').title = $('footerSummary').title = [detailedSummary, 'Counts describe this endpoint’s projected observations and current search/socket filter. The measurement source selects byte columns, not which sockets are listed.', a?.collected, ...(a?.issues || [])]
    .filter(Boolean)
    .join(' · ');
}
// Reference dock controls (▾ menu: Open Window ▸ / Close; ✕: Close) for the Info View and the
// Traffic chart. The Activity list itself cannot be closed, so its strip only offers Open Window.
// Reference control row: Rate/Total toggle and column preset (Status = the four reference columns).
const rateKeys = (): Metric[] =>
  rateMode === 'rate' ? ['download_bps', 'upload_bps'] : ['downloaded', 'uploaded'];
function applyRateMode() {
  $('rateMode').textContent = rateMode === 'rate' ? 'Rate' : 'Total';
  $('rateMode').setAttribute('aria-pressed', String(rateMode === 'total'));
  for (const [key, label] of [
    ['download_bps', 'DL'],
    ['upload_bps', 'UL'],
  ]) {
    const b = document.querySelector<HTMLElement>(`.col-${key} button`);
    if (b) b.childNodes[0].textContent = `${label} ${rateMode === 'rate' ? 'Rate' : 'Total'}`;
  }
}
function applyColumnPreset() {
  document.body.classList.toggle(
    'preset-status',
    $<HTMLSelectElement>('columnPreset').value === 'status',
  );
}
function paneList(): { key: 'info' | 'chart'; label: string }[] {
  return [
    { key: 'info', label: 'Info View' },
    { key: 'chart', label: 'Traffic chart' },
  ];
}
function paneState(): Record<'info' | 'chart', boolean> {
  return {
    info: presentation?.panes.info !== 'hidden',
    chart: presentation?.panes.chart !== 'hidden',
  };
}
function applyPanes() {
  const info = presentation?.panes.info || 'docked',
    chart = presentation?.panes.chart || 'docked';
  document.body.classList.toggle('hide-sidebar', info !== 'docked' && chart !== 'docked');
  document.body.classList.toggle('hide-info', info !== 'docked');
  document.body.classList.toggle('hide-chart', chart !== 'docked');
  document.body.classList.toggle('info-detached', info === 'detached');
  document.body.classList.toggle('chart-detached', chart === 'detached');
  for (const item of document.querySelectorAll<HTMLButtonElement>('.pane-menu button[data-pane]')) {
    const key = item.dataset.pane as 'info' | 'chart';
    item.setAttribute('aria-checked', String(paneState()[key]));
    item.title =
      presentation?.panes[key] === 'detached'
        ? 'Detached — click to dock'
        : paneState()[key]
          ? 'Close pane'
          : 'Open pane';
  }
  const layout = $<HTMLSelectElement>('layoutPreset');
  if (layout)
    layout.value = info !== 'docked' ? 'activity' : chart === 'docked' ? 'chart' : 'plain';
  void graph?.update(selected, sequence + ':panes');
}
function setPane(key: 'info' | 'chart', open: boolean) {
  void window.flowgate.paneControl(key, open ? 'dock' : 'close').catch(message);
}
function paneControls(self?: 'info' | 'chart', summaryText = '▾') {
  const wrap = element('span', '', 'pane-controls-inner');
  const menu = element('details', '', 'desktop-menu pane-menu');
  const summary = element('summary', summaryText);
  summary.title = 'Window menu';
  summary.setAttribute(
    'aria-label',
    (self ? paneList().find((p) => p.key === self)!.label : 'Activity') + ' window menu',
  );
  const panel = element('div', '', 'menu-panel');
  panel.append(element('div', 'Open Window', 'menu-heading'));
  for (const pane of paneList()) {
    const item = element('button', pane.label);
    item.dataset.pane = pane.key;
    item.setAttribute('role', 'menuitemcheckbox');
    item.onclick = () => {
      setPane(pane.key, presentation?.panes[pane.key] === 'detached' || !paneState()[pane.key]);
      menu.open = false;
    };
    panel.append(item);
  }
  if (self) {
    const undock = element('button', 'Undock');
    undock.dataset.undock = self;
    undock.onclick = () => {
      void window.flowgate.paneControl(self, 'undock').catch(message);
      menu.open = false;
    };
    panel.prepend(undock, element('hr'));
    const close = element('button', 'Close');
    close.onclick = () => {
      setPane(self, false);
      menu.open = false;
    };
    panel.append(element('hr'), close);
  }
  menu.append(summary, panel);
  wrap.append(menu);
  if (self) {
    const x = element('button', '✕', 'pane-close');
    x.title =
      'Close ' + paneList().find((p) => p.key === self)!.label + ' (reopen from any ▾ window menu)';
    x.setAttribute('aria-label', x.title);
    x.onclick = () => setPane(self, false);
    wrap.append(x);
  }
  return wrap;
}
function updateFirewallStatus() {
  const status = document.getElementById('firewallMenuStatus');
  if (!status) return;
  const summary = document.querySelector('#controlMenu > summary');
  status.textContent = state?.control.capabilities?.includes(PROTECTION_CAPABILITY)
    ? stateProtection(state)
    : state?.control.capabilities?.includes('daemon-evaluation-v1')
      ? summary?.textContent || 'Firewall · unknown'
      : !state?.control.connected
        ? 'Firewall · unavailable'
        : `Firewall · ${state.control.enforcement?.state || 'unknown'}`;
  status.title =
    document.getElementById('controlStatus')?.title ||
    'Enforcement state unavailable. Monitoring never implies protection.';
  const health = document.getElementById('runtimeHealth');
  if (health) {
    const badge = runtimeBadge(!!state?.control.connected, state?.control.runtimeChecks);
    health.hidden = !badge;
    health.textContent = badge?.text || '';
    health.title = badge?.title || '';
  }
  const queue = document.getElementById('queueHealth');
  if (queue) {
    const warning = queueHealthWarning(!!state?.control.connected, state?.control.queueHealth);
    queue.hidden = !warning;
    queue.textContent = warning?.text || '';
    queue.title = warning?.title || '';
  }

}
function setupMainMenus(windowMenu: HTMLElement) {
  const toolbar = document.querySelector('.toolbar')!;
  const make = (id: string, title: string) => {
    const menu = element('details', '', 'desktop-menu');
    menu.id = id;
    menu.append(element('summary', title), element('div', '', 'menu-panel'));
    return menu;
  };
  const file = make('fileMenu', 'File'),
    tools = make('toolsMenu', 'Tools'),
    help = make('helpMenu', 'Help');
  const exit = element('button', 'Exit FlowGate…');
  exit.onclick = () => void window.flowgate.quit();
  file.lastElementChild!.append(exit);
  const control = $('controlMenu'),
    options = $('optionsMenu');
  // The stateful controls keep their existing IDs and authorization paths, inside Tools.
  const controlTitle = control.querySelector('summary')!;
  controlTitle.dataset.menuLabel = 'Firewall';
  tools.lastElementChild!.append(control, element('hr'), options);
  const about = element('button', 'About FlowGate');
  const dialog = element('dialog');
  dialog.id = 'aboutFlowGate';
  dialog.append(
    element('h2', 'FlowGate'),
    element(
      'p',
      'Activity, stored firewall policy and explicit bounded evaluation. Monitoring and firewall enforcement are separate.',
    ),
  );
  const close = element('button', 'Close');
  close.onclick = () => dialog.close();
  dialog.append(close);
  document.body.append(dialog);
  about.onclick = () => {
    (help as HTMLDetailsElement).open = false;
    dialog.showModal();
  };
  help.lastElementChild!.append(about);
  const windowPanel = windowMenu.querySelector('.menu-panel')!;
  for (const [label, id] of [
    ['Activity', 'activityTab'],
    ['Rule list', 'rulesTab'],
    ['Pending requests', 'requestsTab'],
    ['Decision log', 'decisionLogTab'],
    ['Observed usage', 'observedUsageTab'],
  ]) {
    const b = element('button', label);
    b.onclick = () => {
      $(id).click();
      const details = windowMenu.querySelector('details');
      if (details) details.open = false;
    };
    windowPanel.append(b);
  }
  $('toolbarUnits').before(file, tools, windowMenu, help);
  // Preserve an obvious state entry point; text is updated by the existing evaluation state.
  const status = element('button', 'Firewall controls', 'firewall-state');
  status.id = 'firewallMenuStatus';
  status.onclick = () => {
    (tools as HTMLDetailsElement).open = true;
    (control as HTMLDetailsElement).open = true;
  };
  $('toolbarUnits').after(status);
  // Advisory runtime health beside, not inside, the protection entry (its text is ellipsized).
  const health = element('span', '', 'runtime-health');
  health.id = 'runtimeHealth';
  health.hidden = true;
  health.setAttribute('role', 'status');
  status.after(health);
  const queue = element('span', '', 'queue-health');
  queue.id = 'queueHealth';
  queue.hidden = true;
  queue.setAttribute('role', 'status');
  queue.tabIndex = 0;
  toolbar.after(queue);
  new MutationObserver(updateFirewallStatus).observe(controlTitle, {
    childList: true,
    characterData: true,
    subtree: true,
    attributes: true,
  });
  updateFirewallStatus();
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    const open = [...toolbar.querySelectorAll<HTMLDetailsElement>('.desktop-menu[open]')];
    if (!open.length) return;
    for (const menu of open) menu.open = false;
    open[0].querySelector<HTMLElement>('summary')?.focus();
  });
  for (const menu of toolbar.querySelectorAll<HTMLDetailsElement>('.desktop-menu'))
    menu.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        menu.open = false;
        menu.querySelector<HTMLElement>('summary')?.focus();
      }
    });
}
function displayMetric(s: ReturnType<typeof sum>, rate = false) {
  return s.mixed
    ? 'Mixed sources'
    : displayAmount(s.value, rate, displayUnit) + (s.value !== undefined && s.partial ? ' *' : '');
}
function setupPaneControls() {
  $('infoPaneControls').append(paneControls('info'));
  $('tabsPaneControls').append(paneControls());
  // Toolbar "Window" menu (reference: Window menu lists dockable windows).
  const windowMenu = paneControls(undefined, 'Window');
  windowMenu.classList.add('toolbar-window-menu');
  (document.getElementById('controlMenu') || document.querySelector('.brand'))!.after(windowMenu);
  // Display units never change the chosen accounting source or numeric sorting.
  const units = $<HTMLSelectElement>('displayUnits');
  for (const value of DISPLAY_UNITS) units.add(new Option(value, value));
  const applyUnit = (value: DisplayUnit) => {
    displayUnit = value;
    units.value = value;
    for (const small of document.querySelectorAll('.rate-header small'))
      small.textContent = value + ' (def)';
    graph?.setUnit(value);
    if (state) updateObservedUsage(state, value);
    if (state) renderTree();
  };
  units.onchange = () => {
    if (!isDisplayUnit(units.value)) return;
    applyUnit(units.value);
    void window.flowgate.paneUpdate({ unit: displayUnit }).catch(message);
  };
  void window.flowgate
    .preferences()
    .then((p) => applyUnit(isDisplayUnit(p.displayUnit) ? p.displayUnit : 'autoByte'));
  const sourceLabel = element('label', 'Accounting source ', 'source-control');
  sourceLabel.append($('activitySource'));
  document.querySelector('#controlMenu .menu-panel')!.prepend(sourceLabel);
  setupMainMenus(windowMenu);
  $<HTMLSelectElement>('layoutPreset').onchange = () => {
    const v = $<HTMLSelectElement>('layoutPreset').value;
    void window.flowgate.paneControl('info', v === 'activity' ? 'close' : 'dock');
    void window.flowgate.paneControl('chart', v === 'chart' ? 'dock' : 'close');
  };
  const chartHead = document.querySelector('#trafficGraph .graph-heading');
  if (chartHead) {
    const c = element('span', '', 'pane-controls');
    const controls = paneControls('chart');
    // Chart source / window options live in the chart's ▾ menu (reference header has no selects).
    const panel = controls.querySelector('.menu-panel')!;
    for (const [id, heading] of [
      ['graphSource', 'Source'],
      ['graphWindow', 'Window'],
    ]) {
      const select = document.getElementById(id) as HTMLSelectElement;
      panel.append(element('hr'), element('div', heading, 'menu-heading'));
      for (const option of Array.from(select.options)) {
        const item = element('button', option.textContent || '');
        item.setAttribute('role', 'menuitemradio');
        const sync = () => item.setAttribute('aria-checked', String(select.value === option.value));
        sync();
        select.addEventListener('change', sync);
        item.onclick = () => {
          select.value = option.value;
          select.dispatchEvent(new Event('change'));
          (controls.querySelector('details') as HTMLDetailsElement).open = false;
        };
        panel.append(item);
      }
    }
    c.append(controls);
    chartHead.append(c);
  }
  $('rateMode').onclick = () => {
    const was = rateKeys();
    rateMode = rateMode === 'rate' ? 'total' : 'rate';
    if (was.includes(sort as Metric)) sort = rateKeys()[was.indexOf(sort as Metric)];
    applyRateMode();
    renderTree();
  };
  $('columnPreset').onchange = applyColumnPreset;
  $('refreshNow').onclick = () => void window.flowgate.snapshot().then(consume);
  applyRateMode();
  applyColumnPreset();
  document.addEventListener('pointerdown', (event) => {
    for (const menu of document.querySelectorAll<HTMLDetailsElement>('.pane-menu[open]'))
      if (!menu.contains(event.target as Node)) menu.open = false;
  });
  applyPanes();
}
const renderedRows = new Map<
  string,
  { signature: string; presentation: string; policyRevision: number; node: HTMLTableRowElement }
>();
let treePolicyRevision = 0;
function renderTree() {
  for (const th of document.querySelectorAll<HTMLElement>('#headers th')) {
    const key = th.className.replace('col-', '');
    const actual =
      key === 'download_bps' ? rateKeys()[0] : key === 'upload_bps' ? rateKeys()[1] : key;
    th.setAttribute(
      'aria-sort',
      actual === sort ? (descending ? 'descending' : 'ascending') : 'none',
    );
  }
  const focused = document.activeElement as HTMLElement;
  const focusedPolicy = focused?.classList.contains('policy-cell')
    ? { id: focused.closest('tr')?.dataset.id, direction: focused.dataset.direction }
    : undefined;
  visible = flatten(roots, expanded, sort, descending, measurementSource);
  const body = $('rows');
  const ordered: HTMLTableRowElement[] = [];
  const liveIds = new Set<string>();
  for (const { row: r, depth } of visible) {
    liveIds.add(r.id);
    const rowSignature = rowStructure(r, depth, selected === r.id, expanded.has(r.id));
    const rateValues = rateKeys().map((key) => sum(r.rows, key, measurementSource));
    const totalValues = (['downloaded', 'uploaded'] as Metric[]).map((key) =>
      sum(r.rows, key, measurementSource),
    );
    const cellPresentation = JSON.stringify([
      measurementSource,
      displayUnit,
      rateMode,
      rateValues,
      totalValues,
    ]);
    const cached = renderedRows.get(r.id);
    if (cached?.signature === rowSignature) {
      if (cached.presentation !== cellPresentation) {
        for (const [index, key] of rateKeys().entries()) {
          const value = rateValues[index],
            cell = cached.node.cells[index + 1];
          const className =
            'numeric ' +
            (value.value && value.value > 0 ? (key.startsWith('download') ? 'down' : 'up') : '');
          if (cell.className !== className) cell.className = className;
          const text = displayMetric(value, rateMode === 'rate'),
            span = cell.querySelector('.rate-value')!;
          if (span.textContent !== text) span.textContent = text;
          cell.title = `${measurementSource.toUpperCase()} · ${value.known}/${value.count} measured sockets${value.mixed ? ' · incompatible measurement sources' : ''}`;
        }
        for (const [index, key] of (['downloaded', 'uploaded'] as Metric[]).entries()) {
          const cell = cached.node.cells[index + 6],
            text = displayMetric(totalValues[index]);
          if (cell.textContent !== text) cell.textContent = text;
        }
        cached.presentation = cellPresentation;
      }
      if (cached.policyRevision !== treePolicyRevision) {
        const policy = statusStrip(r),
          previous = cached.node.querySelector('.rule-status')!;
        // Keep unchanged controls/focus. Handlers capture only the stable row ID;
        // current row identity is resolved by renderInfo and the main rule service.
        if (previous.innerHTML !== policy.innerHTML) previous.replaceWith(policy);
        cached.policyRevision = treePolicyRevision;
      }
      const status=cached.node.querySelector<HTMLElement>('.connection-status-slot');
      if(status) {updateConnectionStatus(status,r);if(!r.inactive) cached.node.title=status.title;}
      ordered.push(cached.node);
      continue;
    }
    const tr = element('tr');
    tr.dataset.id = r.id;
    if (r.inactive) {
      tr.classList.add('inactive-app');
      tr.title = `Not running · ${r.inactive.rules} stored rule${r.inactive.rules === 1 ? '' : 's'}${r.inactive.earlierVersion ? ' · earlier version of a running program' : ''}\n${r.inactive.executable}`;
    }
    tr.setAttribute('aria-level', String(depth + 1));
    tr.setAttribute('aria-selected', String(selected === r.id));
    if (r.children.length) tr.setAttribute('aria-expanded', String(expanded.has(r.id)));
    tr.onclick = () => {
      selected = r.id;
      for (const row of document.querySelectorAll<HTMLElement>('#rows tr'))
        row.setAttribute('aria-selected', String(row.dataset.id === selected));
      renderInfo();
      $('tree').focus();
    };
    tr.ondblclick = (event) => {
      if ((event.target as HTMLElement).closest('button,input,select')) return;
      if (r.children.length) {
        if (expanded.has(r.id)) expanded.delete(r.id);
        else expanded.add(r.id);
        renderTree();
        renderInfo();
      } else void window.flowgate.paneControl('info', 'open').catch(message);
    };
    const name = element('td');
    name.className = `name depth-${depth}`;
    const toggle = element(
      'button',
      r.children.length ? (expanded.has(r.id) ? '◢' : '▷') : '',
      'disclosure',
    );
    toggle.tabIndex = -1;
    toggle.setAttribute('aria-label', (expanded.has(r.id) ? 'Collapse ' : 'Expand ') + r.label);
    toggle.disabled = !r.children.length;
    toggle.onclick = (e) => {
      e.stopPropagation();
      if (expanded.has(r.id)) {
        expanded.delete(r.id);
        const current = allRows(roots).find((v) => v.id === r.id) || r;
        if (allRows([current]).some((v) => v.id === selected)) selected = r.id;
      } else expanded.add(r.id);
      renderTree();
      renderInfo();
    };
    const inactiveApp = r.inactive && {
      key: r.inactive.key,
      revision: r.inactive.revision,
      name: r.label,
      executable: r.inactive.executable,
    };
    const displayApp = r.runtimeApplication?.application || r.process?.application || r.displayApplication || inactiveApp;
    const displayKey =
      displayApp && JSON.stringify([displayApp.key, displayApp.revision, displayApp.executable]);
    let rowLabel =
      r.presentationLabel ? r.presentationLabel : r.applicationZone ? r.label : r.kind === 'application' && displayKey ? appNames.get(displayKey) || r.label : r.label;
    let icon: HTMLElement = installedIcon(
      r.kind === 'application' || r.kind === 'process' ? r.displayApplication || inactiveApp || rowApplication(r)
        : r.kind === 'program' ? r.children.map(c => c.process?.application || c.displayApplication || (c.inactive && {key:c.inactive.key, revision:c.inactive.revision, executable:c.inactive.executable, name:c.label})).find(Boolean) || undefined : undefined,
      r.kind,
    );
    if(r.applicationZone){
      icon=element('span','', 'application-zone-icon');
      icon.innerHTML='<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M1 2h14L10 8v6l-4-2V8z"/></svg>';
      icon.title='Application + '+zoneLabel(r.applicationZone.zone)+' filter';
    }
    if (r.socket) {
      const direction = initiationPresentation(r.socket);
      icon = element('span', direction.glyph, 'connection-direction ' + direction.className);
      icon.title = direction.title;
      icon.setAttribute('role', 'img');
      icon.setAttribute('aria-label', direction.label);
      if (direction.state === 'listening') rowLabel = r.socket.socket.local;
      if (direction.state === 'unconnected') rowLabel = r.socket.socket.local;
    }
    // Every row uses the identical slot. Hover explains the observation;
    // clicking also opens the persistent Info panel.
    const clickable=r.kind==='application'&&!r.applicationZone;
    const led=element(clickable?'button':'span','','connection-status-slot');
    if(clickable) {
      (led as HTMLButtonElement).type='button';
      led.onclick=(event)=>{
        event.stopPropagation();selected=r.id;
        for(const row of document.querySelectorAll<HTMLElement>('#rows tr')) row.setAttribute('aria-selected',String(row.dataset.id===selected));
        renderInfo();void window.flowgate.paneControl('info','open').catch(message);
      };
    } else led.setAttribute('aria-hidden','true');
    updateConnectionStatus(led,r);
    if(!r.inactive) tr.title=led.title;
    const textLabel = element('span', rowLabel, 'row-name-text');
    if (r.kind === 'application' && displayKey && !r.applicationZone) textLabel.dataset.displayKey = displayKey;
    name.append(led, toggle, icon, textLabel);
    if (r.identityNote) name.append(element('span', ' · ' + r.identityNote, 'row-inactive-note'));
    if (r.requestEvent && !r.process && !r.inactive && !r.rows.length)
      name.append(element('span', awaiting(r.requestEvent) ? ' · awaiting permission' : ' · recent request, no observed socket', 'row-inactive-note'));
    if (r.inactive && (r.inactive.earlierVersion || r.inactive.where))
      name.append(
        element(
          'span',
          (r.inactive.earlierVersion ? ' · earlier version' : '') +
            (r.inactive.where ? ' · ' + r.inactive.where : ''),
          'row-inactive-note',
        ),
      );
    name.title = r.process?.executable || r.inactive?.executable || r.socket?.socket.remote || r.label;
    tr.append(name);
    for (const key of rateKeys()) {
      const s = sum(r.rows, key, measurementSource);
      const td = element(
        'td',
        displayMetric(s, rateMode === 'rate'),
        'numeric ' + (s.value && s.value > 0 ? (key.startsWith('download') ? 'down' : 'up') : ''),
      );
      const rateText = td.textContent || '';
      td.replaceChildren(element('span', rateText, 'rate-value'));
      td.title = `${measurementSource.toUpperCase()} · ${s.known}/${s.count} measured sockets${s.mixed ? ' · incompatible measurement sources' : ''}`;
      tr.append(td);
    }
    tr.append(statusStrip(r));
    tr.append(
      element('td', r.applicationZone?'—':String(r.rows.length), 'numeric'),
      element('td', r.pid === undefined ? '' : String(r.pid), 'numeric'),
    );
    for (const key of ['downloaded', 'uploaded'] as Metric[])
      tr.append(element('td', displayMetric(sum(r.rows, key, measurementSource)), 'numeric'));
    for (const value of [
      r.socket?.socket.protocol,
      r.socket?.socket.local,
      r.socket?.socket.remote,
      r.socket?.state,
    ]) {
      const td = element('td', value ?? '');
      td.title = value ?? '';
      tr.append(td);
    }
    tr.append(element('td', '', 'filler'));
    // Replace the old keyed node in place before ordering. Leaving it in tbody
    // shifts every following sibling and turns one selection change into N moves.
    replaceKeyedRow(cached?.node, tr);
    renderedRows.set(r.id, {
      signature: rowSignature,
      presentation: cellPresentation,
      policyRevision: treePolicyRevision,
      node: tr,
    });
    ordered.push(tr);
  }
  for (const [id, cached] of renderedRows)
    if (!liveIds.has(id)) {
      cached.node.remove();
      renderedRows.delete(id);
    }
  for (let i = 0; i < ordered.length; i++)
    if (body.children[i] !== ordered[i]) body.insertBefore(ordered[i], body.children[i] || null);
  while (body.children.length > ordered.length) body.lastElementChild!.remove();
  if (focusedPolicy)
    for (const row of body.querySelectorAll<HTMLElement>('tr'))
      if (row.dataset.id === focusedPolicy.id)
        row
          .querySelector<HTMLButtonElement>(
            `.policy-cell[data-direction="${focusedPolicy.direction}"]`,
          )
          ?.focus({ preventScroll: true });
  for (const th of Array.from($('headers').children)) {
    const key = th.className.slice(4);
    th.setAttribute('aria-sort', key === sort ? (descending ? 'descending' : 'ascending') : 'none');
  }
}
function renderInfo() {
  syncSelection();
  void graph?.update(selected, sequence);
  const live = $('info');
  const info = element('dl');
  const commit = () => {
    const details = element('details', '', 'info-technical');
    details.open = !!live.querySelector('details[open]');
    details.append(element('summary', 'Identity and measurement details'));
    const technical = element('dl');
    for (const dt of Array.from(info.querySelectorAll('dt'))) {
      if (
        [
          'Executable',
          'Executable status',
          'Recorded caller paths',
          'Script',
          'Identity',
          'Totals',
          'Evidence',
          'Socket identity',
          'Ownership evidence category',
          'Measurement',
          'Rule inventory',
          'Incoming rule scopes',
          'Outgoing rule scopes',
        ].includes(dt.textContent || '')
      ) {
        const dd = dt.nextElementSibling;
        technical.append(dt);
        if (dd) technical.append(dd);
      }
    }
    if (technical.childElementCount) {
      details.append(technical);
      info.append(details);
    }
    // Preserve text selection and expanded details during unchanged polling.
    if (live.textContent !== info.textContent) live.replaceChildren(...Array.from(info.childNodes));
  };
  const liveRow = allRows(roots).find((r) => r.id === selected);
  if (liveRow && ['process', 'socket'].includes(liveRow.kind))
    retainedSelection = { generation: state.control.generation, row: liveRow };
  else if (
    liveRow ||
    retainedSelection?.row.id !== selected ||
    retainedSelection.generation !== state.control.generation
  )
    retainedSelection = undefined;
  const retained = !liveRow && retainedSelection?.row;
  const r = liveRow || (retained ? { ...retained, rows: [], children: [] } : undefined);
  // Not running: no live policy summary; its rules are listed in Info View and edited from its In/Out cells.
  activityPolicy?.update(r?.inactive ? undefined : r, state);
  $('infoProperties').textContent =
    r?.kind === 'socket'
      ? 'Connection properties'
      : r?.kind === 'process'
        ? 'Process properties'
        : r?.kind === 'application'
          ? 'Application properties'
          : r?.kind === 'launch'
            ? 'Launch properties'
            : 'Overview';
  const selectedApp = r?.process?.application || r?.displayApplication;
  const rawPath = r?.process?.executable || r?.displayApplication?.executable || '';
  const pathText = selectedApp?.display_executable || rawPath.replace(/ \(deleted\)$/, '');
  if ($('selectedExecutable').textContent !== pathText)
    $('selectedExecutable').textContent = pathText;
  $('selectedExecutable').title =
    rawPath +
    (rawPath.endsWith(' (deleted)')
      ? ' · Running replaced/deleted executable; original identity retained.'
      : '');
  $('selectedExecutable').hidden = !pathText;
  const selectedName = $('selectedName');
  if (selectedName.dataset.identity !== (r?.id || '') || selectedName.dataset.label !== (r?.label || '')) {
    selectedName.dataset.identity = r?.id || '';
    // The chart legend names the selected entity (reference), not the type word shown as title.
    selectedName.dataset.label = r?.label || '';
    selectedName.replaceChildren(
      ...(r ? [installedIcon(r.displayApplication || rowApplication(r), r.kind)] : []),
      document.createTextNode(
        !r
          ? 'FlowGate Activity'
          : r.kind === 'application'
            ? 'Application'
            : r.kind === 'launch'
              ? 'Game launch'
              : r.kind === 'process'
              ? `Process ${r.pid ?? ''}`.trim()
              : r.kind === 'socket'
                ? 'Connection'
                : r.kind === 'unidentified'
                  ? 'Unidentified'
                  : r.label,
      ),
    );
  }
  if (!r) {
    field(
      info,
      'Selection',
      selected
        ? 'Selected socket is no longer visible.'
        : 'Select an application, process or connection.',
    );
    commit();
    return;
  }
  if (retained)
    field(
      info,
      'Observation',
      'Selected instance is no longer visible. No target is rebound; reselect a live instance to create a rule.',
    );
  if (r.kind === 'network') {
    field(info, 'Network', r.label);
    const config = state.control.networkZones;
    field(info, 'Target', 'All programs · configured ' + r.label + ' policy zone');
    field(
      info,
      'Coverage',
      config
        ? 'Traffic totals unavailable; UDP socket totals may span peers.'
        : NETWORK_UNAVAILABLE,
    );
    if (config) {
      field(info, 'Definition', config.model);
      field(
        info,
        'Prefixes',
        (r.id === 'network:local' ? config.local_prefixes : config.internet_prefixes).join(', ') ||
          'No configured prefixes',
      );
    }

    commit();
    return;
  }
  if (r.kind === 'inactive-group') {
    field(info, 'Programs', String(r.children.length));
    field(info, 'Status', 'Saved programs without a currently observed running instance. Expand to view or edit their individual rules.');
    commit();
    return;
  }
  if (r.kind === 'program') {
    field(info, 'Program', r.label);
    field(info, 'Executable', r.program?.executable || '');
    field(info, 'Accounts and identities', r.children.map(c => c.presentationLabel || c.label).join('\n'));
    field(info, 'Permissions', 'Expand this program to edit each account separately. This group does not grant or combine permissions.');
    commit();
    return;
  }
  if (r.kind === 'launch') {
    const prov = r.children.find((c) => c.process?.provenance)?.process?.provenance;
    field(info, 'Game', r.label);
    if (prov?.launch?.game) field(info, 'Executable', prov.launch.game.executable);
    if (prov?.launch)
      field(
        info,
        'Launch',
        `${prov.launch.kind} · ${prov.launch.launcher_name} PID ${prov.launch.launcher_pid}${prov.launch.runtime ? ' · ' + prov.launch.runtime : ''}`,
      );
    if (prov?.launch?.prefix) field(info, 'Prefix', prov.launch.prefix);
    field(info, 'Processes', r.children.map((c) => c.label).join('\n'));
    field(
      info,
      'Observation only',
      'Grouped by verified launch provenance (unbroken parent chain). Not a firewall target: each process keeps its own application identity and rules.',
    );
    commit();
    return;
  }
  if (r.kind === 'overview') {
    field(
      info,
      'Scope',
      state.control.permissions?.observation_scope === 'machine'
        ? 'Machine · current network namespace'
        : 'Visible sockets · current network namespace',
    );
    // Nested (launched-by) applications are applications too.
    field(info, 'Applications', String(allRows(r.children).filter((c) => c.kind === 'application').length));
    field(info, 'Sockets', String(r.rows.length));
    const evidence = state.observation.activity?.tcp_initiation;
    field(
      info,
      'TCP initiation',
      evidence
        ? evidence.state + ' · ' + evidence.reason
        : 'Snapshot evidence only; established direction may be unknown.',
    );
    field(
      info,
      'Measurement',
      'TCP transport payload and UDP API-reported payload are shown separately. Socket sums include local perspectives; they are not deduplicated internet usage.',
    );
    field(
      info,
      'Coverage',
      state.observation.activity?.complete ? 'Complete visible census' : 'Partial visibility',
    );
    commit();
    return;
  }
  if(r.applicationZone){
    const status=ruleStatus(r,state);
    field(info,'Name',r.label);
    field(info,'Scope',`${zoneLabel(r.applicationZone.zone)} · ${r.applicationZone.model==='automatic-peer-v1'?'automatic':'legacy configured prefixes'}`);
    field(info,'Target',`${r.process?.application.display_name||r.process?.application.name||r.inactive?.executable||r.applicationZone.parentLabel} · application/revision/user, not all programs`);
    field(info,'Rules',[...status.incoming,...status.outgoing].map(x=>ruleDescription(x,status.now)).join('\n')||'No own rule in this zone. Parent/application and global policies may still apply.');
    field(info,'Edit','Use this row’s In or Out control. Multiple rules are listed separately; parent Any-network rules are not edited here.');
    field(info,'Measurement','Zone-attributed traffic intervals are not supplied by the backend; no lifetime totals are relabelled.');
    field(info,'Enforcement',state.control.protection?.state||state.control.enforcement?.state||'Unknown');
    commit();return;
  }
  if(r.kind==='application'&&!r.applicationZone) {
    const details=appFastPathDetails(r.rows);
    field(info,'Fast path',details?.title||'No UDP fast-path evidence for this application. The dot describes an observed connected peer, not permission or delivery.');
  }
  if (r.runtimeApplication) {
    const a=r.runtimeApplication;
    field(info,'Windows application',a.application.executable);
    if (a.display_source==='last-verified-partial-snapshot') field(info,'Identity observation',`Last verified at ${a.display_verified_at||'unknown'}. Current collection is incomplete: visible holders are an unchanged, non-empty subset of the previously verified holders. Retained for at most 3 seconds; missing holders are not claimed as currently observed. Display only, not authorization evidence.`);
    if (a.display_source==='last-verified-snapshot') field(info,'Identity observation',`Last verified at ${a.display_verified_at||'unknown'}. Retained for at most 3 seconds while fresh Wine annotation is unavailable; this exact socket and its visible holders are unchanged. Display only, not authorization evidence.`);
    if (a.display_source==='established-grant') field(info,'Identity observation','Last verified identity from initial authorization of this still-observed exact socket. Reused for display while fresh activity annotation is unavailable; not a new ownership census.');
    field(info,'Wine prefix',a.evidence.prefix);
    field(info,'Windows ownership',a.evidence.windows_handle_holders.map(h=>`PID ${h.pid} · creation ${h.creation_time} · ${h.image}`).join('\n'));
    field(info,'Unix socket holder',`wineserver PID ${a.evidence.broker_pid}, start ${a.evidence.broker_start_ticks}; socket cookie ${a.evidence.socket_cookie}`);
    field(info,'Rule identity',`${a.application.key} · revision ${a.application.revision} · ${accountLabel(a.uid)}`);
  }
  if (r.requestEvent) {
    const e=r.requestEvent;
    field(info, 'Last request', `${e.state} · ${e.flow.direction} ${e.flow.protocol} · ${e.flow.remote}`);
    field(info, 'Request reason', e.reason || 'Awaiting decision');
    if (e.attribution.reason_code)
      field(info, 'Recorded attribution category', `${attributionReasonLabel(e.attribution.reason_code)} (${e.attribution.reason_code})`);
    field(info, 'Recorded executable', e.attribution.application?.executable || 'Unknown');
    field(info, 'Recorded caller', e.attribution.owners.map(p => `${p.pid} · ${p.provenance?.invocation?.path || p.provenance?.parent?.invocation?.path || p.provenance?.parent?.executable || 'caller unavailable'}`).join('\n'));
    field(info, 'Observation', 'Request evidence retained by the daemon; absence of a current socket does not establish that the process exited.');
    if (awaiting(e) || requestRuleAvailable(e, state.control.capabilities)) {
      const review=element('button', awaiting(e) ? 'Review pending request' : 'Create rule for future connections');
      review.onclick=()=>{selectRequest(e.id); $('requestsTab').click(); renderRequests();};
      info.append(review);
    }
  }
  if (r.displayApplication && !r.requestEvent) {
    field(info, 'Display application', r.displayApplication.executable);
    field(
      info,
      'Observation only',
      'Common application of shared holders. Not a firewall permission target.',
    );
  }
  if (r.kind === 'application' || r.kind === 'process')
    field(
      info,
      'Name',
      r.process?.application
        ? appNames.get(
            JSON.stringify([
              r.process.application.key,
              r.process.application.revision,
              r.process.application.executable,
            ]),
          ) ||
            r.process.application.display_name ||
            r.process.application.name.replace(/ \(deleted\)$/, '')
        : r.inactive
          ? r.presentationLabel || appNames.get(JSON.stringify([r.inactive.key, r.inactive.revision, r.inactive.executable])) || r.label
          : r.label,
    );
  if (r.inactive) {
    // Not running: only its stored rules are known; nothing is observed or verified now.
    field(info, 'State', 'Not currently observed · listed because stored rules name this application');
    if (r.inactive.followsUpdates)
      field(info, 'Version', 'Rules follow updates of this program: same verified executable path, user and prefix; any revision. Newest recorded revision is shown below.');
    else if (r.inactive.earlierVersion)
      field(info, 'Version', 'Earlier version (the executable changed since these rules were made); they do not apply to the current file');
    field(info, 'Executable', r.inactive.executable);
    if (r.inactive.invocations?.length) {
      field(info, 'Recorded scripts', r.inactive.invocations.join('\n'));
      field(info, 'Permission scope', 'These rules match the interpreter executable, not only the named script. Script context was recorded when the rule was created.');
    }
    field(info, 'User', accountLabel(r.inactive.uid));
    field(info, 'Identity', `${r.inactive.key}\nRevision: ${r.inactive.revision}`);
    const callers = applicationCallers.forApplication(r.inactive.key,r.inactive.revision,r.inactive.uid);
    const nodeRuntime = /^(node|nodejs)$/.test(r.inactive.executable.split('/').pop()||'');
    if(callers.length){
      field(info,'Recorded callers',callers.map(c=>`${c.name} · ${new Date(c.captured).toLocaleString()}`).join('\n'));
      field(info,'Caller evidence','Recent connection snapshots, not the creator of this rule. Historical processes may have ended.');
      field(info,'Recorded caller paths',callers.map(c=>`${c.executable}\nCaller PID ${c.pid} · start ${c.start} · socket-owner PID ${c.ownerPid}\nRequest ${c.request} · captured ${c.captured}`).join('\n\n'));
    }else if(nodeRuntime)field(info,'Recorded callers','Unavailable: no caller snapshot retained for this identity.');
    if(nodeRuntime)field(info,'Script','No script path was retained in this stored executable identity.');

    const now = state.control.serverNow ?? Date.now();
    const rules = (state.control.rules || []).filter((x) => inactiveRuleMatches(r.inactive!, x) && (!r.applicationZone || matchesApplicationZone(x.filter, r.applicationZone)));
    field(info, 'Rules', rules.map((x) => ruleDescription(x, now)).join('\n') || 'None');
    field(info, 'Edit', 'Add or edit saved rules without starting the program. Select its Local Network or Internet row for network-specific permissions.');
    const controls = element('dd');
    for (const direction of ['incoming', 'outgoing'] as const) {
      const edit = element('button', direction === 'incoming' ? 'Incoming rules…' : 'Outgoing rules…');
      edit.type = 'button';
      edit.onclick = () => showInactiveRules(edit, r, direction);
      controls.append(edit);
    }
    info.append(element('dt', 'Manage rules'), controls);
  }
  if (r.revisions && r.revisions.length > 1)
    field(info, 'Running revisions', r.revisions.join('\n') + '\nSame verified program and user; each process keeps its own exact identity.');
  if (r.foldedVersions?.length) {
    // Saved rules of other revisions of this program/user: listed with their exact
    // scope, never presented as separate programs and never merged into another scope.
    const now = state.control.serverNow ?? Date.now();
    field(info, 'Other recorded versions', r.foldedVersions.map((v) => {
      const rules = (state.control.rules || []).filter((x) => inactiveRuleMatches(v, x));
      return `${v.followsUpdates ? 'Rules following updates' : `Revision ${v.revision} only`} · ${v.executable}\n` +
        (rules.map((x) => ruleDescription(x, now)).join('\n') || 'None');
    }).join('\n\n'));
  }
  if (r.kind === 'application' && r.parent?.startsWith('app:')) {
    // Grouped beneath the verified application that launched it (display only).
    const launcher = r.process?.provenance?.parent;
    field(
      info,
      'Launched by',
      `${appNames.get(JSON.stringify([launcher?.application?.key, launcher?.application?.revision, launcher?.application?.executable])) || launcher?.application?.display_name || launcher?.name || 'verified application'}` +
        ' · verified process chain. Display only: its own rules apply; allowing the launcher grants it nothing.',
    );
  }
  if (r.process) {
    if (
      r.process.application.executable_status === 'deleted' ||
      r.process.executable.endsWith(' (deleted)')
    )
      field(
        info,
        'Executable status',
        'Replaced/deleted on disk; this running image retains its original identity. Installed icon/name are display metadata only.',
      );
    field(info, 'Executable', r.process.executable);
    field(info, 'User', accountLabel(r.process.uid));
    field(
      info,
      'Identity',
      `${r.process.application.key}\nRevision: ${r.process.application.revision}`,
    );
    const launch = r.process.provenance;
    if (launch && launch.evidence !== 'none')
      field(
        info,
        'Launch provenance',
        launch.evidence === 'verified' && launch.launch
          ? `${launch.role || 'process'} of ${launch.launch.game?.name || launch.launch.launcher_name} · ${launch.launch.kind} launcher PID ${launch.launch.launcher_pid}${launch.launch.prefix ? '\nPrefix ' + launch.launch.prefix : ''}\nDisplay only; rules use this process's own identity.`
          : `Unavailable · ${launch.reason}`,
      );
    if (r.kind === 'process')
      field(
        info,
        'Process',
        `${r.process.thread_group_pid ? `Worker TID ${r.process.pid} · thread-group PID ${r.process.thread_group_pid}` : r.process.pid} · start ${r.process.start_ticks} · ${accountLabel(r.process.uid)}`,
      );
  }
  if (r.socket) {
    const s = r.socket;
    if (isKernelTimeWait(s)) field(info, 'Lifecycle', KERNEL_LIFECYCLE_EXPLANATION);
    for (const [label, value] of [
      ['Protocol', s.socket.protocol],
      ['Fast path', fastPathIndicator(s).label+' · '+fastPathIndicator(s).title],
      ['Local endpoint', s.socket.local],
      ['Remote endpoint', s.socket.remote],
      ['State', s.state],
      ['Initiation', initiationPresentation(s).title],
      ['Ownership', s.ownership],
      ['Ownership evidence category', ownershipExplanation(s.ownership_category)],
      ['Socket creation user', accountLabel(s.socket.uid)],
      ...(s.display_application
        ? [
            [
              'Display association',
              `${s.display_application.name || s.display_application.executable} · observation only, not a permission target`,
            ],
          ]
        : []),
      ['Evidence', s.evidence],
      [
        'Network zone',
        scopeZoneText(s.network_scope),
      ],
      ['Measurement', trafficDetails(s.traffic)],
      ['Socket identity', `${s.socket.netns} · ${s.socket.cookie}`],
    ])
      field(info, label, value);
    for (const id of s.owners) {
      const p = state.observation.activity?.processes[id];
      field(
        info,
        'Visible holder',
        p
          ? `${p.thread_group_pid ? `Worker TID ${p.pid} · thread-group PID ${p.thread_group_pid}` : p.pid} · ${p.executable}`
          : id,
      );
    }
  } else {
    field(info, 'Visible sockets', String(r.rows.length));
    field(
      info,
      'Totals',
      'Currently visible socket intervals, not historical bytes exclusively transferred by this owner.',
    );
    const s = sum(r.rows, 'uploaded');
    field(
      info,
      'Coverage',
      `${s.known}/${s.count} supported sockets${s.mixed ? ' · mixed sources are not summed' : ''}`,
    );
    if (r.kind === 'unidentified')
      field(
        info,
        'Ownership',
        'Unresolved and mixed-application shared sockets, counted once. This group is not an application or permission target.',
      );
    if (r.kind === 'kernel-lifecycle') field(info, 'Lifecycle', KERNEL_LIFECYCLE_EXPLANATION);
  }
  commit();
}
function eventName(e: ViewEvent) {
  return (
    e.attribution.application?.display_name ||
    e.attribution.application?.name.replace(/ \(deleted\)$/, '') ||
    e.attribution.application?.executable ||
    'Unidentified application'
  );
}
// The permission window keeps showing a request decided "For a while" while
// its lease is active (main.ts holds the card), even after the list drops it.
let decidedEvent: ViewEvent | undefined;
function currentEvent() {
  if (promptID && promptGeneration !== state?.control.generation) return undefined;
  const found = state?.control.events.find((e) => e.id === selectedRequest);
  if (found || !promptID) {
    if (promptID) decidedEvent = found;
    return found;
  }
  return decidedEvent?.id === selectedRequest && leaseHolds(state.control, selectedRequest)
    ? decidedEvent
    : undefined;
}
function actionable(e: ViewEvent | undefined) {
  return (
    !!e &&
    state.control.connected &&
    canDecide(state.control) &&
    e.state === 'awaiting-decision' &&
    e.remainingMs > 0 &&
    !e.attempt &&
    !reviewFailureOf(e) &&
    !localSubmitted.has(state.control.generation + ':' + e.id) &&
    !!e.scope_previews[chosenScope]
  );
}
function selectRequest(id: string) {
  selectedRequest = id;
  chosenScope = 'once';
  decisionZone = 'any';
  resetRemember();
  clearTimeout(reviewTimer);
  decisionReviews = {};
  reviewFor = '';
  reviewMessage = '';
  ++reviewSequence;
  cardNote = undefined;
  ++ruleSequence;
  ruleChecking = false;
  ruleMessage = '';
  endedFlow.clearReviews();
  detailSignature = '';
}
function renderRequests() {
  const events = state.control.events,
    groups = requestGroups(events);
  if (!promptID) {
    // Settled/finalized/expired requests leave at once; selection moves to the
    // next group unless the user is following their own decision's result.
    const selected = events.find((e) => e.id === selectedRequest);
    if (
      !selected ||
      !(
        awaiting(selected) ||
        selected.attempt ||
        reviewFailureOf(selected) ||
        requestRuleAvailable(selected, state.control.capabilities) ||
        localSubmitted.has(state.control.generation + ':' + selected.id)
      )
    ) {
      const next = groups[0]?.representative.id ?? '';
      if (next !== selectedRequest && (next || selected)) selectRequest(next);
    }
  }
  const selectedGroup = (() => {
    const s = events.find((e) => e.id === selectedRequest);
    return s ? groupKey(s) : '';
  })();
  const signature = JSON.stringify([
    selectedGroup,
    state.control.generation,
    state.control.connected,
    state.control.readOnly,
    state.control.permissions,
    groups.map((g) => [g.key, g.representative.id, g.count, g.representative.attempt?.phase]),
  ]);
  if (!promptID && signature !== eventSignature) {
    eventSignature = signature;
    const body = $('requestRows');
    body.replaceChildren();
    for (const g of groups) {
      const e = g.representative,
        tr = element('tr');
      tr.dataset.id = e.id;
      tr.dataset.group = g.key;
      tr.tabIndex = 0;
      tr.setAttribute('aria-selected', String(selectedGroup === g.key));
      for (const v of [
        eventName(e),
        e.flow.direction,
        e.flow.protocol,
        e.flow.remote,
        String(g.count),
        e.attempt ? e.attempt.phase : 'awaiting decision',
      ])
        tr.append(element('td', v));
      tr.title =
        g.count > 1
          ? `${g.count} similar requests. A decision answers the oldest one; Remember also settles the others it covers.`
          : '';
      const select = () => {
        // Always the group's current representative; a decision never fans out.
        const current = requestGroups(state.control.events).find((x) => x.key === g.key);
        selectRequest(current?.representative.id ?? e.id);
        renderRequests();
      };
      tr.onclick = select;
      tr.onkeydown = (k) => {
        if (k.key === 'Enter' || k.key === ' ') {
          k.preventDefault();
          select();
        }
      };
      body.append(tr);
    }
  }
  const e = currentEvent();
  const sig = JSON.stringify([
    selectedRequest,
    state.control.generation,
    e ? [e.id, e.flow, e.attribution, e.deadline, e.scope_previews] : null,
    rememberMode(),
    forAWhileMode(),
    forAWhileDurations(state.control),
    e?.previous_revision_rules,
    e ? pairSignature(e, state.control.events) : null,
  ]);
  if (sig !== detailSignature) {
    detailSignature = sig;
    const container = $('requestDetails');
    container.replaceChildren();
    if (!e) {
      container.append(
        element(
          'p',
          promptID && promptGeneration !== state.control.generation
            ? 'Daemon session changed. This old request is no longer actionable.'
            : selectedRequest
              ? 'Request no longer present. It may have expired or been resolved by another client.'
              : 'No pending connection selected.',
          'hint',
        ),
      );
      return;
    }
    container.tabIndex = -1;
    container.onkeydown = (event) => {
      if (event.key === 'Enter' && event.target === container) event.preventDefault();
    };
    container.append(
      ...buildRequestCard(e, {
        name: eventName(e),
        rememberMode: rememberMode(),
        forAWhile: forAWhileMode(),
        rememberOptions: rememberOptions(e, eventName(e)),
        forAWhileDurations: forAWhileDurations(state.control),
        pair: localPairView(e, state.control.events, state.control.capabilities),
        gameApplication: gameApplication(e),
        detailsOpen: detailsOpenFor === e.id,
        onDetails: (open) => {
          detailsOpenFor = open ? e.id : '';
          measurePrompt();
        },
      }),
    );
    const controls = $('decisionControls'),
      dock = $('decisionDock');
    for (const action of ['allow', 'block'] as const)
      $<HTMLButtonElement>(action).onclick = () => void decideFromCard(e.id, action);
    const rememberBox = $<HTMLInputElement>('rememberToggle');
    if (rememberBox) {
      rememberBox.checked = rememberOn;
      rememberBox.onchange = () => setOption('remember', rememberBox.checked);
    }
    const whileBox = $<HTMLInputElement>('forAWhileToggle');
    if (whileBox) {
      whileBox.checked = forAWhileOn;
      whileBox.onchange = () => setOption('forAWhile', whileBox.checked);
    }
    const leaseDuration = $<HTMLSelectElement>('forAWhileDuration');
    if (leaseDuration) {
      if (!forAWhileDurations(state.control).includes(forAWhileSeconds))
        forAWhileSeconds = defaultForAWhile(savedForAWhile, forAWhileDurations(state.control));
      leaseDuration.value = String(forAWhileSeconds);
      leaseDuration.onchange = () => {
        const seconds = Number(leaseDuration.value);
        if (!forAWhileDurations(state.control).includes(seconds)) return;
        forAWhileSeconds = savedForAWhile = seconds;
        cardNote = undefined;
        void window.flowgate.preferences({ forAWhileSeconds: seconds }).catch(() => {});
        updateDecisions();
      };
    }
    const panel = $('rememberPanel');
    if (panel) {
      for (const input of panel.querySelectorAll<HTMLInputElement>('input[data-field]')) {
        const field = input.dataset.field as keyof RememberFields | 'application';
        if (field === 'application') continue;
        input.checked = rememberFields[field];
        input.onchange = () => {
          rememberFields = { ...rememberFields, [field]: input.checked };
          cardNote = undefined;
          invalidateReview();
        };
      }
      const duration = $<HTMLSelectElement>('rememberDuration');
      duration.value = String(rememberDuration);
      duration.onchange = () => {
        rememberDuration = Number(duration.value);
        syncRememberScope();
        invalidateReview(0);
      };
      $('refreshDecision').onclick = () =>
        void (endedRuleMode(currentEvent()) ? prepareRequestRule() : prepareDecisions());
    }
    if (!rememberMode()) {
      // Legacy backend (no Remember fields): scope list and reviewed network scope.
      const scopes = element('select');
      scopes.id = 'scope';
      scopes.setAttribute('aria-label', 'Permission scope');
      const offered = Object.keys(e.scope_previews) as Scope[];
      if (!offered.includes(chosenScope)) chosenScope = offered[0] ?? 'once';
      for (const key of offered) {
        const option = element('option', scopeLabels[key]);
        option.value = key;
        scopes.append(option);
      }
      scopes.value = chosenScope;
      scopes.onchange = () => {
        chosenScope = scopes.value as Scope;
        void prepareDecisions();
      };
      controls.append(scopes);
      const networks = element('div', '', 'decision-network');
      const networkLabel = element('label', 'Remember on ');
      const zone = element('select');
      zone.id = 'decisionZone';
      zone.setAttribute('aria-label', 'Remember network scope');
      zone.append(new Option('Any network', 'any'));
      if (
        state.control.capabilities?.includes(REMEMBER_ZONE_CAPABILITY) &&
        e.flow.network_scope?.state === 'known' &&
        e.flow.network_scope.revision === state.control.networkZones?.revision
      )
        zone.append(new Option(zoneLabel(e.flow.network_scope.zone), e.flow.network_scope.zone));
      zone.value = decisionZone;
      if (!zone.value) {
        decisionZone = 'any';
        zone.value = 'any';
        decisionReviews = {};
      }
      zone.onchange = () => {
        decisionZone = zone.value as typeof decisionZone;
        void prepareDecisions();
      };
      networkLabel.append(zone);
      networks.append(networkLabel);
      const refresh = element('button', 'Refresh review', 'link-button');
      refresh.id = 'refreshDecision';
      refresh.onclick = () => void prepareDecisions();
      networks.append(refresh);
      controls.after(networks);
    }
    const reconcile = $<HTMLButtonElement>('decisionReconcile');
    reconcile.onclick = async () => {
      const current = currentEvent(),
        token = current?.attempt?.reconcile;
      if (!current || !token) return;
      reconcile.disabled = true;
      const submitted = state.control.generation;
      try {
        const result = await window.flowgate.decisionReconcile({
          generation: submitted,
          id: current.id,
          preview_token: token,
        });
        recordDecisionResult(cardResults, current.id, submitted, state.control.generation, { text: shortAttempt(result, current), detail: result.message, phase: result.phase });
      } catch (error) {
        note(current, shortError(errorText(error)), errorText(error));
      } finally {
        updateDecisions();
      }
    };
    const future = $<HTMLButtonElement>('futureApplicationRule');
    future.onclick = async () => {
      const original = currentEvent();
      if (!original || !reviewFailureOf(original)) return;
      future.disabled = true;
      try {
        await window.flowgate.openFutureApplicationRule({ generation: state.control.generation, id: original.id });
        note(original, 'Application-rule editor opened. The original connection was not allowed.');
      } catch (error) {
        note(original, shortError(errorText(error)), errorText(error));
      } finally {
        updateDecisions();
      }
    };
    if (!promptID) {
      const open = element('button', 'Open permission window', 'open-prompt');
      open.type = 'button';
      open.onclick = () => void window.flowgate.openPrompt(e.id);
      dock.after(open);
    }
  }
  updateDecisions();
}
function shortAttempt(a: Attempt, e?: ViewEvent) {
  if (a.phase === 'submitting') return 'Submitting…';
  if (a.phase === 'unknown')
    return a.reconcile ? 'Result unknown · no retry sent. Use Check result.' : 'Result unknown · no retry sent.';
  if (a.phase === 'rejected') return 'Not decided: ' + shortError(a.message.replace(/^Backend rejected: /, ''));
  const verdict = /\bblocked\b/.test(a.message) || e?.state === 'blocked' ? 'Denied' : 'Allowed';
  return a.scope === 'for-a-while'
    ? a.leaseUntil
      ? `${verdict} for a while (until ${new Date(a.leaseUntil).toLocaleTimeString()}).`
      : `${verdict} for a while.`
    : a.rule
      ? `${verdict} · rule saved.`
      : `${verdict} once.`;
}
async function decideFromCard(id: string, action: 'allow' | 'block') {
  syncRememberScope();
  const e = currentEvent();
  if (!e || e.id !== id || (Boolean(promptID) && (!promptLayoutReady || performance.now() < promptStableAt)))
    return;
  const plan = promptPlan(e, action, {
    generation: state.control.generation,
    zoneRevision: state.control.networkZones?.revision || '',
    capabilities: state.control.capabilities,
    forAWhile: forAWhileOn,
    forAWhileSeconds,
    remember: rememberMode() && rememberOn,
    fields: rememberFields,
    duration: rememberDuration,
    pairIds: localPairView(e, state.control.events, state.control.capabilities)?.pairIds,
  });
  if (plan.kind === 'unavailable') return note(e, plan.note);
  if (plan.kind === 'pair') {
    // One click answers both hooks of this exact connection (Once); the backend
    // confirms the pair and returns both verdicts, or refuses without a change.
    if (!state.control.connected || !canDecide(state.control)) return;
    const keys = plan.choice.ids.map((x) => state.control.generation + ':' + x);
    if (keys.some((k) => localSubmitted.has(k))) return;
    keys.forEach((k) => localSubmitted.add(k));
    cardNote = undefined;
    updateDecisions();
    try {
      const r = await window.flowgate.decidePair(plan.choice);
      cardResults.set(e.id, { text: r.text, detail: r.message });
    } catch (error) {
      keys.forEach((k) => localSubmitted.delete(k));
      note(e, shortError(errorText(error)), errorText(error));
    }
    updateDecisions();
    return;
  }
  if (plan.kind === 'ended-lease') {
    // A process lease only: the ended request is never decided or delivered.
    if (endedLeaseBusy.has(e.id) || endedLeaseDone.has(e.id)) return;
    endedLeaseBusy.add(e.id);
    cardNote = undefined;
    updateDecisions();
    try {
      const r = await window.flowgate.requestForAWhile(plan.choice);
      endedLeaseDone.add(e.id);
      cardResults.set(e.id, { text: endedLeaseResult(r.lease), detail: r.message });
    } catch (error) {
      note(e, shortError(errorText(error)), errorText(error));
    } finally {
      endedLeaseBusy.delete(e.id);
      updateDecisions();
    }
    return;
  }
  if (plan.kind === 'request-rule') {
    // Never a decision for the ended request: a rule for future connections.
    if (!state.control.connected || !canManageRules(state.control))
      return note(e, 'Rule management is unavailable.');
    if (ruleBusy.has(e.id)) return;
    ruleBusy.add(e.id);
    cardNote = undefined;
    updateDecisions();
    try {
      const outcome = await endedFlow.save(plan.choice, state.control.serverNow || Date.now());
      if (outcome.phase === 'saved') cardResults.set(e.id, { text: outcome.text, detail: outcome.detail });
      else {
        cardNote = { id: e.id, text: outcome.text, detail: outcome.detail };
        if (outcome.phase === 'refused' && !endedFlow.pinned.has(e.id)) void prepareRequestRule();
      }
    } finally {
      ruleBusy.delete(e.id);
      updateDecisions();
    }
    return;
  }
  if (!actionable(e)) return;
  const preview = decisionReviews[action];
  if (
    needsDecisionReview() &&
    (reviewFor !== reviewKey() ||
      !preview ||
      Date.parse(preview.expires_at) <= (state.control.serverNow || Date.now()))
  )
    return;
  const decision = decisionFor(action, e, needsDecisionReview() ? preview : undefined),
    key = state.control.generation + ':' + e.id;
  localSubmitted.add(key);
  cardNote = undefined;
  updateDecisions();
  try {
    const result = await window.flowgate.decide(decision);
    recordDecisionResult(cardResults, e.id, decision.generation, state.control.generation, { text: shortAttempt(result, e), detail: result.message, phase: result.phase });
  } catch (error) {
    // Thrown before or instead of a decision (e.g. For a while refused): nothing
    // was decided, so the request stays answerable with another choice.
    localSubmitted.delete(key);
    note(e, shortError(errorText(error)), errorText(error));
  }
  updateDecisions();
}
const ruleBusy = new Set<string>();
// Details view of the request card stays open across rebuilds of the same request.
let detailsOpenFor = '';
// The verified game's own Activity application (for its icon), never a target.
function gameApplication(e: ViewEvent): Application | undefined {
  const p = verifiedLaunch(e.attribution.provenance);
  if (!p) return;
  const game = Object.values(state.observation.activity?.processes || {}).find(
    (x) => x.provenance?.group === p.group && x.provenance?.role === 'game' && verifiedLaunch(x.provenance),
  );
  return game?.application?.key ? game.application : undefined;
}
// Temporary decisions (For a while leases), keyed so an open disclosure stays open.
function renderLeases(container: HTMLElement | null, leases: ProcessLease[], ownEvent = '') {
  if (!container) return;
  const now = state.control.serverNow || Date.now(),
    keep = new Set(leases.map((l) => l.id));
  for (const old of [...container.querySelectorAll<HTMLElement>('details[data-lease]')])
    if (!keep.has(old.dataset.lease!)) old.remove();
  for (const lease of leases) {
    let box = container.querySelector<HTMLDetailsElement>(`details[data-lease="${CSS.escape(lease.id)}"]`);
    if (!box) {
      box = element('details', '', 'lease');
      box.dataset.lease = lease.id;
      const summary = element('summary', '', 'lease-line');
      const list = element('dl', '', 'connection-fields');
      for (const [label, value] of leaseDetails(lease)) field(list, label, value);
      box.append(summary, list);
      container.append(box);
    }
    const summary = box.querySelector('summary')!;
    summary.id = lease.event_id === ownEvent && ownEvent ? 'leaseLine' : '';
    summary.textContent = leaseLine(lease, now);
    summary.title = FOR_A_WHILE_TOOLTIP;
  }
  container.hidden = leases.length === 0;
}
function updateDecisions() {
  syncRememberScope();
  const e = currentEvent(),
    now = state.control.serverNow || Date.now(),
    groups = state.control.connected ? requestGroups(state.control.events) : [],
    group = e ? groups.find((g) => g.key === groupKey(e)) : undefined;
  if (promptID && $('dismiss')) {
    const other = groups.filter(
      (g) => !g.representative.attempt && (!e || g.key !== groupKey(e)),
    ).length;
    $('dismiss').textContent = other
      ? `Next request (${other})`
      : !reviewFailureOf(e) && e?.state === 'awaiting-decision' && e.remainingMs > 0
        ? 'Decide later'
        : 'Close';
    $('dismiss').title =
      'Dismiss this view without Allow or Deny. Unanswered requests retain their original deadlines; this group does not open again automatically.';
  }
  if ($('promptPending')) $('promptPending').textContent = `Pending requests (${groups.length})`;
  if (!promptID) {
    const leases = activeLeases(state.control.processLeases, now);
    renderLeases($('leaseRows'), leases);
    if ($('temporaryDecisions')) $('temporaryDecisions').hidden = leases.length === 0;
  }
  renderLeases($('leaseInfo'), leasesForRequest(state.control.processLeases, e, now), e?.id);
  if ($('similarRequests'))
    $('similarRequests').textContent =
      group && group.count > 1 ? `+${group.count - 1} similar requests` : 'None';
  if ($('similarRequests'))
    $('similarRequests').title = group && group.count > 1 ? 'Allow/Deny answers this request; Remember also settles the others it covers.' : '';
  if ($('askSource') && e) $('askSource').textContent = askSource(e, state.control.rules);
  const ended = endedRequest(e),
    ruleMode = endedRuleMode(e),
    instanceEnded = processInstanceEnded(e),
    ruleDone = !!e && (endedFlow.saved.has(e.id) || cardResults.get(e.id)?.text === ENDED_RULE_RESULT),
    rulePinned = !!e && endedFlow.pinned.has(e.id),
    pacing = Boolean(promptID) && (!promptLayoutReady || performance.now() < promptStableAt),
    remembering = rememberMode() && rememberOn,
    temporary = forAWhileOn && forAWhileMode() && !remembering,
    leaseMode = endedLeaseAvailable(e, state.control.capabilities),
    liveLeaseUnavailable = liveLeaseReason(e, state.control.capabilities),
    leaseDone = !!e && endedLeaseDone.has(e.id),
    unverifiable = e ? ruleUnverifiable.get(e.id) : undefined;
  // Live Remember: a review that no longer matches (zones, fields, expiry duration
  // changed) or that expired is renewed automatically, at most every 2 s.
  if (!ended && remembering && actionable(e) && !reviewChecking && !reviewMessage) {
    const fresh =
      reviewFor === reviewKey() && !!decisionReviews.allow && Date.parse(decisionReviews.allow.expires_at) > now + 1000;
    if (!fresh && performance.now() - autoReviewAt > 2000) {
      autoReviewAt = performance.now();
      clearTimeout(reviewTimer);
      reviewTimer = setTimeout(() => void prepareDecisions(), 0);
    }
  }
  if (ruleMode && remembering && !ruleDone && !rulePinned && !ruleChecking && !unverifiable && !(rememberFields.process && instanceEnded)) {
    // Review (again) when missing or expired; a refusal waits for Refresh review,
    // and re-reviews are spaced so an odd preview can never loop.
    const key = ruleKey(e);
    if (
      (ruleMessageFor !== key || !ruleMessage) &&
      performance.now() - ruleReviewedAt > 2000 &&
      !(['allow', 'block'] as const).every((a) => endedFlow.fresh(ruleChoice(e!, a), now))
    ) {
      ruleReviewedAt = performance.now();
      scheduleRequestRule(0);
    }
  }
  for (const id of ['allow', 'block'] as const) {
    const b = $<HTMLButtonElement>(id);
    if (!b) continue;
    const review = decisionReviews[id];
    if (ended && temporary) {
      // For a while on an ended request: creates the process lease only.
      b.disabled =
        pacing || !leaseMode || leaseDone || endedLeaseBusy.has(e!.id) || !state.control.connected || !canDecide(state.control);
      b.title = leaseMode
        ? `${id === 'allow' ? 'Allow' : 'Deny'} new connections of process ${e!.request_rule?.pid ?? ''} for a while; this ended request is not delivered`
        : endedLeaseReason(e, state.control.capabilities);
      continue;
    }
    if (ended) {
      const pinned = e && endedFlow.pinned.get(e.id);
      b.disabled =
        pacing ||
        !ruleMode ||
        !remembering ||
        ruleDone ||
        ruleBusy.has(e!.id) ||
        !!unverifiable ||
        !state.control.connected ||
        !canManageRules(state.control) ||
        (rememberFields.process && instanceEnded) ||
        (pinned ? pinned.action !== id : !endedFlow.fresh(ruleChoice(e!, id), now));
      b.title = !remembering
        ? ENDED_NEEDS_REMEMBER
        : unverifiable
          ? IDENTITY_UNVERIFIABLE_TEXT
          : `${id === 'allow' ? 'Allow' : 'Deny'}: save a rule for future connections; this request stays ended`;
      continue;
    }
    b.disabled =
      pacing ||
      !actionable(e) ||
      (temporary && !!liveLeaseUnavailable) ||
      (needsDecisionReview() &&
        (reviewFor !== reviewKey() ||
          !review ||
          Date.parse(review.expires_at) <= now));
    b.title = needsDecisionReview()
      ? rememberBlockReason(e, now) || review?.summary || review?.scope_preview || 'Review required'
      : temporary
        ? liveLeaseUnavailable || FOR_A_WHILE_TOOLTIP
        : rememberMode()
          ? 'Once: this connection attempt only; creates no rule'
          : e?.scope_previews[chosenScope] || '';
  }
  const locked =
    pacing ||
    !e ||
    !!e.attempt ||
    ended ||
    localSubmitted.has(state.control.generation + ':' + e.id) ||
    !state.control.connected ||
    !canDecide(state.control) ||
    e.state !== 'awaiting-decision' ||
    e.remainingMs <= 0;
  const scope = $<HTMLSelectElement>('scope');
  if (scope) scope.disabled = locked;
  const toggle = $<HTMLInputElement>('rememberToggle');
  // An ended request keeps Remember: it is the way to a rule for future connections.
  // An Electron runtime whose app is unverified: no application-wide rule (backend refuses too).
  const runtimeUnverified = e?.attribution.permission_target?.kind === 'runtime-unverified';
  const processRemember = runtimeUnverified && !ended && !!e?.scope_previews['process-remember'];
  if (processRemember) {
    rememberFields = { ...rememberFields, process: true };
    decisionZone = 'any';
    const processBox = document.querySelector<HTMLInputElement>('#rememberPanel input[data-field=process]');
    if (processBox) processBox.checked = true;
  }
  if (toggle) {
    toggle.disabled = (runtimeUnverified && !processRemember) || (ruleMode ? ruleDone || rulePinned || pacing : locked);
    toggle.parentElement!.title = runtimeUnverified
      ? e!.attribution.permission_target!.remember
      : "Create rule and don't ask me again";
    toggle.parentElement!.classList.toggle('unavailable', runtimeUnverified && !processRemember);
    if (runtimeUnverified && !processRemember && rememberOn) setOption('remember', false);
  }
  const scopeLine = $('permissionScope');
  if (scopeLine)
    scopeLine.textContent =
      (rememberOn ? scopeLine.dataset.remember : forAWhileOn
        ? `For a while: ${ended ? (endedLeaseReason(e, state.control.capabilities) || forAWhileNote(forAWhileSeconds)) : (liveLeaseUnavailable || forAWhileNote(forAWhileSeconds))}`
        : scopeLine.dataset.once) ||
      scopeLine.textContent;
  const whileBox = $<HTMLInputElement>('forAWhileToggle');
  if (whileBox) {
    // An ended request offers For a while only while its exact process runs.
    whileBox.disabled = ended
      ? pacing || !leaseMode || leaseDone || endedLeaseBusy.has(e!.id)
      : locked || !!liveLeaseUnavailable;
    whileBox.parentElement!.title = ended
      ? endedLeaseReason(e, state.control.capabilities) || FOR_A_WHILE_TOOLTIP
      : liveLeaseUnavailable || FOR_A_WHILE_TOOLTIP;
    whileBox.parentElement!.classList.toggle('unavailable', ended ? !leaseMode : !!liveLeaseUnavailable);
  }
  const showLease = temporary && (!ended || leaseMode) && !leaseDone;
  if ($('forAWhileNote')) {
    $('forAWhileNote').hidden = !showLease;
    $('forAWhileNote').textContent = forAWhileNote(forAWhileSeconds);
  }
  // Duration selector only while For a while is checked; the expiry shown is a
  // preview, the countdown after the click uses the backend's until.
  if ($('forAWhileDurationWrap')) {
    $('forAWhileDurationWrap').hidden = !showLease;
    $<HTMLSelectElement>('forAWhileDuration').disabled = pacing || endedLeaseBusy.has(e?.id ?? '') || (!ended && locked);
    $('forAWhileExpiry').textContent = showLease ? expiryPreview(forAWhileSeconds, now) : '';
  }
  const panel = $('rememberPanel');
  if (panel) {
    panel.hidden = !remembering || (ended && !ruleMode);
    for (const input of panel.querySelectorAll<HTMLInputElement>('input[data-field]')) {
      if (input.dataset.field === 'application') continue;
      if (!ruleMode) {
        input.disabled = locked || input.dataset.available !== 'true' || (processRemember && input.dataset.field === 'process');
        continue;
      }
      const endedProcess = input.dataset.field === 'process' && instanceEnded;
      // Never silently unchecked: an ended process stays checked until the user unchecks it.
      input.disabled =
        ruleDone || rulePinned || input.dataset.available !== 'true' || (endedProcess && !input.checked);
      if (endedProcess)
        input.parentElement!.title =
          'This process instance has ended, so a process-only rule could never match. Uncheck to save a rule for the application.';
      input.parentElement!.classList.toggle('instance-ended', endedProcess);
    }
    const duration = $<HTMLSelectElement>('rememberDuration');
    duration.disabled = ruleMode ? ruleDone || rulePinned : locked;
    // Backend offers persistent only with rule storage; temporary only as "application".
    for (const option of duration.options)
      option.disabled = !ruleMode && !e?.scope_previews[rememberScope(Number(option.value))];
    const allowReview = ruleMode && e ? endedFlow.reviews.allow : undefined;
    $('rememberSummary').textContent = ruleMode
      ? ruleDone || unverifiable
        ? ''
        : rememberFields.process && instanceEnded
          ? ''
          : ruleChecking
            ? 'Checking rule…'
            : allowReview && endedFlow.fresh(ruleChoice(e!, 'allow'), now)
              ? 'Future connections only; this request has ended.'
              : ruleMessage
                ? ''
                : 'Rule review required.'
      : // Live request: one short reason whenever Allow/Deny are not available.
        rememberBlockReason(e, now) ||
          (reviewFor === reviewKey()
            ? rememberReviewText(decisionReviews.allow, decisionReviews.block, e?.ask_rule).replace(/^Rule: .*? · /, '').replace(/^Rule: .*$/, '')
            : '');
  }
  if ($('refreshDecision')) {
    const refresh = $<HTMLButtonElement>('refreshDecision');
    const failed = ruleMode ? !!ruleMessage : !!reviewMessage;
    const expired = !ruleMode && reviewFor === reviewKey() && Date.parse(decisionReviews.allow?.expires_at || '') <= now;
    // Legacy scope list keeps its explicit review button; Remember shows it only to recover.
    refresh.hidden = rememberMode()
      ? (ended && !ruleMode) || !(failed || expired) || ruleDone || !!unverifiable
      : !needsDecisionReview() || ended;
    refresh.disabled = ruleMode ? ruleChecking || rulePinned : reviewChecking || !actionable(e);
  }
  if ($('scopePreview')) {
    // One preview (the Allow review; Deny differs only in its verb) and its overlap list.
    const text = ruleMode
      ? (endedFlow.reviews.allow ?? endedFlow.reviews.block)?.scope_preview || ''
      : needsDecisionReview()
        ? (decisionReviews.allow ?? decisionReviews.block)?.scope_preview || 'Review required'
        : e?.scope_previews[chosenScope] || 'Authoritative scope unavailable; decisions disabled.';
    const split = splitPreview(text);
    $('scopePreview').textContent = split.preview || '—';
    if ($('ruleOverlaps')) $('ruleOverlaps').textContent = split.overlaps.join('\n') || 'None reported';
  }
  const zone = $<HTMLSelectElement>('decisionZone');
  if (zone) {
    zone.disabled = !!scope?.disabled || !needsDecisionReview() || processRemember;
    zone.title = needsDecisionReview()
      ? 'Scope of the remembered rule'
      : 'Any network · backend upgrade required for remembered zone rules';
    zone.parentElement!.parentElement!.hidden = chosenScope === 'once';
  }
  if ($('decisionReview'))
    $('decisionReview').textContent = reviewChecking
      ? remembering
        ? ''
        : 'Checking remembered scope…'
      : remembering || ended
        ? ''
        : (reviewMessage ? shortError(reviewMessage) : '') ||
          (needsDecisionReview() && !decisionReviews.allow
            ? 'Choose scope, then refresh review.'
            : needsDecisionReview() && Date.parse(decisionReviews.allow?.expires_at || '') <= now
              ? 'Review expired · refresh to decide.'
              : '');
  if ($('decisionReconcile')) {
    const reconcile = $<HTMLButtonElement>('decisionReconcile');
    reconcile.hidden = !e?.attempt?.reconcile;
    reconcile.disabled = !state.control.connected;
  }
  // Outcome text lives in Details → Status so state changes do not resize the compact card.
  // A submission from a hidden window that did not succeed is shown on its card again.
  const kept = e && state.control.permissionResults?.find((r) => r.eventId === e.id && r.severity !== 'ok');
  const local = e ? cardResults.get(e.id) ?? (kept ? { text: kept.text, detail: kept.detail } : undefined) : undefined,
    failure = reviewFailureOf(e);
  if ($('requestResult')) {
    $('requestResult').textContent = !e
      ? ''
      : ruleDone
        ? ENDED_RULE_RESULT
        : showsLocalResult(local, e.attempt, state.control.generation)
          ? local!.text
          : e.attempt
            ? shortAttempt(e.attempt, e)
            : !state.control.connected
              ? 'Disconnected · decisions unavailable. No retry sent.'
              : failure
                ? endedSummary(failure)
                : '';
    $('requestResult').hidden = !$('requestResult').textContent;
  }
  if ($('decisionNote')) {
    const own = cardNote && e && cardNote.id === e.id ? cardNote : undefined;
    $('decisionNote').textContent = ruleDone
      ? ''
      : own?.text ||
        (leaseDone
          ? ''
          : ended && temporary && !leaseMode
          ? endedLeaseReason(e, state.control.capabilities)
          : ended && ruleMode && !remembering && !temporary
          ? leaseMode ? ENDED_NEEDS_CHOICE : ENDED_NEEDS_REMEMBER
          : ended && ruleMode && rememberFields.process && instanceEnded
            ? ENDED_PROCESS
            : ruleMode && unverifiable
              ? IDENTITY_UNVERIFIABLE_TEXT
            : ruleMode && ruleMessage
              ? shortError(ruleMessage) + ' · Selections kept.'
              : ''); // live Remember: the reason is the panel's summary line
    $('decisionNote').hidden = !$('decisionNote').textContent;
  }
  if ($('requestStatus') && e) {
    // Short labelled fields; only the latest result, never an older error after a success.
    const own = cardNote && cardNote.id === e.id ? cardNote.detail : '';
    $('requestStatus').textContent = e.reason || '—';
    $('requestLastResult').textContent =
      (ruleDone ? endedFlow.saved.get(e.id) || (showsLocalResult(local, e.attempt, state.control.generation) ? local?.detail : undefined) : (showsLocalResult(local, e.attempt, state.control.generation) ? local?.detail : undefined) || own || e.attempt?.message) ||
      (e.attempt?.phase === 'unknown' && e.state !== 'awaiting-decision'
        ? `Backend now reports ${e.state}; the original acknowledgement remains unknown.`
        : '—');
    $('requestReviewDetail').textContent = (ruleDone ? '' : ruleMode ? ruleMessage || unverifiable : reviewMessage) || '—';
  }
  if ($('revalidationDetails')) {
    $('revalidationDetails').textContent = failure ? `${failure.code}: ${failure.message}` : '—';
  }
  if ($('futureApplicationRule')) {
    const future = $<HTMLButtonElement>('futureApplicationRule');
    future.hidden = !failure || ruleMode;
    future.disabled = !state.control.connected || !canManageRules(state.control) ||
      !!e?.attempt && ['unknown', 'submitting'].includes(e.attempt.phase);
    future.textContent = rememberFields.process
      ? 'Switch to application scope for future connections…'
      : 'Create application rule for future connections…';
    future.title = 'Separate application-wide rule, independently verified from fresh Activity. Does not release this request. No automatic scope switch or save.';
  }
  if ($('permissionTarget'))
    $('permissionTarget').textContent = ended && temporary && leaseMode
      ? `Ended request: For a while covers new ${e!.flow.direction} connections of process ${e!.request_rule?.pid ?? ''} only; this request is not delivered.`
      : ruleMode
      ? 'Ended request: Allow/Deny with Remember saves a rule for future connections only.'
      : failure
        ? 'No rule saved · the original connection was not allowed.'
        : temporary
          ? liveLeaseUnavailable || `For a while: this connection and new connections. ${forAWhileNote(forAWhileSeconds)}`
          : rememberMode()
            ? remembering
              ? 'Remember: create a rule for the checked properties'
              : 'Once: this connection attempt only · no rule'
            : needsDecisionReview() && reviewFor === reviewKey() && decisionReviews.allow
              ? `Application + peer/service · ${decisionZone === 'any' ? 'Any network' : zoneLabel(decisionZone)} · ${decisionReviews.allow.rule.expires.startsWith('0001-') ? 'persistent' : 'until ' + new Date(decisionReviews.allow.rule.expires).toLocaleTimeString()}`
              : permissionTarget(chosenScope, e?.flow.protocol || '', needsDecisionReview() ? decisionZone : 'any');
  // One short status line: the countdown, or what the request is now. An ended request
  // shows its most specific reason here (the countdown's slot, so the card does not resize);
  // Details → Status keeps every reason.
  const expiry = document.querySelector<HTMLElement>('.expiry');
  if (expiry) {
    const limited = !!e && (!e.attribution.visibility_complete || e.attribution.status !== 'directly-associated');
    const endedLine = ended ? endedStatusLine($('decisionNote')?.textContent, $('requestResult')?.textContent) : '';
    expiry.classList.toggle('ended', !!endedLine);
    expiry.title = endedLine;
    expiry.textContent = !e
      ? ''
      : ended
        ? endedLine
        : e.remainingMs > 0 && e.state === 'awaiting-decision'
          ? `${Math.ceil(e.remainingMs / 1000)} s left` +
            (group && group.count > 1 ? ` · +${group.count - 1} similar` : '') +
            (limited ? ' · limited attribution' : '')
          : `Request ${e.state === 'awaiting-decision' ? 'expired' : e.state}`;
  }
  measurePrompt();
}
let guiBuild: GuiBuild | undefined;
function renderBuildVersion() {
  const el = document.getElementById('buildVersion');
  if (!el) return;
  // guiBuild() may resolve before the first state publication.
  const v = headerVersion(guiBuild, state?.control.connected ? state.control.daemonBuild : undefined);
  el.textContent = v.text;
  el.title = v.title;
  el.classList.toggle('mismatch', v.mismatch);
}
function consume(next: ClientState) {
  if (!acceptsPublication(state, next)) return;
  state = next;
  if (!promptID) refreshUpload(state);
  applicationCallers.observe(next);
  const present = new Set(state.control.events.map((e) => state.control.generation + ':' + e.id));
  for (const key of localSubmitted) if (!present.has(key)) localSubmitted.delete(key);
  // The permission window shows controller status only when it limits decisions.
  const degraded = state.control.connected ? runtimeDegradation(state.control.runtimeChecks) : undefined;
  $('controlStatus').textContent =
    promptID && state.control.connected && !state.control.readOnly
      ? ''
      : state.control.message +
        (state.control.connected && state.control.readOnly ? ' · read-only' : '') +
        (degraded ? ' · ' + degraded.text : '');
  while (cardResults.size > 128) cardResults.delete(cardResults.keys().next().value!);
  renderBuildVersion();
  $('controlStatus').title = [
    state.control.message,
    state.control.enforcement?.detail,
    ...(degraded?.lines || []),
    state.control.permissions
      ? `${state.control.permissions.role} · ${state.control.permissions.policy_scope} policy · rule management ${state.control.permissions.can_manage_rules ? 'permitted' : 'denied'} · decisions ${state.control.permissions.can_decide ? 'permitted' : 'denied'}`
      : 'Legacy permission contract',
  ]
    .filter(Boolean)
    .join('\n');
  if (!promptID) {
    updateFirewallStatus();
    for (const th of document.querySelectorAll<HTMLElement>('.col-rule_status button'))
      th.title = state.control.capabilities?.includes(POLICY_CAPABILITY)
        ? 'Priority · DL Limit · UL Limit · In Blocker · Out Blocker · In Quota · Out Quota. Upload limits are experimental and separate from firewall Blocker policy.'
        : 'Compatibility inventory (listed rules; no backend summary).';
    $('observerStatus').textContent = state.observation.message;
    $('observerStatus').title = state.observation.message;
    $('pendingCount').textContent = String(requestGroups(state.control.events).length);
    const stamp =
      state.observation.generation + ':' + (state.observation.activity?.sequence ?? 'offline');
    if (stamp !== sequence) {
      sequence = stamp;
      buildTree();
    }
    if (lastGeneration && lastGeneration !== state.control.generation) {
      selectedRequest = '';
      chosenScope = 'once';
    }
    lastGeneration = state.control.generation;
    const rulesStamp = JSON.stringify([
      state.control.connected,
      state.control.generation,
      state.control.permissions,
      state.control.enforcement?.state,
      state.control.rules,
      state.control.rule_states,
      state.control.networkZones?.revision,
      state.control.policy
        ? [
            state.control.policy.snapshot.token,
            state.control.policy.applications.map((a) => [a.ref, a.process_ids]),
            state.control.policy.rows,
            state.control.policy.processes,
          ]
        : state.control.policyError,
      (state.control.rules || []).map((r) => ruleState(r, state.control.serverNow ?? NaN)),
    ]);
    if (ruleSignature !== rulesStamp) {
      ruleSignature = rulesStamp;
      treePolicyRevision++;
      renderTree();
      renderInfo();
    }
  }
  renderRequests();
  if (!promptID) {
    const details = $('requestDetails');
    details.dataset.eventId = currentEvent()?.id || '';
    updateWorkflows(state);
    updateDecisionLog(state);
    updateObservedUsage(state, displayUnit);
    renderPermissionResults();
  }
}
// Pending requests › Results: every submission outcome, newest first; the ones
// that did not succeed (refused, unknown, conflicting rule) are flagged in the
// footer until reviewed.
let resultsSignature = '';
let resultsSeen = '';
function renderPermissionResults() {
  const list = state.control.permissionResults ?? [];
  const attention = list.filter((r) => r.severity !== 'ok' && Number(r.id) > Number(resultsSeen || 0));
  const button = $<HTMLButtonElement>('resultsAttention');
  if (button) {
    button.hidden = attention.length === 0;
    button.textContent = `${attention.length} permission result${attention.length === 1 ? '' : 's'} to review`;
    button.onclick = () => {
      $('requestsTab').click();
      $('permissionResultsView')?.scrollIntoView({ block: 'nearest' });
    };
  }
  if (!$('requestsView').hidden && list[0]) resultsSeen = list[0].id;
  const signature = JSON.stringify(list.map((r) => r.id));
  if (signature === resultsSignature) return;
  resultsSignature = signature;
  const rows = $('permissionResultRows');
  rows.replaceChildren();
  for (const r of list.slice(0, 20)) {
    const li = element('li', '', 'permission-result result-' + r.severity);
    li.dataset.event = r.eventId;
    const box = element('details');
    const summary = element('summary');
    summary.append(
      element('span', new Date(r.at).toLocaleTimeString(), 'result-time'),
      element('strong', r.application),
      element('span', r.destination, 'result-destination'),
      element('span', r.text, 'result-text'),
    );
    box.append(summary, element('p', r.detail || r.text, 'result-detail'));
    li.append(box);
    rows.append(li);
  }
  $('permissionResultsView').hidden = list.length === 0;
}
function consumePresentation(frame: PaneFrame) {
  if (promptID || (presentation && frame.presentation.revision < presentation.revision)) return;
  const old = presentation;
  presentation = frame.presentation;
  if (!$('activityView')) return;
  const p = presentation;
  const nextSelection =
    selectionPending && selectionPending !== p.selection ? selected : p.selection;
  const selectionChanged = selected !== nextSelection;
  selected = nextSelection;
  measurementSource = p.source;
  displayUnit = p.unit;
  $<HTMLSelectElement>('displayUnits').value = p.unit;
  $<HTMLSelectElement>('activitySource').value = p.source;
  for (const small of document.querySelectorAll('.rate-header small'))
    small.textContent = p.unit + ' (def)';
  graph?.setSource(p.source);
  graph?.setUnit(p.unit);
  graph?.setPresentation(p.chart);
  applyPanes();
  if (state && (selectionChanged || old?.source !== p.source || old?.unit !== p.unit)) {
    renderTree();
    renderInfo();
  }
}
if (!promptID) {
  window.flowgate.onPaneFrame(consumePresentation);
  void window.flowgate.paneSnapshot().then(consumePresentation);
  window.flowgate.onPaneRule((action) => {
    if (
      !state ||
      action.selection !== selected ||
      action.generation !== state.observation.generation
    ) {
      message('Selection changed; review the current Activity target.');
      return;
    }
    if (activityPolicy?.hasOutstandingAction()) {
      message('Resolve the current quick action before opening another rule action.');
      return;
    }
    if (resumeRuleEditor()) {
      message('Finish the existing editor before opening another rule action.');
      return;
    }
    if (($('confirmation') as HTMLDialogElement)?.open) {
      message('Finish the current confirmation first.');
      return;
    }
    const editor = $('ruleEditor');
    if (editor && !editor.hidden) {
      editor.querySelector<HTMLElement>('input,button')?.focus();
      message('Finish the open editor before opening another rule action.');
      return;
    }
    $('activityTab').click();
    if (action.kind === 'quick' && presentation?.panes.info !== 'docked') {
      showFloatingRuleStatus();
    }
    const focus =
      action.kind === 'quick'
        ? `cell:${action.tier}:${action.direction}`
        : action.kind === 'new'
          ? 'add-rule'
          : `list:${action.id}:${action.kind === 'edit' ? 'advanced' : 'delete'}`;
    const button = document.querySelector<HTMLButtonElement>(
      `#infoRules [data-focus="${CSS.escape(focus)}"]`,
    );
    if (!button || button.disabled) {
      message('Rule entry is unavailable for the current target.');
      return;
    }
    const details = button.closest('details');
    if (details) details.open = true;
    button.click();
  });
}
void window.flowgate.hostIdentity?.().then(label => {
  hostLabel = label;
  if (state) { buildTree(); renderTree(); }
}).catch(() => {});
window.addEventListener('flowgate-account-name', () => { if (state) { buildTree(); renderInfo(); } });
window.flowgate.subscribe(consume);
if (!promptID) window.setInterval(() => { if(state) refreshUpload(state); }, 1000);
window.flowgate.onClock((clock) => {
  const next = advanceClock(state, clock);
  if (next && next !== state) consume(next);
});
void window.flowgate
  .snapshot()
  .then(consume)
  .catch((e) => {
    root.textContent = 'FlowGate could not initialize: ' + String(e);
  });

document.addEventListener('visibilitychange', () => {
  if (!document.hidden) {
    void window.flowgate.snapshot().then(consume);
    void graph?.update(selected, sequence + ':resume:' + performance.now());
  }
});

// Age status locally without replacing rows or starting API/ownership work.
if (!promptID) window.setInterval(() => {
  for(const tr of document.querySelectorAll<HTMLElement>('#rows tr')) {
    const row=allRows(roots).find(r=>r.id===tr.dataset.id);
    const slot=tr.querySelector<HTMLElement>('.connection-status-slot');
    if(row&&slot) updateConnectionStatus(slot,row);
  }
},1000);
