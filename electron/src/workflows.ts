import { accountLabel } from './accounts';
import { setupConnectionChecks } from './connection-checks-view';
import { setupDecisionTimeout } from './decision-timeout-view';
import { setupShapingDefaults } from './shaping-defaults-view';
import { setupEndpointPermissions } from './endpoint-view';
import { canManageEndpoints, ENDPOINT_SCOPE, ENDPOINT_PRECEDENCE, ENDPOINT_LIFETIME } from './endpoint-policy';
import { setupZoneMigration } from './zone-migration-view';
import { setupProtectionControls } from './protection-view';
import { ZONE_CAPABILITY, zoneLabel, zoneRuleLabel } from './network-zones';
import { ANY_PROTOCOL_CAPABILITY, PROCESS_CAPABILITY, targetLabel } from './process-rules';
import { renderDaemonEvaluation } from './evaluation-view';
import { canManageRules, STORED_ASK_CAPABILITY } from './protocol';
import { reviewedScope, previewSeconds } from './editor-presentation';
import { revisionScope, savedRuleState } from './rule-status';
import type {
  ClientState,
  Rule,
  RuleDraft,
  RuleEdit,
  Preferences,
  RuleSource,
  RulePreview,
  Attempt,
} from './protocol';
const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
const node = (tag: string, text: string) => {
  const n = document.createElement(tag);
  n.textContent = text;
  return n;
};
let endpointUI: ReturnType<typeof setupEndpointPermissions> | undefined;
let migrationUI: ReturnType<typeof setupZoneMigration> | undefined;
let editRevision = 0;
let accessState = '';
let editorSource: RuleSource = {};
let stayInActivity = false;
let editorChanged = false;
let requireNetwork = false;
export interface EditorOptions {
  networkZone?: 'local' | 'internet';
  newNetworkSource?: RuleSource;
  requireNetwork?: boolean;
  activity?: boolean;
  quick?: boolean;
  action?: 'allow' | 'block' | 'ask';
  disabled?: boolean;
  protocol?: string;
  expiry?: 'hour' | 'permanent';
  applicationScope?: boolean;
  futureOnly?: boolean;
}
let previewNeedsRefresh = false;
let previewTimer: ReturnType<typeof setTimeout> | undefined;
let previewing = false;
let previewQueued = false;
function queuePreview() {
  clearTimeout(previewTimer);
  previewQueued = false;
  previewTimer = setTimeout(() => {
    previewTimer = undefined;
    void previewRule();
  }, 250);
}
let futureOnlyDraft = false;
const resultMessage = (result: { phase: string; message: string }) => result.phase === 'acknowledged' && futureOnlyDraft
  ? result.message + ' Rule saved for future matching connections. The original connection was not allowed.'
  : result.message;
let previewNetworkRevision = '';
let previewExpires = 0,
  reconcileReceipt = '';
let showTab: (s: string) => void = () => {};
let state: ClientState,
  selected = '',
  signature = '',
  draft: RuleDraft | undefined,
  receipt = '',
  saving = false,
  unresolved = false;
const status = (s: string) => {
  for (const id of ['ruleFeedback', 'feedback', 'paneMessage']) {
    const output = $(id);
    if (output) output.textContent = s;
  }
};
function editorMessage(s: string) {
  $('editorFeedback').textContent = s;
}
function writable() {
  return !!state && canManageRules(state.control);
}
function editValue(): RuleEdit {
  for (const [toggle, field] of [
    ['anyLocal', 'editLocal'],
    ['anyRemote', 'editRemote'],
  ]) {
    const value = Number($<HTMLInputElement>(field).value);
    if (
      !$<HTMLInputElement>(toggle).checked &&
      (!Number.isInteger(value) || value < 1 || value > 65535)
    )
      throw Error('Enter a port from 1 to 65535, or choose Any port.');
  }
  if (
    !$<HTMLInputElement>('anyAddress').checked &&
    ['', '*'].includes($<HTMLInputElement>('editAddress').value.trim())
  )
    throw Error('Enter an IP address/CIDR, or choose Any address.');
  return {
    token: draft!.token,
    ...(!$<HTMLInputElement>('editShareRoot').disabled ? { share_with_root: $<HTMLInputElement>('editShareRoot').checked } : {}),
    action: $<HTMLSelectElement>('editAction').value as RuleEdit['action'],
    protocol: $<HTMLSelectElement>('editProtocol').value,
    network_zone: $<HTMLSelectElement>('editZone').value as RuleEdit['network_zone'],
    remote_address: $<HTMLInputElement>('anyAddress').checked
      ? '*'
      : $<HTMLInputElement>('editAddress').value,
    local_port: $<HTMLInputElement>('anyLocal').checked
      ? 0
      : Number($<HTMLInputElement>('editLocal').value),
    remote_port: $<HTMLInputElement>('anyRemote').checked
      ? 0
      : Number($<HTMLInputElement>('editRemote').value),
    priority: Number($<HTMLInputElement>('editPriority').value),
    disabled: !$<HTMLInputElement>('editEnabled').checked,
    expiry: $<HTMLSelectElement>('editExpiry').value as RuleEdit['expiry'],
    ...(draft?.observed
      ? { creation_scope: $<HTMLSelectElement>('createScope').value as 'application' | 'custom' }
      : {}),
  };
}
function invalidate() {
  editRevision++;
  receipt = '';
  previewExpires = 0;
  $('rulePreview').textContent = 'Preview required before saving.';
  $('scopeSummary').textContent = draft?.observed && !$<HTMLSelectElement>('createScope').value
    ? 'Choose a scope to preview it.'
    : 'Preview pending.';
  $<HTMLButtonElement>('saveRule').disabled = true;
}
function showRuleEditor() {
  const panel = $<HTMLDialogElement>('ruleEditor');
  panel.hidden = false;
  if (!panel.open) panel.showModal();
  $('resumeEditor').hidden = true;
}
function hideRuleEditor() {
  const panel = $<HTMLDialogElement>('ruleEditor');
  panel.close();
  panel.hidden = true;
  clearTimeout(previewTimer);
  previewTimer = undefined;
  previewQueued = false;
}
function showRuleExpiry(rule: Rule, process: boolean) {
  const expires = rule.expires.startsWith('0001-') ? '' : new Date(rule.expires).toLocaleString();
  const expiry = $<HTMLSelectElement>('editExpiry');
  const preserve = expiry.options[0];
  preserve.hidden = preserve.disabled = !rule.id;
  preserve.textContent = expires
    ? 'Keep original deadline · ' + expires
    : process ? 'Keep this daemon session lifetime' : 'Keep persistent';
  if (!rule.id) {
    expiry.value = expires ? 'hour' : 'permanent';
    $('absoluteExpiry').textContent = '';
    return;
  }
  $('absoluteExpiry').textContent = expires ? 'Expires: ' + expires
    : process ? 'This daemon session · ends on process exit.' : 'Persistent: no expiry.';
}
export async function openRule(source: RuleSource, options: EditorOptions = {}) {
  if (draft) {
    showRuleEditor();
    editorMessage('An unfinished editor is already open. Save or close it first.');
    $('editAction').focus();
    return;
  }
  try {
    draft = await window.flowgate.ruleDraft(source);
    editorChanged = false;
    futureOnlyDraft = !!options.futureOnly;
    editorSource = source;
    stayInActivity = !!options.activity;
    requireNetwork = !!options.requireNetwork;
    $('ruleEditor').classList.toggle('quick-editor', !!options.quick);
    $('editorMode').textContent = options.quick ? 'Advanced editor' : 'Compact editor';
    unresolved = false;
    reconcileReceipt = '';
    previewNeedsRefresh = false;
    saving = false;
    const r = draft.rule;
    if (r.network_endpoint) throw Error('Endpoint rules are immutable. Delete and recreate through Endpoint permission.');
    $('editorApplication').textContent =
      `${draft.targetScope === 'process' ? 'This process · ' : targetLabel(r.filter.process) + ' · '}${r.executable || r.filter.application} · ${r.filter.direction} · ${accountLabel(r.filter.uid)}`;
    $('editorIdentity').textContent =
      `${r.executable}\n${r.filter.application} · ${revisionScope(state?.control.rules?.find((x) => x.id === r.id) || r)}\n${r.filter.direction} · ${accountLabel(r.filter.uid)} · ${draft.source}`;
    // Ask is offered only with stored-ask-v1; an existing Ask rule without it stays read-only.
    const askWritable = !!state?.control.capabilities?.includes(STORED_ASK_CAPABILITY);
    const askOption = $('editAction').querySelector<HTMLOptionElement>('option[value=ask]')!;
    askOption.hidden = askOption.disabled = !askWritable && r.action !== 'ask';
    $<HTMLSelectElement>('editAction').disabled = !askWritable && r.action === 'ask';
    $('editAction').title = askWritable ? 'Ask: prompt for each new connection' : '';
    $<HTMLSelectElement>('editAction').value = r.action;
    $<HTMLSelectElement>('editProtocol').value = r.filter.protocol;
    const zone = $<HTMLSelectElement>('editZone');
    zone.options[0].textContent = requireNetwork ? 'Choose Local or Internet…' : 'Any network';
    zone.value = options.networkZone || r.filter.network_zone || '';
    zone.disabled =
      !!source.id || !!source.zone || !state?.control.capabilities?.includes(ZONE_CAPABILITY);
    $('editZone').title = source.id
      ? 'Create a new rule to change the network scope.'
      : state?.control.capabilities?.includes(ZONE_CAPABILITY)
        ? 'Choose the network scope.'
        : 'Backend update required';
    const newNetwork = $<HTMLButtonElement>('newNetworkRule');
    newNetwork.hidden = !options.newNetworkSource || !!r.filter.network_zone;
    newNetwork.onclick = () => {
      if (!options.newNetworkSource || saving || unresolved) return;
      const create = async () => {
        hideRuleEditor();
        draft = undefined;
        const action = r.action === 'allow' || r.action === 'block' || r.action === 'ask' ? r.action : undefined;
        await openRule(options.newNetworkSource!, { activity: options.activity, action, requireNetwork: true });
      };
      if (editorChanged)
        confirmAction('Discard editor changes?', 'Start a separate rule with its own network scope. Changes in this draft will be discarded.', create, 'Start new rule');
      else void create();
    };
    if (r.filter.all_programs)
      $('editorApplication').textContent =
        `All programs · ${r.filter.all_uids ? 'all users' : 'current user'} · ${zoneLabel(r.filter.network_zone)} · ${r.filter.direction}`;

    const address = r.filter.remote_address || '*';
    $<HTMLInputElement>('editAddress').value = address === '*' ? '' : address;
    $<HTMLInputElement>('anyAddress').checked = address === '*';
    $<HTMLInputElement>('anyLocal').checked = !r.filter.local_port;
    $<HTMLInputElement>('anyRemote').checked = !r.filter.remote_port;
    $<HTMLInputElement>('editLocal').value = r.filter.local_port ? String(r.filter.local_port) : '';
    $<HTMLInputElement>('editRemote').value = r.filter.remote_port
      ? String(r.filter.remote_port)
      : '';
    $<HTMLInputElement>('editPriority').value = String(r.priority);
    $<HTMLInputElement>('editEnabled').checked = !r.disabled;
    $<HTMLInputElement>('editShareRoot').checked = r.share_with_root === true;

    $<HTMLSelectElement>('editExpiry').value = 'preserve';
    showRuleExpiry(r, !!r.filter.process || draft.targetScope === 'process');
    $('creationScopeFields').hidden = !draft.observed;
    $<HTMLSelectElement>('createScope').value = '';
    for (const e of document.querySelectorAll<HTMLElement>('#editPriority,label[for=editPriority]'))
      e.hidden = !!draft.observed || !!r.filter.all_programs;
    $<HTMLOptionElement>('editProtocol').querySelector<HTMLOptionElement>(
      'option[value="*"]',
    )!.disabled =
      !!draft.observed &&
      !state?.control.capabilities?.some((cap) =>
        [ANY_PROTOCOL_CAPABILITY, ZONE_CAPABILITY].includes(cap),
      );
    $('editExpiry').querySelector('option[value=permanent]')!.textContent =
      r.filter.process || draft.targetScope === 'process'
        ? 'This daemon session (ends on exit)'
        : 'Persistent (no expiry)';
    $('editExpiry').querySelector('option[value=hour]')!.textContent =
      r.filter.process || draft.targetScope === 'process'
        ? 'New deadline · up to 1 hour from preview'
        : 'New deadline · 1 hour from preview';
    if (options.action) $<HTMLSelectElement>('editAction').value = options.action;
    if (options.disabled !== undefined)
      $<HTMLInputElement>('editEnabled').checked = !options.disabled;
    if (draft.observed && options.protocol && ['tcp', 'udp', '*'].includes(options.protocol))
      $<HTMLSelectElement>('editProtocol').value = options.protocol;
    if (options.expiry) $<HTMLSelectElement>('editExpiry').value = options.expiry;
    if (draft.observed && options.applicationScope) {
      $<HTMLSelectElement>('createScope').value = 'application';
      for (const id of ['anyAddress', 'anyLocal', 'anyRemote'])
        $<HTMLInputElement>(id).checked = true;
    }
    showRuleEditor();
    invalidate();
    if (options.quick && draft.observed)
      $('absoluteExpiry').textContent =
        options.expiry === 'permanent'
          ? draft.targetScope === 'process'
            ? 'Requested: this daemon session, ends on process exit.'
            : 'Requested: persistent, no expiry.'
          : 'Requested: one hour from backend preview.';
    if (options.quick)
      $('scopeSummary').textContent = draft.observed
        ? `Proposed ${draft.targetScope === 'process' ? 'this process only' : 'application, all instances'} · ${options.protocol?.toUpperCase() || r.filter.protocol.toUpperCase()} · ${r.filter.direction} · all addresses and ports for this protocol. Backend verification required.`
        : `Preserved scope: ${reviewedScope(r)}`;
    editorMessage(
      !askWritable && r.action === 'ask'
        ? 'Ask rule is read-only: backend update required (stored-ask-v1). It is never re-saved as Allow/Block.'
        : draft.observed
          ? 'The preview verifies the live process.'
          : 'Fields are validated by Go. Existing identity and absolute expiry are preserved.',
    );
    if (options.futureOnly) {
      $('editorMode').textContent = 'Future application rule';
      $('scopeSummary').textContent = 'Application · all instances · future matching connections only. The ended connection is not approved. Preview independently verifies the current application identity.';
      editorMessage('The original connection is unaffected. Review the scope and lifetime before saving.');
    }
    updateButtons();
    queuePreview();
    $('editAction').focus();
  } catch (e) {
    status(String(e));
  }
}
export function resumeRuleEditor() {
  if (!draft) return false;
  showRuleEditor();
  if (!receipt && !previewNeedsRefresh) queuePreview();
  $('editAction').focus();
  return true;
}
export function setupRuleEditor(resumeAfter: Element) {
  const confirmation = node('dialog', '');
  confirmation.id = 'confirmation';
  confirmation.innerHTML = `<h2 id="confirmTitle"></h2><p id="confirmText"></p><div class="editor-actions"><button id="confirmNo">Cancel</button><button id="confirmYes">Continue</button></div>`;
  document.body.append(confirmation);
  const panel = document.createElement('dialog');
  panel.id = 'ruleEditor';
  panel.hidden = true;
  panel.setAttribute('aria-labelledby', 'ruleEditorTitle');
  panel.innerHTML = `<header><h2 id="ruleEditorTitle">Rule editor</h2><span><button id="editorMode">Compact editor</button> <button id="minimizeEditor">Minimize</button> <button id="closeEditor">Close</button></span></header><div class="editor-body"><h3>Application</h3><details class="editor-identity"><summary id="editorApplication">Application identity</summary><pre id="editorIdentity"></pre></details><h3>Rule and scope</h3><div id="creationScopeFields" hidden><label for="createScope">Scope</label> <select id="createScope"><option value="">Choose scope…</option><option value="custom">Specified address / ports</option><option value="application">All addresses / ports for this protocol</option></select></div><div class="editor-fields"><label for="editAction">Action</label><select id="editAction"><option value="allow">Allow</option><option value="block">Block</option><option value="ask">Ask</option></select><label for="editProtocol">Protocol</label><select id="editProtocol"><option value="tcp">TCP</option><option value="udp">UDP</option><option value="*">Any</option></select><label for="editZone">Network</label><div class="editor-network"><select id="editZone" aria-label="Network zone"><option value="">Any network</option><option value="local">Local Network</option><option value="internet">Internet</option></select><button id="newNetworkRule" type="button" hidden>New rule for another network…</button></div><label for="editAddress">Remote address</label><div class="scope-input"><label><input id="anyAddress" type="checkbox">Any address</label><input id="editAddress" maxlength="256" placeholder="IP address or CIDR"></div><label for="editLocal">Local port</label><div class="scope-input"><label><input id="anyLocal" type="checkbox">Any port</label><input id="editLocal" type="number" min="1" max="65535" aria-label="Specific local port"></div><label for="editRemote">Remote port</label><div class="scope-input"><label><input id="anyRemote" type="checkbox">Any port</label><input id="editRemote" type="number" min="1" max="65535" aria-label="Specific remote port"></div><label for="editPriority">Priority</label><input id="editPriority" type="number" min="-1000" max="1000"><label for="editExpiry">Expiry</label><select id="editExpiry"><option value="preserve">Keep current expiry</option><option value="hour">For 1 hour from preview</option><option value="permanent">Persistent (no expiry)</option></select><label for="editShareRoot">Also apply when run as root</label><div><input id="editShareRoot" type="checkbox"><small>Exact executable and rule scope. For interpreters, this covers all scripts they run. Requires administrator access.</small></div><label for="editEnabled">Enabled</label><input id="editEnabled" type="checkbox"></div><p id="absoluteExpiry"></p><h3>Review scope</h3><p id="scopeSummary"></p><details id="backendScope"><summary>Full backend preview</summary><p id="rulePreview" class="scope-preview"></p></details><p id="editorFeedback" role="status"></p></div><footer><button id="reloadRule">Reload version, keep fields</button><button id="previewRule">Preview</button><button id="saveRule" disabled>Save</button><span id="previewValidity" role="timer"></span><button id="reconcileRule" hidden>Check save result</button></footer>`;
  const editorFooter = panel.querySelector('footer')!;
  editorFooter.append(panel.querySelector('#closeEditor')!);
  document.body.append(panel);
  $('editorMode').onclick = () => {
    const compact = panel.classList.toggle('quick-editor');
    $('editorMode').textContent = compact ? 'Advanced editor' : 'Compact editor';
  };
  for (const id of ['editProtocol', 'editAddress', 'editLocal', 'editRemote', 'editPriority']) {
    const input = $(id);
    input.classList.add('advanced-rule-field');
    input.closest('.scope-input')?.classList.add('advanced-rule-field');
    panel.querySelector(`label[for="${id}"]`)?.classList.add('advanced-rule-field');
  }
  document.addEventListener('keydown', (e) => {
    if ($('rulesTab') && e.ctrlKey && e.key.toLowerCase() === 'e') {
      e.preventDefault();
      const id = selected || state?.control.rules?.[0]?.id;
      if (id) void openRule({ id });
    }
  });
  const resume = node('button', 'Resume editor') as HTMLButtonElement;
  resume.id = 'resumeEditor';
  resume.hidden = true;
  resumeAfter.after(resume);
  resume.onclick = () => resumeRuleEditor();
  const minimize = () => {
    if (saving) return;
    hideRuleEditor();
    resume.hidden = false;
    resume.focus();
  };
  panel.addEventListener('cancel', (event) => {
    event.preventDefault();
    minimize();
  });
  $('minimizeEditor').onclick = minimize;
  panel.addEventListener('input', (event) => {
    if (!draft || unresolved || saving) return;
    if (event.target === $('createScope') && $<HTMLSelectElement>('createScope').value === 'application') {
      for (const id of ['anyAddress', 'anyLocal', 'anyRemote'])
        $<HTMLInputElement>(id).checked = true;
    }
    editorChanged = true;
    invalidate();
    updateButtons();
    queuePreview();
  });
  $('closeEditor').onclick = () => {
    if (saving) return;
    const close = async () => {
      hideRuleEditor();
      draft = undefined;
      resume.hidden = true;
      receipt = '';
      reconcileReceipt = '';
      unresolved = false;
    };
    if (unresolved)
      confirmAction(
        'Unresolved save',
        'The rule may already exist. Check saved rules before creating again. Closing this draft sends nothing and abandons this receipt in the editor.',
        close,
      );
    else void close();
  };
  $('reloadRule').onclick = async () => {
    if (!draft || saving || unresolved) return;
    if (draft.observed) {
      editorMessage(
        'Close and select the application again to change identity. Fields are not rebound automatically.',
      );
      return;
    }
    try {
      const old = draft;
      draft = await window.flowgate.ruleDraft(editorSource);
      showRuleExpiry(draft.rule, !!draft.rule.filter.process || draft.targetScope === 'process');
      invalidate();
      editorMessage(
        'Current version loaded; entered fields retained. Review the updated preview.',
      );
      queuePreview();
    } catch (e) {
      editorMessage(String(e));
    }
  };
  $('previewRule').onclick = () => void previewRule();
  $('saveRule').onclick = async () => {
    if (!receipt || saving || unresolved) return;
    const r = receipt;
    receipt = '';
    saving = true;
    updateButtons();
    try {
      const result = await window.flowgate.ruleSave(r);
      editorMessage(resultMessage(result));
      if (result.phase === 'acknowledged') {
        if (result.rule) {
          selected = result.rule.id;
          if (!stayInActivity) showTab('rules');
          else
            window.dispatchEvent(
              new CustomEvent('activity-rule-saved', { detail: result.rule.id }),
            );
          if ($('ruleInfo')) selectRule();
        }
        hideRuleEditor();
        $('resumeEditor').hidden = true;
        draft = undefined;
        status(resultMessage(result));
      }
      if (result.phase === 'unknown') {
        unresolved = true;
        reconcileReceipt = result.reconcile || '';
      }
    } catch (e) {
      editorMessage(String(e));
    } finally {
      saving = false;
      updateButtons();
    }
  };
  $('reconcileRule').onclick = async () => {
    if (!reconcileReceipt || saving) return;
    saving = true;
    updateButtons();
    try {
      const result = await window.flowgate.ruleReconcile(reconcileReceipt);
      editorMessage(resultMessage(result));
      if (result.phase === 'acknowledged' && result.rule) {
        selected = result.rule.id;
        draft = undefined;
        unresolved = false;
        reconcileReceipt = '';
        hideRuleEditor();
        $('resumeEditor').hidden = true;
        if (!stayInActivity) showTab('rules');
        else
          window.dispatchEvent(new CustomEvent('activity-rule-saved', { detail: result.rule.id }));
        if ($('ruleInfo')) selectRule();
        status(resultMessage(result));
      }
    } catch (e) {
      editorMessage(String(e));
    } finally {
      saving = false;
      updateButtons();
    }
  };
}
async function previewRule() {
  if (!draft || $('ruleEditor').hidden || $<HTMLButtonElement>('previewRule').disabled) return;
  clearTimeout(previewTimer);
  previewTimer = undefined;
  if (previewing) {
    previewQueued = true;
    return;
  }
  invalidate();
  const revision = editRevision;
  const currentDraft = draft;
  const networkRevision = state?.control.networkZones?.revision || '';
  const current = () => revision === editRevision && draft === currentDraft && !$('ruleEditor').hidden;
  previewing = true;
  try {
    const value = editValue();
    editorMessage('Checking scope…');
    const r = await window.flowgate.rulePreview(value);
    if (!current()) return;
    if (value.network_zone && networkRevision !== (state?.control.networkZones?.revision || ''))
      throw Error('Network classification changed. Refresh the preview.');
    receipt = r.receipt;
    previewNetworkRevision = networkRevision;
    previewNeedsRefresh = false;
    const summary = r.verifiedRule
      ? reviewedScope(r.verifiedRule)
      : 'Backend preview ready. Review full scope below.';
    $('scopeSummary').textContent = futureOnlyDraft
      ? 'The ended connection is not approved. ' + summary
      : summary;
    if (!r.verifiedRule) $<HTMLDetailsElement>('backendScope').open = true;
    $('rulePreview').textContent = r.preview;
    previewExpires = r.expiresAt ? Date.parse(r.expiresAt) : 0;
    if (r.verifiedRule) {
      const rule = r.verifiedRule;
      $('editorApplication').textContent =
        `Verified · ${rule.filter.all_programs ? 'All programs · ' + (rule.filter.all_uids ? 'all users' : accountLabel(rule.filter.uid)) : targetLabel(rule.filter.process) + ' · ' + rule.executable} · ${zoneLabel(rule.filter.network_zone)} · ${rule.filter.direction}`;
      $('editorIdentity').textContent =
        `${rule.executable}\n${rule.filter.application} · ${revisionScope(state?.control.rules?.find((x) => x.id === rule.id) || rule)}\n${rule.filter.direction} · ${accountLabel(rule.filter.uid)}${r.processID ? ' · observed process ' + r.processID : ''}`;
      $('absoluteExpiry').textContent = rule.expires.startsWith('0001-')
        ? rule.filter.process
          ? 'This daemon session · ends on process exit.'
          : 'Persistent: no expiry.'
        : 'Expires: ' + new Date(rule.expires).toLocaleString();
    }
    $<HTMLButtonElement>('saveRule').disabled = !writable();
    editorMessage('Review this scope before Save. Saving does not start enforcement.');
    updateButtons();
  } catch (e) {
    if (!current()) return;
    editorMessage(
      /stale_target|unsupported_target|unsupported_process|target_inactive|immutable_target/.test(
        String(e),
      )
        ? String(e) +
            ' Close this editor and select a live supported application again; your draft has not been rebound.'
        : String(e),
    );
  } finally {
    previewing = false;
    if (previewQueued) {
      previewQueued = false;
      void previewRule();
    }
  }
}

export function setRuleListReturn(action?: () => void) {
  const button = $<HTMLButtonElement>('ruleListReturn');
  button.hidden = !action;
  button.onclick = action ?? null;
}
export function setupWorkflows(chooseTab: (s: string) => void) {
  showTab = chooseTab;
  $('requestsTab').after(node('button', 'Rules'));
  const ruleTab = $('requestsTab').nextElementSibling as HTMLButtonElement;
  ruleTab.id = 'rulesTab';
  ruleTab.onclick = () => chooseTab('rules');
  const view = node('main', '');
  view.id = 'rulesView';
  view.hidden = true;
  view.innerHTML = `<section class="rules-main"><div class="filterbar"><button id="editRule">Edit selected</button><button id="toggleRule">Enable / Disable…</button><button id="deleteRule">Delete…</button></div><div class="table-scroll"><div id="ruleListEmpty" class="hint" hidden><p>No saved rules yet.</p><button id="ruleListReturn" type="button" hidden>Back to app rules</button></div><table id="rulesTable" tabindex="0" aria-label="Saved rules"><thead><tr><th>Application</th><th>Action</th><th>Direction</th><th>Protocol</th><th>Endpoint scope</th><th>Expiry</th><th>State</th></tr></thead><tbody id="ruleRows"></tbody></table></div><p class="hint">Rules are evaluated by Go. Changing rules does not necessarily disconnect already-approved TCP sessions.</p><p id="deleteCompatibility" class="hint"></p><p id="ruleFeedback" role="status"></p></section><aside><h2>Rule information</h2><dl id="ruleInfo"></dl></aside>`;
  $('requestsView').after(view);
  endpointUI = setupEndpointPermissions();
  for (const [id, label] of [
    ['settingsMenu', 'Settings'],
    ['monitoringMenu', 'UDP: …'],
    ['controlMenu', 'Firewall'],
  ]) {
    const menu = node('details', '');
    menu.id = id;
    menu.className = 'desktop-menu';
    menu.append(node('summary', label), node('div', ''));
    menu.lastElementChild!.className = 'menu-panel';
    document.querySelector('.brand')!.after(menu);
  }
  const closeOutsideMenus = (event: Event) => {
    for (const menu of document.querySelectorAll<HTMLDetailsElement>('.desktop-menu[open]'))
      if (!menu.contains(event.target as Node)) menu.open = false;
  };
  document.addEventListener('pointerdown', closeOutsideMenus, { capture: true });
  document.addEventListener('click', (event) => {
    if (event.detail === 0) closeOutsideMenus(event);
  }, { capture: true });
  setupDecisionTimeout($<HTMLDetailsElement>('settingsMenu'));
  const evaluation = node('section', '');
  evaluation.className = 'evaluationbar';
  evaluation.innerHTML = `<select id="evalProfile" aria-label="Evaluation profile"><option value="incoming">Incoming only</option><option value="both" disabled>Both directions · support not advertised</option></select><button id="evalStart">Start 5-minute evaluation…</button><button id="evalStop">Stop evaluation</button><button id="evalCancel" hidden>Cancel authentication</button><button id="evalStatus">Status</button><button id="evalRecover">Recovery…</button><span id="evaluationStatus" role="status"></span>`;
  document.querySelector('#controlMenu .menu-panel')!.append(evaluation);
  setupProtectionControls();
  setupConnectionChecks($('controlMenu').querySelector<HTMLElement>('.menu-panel')!);
  migrationUI = setupZoneMigration();
  setupRuleEditor(ruleTab);
  $('editRule').onclick = () => void openRule({ id: selected });
  $('toggleRule').onclick = async () => {
    if (!$('ruleEditor').hidden) {
      status('Close the unfinished editor first.');
      return;
    }
    await openRule({ id: selected });
    if (draft && draft.rule.id === selected) {
      $<HTMLInputElement>('editEnabled').checked = draft.rule.disabled;
      invalidate();
    }
  };
  $('deleteRule').onclick = () => {
    const r = state.control.rules?.find((r) => r.id === selected);
    if (r) confirmRuleDelete(r, state.control.generation);
  };
  $('evalStart').onclick = async () => {
    const e = await window.flowgate.evaluationState();
    if (e.mode === 'daemon') {
      renderDaemonEvaluation(e);
      if (!e.canStart || !e.tokens) return;
      const frozen = { ...e.tokens };
      confirmAction(
        'Review incoming firewall evaluation',
        e.status!.review,
        async () => {
          $<HTMLDetailsElement>('controlMenu').open = true;
          try {
            await window.flowgate.evaluation('start', frozen);
          } catch (error) {
            $('evaluationStatus').textContent = String(error);
          }
        },
        'Start incoming evaluation',
      );
      return;
    }
    confirmAction(
      'Start five-minute evaluation',
      'This explicitly enables firewall evaluation for the selected profile. New unmatched connections wait for a decision and may be blocked. Authenticate only in the separate terminal. The controller keeps its original five-minute deadline if this window closes.',
      () => evaluate('start'),
    );
  };
  $('evalRecover').onclick = () =>
    confirmAction(
      'Recover controller',
      'Authenticate in the terminal to inspect and clean up the recorded FlowGate controller. Activity will continue.',
      () => evaluate('recover'),
    );
  $('evalStop').onclick = () => void evaluate('stop');
  $('evalCancel').onclick = () => void evaluate('cancel');
  $('evalStatus').onclick = () => void evaluate('status');
  let evalBusy = false;
  setInterval(async () => {
    if (evalBusy || document.hidden) return;
    evalBusy = true;
    try {
      const e = await window.flowgate.evaluationState();
      if (e.mode === 'daemon') {
        renderDaemonEvaluation(e);
        return;
      }
      const c = state?.control,
        active = c?.connected && c.enforcement;
      const remaining = active
        ? Math.max(
            0,
            Math.ceil(
              (Date.parse(active.stops_at) - (state.control.serverNow ?? Date.now())) / 1000,
            ),
          )
        : 0;
      $('evaluationStatus').textContent = active
        ? `${active.state} · ${active.profile} · ${remaining}s · ${active.detail} · ${e.phase === 'idle' ? 'Independent controller; closing FlowGate leaves it running.' : e.message}`
        : `${e.phase === 'stopped' ? 'Cleanup confirmed' : 'Enforcement state unknown'} · ${e.message}`;
      $('evalCancel').hidden = !e.starting;
      $<HTMLButtonElement>('evalStart').disabled =
        e.busy || !!(c?.connected && !c.readOnly) || e.phase === 'active';
      $<HTMLSelectElement>('evalProfile').disabled = $<HTMLButtonElement>('evalStart').disabled;
      for (const id of ['evalStop', 'evalStatus', 'evalRecover'])
        $<HTMLButtonElement>(id).disabled =
          e.busy || c?.mode === 'daemon-monitor' || c?.backendMode === 'daemon-monitor';
      if (c?.mode === 'daemon-monitor' || c?.backendMode === 'daemon-monitor') {
        $<HTMLButtonElement>('evalStart').disabled = true;
        $<HTMLSelectElement>('evalProfile').disabled = true;
        $('evaluationStatus').textContent =
          'Independent non-enforcing daemon · stored policy only. Evaluation transitions are not supported by this connection.';
      }
    } finally {
      evalBusy = false;
    }
  }, 500);
  const tools = node('div', '');
  tools.className = 'extendedbar';
  tools.innerHTML = `<button id="extendedEnable">Start UDP monitoring…</button><button id="extendedStop">Stop UDP monitoring…</button><span id="extendedStatus" role="status"></span>`;
  document.querySelector('#monitoringMenu .menu-panel')!.append(tools);
  const perform = async (a: 'enable' | 'stop') => {
    try {
      extendedError = '';
      $<HTMLButtonElement>('extendedEnable').disabled = true;
      $<HTMLButtonElement>('extendedStop').disabled = true;
      await window.flowgate.extended(a);
    } catch (e) {
      $('extendedStatus').textContent = String(e);
      extendedError = String(e);
    }
  };
  let extendedError = '';
  const badge = document.querySelector<HTMLElement>('#monitoringMenu > summary')!;
  badge.id = 'extendedBadge';
  badge.setAttribute('aria-label', 'UDP monitoring');
  const review = async (action: 'enable' | 'stop') => {
    try {
      const e = await window.flowgate.extendedState();
      const starting = action === 'enable';
      if (!(starting ? e.canEnable : e.canStop))
        throw Error('UDP monitoring status changed. Review the current state in the UDP menu.');
      const label = starting ? 'Start UDP monitoring' : 'Stop UDP monitoring';
      const text = starting
        ? 'FlowGate will measure UDP socket bytes across all peers. UDP measurements are separate from TCP measurements. Collection keeps running when you close the GUI. ' +
          (e.mode === 'daemon' ? 'The daemon handles the request without a sudo prompt.' : 'The legacy collector requires authentication in a separate terminal.')
        : 'FlowGate will stop collecting new UDP measurements and live UDP rates will become unavailable. Previously recorded usage remains available.';
      confirmAction(label, text + ' TCP monitoring and firewall protection stay as they are.', () => perform(action), label);
    } catch (error) {
      extendedError = String(error);
      $('extendedStatus').textContent = extendedError;
    }
  };
  $('extendedEnable').onclick = () => void review('enable');
  $('extendedStop').onclick = () => void review('stop');
  let extendedBusy = false;
  setInterval(async () => {
    if (extendedBusy || document.hidden) return;
    extendedBusy = true;
    try {
      const e = await window.flowgate.extendedState(),
        u = state?.observation.activity?.udp;
      const label = e.mode === 'daemon' ? e.state : u?.state || 'disabled';
      const partial = label === 'partial' || e.partial;
      const short = label === 'active' || label === 'partial' ? 'On' : label === 'disabled' ? 'Off'
        : label === 'unknown' ? 'Offline' : label === 'unsupported' ? 'Unavailable'
        : label.charAt(0).toUpperCase() + label.slice(1);
      badge.textContent = `UDP: ${short}${partial ? ' (partial)' : ''}`;
      badge.title = `UDP monitoring: ${short}${partial ? ' · partial coverage' : ''}`;
      badge.setAttribute('aria-label', `UDP monitoring: ${short}${partial ? ', partial coverage' : ''}`);
      $('extendedStatus').textContent =
        e.mode === 'daemon'
          ? `${e.state}${e.partial ? ' · partial coverage' : ''} · Measurements: ${e.canView ? 'permitted' : 'not authorized'} · Collector control: ${e.canControl ? 'permitted' : 'read-only'}. ${e.message} ${extendedError}`
          : `Legacy path · UDP ${label} · ${u?.reason || 'No collector snapshot'} · ${extendedError || e.message}`;
      $<HTMLButtonElement>('extendedEnable').disabled = !e.canEnable;
      $<HTMLButtonElement>('extendedStop').disabled = !e.canStop;
    } catch (e) {
      badge.textContent = 'UDP: Unavailable';
      badge.title = 'UDP monitoring status unavailable';
      badge.setAttribute('aria-label', 'UDP monitoring: unavailable');
      $('extendedStatus').textContent = String(e);
      $<HTMLButtonElement>('extendedEnable').disabled = true;
      $<HTMLButtonElement>('extendedStop').disabled = true;
    } finally {
      extendedBusy = false;
    }
  }, 750);
  void setupSizing();
}
async function evaluate(a: 'start' | 'stop' | 'status' | 'recover' | 'cancel') {
  for (const id of ['evalStart', 'evalStop', 'evalStatus'])
    $<HTMLButtonElement>(id).disabled = true;
  try {
    const current = await window.flowgate.evaluationState();
    if (current.mode === 'daemon') {
      if (!current.tokens) throw Error('Daemon status unavailable; no evaluation action sent.');
      await window.flowgate.evaluation(a, { ...current.tokens });
      return;
    }
    await window.flowgate.evaluation(
      a,
      a === 'start'
        ? ($<HTMLSelectElement>('evalProfile').value as 'incoming' | 'both')
        : undefined,
    );
  } catch (e) {
    $('evaluationStatus').textContent = String(e);
  }
}
function confirmAction(
  title: string,
  text: string,
  fn: () => Promise<void>,
  actionLabel = 'Continue',
) {
  $('confirmYes').textContent = actionLabel;
  $('confirmTitle').textContent = title;
  $('confirmText').textContent = text;
  const d = $<HTMLDialogElement>('confirmation');
  $('confirmNo').onclick = () => d.close();
  $('confirmYes').onclick = () => {
    d.close();
    void fn();
  };
  d.showModal();
}
function updateButtons() {
  if (
    draft?.observed &&
    receipt &&
    (draft.generation !== state?.control.generation ||
      !writable() ||
      (previewExpires && previewExpires <= (state?.control.serverNow ?? Date.now())))
  ) {
    previewNeedsRefresh = true;
    invalidate();
    editorMessage(
      'Preview expired or session/permission changed. Review a fresh preview; identity is not rebound.',
    );
  }
  for (const input of document.querySelectorAll<HTMLInputElement | HTMLSelectElement>(
    '#ruleEditor input,#ruleEditor select',
  ))
    input.disabled = saving || unresolved;
  const rule = draft?.rule;
  $<HTMLInputElement>('editShareRoot').disabled ||= !rule ||
    !state?.control.capabilities?.includes('explicit-root-sharing-v1') ||
    state.control.permissions?.role !== 'administrator' ||
    !!rule.filter.process || draft?.targetScope === 'process' ||
    !!rule.filter.all_programs || !!rule.preset || !!editorSource.zone;
  for (const [toggle, field] of [
    ['anyAddress', 'editAddress'],
    ['anyLocal', 'editLocal'],
    ['anyRemote', 'editRemote'],
  ]) {
    const any = $<HTMLInputElement>(toggle);
    $<HTMLInputElement>(field).disabled ||= any.checked;
    if (draft?.observed && $<HTMLSelectElement>('createScope').value === 'application')
      any.disabled = true;
  }
  const remaining = previewSeconds(previewExpires, state?.control.serverNow ?? Date.now());
  $('previewValidity').textContent =
    receipt && previewExpires
      ? `Review valid for ${remaining}s`
      : previewNeedsRefresh
        ? 'Refresh required · draft kept'
        : '';
  $('previewRule').textContent = previewNeedsRefresh ? 'Refresh preview' : 'Preview';
  if (draft?.observed) {
    $<HTMLInputElement>('editPriority').disabled = true;
    if ($<HTMLSelectElement>('createScope').value === 'application')
      for (const id of ['editAddress', 'editLocal', 'editRemote'])
        $<HTMLInputElement>(id).disabled = true;
  }
  for (const id of ['previewRule', 'reloadRule'])
    $<HTMLButtonElement>(id).disabled = saving || unresolved || !writable();
  $<HTMLButtonElement>('saveRule').disabled = saving || unresolved || !receipt || !writable();
  $<HTMLButtonElement>('reloadRule').hidden = !!draft?.observed;
  $<HTMLButtonElement>('previewRule').disabled ||=
    (!!draft?.observed && !$<HTMLSelectElement>('createScope').value) ||
    (requireNetwork && !$<HTMLSelectElement>('editZone').value) ||
    (draft?.rule.action === 'ask' && !state?.control.capabilities?.includes(STORED_ASK_CAPABILITY));
  $<HTMLSelectElement>('editZone').disabled ||=
    !!editorSource.id ||
    !!editorSource.zone ||
    !state?.control.capabilities?.includes(ZONE_CAPABILITY);
  $<HTMLButtonElement>('newNetworkRule').disabled = saving || unresolved || !writable();
  if ($<HTMLSelectElement>('editZone').value && receipt &&
      state?.control.networkZones?.revision !== previewNetworkRevision) {
    receipt = ''; previewNeedsRefresh = true;
    $<HTMLButtonElement>('saveRule').disabled = true;
    if (!saving && !unresolved) editorMessage('Network classification changed. Draft kept; refresh the authoritative preview.');
  }
  const observed = draft?.observed && editorSource.observed;
  if (
    observed &&
    (!state?.observation.connected ||
      state.control.generation !== observed.generation ||
      state.observation.generation !== observed.generation ||
      !state.observation.activity?.processes[observed.process_id])
  ) {
    $<HTMLButtonElement>('previewRule').disabled = true;
    $<HTMLButtonElement>('saveRule').disabled = true;
    if (!saving && !unresolved)
      editorMessage(
        'Selected instance is no longer available in this session. Draft kept; close and reselect a live instance. No application fallback.',
      );
  }
  if (draft?.rule.filter.process) {
    const targetState = state?.control.rule_states?.[draft.rule.id];
    if (
      !state?.control.capabilities?.includes(PROCESS_CAPABILITY) ||
      targetState?.state !== 'active'
    ) {
      $<HTMLButtonElement>('previewRule').disabled = true;
      $<HTMLButtonElement>('saveRule').disabled = true;
      if (!saving && !unresolved)
        editorMessage(
          `${targetState?.reason || 'Process target unavailable in this session'}. Draft kept; target cannot be rebound. Delete remains available from the rule list.`,
        );
    }
  }
  $('reconcileRule').hidden = !reconcileReceipt;
  $<HTMLButtonElement>('reconcileRule').disabled = saving || !state?.control.connected;
  $<HTMLButtonElement>('closeEditor').disabled = saving;
}
export function updateRuleEditor(next: ClientState) {
  state = next;
  updateButtons();
}
export function updateWorkflows(next: ClientState) {
  updateRuleEditor(next);
  endpointUI?.update(next);
  migrationUI?.update(next, selected);
  const rules = state.control.rules || [],
    sig = JSON.stringify([rules, state.control.rule_states, rules.map((r) => savedRuleState(r, next.control))]);
  if (sig !== signature) {
    signature = sig;
    const empty = rules.length === 0;
    $('ruleListEmpty').hidden = !empty;
    $('rulesTable').hidden = empty;
    $('ruleInfo').closest('aside')!.hidden = empty;
    const body = $('ruleRows');
    body.replaceChildren();
    for (const r of rules) {
      const tr = node('tr', '');
      tr.dataset.id = r.id;
      tr.tabIndex = 0;
      for (const value of [
        r.network_endpoint ? 'Network endpoint · all users/programs' : r.preset
          ? `Essential · ${r.preset.component} · ${r.executable || (r.filter.all_programs ? 'All programs' : r.filter.application)}`
          : r.executable || r.filter.application,
        r.action,
        r.filter.direction,
        r.filter.protocol,
        `${zoneRuleLabel(r)} · ${r.filter.remote_address || r.filter.remote || '*'} · local ${r.filter.local_port || '*'} / remote ${r.filter.remote_port || '*'}`,
        r.expires.startsWith('0001')
          ? r.filter.process
            ? 'This daemon session / until process exit'
            : 'No expiry'
          : r.expires,
        savedRuleState(r, state.control),
      ]) {
        const td = node('td', value);
        td.title = value;
        tr.append(td);
      }
      tr.onclick = () => {
        selected = r.id;
        selectRule();
      };
      tr.onkeydown = (e) => {
        if (e.key === 'Enter') {
          selected = r.id;
          selectRule();
          if (!r.network_endpoint) void openRule({ id: r.id });
        }
      };
      body.append(tr);
    }
    selectRule();
  }
  for (const id of ['editRule', 'toggleRule', 'deleteRule'])
    $<HTMLButtonElement>(id).disabled = !writable() || !rules.some((r) => r.id === selected);
  const chosen = rules.find((r) => r.id === selected);
  const endpointSelected = !!chosen?.network_endpoint;
  const presetSelected = chosen?.schema === 5;
  if (endpointSelected && !canManageEndpoints(state.control)) $<HTMLButtonElement>('deleteRule').disabled = true;
  for (const id of ['editRule', 'toggleRule']) {
    $<HTMLButtonElement>(id).disabled ||= presetSelected || endpointSelected;
    $<HTMLButtonElement>(id).title = endpointSelected ? 'Recreate through Endpoint permission to change scope.' : presetSelected
      ? 'Manage this legacy preset through the Essential API.'
      : '';
  }
  const compatible = state.control.capabilities?.includes('conditional-rule-delete-v1');
  $<HTMLButtonElement>('deleteRule').disabled ||= !compatible;
  $('deleteCompatibility').textContent = compatible || !rules.length
    ? ''
    : 'Safe Delete unavailable: backend must advertise conditional-rule-delete-v1. No unconditional fallback.';
  const access = state.control.connected ? (!writable() ? 'readonly' : 'write') : 'offline';
  if (access !== accessState) {
    accessState = access;
    status(
      access === 'offline'
        ? 'Controller disconnected. Displayed rules may be stale; mutations disabled.'
        : access === 'readonly'
          ? 'Read-only controller; mutations disabled.'
          : state.control.enforcement?.state === 'stopped'
            ? 'Stored rules editable · protection stopped.'
            : 'Connected. Rule changes require a backend preview.',
    );
  }
  const detail = $('requestDetails');
  if (detail && !detail.querySelector('#createRule')) {
    const b = node('button', 'Create rule…') as HTMLButtonElement;
    b.id = 'createRule';
    b.onclick = () => {
      const event = detail.dataset.eventId;
      if (event) void openRule({ event });
    };
    detail.append(b);
  }
  const b = $<HTMLButtonElement>('createRule');
  if (b) {
    const id = detail.dataset.eventId;
    b.disabled =
      !writable() ||
      !state.control.events.some(
        (e) =>
          e.id === id &&
          e.remembered_filter &&
          e.state === 'awaiting-decision' &&
          e.remainingMs > 0,
      );
  }
}
function selectRule() {
  if (state) migrationUI?.update(state, selected);
  for (const tr of document.querySelectorAll<HTMLTableRowElement>('#ruleRows tr'))
    tr.setAttribute('aria-selected', String(tr.dataset.id === selected));
  const r = state.control.rules?.find((r) => r.id === selected);
  const info = $('ruleInfo');
  const fields = r
    ? [
        [
          'Application',
          r.filter.all_programs ? 'All programs' : r.executable || r.filter.application,
        ],
        [
          'Target',
          r.network_endpoint ? 'Network endpoint · all matching users/programs' : r.preset
            ? r.filter.peer_service
              ? 'All programs → exact local service'
              : r.filter.all_programs
                ? 'All programs'
                : 'Exact application'
            : targetLabel(r.filter.process),
        ],
        ...(r.network_endpoint ? [['Scope', ENDPOINT_SCOPE], ['Precedence', ENDPOINT_PRECEDENCE], ['Removal / expiry', ENDPOINT_LIFETIME], ['Changes', 'Delete and recreate; generic edit and enable/disable are unavailable.']] : []),
        ...(r.preset
          ? [
              ['Preset', `${r.preset.name} · ${r.preset.component}`],
              ['Preset revision', r.preset.revision],
              ['Preset entry', r.preset.entry_id],
              ['Local address', r.filter.local_address || '*'],
              [
                'Interface',
                `${r.filter.interface_name || 'Any'} · index ${r.filter.interface_index || 'Any'}`,
              ],
              [
                'Local service',
                r.filter.peer_service
                  ? `${r.filter.peer_service.application} · revision ${r.filter.peer_service.revision} · ${accountLabel(r.filter.peer_service.uid)}`
                  : 'Not constrained',
              ],
            ]
          : []),
        [
          'Target lifetime',
          state.control.rule_states?.[r.id]?.reason ||
            (r.filter.process
              ? 'Unavailable; no target rebound'
              : r.preset
                ? 'Preset-owned exact scope'
                : 'Application-wide'),
        ],
        ['Action / direction', r.action + ' · ' + r.filter.direction],
        ['Protocol', r.filter.protocol],
        ['Remote address', r.filter.remote_address || r.filter.remote || '*'],
        [
          'Ports',
          `Local ${r.filter.local_port || 'any'} · remote ${r.filter.remote_port || 'any'}`,
        ],
        [
          'Absolute expiry',
          r.expires.startsWith('0001')
            ? r.filter.process
              ? 'This daemon session / until process exit'
              : 'No expiry'
            : r.expires,
        ],
        ['Rule state', savedRuleState(r, state.control)],
        ['Priority', String(r.priority)],
        [
          'Application identity',
          r.filter.application ||
            (r.preset ? 'Not application-bound; see exact local-service/interface scope' : ''),
        ],
        ['Revision', r.filter.revision],
        ['User', r.filter.all_uids ? 'All users' : accountLabel(r.filter.uid)],
        ['Edit version', String(r.version)],
      ]
    : [];
  const signature = JSON.stringify([!!state.control.rules?.length, fields]);
  if (info.dataset.signature !== signature) {
    info.dataset.signature = signature;
    info.replaceChildren();
    if (!r && state.control.rules?.length) info.textContent = 'Select a saved rule.';
    for (const [label, value] of fields) info.append(node('dt', label), node('dd', value));
  }
}
async function setupSizing() {
  let prefs: Preferences = await window.flowgate.preferences();
  const settingsPanel = document.querySelector('#settingsMenu .menu-panel')!;
  setupShapingDefaults(settingsPanel, prefs);
  const save = () =>
    void window.flowgate.preferences({
      sidebar: prefs.sidebar,
      columns: prefs.columns,
      keepInTray: prefs.keepInTray,
    });
  const controls = node('section', '');
  controls.className = 'backgroundbar';
  controls.innerHTML = `<label><input type="checkbox" id="keepInTray"> Keep running in the tray when the window closes</label><span>When enabled, closing hides this window; requests stay monitored. Use File to quit the UI.</span><span id="backgroundStatus" role="status"></span>`;
  settingsPanel.append(controls);
  $<HTMLInputElement>('keepInTray').checked = prefs.keepInTray === true;
  $('keepInTray').onchange = () => {
    prefs.keepInTray = $<HTMLInputElement>('keepInTray').checked;
    save();
  };
  let checking = false;
  const refresh = async () => {
    if (checking || document.hidden) return;
    checking = true;
    try {
      const s = await window.flowgate.backgroundStatus();
      $('backgroundStatus').textContent =
        (s.trayAvailable ? 'Tray available. ' : 'Tray unavailable: closing will quit instead. ') +
        s.notifications;
    } finally {
      checking = false;
    }
  };
  void refresh();
  setInterval(() => void refresh(), 3000);
  const applySidebarWidth = (width: number) => {
    document.documentElement.style.setProperty('--desktop-saved-sidebar-width', width + 'px');
  };
  if (prefs.sidebar) applySidebarWidth(prefs.sidebar);
  for (const aside of document.querySelectorAll<HTMLElement>('main aside')) {
    const grip = node('div', '');
    grip.className = 'sidebar-grip';
    grip.tabIndex = 0;
    grip.setAttribute('role', 'separator');
    grip.setAttribute('aria-label', 'Resize information panel');
    aside.before(grip);
    const resize = (n: number) => {
      prefs.sidebar = Math.round(Math.max(240, Math.min(600, n)));
      applySidebarWidth(prefs.sidebar);
    };
    grip.onkeydown = (e) => {
      if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
        e.preventDefault();
        resize(
          (prefs.sidebar || aside.getBoundingClientRect().width) +
            (e.key === 'ArrowLeft' ? 10 : -10),
        );
        save();
      }
    };
    grip.onpointerdown = (e) => {
      grip.setPointerCapture(e.pointerId);
      const start = e.clientX,
        w = aside.getBoundingClientRect().width;
      grip.onpointermove = (e) => resize(w + start - e.clientX);
      grip.onpointerup = () => {
        grip.onpointermove = null;
        save();
      };
    };
  }
  for (const h of document.querySelectorAll<HTMLElement>('#headers th:not(.col-filler)')) {
    const key = h.className.slice(4);
    const saved = prefs.columns?.[key];
    if (saved) h.style.width = saved + 'px';
    const grip = node('span', '');
    grip.className = 'column-grip';
    h.append(grip);
    grip.onpointerdown = (e) => {
      e.stopPropagation();
      grip.setPointerCapture(e.pointerId);
      const start = e.clientX,
        w = h.getBoundingClientRect().width;
      grip.onpointermove = (e) => {
        h.style.width = Math.max(45, Math.min(700, w + e.clientX - start)) + 'px';
      };
      grip.onpointerup = () => {
        grip.onpointermove = null;
        if (!h.style.width) return;
        prefs.columns = { ...prefs.columns, [key]: Math.round(parseFloat(h.style.width)) };
        save();
      };
    };
  }
}

export function confirmRuleDelete(r: Rule, generation: string) {
  if (!writable() || !state.control.capabilities?.includes('conditional-rule-delete-v1') || (r.network_endpoint && !canManageEndpoints(state.control))) return;
  // Freeze exactly the snapshot displayed in this confirmation, including its generation.
  const snapshot = { id: r.id, generation: generation, version: r.version ?? 0 };
  confirmAction(
    'Delete rule',
    `Delete ${r.filter.all_programs ? 'All programs · ' + (r.filter.all_uids ? 'all users' : accountLabel(r.filter.uid)) : targetLabel(r.filter.process) + ' · ' + (r.executable || r.filter.application)} · ${zoneLabel(r.filter.network_zone)}? Action: ${r.action}; ${r.filter.direction} ${r.filter.protocol}; remote ${r.filter.remote_address || r.filter.remote || '*'}; ports ${r.filter.local_port || '*'} → ${r.filter.remote_port || '*'}; expiry ${r.expires}; ${r.disabled ? 'disabled' : 'enabled'}. Rule ${snapshot.id}, version ${snapshot.version}, generation ${snapshot.generation}. Existing approved TCP sessions may continue.`,
    async () => {
      try {
        status((await window.flowgate.ruleDelete(snapshot)).message);
      } catch (e) {
        status(String(e));
      }
    },
  );
}

export function confirmAppRuleDelete(label: string, rules: Rule[], generation: string) {
  if (!writable() || state.control.generation !== generation ||
      !state.control.capabilities?.includes('conditional-rule-delete-v1') || !rules.length) return;
  const snapshots = rules.map(({ id, version }) => ({ id, version, generation }));
  const count = snapshots.length;
  confirmAction(
    'Delete all app rules',
    `Delete ${count} saved application ${count === 1 ? 'rule' : 'rules'} for ${label}? This covers incoming and outgoing rules for this app and account. Process rules and traffic limits stay in place. Existing approved TCP sessions may continue.`,
    async () => {
      let deleted = 0;
      for (const snapshot of snapshots) {
        try {
          const outcome = await window.flowgate.ruleDelete(snapshot);
          if (outcome.phase !== 'acknowledged') {
            status(`Deleted ${deleted} of ${count} rules. ${outcome.message}`);
            return;
          }
          deleted++;
        } catch (e) {
          status(`Deleted ${deleted} of ${count} rules. ${String(e)}`);
          return;
        }
      }
      status(`Deleted ${deleted} saved application ${deleted === 1 ? 'rule' : 'rules'}.`);
    },
    'Delete all',
  );
}
