import { canManageRules } from './protocol';
import { reviewedScope, previewSeconds } from './editor-presentation';
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
let editRevision = 0;
let accessState = '';
let editorSource: RuleSource = {};
let previewNeedsRefresh = false;
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
  $('ruleFeedback').textContent = s;
  if ($('feedback')) $('feedback').textContent = s;
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
    action: $<HTMLSelectElement>('editAction').value as 'allow' | 'block',
    protocol: $<HTMLSelectElement>('editProtocol').value,
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
  $('scopeSummary').textContent = 'Choose scope, then review the backend preview.';
  $<HTMLButtonElement>('saveRule').disabled = true;
}
export async function openRule(source: RuleSource) {
  if (draft) {
    $('ruleEditor').hidden = false;
    status('An unfinished editor is already open. Save or close it first.');
    return;
  }
  try {
    draft = await window.flowgate.ruleDraft(source);
    editorSource = source;
    unresolved = false;
    reconcileReceipt = '';
    previewNeedsRefresh = false;
    saving = false;
    const r = draft.rule;
    $('editorApplication').textContent =
      `${r.executable || r.filter.application} · ${r.filter.direction} · UID ${r.filter.uid}`;
    $('editorIdentity').textContent =
      `${r.executable}\n${r.filter.application} · revision ${r.filter.revision}\n${r.filter.direction} · UID ${r.filter.uid} · ${draft.source}`;
    $<HTMLSelectElement>('editAction').value = r.action;
    $<HTMLSelectElement>('editProtocol').value = r.filter.protocol;
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
    $<HTMLSelectElement>('editExpiry').value = 'preserve';
    $('absoluteExpiry').textContent = r.expires.startsWith('0001-')
      ? 'Persistent: no expiry.'
      : 'Expires: ' + new Date(r.expires).toLocaleString();
    $('editExpiry').querySelector('option[value=preserve]')!.textContent = r.expires.startsWith(
      '0001-',
    )
      ? 'Keep persistent'
      : 'Keep this expiry';
    $('creationScopeFields').hidden = !draft.observed;
    $<HTMLSelectElement>('createScope').value = '';
    for (const e of document.querySelectorAll<HTMLElement>('#editPriority,label[for=editPriority]'))
      e.hidden = !!draft.observed;
    $<HTMLOptionElement>('editProtocol').querySelector<HTMLOptionElement>(
      'option[value="*"]',
    )!.disabled = !!draft.observed;
    $('ruleEditor').hidden = false;
    invalidate();
    editorMessage(
      draft.observed
        ? 'Observed identity; Preview must verify the live process. Choose explicit scope before reviewing.'
        : 'Fields are validated by Go. Existing identity and absolute expiry are preserved.',
    );
    $('editAction').focus();
  } catch (e) {
    status(String(e));
  }
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
  view.innerHTML = `<section class="rules-main"><div class="filterbar"><button id="editRule">Edit selected</button><button id="toggleRule">Enable / Disable…</button><button id="deleteRule">Delete…</button></div><div class="table-scroll"><table id="rulesTable" tabindex="0" aria-label="Saved rules"><thead><tr><th>Application</th><th>Action</th><th>Direction</th><th>Protocol</th><th>Endpoint scope</th><th>Expiry</th><th>State</th></tr></thead><tbody id="ruleRows"></tbody></table></div><p class="hint">Rules are evaluated by Go. Changing rules does not necessarily disconnect already-approved TCP sessions.</p><p id="deleteCompatibility" class="hint"></p><p id="ruleFeedback" role="status"></p></section><aside><h2>Rule information</h2><dl id="ruleInfo">Select a saved rule.</dl></aside>`;
  $('requestsView').after(view);
  for (const [id, label] of [
    ['optionsMenu', 'Options'],
    ['controlMenu', 'Control'],
  ]) {
    const menu = node('details', '');
    menu.id = id;
    menu.className = 'desktop-menu';
    menu.append(node('summary', label), node('div', ''));
    menu.lastElementChild!.className = 'menu-panel';
    document.querySelector('.brand')!.after(menu);
  }
  document.addEventListener('pointerdown', (event) => {
    for (const menu of document.querySelectorAll<HTMLDetailsElement>('.desktop-menu[open]'))
      if (!menu.contains(event.target as Node)) menu.open = false;
  });
  for (const menu of document.querySelectorAll<HTMLDetailsElement>('.desktop-menu'))
    menu.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') {
        event.stopPropagation();
        menu.open = false;
        (menu.querySelector('summary') as HTMLElement).focus();
      }
    });
  const evaluation = node('section', '');
  evaluation.className = 'evaluationbar';
  evaluation.innerHTML = `<select id="evalProfile" aria-label="Evaluation profile"><option value="incoming">Incoming only</option><option value="both" disabled>Both directions · support not advertised</option></select><button id="evalStart">Start 5-minute evaluation…</button><button id="evalStop">Stop evaluation</button><button id="evalCancel" hidden>Cancel authentication</button><button id="evalStatus">Status</button><button id="evalRecover">Recovery…</button><span id="evaluationStatus" role="status"></span>`;
  document.querySelector('#controlMenu .menu-panel')!.append(evaluation);
  const confirmation = node('dialog', '');
  confirmation.id = 'confirmation';
  confirmation.innerHTML = `<h2 id="confirmTitle"></h2><p id="confirmText"></p><div class="editor-actions"><button id="confirmNo">Cancel</button><button id="confirmYes">Continue</button></div>`;
  document.body.append(confirmation);
  const panel = node('section', '');
  panel.id = 'ruleEditor';
  panel.hidden = true;
  panel.setAttribute('role', 'dialog');
  panel.setAttribute('aria-label', 'Rule editor');
  panel.innerHTML = `<header><strong>FlowGate — Rule editor</strong><span><button id="minimizeEditor">Minimize</button> <button id="closeEditor">Close</button></span></header><div class="editor-body"><div class="editor-tab">Rule</div><h2>For</h2><details class="editor-identity"><summary id="editorApplication">Application identity</summary><pre id="editorIdentity"></pre></details><h2>Rule and scope</h2><div id="creationScopeFields" hidden><label for="createScope">Scope</label> <select id="createScope"><option value="">Choose scope…</option><option value="custom">Specified address / ports</option><option value="application">All addresses / ports for this protocol</option></select></div><div class="editor-fields"><label for="editAction">Action</label><select id="editAction"><option value="allow">Allow</option><option value="block">Block</option></select><label for="editProtocol">Protocol</label><select id="editProtocol"><option value="tcp">TCP</option><option value="udp">UDP</option><option value="*">Any</option></select><label for="editAddress">Remote address</label><div class="scope-input"><label><input id="anyAddress" type="checkbox">Any address</label><input id="editAddress" maxlength="256" placeholder="IP address or CIDR"></div><label for="editLocal">Local port</label><div class="scope-input"><label><input id="anyLocal" type="checkbox">Any port</label><input id="editLocal" type="number" min="1" max="65535" aria-label="Specific local port"></div><label for="editRemote">Remote port</label><div class="scope-input"><label><input id="anyRemote" type="checkbox">Any port</label><input id="editRemote" type="number" min="1" max="65535" aria-label="Specific remote port"></div><label for="editPriority">Priority</label><input id="editPriority" type="number" min="-1000" max="1000"><label for="editExpiry">Expiry</label><select id="editExpiry"><option value="preserve">Preserve absolute expiry</option><option value="hour">For 1 hour from preview</option><option value="permanent">Persistent (no expiry)</option></select><label for="editEnabled">Enabled</label><input id="editEnabled" type="checkbox"></div><p id="absoluteExpiry"></p><h2>Review scope</h2><p id="scopeSummary"></p><details id="backendScope"><summary>Full backend preview</summary><p id="rulePreview" class="scope-preview"></p></details><p id="editorFeedback" role="status"></p></div><footer><button id="reloadRule">Reload version, keep fields</button><button id="previewRule">Preview</button><button id="saveRule" disabled>Save</button><span id="previewValidity" role="timer"></span><button id="reconcileRule" hidden>Check save result</button></footer>`;
  panel.querySelector('header')!.prepend(panel.querySelector('.editor-tab')!);
  const editorFooter = panel.querySelector('footer')!;
  editorFooter.prepend(panel.querySelector('#saveRule')!);
  editorFooter.append(panel.querySelector('#closeEditor')!);
  document.body.append(panel);
  document.addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.key.toLowerCase() === 'e') {
      e.preventDefault();
      const id = selected || state?.control.rules?.[0]?.id;
      if (id) void openRule({ id });
    }
    if (e.key === 'Escape' && draft && !saving) {
      panel.hidden = true;
      $('resumeEditor').hidden = false;
    }
  });
  const resume = node('button', 'Resume editor') as HTMLButtonElement;
  resume.id = 'resumeEditor';
  resume.hidden = true;
  ruleTab.after(resume);
  resume.onclick = () => {
    panel.hidden = false;
    resume.hidden = true;
  };
  $('minimizeEditor').onclick = () => {
    panel.hidden = true;
    resume.hidden = false;
  };
  panel.addEventListener('input', () => {
    if (!unresolved) {
      invalidate();
      updateButtons();
    }
  });
  $('createScope').onchange = () => {
    if ($<HTMLSelectElement>('createScope').value === 'application') {
      for (const id of ['anyAddress', 'anyLocal', 'anyRemote'])
        $<HTMLInputElement>(id).checked = true;
    }
    if ($<HTMLSelectElement>('createScope').value === 'custom')
      $<HTMLInputElement>('anyAddress').checked = false;
    invalidate();
    updateButtons();
  };
  $('closeEditor').onclick = () => {
    if (saving) return;
    const close = async () => {
      panel.hidden = true;
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
      $('absoluteExpiry').textContent = 'Absolute expiry: ' + draft.rule.expires;
      invalidate();
      editorMessage(
        'Current version loaded; entered fields retained. Review expiry and preview again.',
      );
    } catch (e) {
      editorMessage(String(e));
    }
  };
  $('previewRule').onclick = async () => {
    if (!draft || saving || unresolved) return;
    invalidate();
    try {
      const revision = editRevision;
      const r = await window.flowgate.rulePreview(editValue());
      if (revision !== editRevision || !draft || $('ruleEditor').hidden) return;
      receipt = r.receipt;
      previewNeedsRefresh = false;
      $('scopeSummary').textContent = r.verifiedRule
        ? reviewedScope(r.verifiedRule)
        : 'Backend preview ready. Review full scope below.';
      if (!r.verifiedRule) $<HTMLDetailsElement>('backendScope').open = true;
      $('rulePreview').textContent = r.preview;
      previewExpires = r.expiresAt ? Date.parse(r.expiresAt) : 0;
      if (r.verifiedRule) {
        const rule = r.verifiedRule;
        $('editorApplication').textContent =
          `Verified · ${rule.executable} · ${rule.filter.direction} · UID ${rule.filter.uid}`;
        $('editorIdentity').textContent =
          `${rule.executable}\n${rule.filter.application} · revision ${rule.filter.revision}\n${rule.filter.direction} · UID ${rule.filter.uid} · process ${r.processID}`;
        $('absoluteExpiry').textContent = rule.expires.startsWith('0001-')
          ? 'Persistent: no expiry.'
          : 'Expires: ' + new Date(rule.expires).toLocaleString();
      }
      $<HTMLButtonElement>('saveRule').disabled = !writable();
      editorMessage('Review this scope before Save. Saving does not start enforcement.');
      updateButtons();
    } catch (e) {
      editorMessage(
        /stale_target|unsupported_target/.test(String(e))
          ? String(e) +
              ' Close this editor and select a live supported application again; your draft has not been rebound.'
          : String(e),
      );
    }
  };
  $('saveRule').onclick = async () => {
    if (!receipt || saving || unresolved) return;
    const r = receipt;
    receipt = '';
    saving = true;
    updateButtons();
    try {
      const result = await window.flowgate.ruleSave(r);
      editorMessage(result.message);
      if (result.phase === 'acknowledged') {
        if (result.rule) {
          selected = result.rule.id;
          showTab('rules');
          selectRule();
        }
        panel.hidden = true;
        $('resumeEditor').hidden = true;
        draft = undefined;
        status(result.message);
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
      editorMessage(result.message);
      if (result.phase === 'acknowledged' && result.rule) {
        selected = result.rule.id;
        draft = undefined;
        unresolved = false;
        reconcileReceipt = '';
        panel.hidden = true;
        $('resumeEditor').hidden = true;
        showTab('rules');
        selectRule();
        status(result.message);
      }
    } catch (e) {
      editorMessage(String(e));
    } finally {
      saving = false;
      updateButtons();
    }
  };
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
  $('evalStart').onclick = () =>
    confirmAction(
      'Start five-minute evaluation',
      'This explicitly enables firewall evaluation for the selected profile. New unmatched connections wait for a decision and may be blocked. Authenticate only in the separate terminal. The controller keeps its original five-minute deadline if this window closes.',
      () => evaluate('start'),
    );
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
  tools.innerHTML = `<button id="extendedEnable">Enable extended monitoring…</button><button id="extendedStop">Stop extended monitoring</button><span id="extendedStatus"></span>`;
  document.querySelector('#controlMenu .menu-panel')!.append(tools);
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
  const badge = node('button', 'UDP monitoring') as HTMLButtonElement;
  badge.id = 'extendedBadge';
  badge.title = 'Extended UDP monitoring; independent of firewall enforcement';
  document.querySelector('.toolbar')!.insertBefore(badge, $('observerStatus'));
  badge.onclick = () => {
    $<HTMLDetailsElement>('controlMenu').open = true;
    $('extendedEnable').focus();
  };
  $('extendedEnable').onclick = async () => {
    const e = await window.flowgate.extendedState();
    confirmAction(
      'Extended UDP monitoring',
      e.mode === 'daemon'
        ? 'Enable UDP measurement in the connected daemon? No sudo prompt or firewall change. UDP counts socket API bytes across all peers, separate from TCP transport bytes. Collection continues when FlowGate closes until explicitly stopped.'
        : 'Use legacy UDP collection? This backend does not advertise daemon-owned monitoring. Authenticate separately in the terminal. No firewall activation; socket API bytes remain separate from TCP transport bytes.',
      () => perform('enable'),
    );
  };
  $('extendedStop').onclick = () => perform('stop');
  let extendedBusy = false;
  setInterval(async () => {
    if (extendedBusy || document.hidden) return;
    extendedBusy = true;
    try {
      const e = await window.flowgate.extendedState(),
        u = state?.observation.activity?.udp;
      const label = e.mode === 'daemon' ? e.state : u?.state || 'disabled';
      badge.textContent = `UDP monitoring · ${label}${e.partial ? ' *' : ''}`;
      badge.title = `Extended monitoring (${e.mode === 'daemon' ? 'daemon-owned' : 'legacy'}) · ${e.message}`;
      $('extendedStatus').textContent =
        e.mode === 'daemon'
          ? `${e.state}${e.partial ? ' · partial coverage' : ''} · Measurements: ${e.canView ? 'permitted' : 'not authorized'} · Collector control: ${e.canControl ? 'permitted' : 'read-only'}. ${e.message} ${extendedError}`
          : `Legacy path · UDP ${label} · ${u?.reason || 'No collector snapshot'} · ${extendedError || e.message}`;
      $<HTMLButtonElement>('extendedEnable').textContent =
        e.mode === 'daemon' ? 'Enable extended monitoring…' : 'Enable legacy monitoring…';
      $<HTMLButtonElement>('extendedEnable').disabled = !e.canEnable;
      $<HTMLButtonElement>('extendedStop').disabled = !e.canStop;
    } catch (e) {
      badge.textContent = 'UDP monitoring · unknown';
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
  try {
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
function confirmAction(title: string, text: string, fn: () => Promise<void>) {
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
    !!draft?.observed && !$<HTMLSelectElement>('createScope').value;
  $('reconcileRule').hidden = !reconcileReceipt;
  $<HTMLButtonElement>('reconcileRule').disabled = saving || !state?.control.connected;
  $<HTMLButtonElement>('closeEditor').disabled = saving;
}
export function updateWorkflows(next: ClientState) {
  state = next;
  updateButtons();
  const rules = state.control.rules || [],
    sig = JSON.stringify([
      rules,
      rules.map(
        (r) =>
          Date.parse(r.expires) > 0 &&
          Date.parse(r.expires) <= (state.control.serverNow ?? Date.now()),
      ),
    ]);
  if (sig !== signature) {
    signature = sig;
    const body = $('ruleRows');
    body.replaceChildren();
    for (const r of rules) {
      const tr = node('tr', '');
      tr.dataset.id = r.id;
      tr.tabIndex = 0;
      for (const value of [
        r.executable || r.filter.application,
        r.action,
        r.filter.direction,
        r.filter.protocol,
        `${r.filter.remote_address || r.filter.remote || '*'} · local ${r.filter.local_port || '*'} / remote ${r.filter.remote_port || '*'}`,
        r.expires.startsWith('0001') ? 'No expiry' : r.expires,
        Date.parse(r.expires) > 0 &&
        Date.parse(r.expires) <= (state.control.serverNow ?? Date.now())
          ? 'Expired'
          : r.disabled
            ? 'Disabled'
            : 'Enabled',
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
          void openRule({ id: r.id });
        }
      };
      body.append(tr);
    }
    selectRule();
  }
  for (const id of ['editRule', 'toggleRule', 'deleteRule'])
    $<HTMLButtonElement>(id).disabled = !writable() || !rules.some((r) => r.id === selected);
  const compatible = state.control.capabilities?.includes('conditional-rule-delete-v1');
  $<HTMLButtonElement>('deleteRule').disabled ||= !compatible;
  $('deleteCompatibility').textContent = compatible
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
            ? 'Stored rules editable · select an In / Out cell to review policy.'
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
  for (const tr of document.querySelectorAll<HTMLTableRowElement>('#ruleRows tr'))
    tr.setAttribute('aria-selected', String(tr.dataset.id === selected));
  const r = state.control.rules?.find((r) => r.id === selected);
  const info = $('ruleInfo');
  const fields = r
    ? [
        ['Application', r.executable || r.filter.application],
        ['Action / direction', r.action + ' · ' + r.filter.direction],
        ['Protocol', r.filter.protocol],
        ['Remote address', r.filter.remote_address || r.filter.remote || '*'],
        [
          'Ports',
          `Local ${r.filter.local_port || 'any'} · remote ${r.filter.remote_port || 'any'}`,
        ],
        ['Absolute expiry', r.expires.startsWith('0001') ? 'No expiry' : r.expires],
        ['Enabled', r.disabled ? 'No' : 'Yes (expiry still applies)'],
        ['Priority', String(r.priority)],
        ['Application identity', r.filter.application],
        ['Revision', r.filter.revision],
        ['UID', String(r.filter.uid)],
        ['Edit version', String(r.version)],
      ]
    : [];
  const signature = JSON.stringify(fields);
  if (info.dataset.signature !== signature) {
    info.dataset.signature = signature;
    info.replaceChildren();
    if (!r) info.textContent = 'Select a saved rule.';
    for (const [label, value] of fields) info.append(node('dt', label), node('dd', value));
  }
}
async function setupSizing() {
  let prefs: Preferences = await window.flowgate.preferences();
  const save = () => void window.flowgate.preferences(prefs);
  const controls = node('section', '');
  controls.className = 'backgroundbar';
  controls.innerHTML = `<label><input type="checkbox" id="keepInTray"> Keep running in the tray when the window closes</label><span>When enabled, closing hides this window; requests stay monitored. Quit exits the frontend only.</span><button id="quitFlowGate">Quit FlowGate…</button><span id="backgroundStatus" role="status"></span>`;
  document.querySelector('#optionsMenu .menu-panel')!.append(controls);
  $<HTMLInputElement>('keepInTray').checked = prefs.keepInTray === true;
  $('keepInTray').onchange = () => {
    prefs.keepInTray = $<HTMLInputElement>('keepInTray').checked;
    save();
  };
  $('quitFlowGate').onclick = () => void window.flowgate.quit();
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
  for (const aside of document.querySelectorAll<HTMLElement>('main aside')) {
    const defaultSidebar = Math.round(window.innerWidth * 0.38);
    aside.style.width = (prefs.sidebar || defaultSidebar) + 'px';
    document.documentElement.style.setProperty(
      '--info-width',
      (prefs.sidebar || defaultSidebar) + 'px',
    );
    const grip = node('div', '');
    grip.className = 'sidebar-grip';
    grip.tabIndex = 0;
    grip.setAttribute('role', 'separator');
    grip.setAttribute('aria-label', 'Resize information panel');
    aside.before(grip);
    const resize = (n: number) => {
      prefs.sidebar = Math.round(Math.max(240, Math.min(600, n)));
      document.documentElement.style.setProperty('--info-width', prefs.sidebar + 'px');
      for (const a of document.querySelectorAll<HTMLElement>('main aside'))
        a.style.width = prefs.sidebar + 'px';
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
  const headers = [...document.querySelectorAll<HTMLElement>('#headers th')];
  const resizeTable = () => {
    $('tree').style.width =
      headers.reduce(
        (n, h) => n + parseFloat(h.style.width || String(h.getBoundingClientRect().width)),
        0,
      ) + 'px';
  };
  for (const h of headers) {
    const key = h.className.slice(4);
    h.style.width = (prefs.columns?.[key] || h.getBoundingClientRect().width) + 'px';
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
        resizeTable();
      };
      grip.onpointerup = () => {
        grip.onpointermove = null;
        prefs.columns = { ...prefs.columns, [key]: Math.round(parseFloat(h.style.width)) };
        save();
      };
    };
  }
  resizeTable();
}

export function confirmRuleDelete(r: Rule, generation: string) {
  if (!writable() || !state.control.capabilities?.includes('conditional-rule-delete-v1')) return;
  // Freeze exactly the snapshot displayed in this confirmation, including its generation.
  const snapshot = { id: r.id, generation: generation, version: r.version ?? 0 };
  confirmAction(
    'Delete rule',
    `Delete ${r.executable || r.filter.application}? Action: ${r.action}; ${r.filter.direction} ${r.filter.protocol}; remote ${r.filter.remote_address || r.filter.remote || '*'}; ports ${r.filter.local_port || '*'} → ${r.filter.remote_port || '*'}; expiry ${r.expires}; ${r.disabled ? 'disabled' : 'enabled'}. Rule ${snapshot.id}, version ${snapshot.version}, generation ${snapshot.generation}. Existing approved TCP sessions may continue.`,
    async () => {
      try {
        status((await window.flowgate.ruleDelete(snapshot)).message);
      } catch (e) {
        status(String(e));
      }
    },
  );
}
