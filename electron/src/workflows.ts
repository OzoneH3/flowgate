import type { ClientState, Rule, RuleDraft, RuleEdit, Preferences } from './protocol';
const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
const node = (tag: string, text: string) => {
  const n = document.createElement(tag);
  n.textContent = text;
  return n;
};
let editRevision = 0;
let accessState = '';
let editorSource: { id?: string; event?: string } = {};
let state: ClientState,
  selected = '',
  signature = '',
  draft: RuleDraft | undefined,
  receipt = '',
  saving = false,
  unresolved = false;
const status = (s: string) => {
  $('ruleFeedback').textContent = s;
};
function editorMessage(s: string) {
  $('editorFeedback').textContent = s;
}
function writable() {
  return state?.control.connected && !state.control.readOnly;
}
function editValue(): RuleEdit {
  return {
    token: draft!.token,
    action: $<HTMLSelectElement>('editAction').value as 'allow' | 'block',
    protocol: $<HTMLSelectElement>('editProtocol').value,
    remote_address: $<HTMLInputElement>('editAddress').value,
    local_port: Number($<HTMLInputElement>('editLocal').value),
    remote_port: Number($<HTMLInputElement>('editRemote').value),
    priority: Number($<HTMLInputElement>('editPriority').value),
    disabled: !$<HTMLInputElement>('editEnabled').checked,
    expiry: $<HTMLSelectElement>('editExpiry').value as RuleEdit['expiry'],
  };
}
function invalidate() {
  editRevision++;
  receipt = '';
  $('rulePreview').textContent = 'Preview required before saving.';
  $<HTMLButtonElement>('saveRule').disabled = true;
}
async function open(source: { id?: string; event?: string }) {
  if (draft) {
    $('ruleEditor').hidden = false;
    status('An unfinished editor is already open. Save or close it first.');
    return;
  }
  try {
    draft = await window.flowgate.ruleDraft(source);
    editorSource = source;
    unresolved = false;
    saving = false;
    const r = draft.rule;
    $('editorIdentity').textContent =
      `${r.executable}\n${r.filter.application} · revision ${r.filter.revision}\n${r.filter.direction} · UID ${r.filter.uid} · ${draft.source}`;
    $<HTMLSelectElement>('editAction').value = r.action;
    $<HTMLSelectElement>('editProtocol').value = r.filter.protocol;
    $<HTMLInputElement>('editAddress').value = r.filter.remote_address || '*';
    $<HTMLInputElement>('editLocal').value = String(r.filter.local_port || 0);
    $<HTMLInputElement>('editRemote').value = String(r.filter.remote_port || 0);
    $<HTMLInputElement>('editPriority').value = String(r.priority);
    $<HTMLInputElement>('editEnabled').checked = !r.disabled;
    $<HTMLSelectElement>('editExpiry').value = 'preserve';
    $('absoluteExpiry').textContent = 'Absolute expiry: ' + r.expires;
    $('ruleEditor').hidden = false;
    invalidate();
    editorMessage(
      'Fields are validated by Go. Existing identity and absolute expiry are preserved.',
    );
    $('editAction').focus();
  } catch (e) {
    status(String(e));
  }
}
export function setupWorkflows(chooseTab: (s: string) => void) {
  $('requestsTab').after(node('button', 'Rules'));
  const ruleTab = $('requestsTab').nextElementSibling as HTMLButtonElement;
  ruleTab.id = 'rulesTab';
  ruleTab.onclick = () => chooseTab('rules');
  const view = node('main', '');
  view.id = 'rulesView';
  view.hidden = true;
  view.innerHTML = `<section class="rules-main"><div class="filterbar"><button id="editRule">Edit selected</button><button id="toggleRule">Enable / Disable…</button><button id="deleteRule">Delete…</button></div><div class="table-scroll"><table id="rulesTable" tabindex="0" aria-label="Saved rules"><thead><tr><th>Application</th><th>Action</th><th>Direction</th><th>Protocol</th><th>Endpoint scope</th><th>Expiry</th><th>State</th></tr></thead><tbody id="ruleRows"></tbody></table></div><p class="hint">Rules are evaluated by Go. Changing rules does not necessarily disconnect already-approved TCP sessions.</p><p id="ruleFeedback" role="status"></p></section><aside><h2>Rule information</h2><dl id="ruleInfo">Select a saved rule.</dl></aside>`;
  $('requestsView').after(view);
  const evaluation = node('section', '');
  evaluation.className = 'evaluationbar';
  evaluation.innerHTML = `<select id="evalProfile" aria-label="Evaluation profile"><option value="incoming">Incoming only</option><option value="both">Incoming and outgoing</option></select><button id="evalStart">Start 5-minute evaluation…</button><button id="evalStop">Stop evaluation</button><button id="evalCancel" hidden>Cancel authentication</button><button id="evalStatus">Status</button><button id="evalRecover">Recovery…</button><span id="evaluationStatus" role="status"></span>`;
  document.querySelector('.tabs')!.before(evaluation);
  const confirmation = node('dialog', '');
  confirmation.id = 'confirmation';
  confirmation.innerHTML = `<h2 id="confirmTitle"></h2><p id="confirmText"></p><div class="editor-actions"><button id="confirmNo">Cancel</button><button id="confirmYes">Continue</button></div>`;
  document.body.append(confirmation);
  const panel = node('section', '');
  panel.id = 'ruleEditor';
  panel.hidden = true;
  panel.setAttribute('role', 'dialog');
  panel.setAttribute('aria-label', 'Rule editor');
  panel.innerHTML = `<header><strong>FlowGate — Rule editor</strong><span><button id="minimizeEditor">Minimize</button> <button id="closeEditor">Close</button></span></header><div class="editor-body"><h2>For</h2><pre id="editorIdentity"></pre><h2>Rule</h2><div class="editor-fields"><label for="editAction">Action</label><select id="editAction"><option value="allow">Allow</option><option value="block">Block</option></select><label for="editProtocol">Protocol</label><select id="editProtocol"><option value="tcp">TCP</option><option value="udp">UDP</option><option value="*">Any</option></select><label for="editAddress">Remote IP / CIDR</label><input id="editAddress" maxlength="256"><label for="editLocal">Local port (0 = any)</label><input id="editLocal" type="number" min="0" max="65535"><label for="editRemote">Remote port (0 = any)</label><input id="editRemote" type="number" min="0" max="65535"><label for="editPriority">Priority</label><input id="editPriority" type="number" min="-1000" max="1000"><label for="editExpiry">Expiry</label><select id="editExpiry"><option value="preserve">Preserve absolute expiry</option><option value="hour">Explicitly reset to 1 hour</option><option value="permanent">No expiry</option></select><label for="editEnabled">Enabled</label><input id="editEnabled" type="checkbox"></div><p id="absoluteExpiry"></p><h2>Authoritative scope</h2><p id="rulePreview" class="scope-preview"></p><p id="editorFeedback" role="status"></p></div><footer><button id="reloadRule">Reload version, keep fields</button><button id="previewRule">Preview</button><button id="saveRule" disabled>Save</button></footer>`;
  document.body.append(panel);
  document.addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.key.toLowerCase() === 'e') {
      e.preventDefault();
      const id = selected || state?.control.rules?.[0]?.id;
      if (id) void open({ id });
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
  panel.addEventListener('input', invalidate);
  $('closeEditor').onclick = () => {
    if (!saving) {
      panel.hidden = true;
      draft = undefined;
      resume.hidden = true;
      receipt = '';
    }
  };
  $('reloadRule').onclick = async () => {
    if (!draft || saving || unresolved) return;
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
      $('rulePreview').textContent = r.preview;
      $<HTMLButtonElement>('saveRule').disabled = !writable();
      editorMessage('Review backend scope, then save.');
    } catch (e) {
      editorMessage(String(e));
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
        panel.hidden = true;
        $('resumeEditor').hidden = true;
        draft = undefined;
        status(result.message);
      }
      if (result.phase === 'unknown') unresolved = true;
    } catch (e) {
      editorMessage(String(e));
    } finally {
      saving = false;
      updateButtons();
    }
  };
  $('editRule').onclick = () => void open({ id: selected });
  $('toggleRule').onclick = async () => {
    if (!$('ruleEditor').hidden) {
      status('Close the unfinished editor first.');
      return;
    }
    await open({ id: selected });
    if (draft && draft.rule.id === selected) {
      $<HTMLInputElement>('editEnabled').checked = draft.rule.disabled;
      invalidate();
    }
  };
  $('deleteRule').onclick = () => {
    const r = state.control.rules?.find((r) => r.id === selected);
    if (!r) return;
    confirmAction(
      'Delete rule',
      'Delete this saved rule? Existing approved TCP sessions may continue.',
      async () => {
        try {
          status(
            (
              await window.flowgate.ruleDelete({
                id: r.id,
                generation: state.control.generation,
                version: r.version,
              })
            ).message,
          );
        } catch (e) {
          status(String(e));
        }
      },
    );
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
    if (evalBusy) return;
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
        $<HTMLButtonElement>(id).disabled = e.busy;
    } finally {
      evalBusy = false;
    }
  }, 500);
  const tools = node('div', '');
  tools.className = 'extendedbar';
  tools.innerHTML = `<button id="extendedEnable">Enable extended monitoring…</button><button id="extendedStop">Stop extended monitoring</button><span id="extendedStatus"></span>`;
  document.querySelector('.activity-main')!.prepend(tools);
  const perform = async (a: 'enable' | 'stop') => {
    try {
      await window.flowgate.extended(a);
    } catch (e) {
      $('extendedStatus').textContent = String(e);
      extendedError = String(e);
    }
  };
  let extendedError = '';
  $('extendedEnable').onclick = () =>
    confirmAction(
      'Extended UDP monitoring',
      'Enable privileged UDP API-byte collection for this user? This does not activate firewall evaluation. Authenticate in the terminal. Counts cover each socket across all peers, may miss traffic before registration, and remain separate from TCP transport bytes. Close the terminal or use Stop to end collection.',
      () => perform('enable'),
    );
  $('extendedStop').onclick = () => perform('stop');
  let extendedBusy = false;
  setInterval(async () => {
    if (extendedBusy) return;
    extendedBusy = true;
    try {
      const e = await window.flowgate.extendedState(),
        u = state?.observation.activity?.udp;
      $('extendedStatus').textContent =
        `UDP ${u?.state || 'unavailable'}${u?.missed_operations ? ' · partial coverage · ' + u.missed_operations + ' missed operations' : ''} · ${u?.reason || 'No collector snapshot'} · ${extendedError || e.message}`;
      $<HTMLButtonElement>('extendedEnable').disabled = e.busy || u?.state === 'active';
      $<HTMLButtonElement>('extendedStop').disabled = e.busy;
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
  for (const input of document.querySelectorAll<HTMLInputElement | HTMLSelectElement>(
    '#ruleEditor input,#ruleEditor select',
  ))
    input.disabled = saving;
  for (const id of ['previewRule', 'reloadRule'])
    $<HTMLButtonElement>(id).disabled = saving || unresolved || !writable();
  $<HTMLButtonElement>('saveRule').disabled = saving || unresolved || !receipt || !writable();
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
          void open({ id: r.id });
        }
      };
      body.append(tr);
    }
    selectRule();
  }
  for (const id of ['editRule', 'toggleRule', 'deleteRule'])
    $<HTMLButtonElement>(id).disabled = !writable() || !rules.some((r) => r.id === selected);
  const access = state.control.connected
    ? state.control.readOnly
      ? 'readonly'
      : 'write'
    : 'offline';
  if (access !== accessState) {
    accessState = access;
    status(
      access === 'offline'
        ? 'Controller disconnected. Displayed rules may be stale; mutations disabled.'
        : access === 'readonly'
          ? 'Read-only controller; mutations disabled.'
          : 'Connected. Rule changes require a backend preview.',
    );
  }
  const detail = $('requestDetails');
  if (detail && !detail.querySelector('#createRule')) {
    const b = node('button', 'Create rule…') as HTMLButtonElement;
    b.id = 'createRule';
    b.onclick = () => {
      const event = detail.dataset.eventId;
      if (event) void open({ event });
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
  for (const aside of document.querySelectorAll<HTMLElement>('main aside')) {
    aside.style.width = (prefs.sidebar || 330) + 'px';
    const grip = node('div', '');
    grip.className = 'sidebar-grip';
    grip.tabIndex = 0;
    grip.setAttribute('role', 'separator');
    grip.setAttribute('aria-label', 'Resize information panel');
    aside.before(grip);
    const resize = (n: number) => {
      prefs.sidebar = Math.round(Math.max(240, Math.min(600, n)));
      for (const a of document.querySelectorAll<HTMLElement>('main aside'))
        a.style.width = prefs.sidebar + 'px';
    };
    grip.onkeydown = (e) => {
      if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
        e.preventDefault();
        resize((prefs.sidebar || 330) + (e.key === 'ArrowLeft' ? 10 : -10));
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
