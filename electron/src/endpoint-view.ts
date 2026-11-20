import type { ClientState } from './protocol';
import { canManageEndpoints, ENDPOINT_SCOPE, ENDPOINT_PRECEDENCE, ENDPOINT_LIFETIME, ENDPOINT_ZERO_EXPIRY, type EndpointDraft, type EndpointReview } from './endpoint-policy';
export function setupEndpointPermissions() {
  const button = document.createElement('button');
  button.id = 'newEndpointRule'; button.textContent = 'Endpoint permission…';
  document.querySelector('#rulesView .filterbar')!.append(button);
  const dialog = document.createElement('dialog'); dialog.id = 'endpointEditor';
  dialog.setAttribute('aria-labelledby','endpointHeading');
  dialog.innerHTML = `<h2 id="endpointHeading">Network endpoint permission</h2><p id="endpointScope"></p><p id="endpointPrecedence"></p><p id="endpointLifetime"></p><p>Outgoing TCP only. Choose one IP address and remote port. Changes require deleting and recreating this rule.</p><div class="endpoint-fields"><label for="endpointAction">Action</label><select id="endpointAction"><option value="">Choose action…</option><option value="allow">Allow</option><option value="block">Deny</option></select><label for="endpointAddress">Remote IP</label><input id="endpointAddress" maxlength="64" autocomplete="off" placeholder="IP address"><label for="endpointPort">Remote TCP port</label><input id="endpointPort" type="number" min="1" max="65535"><label for="endpointExpiry">Rule expires after</label><select id="endpointExpiry"><option value="">Choose expiry…</option><option value="900">15 minutes</option><option value="3600">1 hour</option><option value="86400">1 day</option><option value="persistent">No expiry</option></select></div><p id="endpointCoverage"></p><section aria-label="Backend scope preview"><h3>Review scope</h3><p id="endpointPreviewText">Preview required.</p><p id="endpointPreviewUntil"></p></section><label class="endpoint-ack"><input id="endpointAcknowledge" type="checkbox">I reviewed this all-users/programs scope and its precedence over application rules.</label><p id="endpointFeedback" role="status"></p><div class="endpoint-actions"><button id="endpointClose">Close</button><button id="endpointPreview">Preview</button><button id="endpointSave" disabled>Save endpoint rule</button><button id="endpointCheck" hidden>Check save result</button></div>`;
  document.body.append(dialog);
  const el = <T extends HTMLElement = HTMLElement>(id: string) => dialog.querySelector<T>('#'+id)!;
  el('endpointScope').textContent = ENDPOINT_SCOPE;
  el('endpointPrecedence').textContent = ENDPOINT_PRECEDENCE;
  el('endpointLifetime').textContent = ENDPOINT_LIFETIME;
  let state: ClientState | undefined, review: EndpointReview | undefined, revision = 0, busy = false, unknown = false;
  let context = '', receipt = '';
  const ack = el<HTMLInputElement>('endpointAcknowledge');
  const now = () => state?.control.serverNow ?? Date.now();
  const currentContext = () => JSON.stringify([state?.control.generation,state?.control.rules]);
  const feedback = (v: string) => { el('endpointFeedback').textContent = v; };
  const invalidate = () => {
    revision++; review = undefined; ack.checked = false;
    el('endpointPreviewText').textContent = 'Preview required.';
    el('endpointPreviewUntil').textContent = '';
    el('endpointCoverage').textContent = 'Enforcement coverage will be reported by a fresh preview.';
  };
  const controls = () => {
    const authority = !!state && canManageEndpoints(state.control);
    button.disabled = !authority;
    button.title = authority ? 'Create a reviewed machine-wide endpoint rule' : 'Requires an authorized administrator and daemon support.';
    el<HTMLButtonElement>('endpointPreview').disabled = busy || unknown || !authority;
    el<HTMLButtonElement>('endpointSave').disabled = busy || unknown || !authority || !review || !ack.checked || review.expiresAt <= now();
    el<HTMLButtonElement>('endpointClose').disabled = busy;
    el<HTMLButtonElement>('endpointCheck').hidden = !unknown;
    el<HTMLButtonElement>('endpointCheck').disabled = busy || !authority;
    for (const id of ['endpointAction','endpointAddress','endpointPort','endpointExpiry','endpointAcknowledge'])
      (el(id) as HTMLInputElement).disabled = busy || unknown || !authority;
  };
  for (const id of ['endpointAction','endpointAddress','endpointPort','endpointExpiry']) el(id).addEventListener('input',() => { invalidate(); controls(); });
  ack.onchange = controls;
  button.onclick = () => { if (!unknown) { invalidate(); feedback(''); } controls(); dialog.showModal(); };
  el('endpointClose').onclick = () => { if (!busy) dialog.close(); };
  dialog.addEventListener('cancel',e => { if (busy) e.preventDefault(); });
  el('endpointPreview').onclick = async () => {
    const rev = ++revision;
    review = undefined; ack.checked = false; busy = true; feedback('Obtaining backend preview…'); controls();
    try {
      const expiry = el<HTMLSelectElement>('endpointExpiry').value;
      if (!expiry) throw Error('Choose an expiry or No expiry explicitly.');
      const d: EndpointDraft = {action:el<HTMLSelectElement>('endpointAction').value as EndpointDraft['action'],remote_address:el<HTMLInputElement>('endpointAddress').value.trim(),remote_port:Number(el<HTMLInputElement>('endpointPort').value),expires:expiry === 'persistent' ? ENDPOINT_ZERO_EXPIRY : new Date(now()+Number(expiry)*1000).toISOString()};
      const p = await window.flowgate.endpointPreview(d);
      if (revision !== rev) throw Error('Fields changed; preview again.');
      review = p; context = currentContext(); receipt = p.receipt;
      el('endpointPreviewText').textContent = p.scope;
      el('endpointPreviewUntil').textContent = 'Preview valid until '+new Date(p.expiresAt).toLocaleTimeString()+'. Rule expiry: '+(p.rule.expires.startsWith('0001-') ? 'No expiry' : new Date(p.rule.expires).toLocaleString());
      el('endpointCoverage').textContent = 'Enforcement at preview: '+p.enforcement.state+' · '+(p.enforcement.covered ? 'outgoing covered' : 'outgoing not covered')+' · '+p.enforcement.reason;
      feedback('Review the full scope and acknowledge it before saving.');
    } catch (e) { feedback(String(e)); }
    finally { busy = false; controls(); }
  };
  const result = (r: import('./protocol').Attempt) => {
    feedback(r.message);
    unknown = r.phase === 'unknown';
    if (r.reconcile) receipt = r.reconcile;
    if (r.phase === 'acknowledged' || r.phase === 'rejected') { receipt = ''; invalidate(); }
  };
  el('endpointSave').onclick = async () => {
    if (!review || !ack.checked || busy || unknown) return;
    busy = true; controls();
    try { result(await window.flowgate.endpointSave({receipt:review.receipt,acknowledge_scope:true})); }
    catch (e) { unknown = true; receipt = review?.receipt || receipt; feedback('Save outcome unknown. Check the result; do not repeat Save. '+String(e)); }
    finally { busy = false; controls(); }
  };
  el('endpointCheck').onclick = async () => {
    if (!receipt || busy) return;
    busy = true; controls();
    try { result(await window.flowgate.endpointReconcile(receipt)); }
    catch (e) { feedback(String(e)); }
    finally { busy = false; controls(); }
  };
  const timer = window.setInterval(controls,250);
  window.addEventListener('unload',() => window.clearInterval(timer),{once:true});
  return {update(next: ClientState) {
    state = next;
    if (review && !busy && !unknown && (context !== currentContext() || !canManageEndpoints(next.control))) { invalidate(); feedback('Policy, generation or administrator access changed. Preview again.'); }
    controls();
  }};
}
