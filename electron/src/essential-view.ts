import {
  essentialDefaults,
  sameEssentialOptions,
  essentialRuleLabel,
  type EssentialView,
  type EssentialOptions,
} from './essential-model';
const node = <K extends keyof HTMLElementTagNameMap>(tag: K, text = '') => {
  const e = document.createElement(tag);
  e.textContent = text;
  return e;
};
export function setupEssentialNetworking() {
  const open = node('button', 'Essential networking…');
  open.id = 'essentialOpen';
  document.querySelector('#controlMenu .menu-panel')!.append(open);
  const d = node('dialog');
  d.id = 'essentialDialog';
  d.className = 'essential-dialog';
  const header = node('header');
  const title = node('h2', 'Essential networking');
  title.tabIndex = -1;
  header.append(title);
  const subtitle = node(
    'p',
    'Review exact detected permissions. Applying never starts protection; held requests may be dropped when policy changes.',
  );
  header.append(subtitle);
  const body = node('section');
  body.className = 'essential-body';
  const opts = node('fieldset'),
    legend = node('legend', 'Optional components — off by default');
  opts.append(legend);
  const choices: Record<keyof EssentialOptions, HTMLInputElement> = {} as Record<
    keyof EssentialOptions,
    HTMLInputElement
  >;
  const labels: Record<keyof EssentialOptions, string> = {
    tailscale: 'Tailscale outer transport · variable peers / Any destination',
    tailscale_incoming: 'Tailscale incoming configured port',
    tailscale_http: 'Tailscale HTTP80 (separate permission)',
    discovery: 'LAN discovery · requires trusted-interface configuration',
  };
  for (const key of Object.keys(essentialDefaults()) as (keyof EssentialOptions)[]) {
    const label = node('label'),
      input = node('input');
    input.type = 'checkbox';
    input.id = 'essential-' + key;
    choices[key] = input;
    label.append(input, document.createTextNode(labels[key]));
    opts.append(label);
    input.onchange = () => {
      if (key === 'tailscale' && !input.checked) {
        choices.tailscale_incoming.checked = false;
        choices.tailscale_http.checked = false;
      }
      paint();
    };
  }
  body.append(opts);
  const message = node('p');
  message.id = 'essentialMessage';
  message.role = 'status';
  body.append(message);
  const components = node('div');
  components.id = 'essentialComponents';
  body.append(components);
  const rules = node('div');
  rules.id = 'essentialRules';
  body.append(rules);
  const preserved = node('p');
  preserved.id = 'essentialPreserved';
  body.append(preserved);
  const issues = node('ul');
  issues.id = 'essentialIssues';
  body.append(issues);
  const footer = node('footer');
  const controls = {
    status: node('button', 'Refresh status'),
    preview: node('button', 'Preview permissions'),
    apply: node('button', 'Apply reviewed permissions'),
    removePreview: node('button', 'Review removal'),
    remove: node('button', 'Remove reviewed records'),
    reconcile: node('button', 'Check uncertain result'),
    close: node('button', 'Close'),
  };
  for (const [key, b] of Object.entries(controls)) {
    b.id = 'essential-' + key;
    footer.append(b);
  }
  d.append(header, body, footer);
  document.body.append(d);
  let v: EssentialView | undefined,
    working = false,
    error = '',
    stamp = '',
    viewEpoch = 0;
  const options = () =>
    Object.fromEntries(
      Object.entries(choices).map(([k, x]) => [k, x.checked]),
    ) as unknown as EssentialOptions;
  function paint() {
    const available = !!v?.permitted && !working && !v.busy,
      uncertain = v?.phase === 'unknown',
      p = v?.preview;
    message.textContent = [
      error,
      !v
        ? 'Loading authoritative preset status…'
        : !v.supported
          ? 'This backend does not provide the authoritative Essential preset.'
          : !v.connected
            ? 'Disconnected. No changes can be sent.'
            : !v.permitted
              ? 'Read-only status. Applying requires the primary machine-administrator connection.'
              : '',
      v?.message,
      working || v?.busy ? 'Waiting for the backend; controls remain disabled.' : '',
    ]
      .filter(Boolean)
      .join(' ');
    controls.status.disabled = working || !!v?.busy || !v?.canStatus;
    controls.preview.disabled = !available || uncertain;
    controls.removePreview.disabled = !available || uncertain;
    controls.apply.hidden = p?.operation !== 'apply';
    controls.remove.hidden = p?.operation !== 'remove';
    controls.reconcile.hidden = !uncertain;
    controls.apply.disabled =
      !available || !v?.canApply || !p || !sameEssentialOptions(options(), p.options);
    controls.remove.disabled = !available || !v?.canApply;
    controls.reconcile.disabled = !available || !v?.canReconcile;
    for (const input of Object.values(choices))
      input.disabled = !v?.permitted || working || !!v?.busy || uncertain;
    choices.tailscale_incoming.disabled ||= !choices.tailscale.checked;
    choices.tailscale_http.disabled ||= !choices.tailscale.checked;
    controls.close.disabled = false;
    const source = p || v?.status;
    const next = JSON.stringify([source, v?.receipt]);
    if (stamp === next) return;
    stamp = next;
    components.replaceChildren();
    for (const c of source?.components || []) {
      const section = node('details');
      section.open = c.essential;
      const summary = node(
        'summary',
        `${c.title} · ${c.state}${c.essential ? ' · Essential' : ' · Optional'}`,
      );
      section.append(summary);
      for (const text of c.details) section.append(node('p', text));
      if (c.id === 'dhcp')
        section.append(
          node(
            'p',
            'Interface client-port protocol exceptions persist until explicit reviewed removal, including the pre-daemon guard. These are not native application identity grants.',
          ),
        );
      if (c.service) {
        const identity = node('pre', JSON.stringify(c.service, null, 2));
        const more = node('details');
        more.append(node('summary', 'Service identity'), identity);
        section.append(more);
      }
      components.append(section);
    }
    rules.replaceChildren();
    if (p) {
      rules.append(
        node(
          'h3',
          p.operation === 'apply'
            ? `Proposed permissions (${p.rules.length})`
            : `Exact removal (${p.rules.length})`,
        ),
      );
      const list = node('ul');
      for (const r of p.rules) {
        const item = node('li', essentialRuleLabel(r));
        item.title = `Rule ${r.id} · version ${r.version} · preset ${r.preset?.revision}\n${r.filter.application} · revision ${r.filter.revision} · ${r.expires}`;
        list.append(item);
      }
      rules.append(
        list,
        node(
          'p',
          `Review expires ${new Date(p.expires_at).toLocaleTimeString()}. Intervening policy or service changes require a new preview.`,
        ),
      );
    } else if (v?.status)
      rules.append(
        node(
          'p',
          `Stored preset records: ${v.status.rule_ids.length}. Inspect individual records in Rules; removal here preserves edited or disabled records.`,
        ),
      );
    if (v?.receipt)
      rules.append(
        node(
          'p',
          `Receipt confirmed · ${v.receipt.operation} · ${v.receipt.rule_ids.length} saved / ${v.receipt.removed_rule_ids.length} removed. Protection state unchanged.`,
        ),
      );
    preserved.textContent = p?.preserved_rule_ids.length
      ? `Preserved records: ${p.preserved_rule_ids.join(', ')}`
      : '';
    issues.replaceChildren(...(source?.issues || []).map((x) => node('li', x)));
  }
  const act = async (action: Parameters<typeof window.flowgate.essential>[0]) => {
    if (working || !v) return;
    const epoch = ++viewEpoch;
    working = true;
    error = '';
    paint();
    try {
      const next = await window.flowgate.essential(action, {
        generation: v.generation,
        ...(['preview', 'apply'].includes(action) ? { options: options() } : {}),
        ...(['apply', 'remove', 'reconcile'].includes(action) ? { token: v.preview?.token } : {}),
      });
      if (epoch === viewEpoch) v = next;
    } catch (e) {
      error = String(e);
    } finally {
      working = false;
      paint();
    }
  };
  controls.status.onclick = () => void act('status');
  controls.preview.onclick = () => void act('preview');
  controls.apply.onclick = () => void act('apply');
  controls.removePreview.onclick = () => void act('remove-preview');
  controls.remove.onclick = () => void act('remove');
  controls.reconcile.onclick = () => void act('reconcile');
  controls.close.onclick = () => d.close();
  open.onclick = async () => {
    if (d.open) return;
    d.showModal();
    title.focus();
    const epoch = ++viewEpoch;
    try {
      const next = await window.flowgate.essentialState();
      if (epoch !== viewEpoch) return;
      v = next;
      paint();
      if (v.canStatus) await act('status');
    } catch (e) {
      error = String(e);
      paint();
    }
  };
  d.onkeydown = (e) => {
    if (e.key === 'Enter' && !(e.target instanceof HTMLButtonElement)) e.preventDefault();
  };
  paint();
  let refreshing = false;
  const timer = setInterval(async () => {
    if (!d.open || working || refreshing || document.hidden) return;
    refreshing = true;
    const epoch = viewEpoch;
    try {
      const next = await window.flowgate.essentialState();
      if (epoch === viewEpoch && !working) {
        v = next;
        paint();
      }
    } catch (e) {
      error = String(e);
      paint();
    } finally {
      refreshing = false;
    }
  }, 1000);
  window.addEventListener('pagehide', () => clearInterval(timer), { once: true });
}
