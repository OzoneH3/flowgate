import type { ProtectionView, ProtectionProfile } from './protection-model';
// Compact controls in the existing firewall menu; selection never starts protection.
export function setupProtectionControls() {
  const section = document.createElement('section');
  section.id = 'continuousProtection';
  section.innerHTML =
    '<h3>Continuous protection</h3><p id="protectionLabel" role="status"></p><label>Protect <select id="protectionProfile"><option value="both">Incoming + outgoing</option><option value="incoming">Incoming only</option></select></label> <button id="protectionCheck">Check readiness</button> <button id="protectionStart">Start protection</button> <button id="protectionStop">Stop protection</button><p id="protectionMessage"></p><details><summary>Protection details</summary><p id="protectionDesired"></p><p id="protectionFailure"></p><p id="protectionConnections"></p><p>Closing this interface leaves daemon protection unchanged. Without the interface, unanswered requests time out according to daemon policy; expired requests cannot be approved later.</p><ul id="protectionChecks"></ul></details>';
  document.querySelector('#controlMenu .menu-panel')!.prepend(section);
  const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
  let value: ProtectionView | undefined,
    busy = false,
    submitted = false,
    error = '';
  const render = (v: ProtectionView) => {
    value = v;
    $('protectionLabel').textContent = v.supported
      ? v.label
      : 'Continuous protection unavailable in this daemon';
    $('protectionMessage').textContent = [
      error,
      v.supported ? v.message : 'Bounded evaluation below is a separate explicit mode.',
    ]
      .filter(Boolean)
      .join(' ');
    $<HTMLButtonElement>('protectionStart').disabled = submitted || !v.canStart;
    $<HTMLButtonElement>('protectionStop').disabled = submitted || !v.canStop;
    $<HTMLButtonElement>('protectionCheck').disabled = submitted || !v.canCheck;
    $<HTMLSelectElement>('protectionProfile').disabled = submitted || v.busy || !v.canCheck;
    $('protectionDesired').textContent = v.status
      ? `Requested: ${v.status.desired_mode} · Actual: ${v.status.state} · Cleanup: ${v.status.cleanup}`
      : '';
    $('protectionFailure').textContent = v.status?.failure_policy || '';
    $('protectionConnections').textContent = v.status?.existing_connections || '';
    const list = $('protectionChecks'),
      checks = v.status?.readiness.checks || [];
    const stamp = JSON.stringify(checks);
    if (list.dataset.stamp !== stamp) {
      list.dataset.stamp = stamp;
      list.replaceChildren(
        ...checks.map((c) => {
          const li = document.createElement('li');
          li.textContent = `${c.id}: ${c.status} · ${c.detail}${c.next ? ' · ' + c.next : ''}`;
          return li;
        }),
      );
    }
  };
  const refresh = async () => {
    if (busy || document.hidden) return;
    busy = true;
    try {
      render(await window.flowgate.protectionState());
    } catch (e) {
      error = String(e);
      if (value) render({ ...value, canStart: false, canStop: false, canCheck: false });
    } finally {
      busy = false;
    }
  };
  const act = async (action: 'status' | 'start' | 'stop') => {
    if (submitted) return;
    // A fresh UI model validates the exact session; main validates again before sending.
    const current = await window.flowgate.protectionState();
    if (submitted) return;
    if (
      !current.tokens ||
      !(action === 'start'
        ? current.canStart
        : action === 'stop'
          ? current.canStop
          : current.canCheck)
    ) {
      render(current);
      return;
    }
    const tokens = {
      ...current.tokens,
      profile: $<HTMLSelectElement>('protectionProfile').value as ProtectionProfile,
    };
    submitted = true;
    error = '';
    render(current);
    try {
      await window.flowgate.protection(action, tokens);
    } catch (e) {
      error = String(e);
    } finally {
      submitted = false;
      await refresh();
    }
  };
  for (const [id, action] of [
    ['protectionCheck', 'status'],
    ['protectionStart', 'start'],
    ['protectionStop', 'stop'],
  ] as const)
    $(id).onclick = () =>
      void act(action).catch((e) => {
        $('protectionMessage').textContent = String(e);
      });
  setInterval(() => void refresh(), 500);
  void refresh();
}
