// Display only. UIDs remain the sole identity and permission keys.
const names = new Map<number, {name: string | null; until: number}>();
const pending = new Set<number>();
export function accountLabel(uid: number | undefined | null): string {
  if (uid === undefined || uid === null || !Number.isSafeInteger(uid) || uid < 0 || uid > 0xffffffff) return 'Unknown account';
  const known = names.get(uid);
  if (known && known.until > Date.now() && known.name) return `${known.name} (UID ${uid})`;
  if ((!known || known.until <= Date.now()) && !pending.has(uid) && typeof window !== 'undefined' && window.flowgate?.accountName) {
    pending.add(uid);
    void window.flowgate.accountName(uid).then(name => {
      if (names.size >= 512) names.delete(names.keys().next().value!);
      names.set(uid, {name: name || null, until: Date.now() + (name ? 60000 : 5000)});
      if (name && name !== known?.name) window.dispatchEvent(new CustomEvent('flowgate-account-name', {detail:uid}));
    }).catch(() => names.set(uid, {name:null, until:Date.now()+5000})).finally(() => pending.delete(uid));
  }
  return `UID ${uid}`;
}

export function accountRowLabel(uid: number | undefined | null): string {
  const label = accountLabel(uid);
  return label.startsWith('UID ') ? `User ${label}` : label;
}

// Update one already-open control when its asynchronous lookup completes.
export function showAccountIn(element: HTMLElement, uid: number, text: (label: string) => string) {
  element.textContent = text(accountLabel(uid));
  const entry = names.get(uid);
  if (entry?.name && entry.until > Date.now()) return;
  const refresh = (event: Event) => {
    if ((event as CustomEvent<number>).detail !== uid) return;
    window.removeEventListener('flowgate-account-name', refresh);
    clearTimeout(timeout);
    if (element.isConnected) element.textContent = text(accountLabel(uid));
  };
  window.addEventListener('flowgate-account-name', refresh);
  const timeout = window.setTimeout(() => window.removeEventListener('flowgate-account-name', refresh), 10000);
}
