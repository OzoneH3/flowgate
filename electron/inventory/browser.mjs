// Read-only DOM projection and trusted Chromium keyboard dispatch.
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

export async function until(check, message, timeout = 5000) {
  const end = Date.now() + timeout;
  do {
    const result = await check();
    if (result) return result;
    await pause(100);
  } while (Date.now() < end);
  throw Error(message);
}

class Connection {
  #next = 0;
  #pending = new Map();
  constructor(socket) {
    this.socket = socket;
    socket.addEventListener('message', event => {
      const message = JSON.parse(event.data);
      const waiting = this.#pending.get(message.id);
      if (waiting) {
        this.#pending.delete(message.id);
        waiting.resolve(message);
      }
    });
    socket.addEventListener('close', () => {
      for (const waiting of this.#pending.values()) waiting.reject(Error('Renderer connection closed'));
      this.#pending.clear();
    });
  }
  static async open(url) {
    const socket = new WebSocket(url);
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => { socket.close(); reject(Error('DevTools connection timed out')); }, 5000);
      socket.addEventListener('open', () => { clearTimeout(timer); resolve(); }, { once: true });
      socket.addEventListener('error', () => { clearTimeout(timer); reject(Error('DevTools connection failed')); }, { once: true });
    });
    return new Connection(socket);
  }
  async send(method, params = {}) {
    const id = ++this.#next;
    const message = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        reject(Error(method + ' timed out'));
      }, 6500);
      this.#pending.set(id, {
        resolve: data => { clearTimeout(timer); resolve(data); },
        reject: error => { clearTimeout(timer); reject(error); },
      });
      this.socket.send(JSON.stringify({ id, method, params }));
    });
    if (message.error) throw Error(method + ': ' + message.error.message);
    return message.result;
  }
  close() { this.socket.close(); }
}

export function matchesWindow(raw, window) {
  let url;
  try { url = new URL(raw); } catch { return false; }
  return url.protocol === 'flowgate:' && url.host === 'app' && !url.username && !url.password &&
    matchesDocument(url, window);
}

function matchesDocument(url, { document, query = {} }) {
  return url.pathname === '/' + document && Object.entries(query).every(([key, value]) =>
    url.searchParams.get(key) === value);
}

export async function renderer(endpoint, window) {
  const target = await until(async () => {
    const pages = await fetch(endpoint + '/json/list', { signal: AbortSignal.timeout(2000) }).then(r => r.json());
    const matches = pages.filter(page => page.type === 'page' && matchesWindow(page.url, window));
    if (matches.length > 1) throw Error('Ambiguous renderer identity ' + JSON.stringify(window));
    return matches[0];
  }, 'Window missing ' + JSON.stringify(window));
  return new Page(await Connection.open(target.webSocketDebuggerUrl), window);
}

const keyCodes = {
  Enter: 13, ' ': 32, Tab: 9, Escape: 27, ArrowUp: 38, ArrowDown: 40,
  ArrowLeft: 37, ArrowRight: 39, Home: 36, End: 35, Backspace: 8,
  PageUp: 33, PageDown: 34,
};
class Page {
  constructor(cdp, identity) { this.cdp = cdp; this.identity = identity; }
  async run(fn, args = [], byValue = true) {
    const result = await this.cdp.send('Runtime.evaluate', {
      expression: '(' + fn.toString() + ')(...' + JSON.stringify(args) + ')',
      returnByValue: byValue, awaitPromise: true,
    });
    if (result.exceptionDetails) throw Error(result.exceptionDetails.exception?.description || result.exceptionDetails.text);
    return byValue ? result.result.value : result.result.objectId;
  }
  async assertIdentity() {
    const url = await this.run(() => location.href);
    if (!matchesWindow(url, this.identity))
      throw Error('Renderer changed before the requested action ' + JSON.stringify(this.identity));
  }
  async key(key, modifiers = 0, closesWindow = false) {
    await this.assertIdentity();
    const punctuation = { '.': ['Period', 190], ':': ['Semicolon', 186], '-': ['Minus', 189], '/': ['Slash', 191] };
    const keyCode = keyCodes[key] ?? punctuation[key]?.[1] ?? key.toUpperCase().charCodeAt(0);
    const code = key === ' ' ? 'Space' : /^[a-z]$/i.test(key) ? 'Key' + key.toUpperCase()
      : /^\d$/.test(key) ? 'Digit' + key : punctuation[key]?.[0] ?? key;
    const base = { key, code, windowsVirtualKeyCode: keyCode, nativeVirtualKeyCode: keyCode, modifiers };
    const text = !modifiers && (key === 'Enter' ? '\r' : key.length === 1 ? key : '');
    try {
      await this.cdp.send('Input.dispatchKeyEvent', { ...base, type: text ? 'keyDown' : 'rawKeyDown', ...(text ? { text } : {}) });
      await this.cdp.send('Input.dispatchKeyEvent', { ...base, type: 'keyUp' });
    } catch (error) {
      if (!closesWindow || this.cdp.socket.readyState !== WebSocket.CLOSED) throw error;
    }
  }
  async locate(locator) {
    return this.run(({ selector, text }) =>
      [...document.querySelectorAll(selector)].filter(e => {
        if (!e.checkVisibility({ checkVisibilityCSS: true, contentVisibilityAuto: false }) ||
            e.closest('[hidden],[inert]') || e.matches(':disabled') || e.getAttribute('aria-disabled') === 'true') return false;
        return text === undefined || (e.innerText ?? '').trim().replace(/\s+/g, ' ') === text;
      }).length, [locator]);
  }
  async focus(locator) {
    await this.assertIdentity();
    await this.cdp.send('Page.bringToFront');
    await until(async () => {
      const count = await this.locate(locator);
      if (count > 1) throw Error('Ambiguous control ' + JSON.stringify(locator));
      return count === 1;
    }, 'Control missing ' + JSON.stringify(locator));
    const objectId = await this.run(({ selector, text }) =>
      [...document.querySelectorAll(selector)].find(e =>
        e.checkVisibility({ checkVisibilityCSS: true, contentVisibilityAuto: false }) &&
        !e.closest('[hidden],[inert]') &&
        (text === undefined || (e.innerText ?? '').trim().replace(/\s+/g, ' ') === text)), [locator], false);
    try {
      await this.cdp.send('DOM.focus', { objectId });
      await until(async () => {
        const { result } = await this.cdp.send('Runtime.callFunctionOn', {
          objectId,
          functionDeclaration: 'function () { return this === document.activeElement && document.hasFocus() && !this.matches(":disabled") && this.getAttribute("aria-disabled") !== "true"; }',
          returnByValue: true,
        });
        return result.value;
      }, 'Control could not receive keyboard focus ' + JSON.stringify(locator), 2000);
    } finally {
      await this.cdp.send('Runtime.releaseObject', { objectId });
    }
  }
  async tabTo(locator) {
    await this.assertIdentity();
    await this.cdp.send('Page.bringToFront');
    const route = [];
    for (let i = 0; i <= 80; i++) {
      const focus = await this.run(({ selector, text }) => {
        const e = document.activeElement;
        if (!e) return {};
        const inside = e.matches(selector) && (text === undefined ||
          (e.innerText ?? '').trim().replace(/\s+/g, ' ') === text);
        return { matched: document.hasFocus() && inside && !e.matches(':disabled') &&
          e.getAttribute('aria-disabled') !== 'true', id: e.id || e.dataset.id || e.localName };
      }, [locator]);
      route.push(focus.id);
      if (focus.matched) return route;
      if (i < 80) await this.key('Tab');
    }
    throw Error('Keyboard Tab route did not focus ' + JSON.stringify(locator) + ' via ' + route.join(', '));
  }
  async verify(assertion) {
    return this.run(({ selector, text, contains, attr, value, enabled, count = 1 }) => {
      const matches = [...document.querySelectorAll(selector)].filter(e => {
        if (!e.checkVisibility({ checkVisibilityCSS: true, contentVisibilityAuto: false }) || e.closest('[hidden],[inert]')) return false;
        const displayed = (e.innerText ?? '').trim().replace(/\s+/g, ' ');
        return (text === undefined || displayed === text)
          && (contains === undefined || displayed.includes(contains))
          && (attr === undefined || Object.entries(attr).every(([name, expected]) => e.getAttribute(name) === expected))
          && (value === undefined || e.value === value)
          && (enabled === undefined || (!e.matches(':disabled') && e.getAttribute('aria-disabled') !== 'true') === enabled);
      });
      return matches.length === count;
    }, [assertion]);
  }
  async watchUdpBadge() {
    await this.run(() => {
      const badge = document.getElementById('extendedBadge');
      if (!badge) throw Error('Missing UDP badge');
      const updates = window.inventoryUdpBadgeUpdates = [];
      const read = (event) => {
        const text = badge.innerText, accessibleName = badge.getAttribute('aria-label');
        const prior = updates.at(-1);
        if (prior?.text !== text || prior?.accessibleName !== accessibleName)
          updates.push({ event, atMs: Date.now(), text, accessibleName });
      };
      read('initial');
      new MutationObserver(() => read('update')).observe(badge, {
        attributes: true, attributeFilter: ['aria-label'], childList: true, characterData: true, subtree: true,
      });
    });
  }
  async watchTooltip(anchorId) {
    await this.run((id) => {
      const probe = new AbortController(), events = [];
      const anchor = () => document.getElementById(id);
      const tip = () => document.getElementById('flowgateTooltip');
      const identify = (element) => element?.id || element?.localName || null;
      let lastAnchorId = null;
      const record = (event, details = {}) => {
        const open = tip()?.matches(':popover-open') ?? false;
        const owner = [...document.querySelectorAll('[aria-describedby]')]
          .find(element => element.getAttribute('aria-describedby').split(/\s+/).includes('flowgateTooltip'));
        if (owner) lastAnchorId = identify(owner);
        events.push({
          atMs: Date.now(), event, focus: identify(document.activeElement),
          anchor: identify(owner), previousAnchor: lastAnchorId, open,
          tooltipText: open ? tip().innerText : null,
          ariaDescribedBy: anchor()?.getAttribute('aria-describedby') ?? null, ...details,
        });
      };
      const options = { capture: true, signal: probe.signal };
      for (const kind of ['focusin', 'focusout'])
        document.addEventListener(kind, (event) => record(kind, {
          target: identify(event.target), related: identify(event.relatedTarget),
        }), options);
      document.addEventListener('keydown', event => record('keydown', {
        target: identify(event.target), key: event.key,
      }), options);
      document.addEventListener('beforetoggle', event => {
        if (event.target === tip())
          record(event.newState === 'open' ? 'tooltip-open' : 'tooltip-dismiss', {
            open: event.newState === 'open',
            tooltipText: event.newState === 'open' ? tip().textContent : null,
          });
      }, options);
      record('start');
      window.finishInventoryTooltip = () => {
        record('capture');
        probe.abort();
        delete window.finishInventoryTooltip;
        return { anchorId: id, events };
      };
    }, [anchorId]);
  }
  async capture(root, observe) {
    await this.assertIdentity();
    if (!await this.verify({ selector: root })) throw Error('Capture root is not displayed: ' + root);
    return readProjectedControls(this.cdp, root, observe);
  }
  close() { this.cdp.close(); }
}

export async function readProjectedControls(cdp, selector, observe) {
  // Capture the elements and their displayed state in one renderer evaluation.
  // An ordinal in a separately read DOM tree can point to a different element
  // when a sibling is inserted or removed between protocol calls.
  const objectGroup = 'flowgate-control-capture';
  const { result, exceptionDetails } = await cdp.send('Runtime.evaluate', {
    expression: '(' + projectDOM.toString() + ')(' + JSON.stringify(selector) + ')',
    objectGroup,
  });
  try {
    if (exceptionDetails || !result.objectId) throw Error('Could not project ' + selector);
    const { result: properties } = await cdp.send('Runtime.getProperties', {
      objectId: result.objectId, ownProperties: true,
    });
    const property = name => properties.find(entry => entry.name === name)?.value?.objectId;
    if (observe) {
      const { result: observation } = await cdp.send('Runtime.callFunctionOn', {
        objectId: property('observation'), functionDeclaration: 'function () { return this; }', returnByValue: true,
      });
      observe(observation.value);
    }
    const { result: projected } = await cdp.send('Runtime.callFunctionOn', {
      objectId: property('controls'), functionDeclaration: 'function () { return this; }', returnByValue: true,
    });
    const { result: references } = await cdp.send('Runtime.getProperties', {
      objectId: property('elements'), ownProperties: true,
    });
    const handles = new Map(references.map(ref => [ref.name, ref.value?.objectId]));
    const controls = projected.value;
    const backendIds = await Promise.all(controls.map(async (_, index) => {
      const objectId = handles.get(String(index));
      if (!objectId) throw Error('Projected DOM control has no element reference');
      const { node } = await cdp.send('DOM.describeNode', { objectId });
      return node.backendNodeId;
    }));
    const { nodes } = await cdp.send('Accessibility.getFullAXTree');
    const names = new Map(nodes.filter(node => !node.ignored && node.backendDOMNodeId)
      .map(node => [node.backendDOMNodeId, { name: node.name?.value, role: node.role?.value }]));
    return controls.map((control, index) => {
      const ax = names.get(backendIds[index]);
      if (ax?.name && ax.name !== control.text) control.accessibleName = ax.name;
      if (ax?.role && !['generic', 'none', 'presentation'].includes(ax.role)) control.role = ax.role;
      return control;
    });
  } finally {
    await cdp.send('Runtime.releaseObjectGroup', { objectGroup });
  }
}

function projectDOM(selector) {
  const root = document.querySelector(selector);
  const all = [root, ...root.querySelectorAll('*')];
  const supported = new Set(['main', 'aside', 'header', 'footer', 'section', 'nav', 'dialog',
    'details', 'summary', 'fieldset', 'legend', 'button', 'a', 'input', 'textarea',
    'select', 'output', 'table', 'caption', 'thead', 'tbody', 'tr', 'th', 'td',
    'p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'ol', 'ul', 'li', 'dl', 'dt', 'dd', 'pre', 'label',
    'meter', 'progress']);
  const panels = new Set(['main', 'aside', 'header', 'footer', 'section', 'nav', 'dialog', 'fieldset',
    'details', 'table', 'thead', 'tbody', 'tr', 'ol', 'ul', 'dl']);
  const roleFor = {
    input: 'textbox', select: 'combobox', textarea: 'textbox', a: 'link', p: 'paragraph',
    summary: 'disclosure', tr: 'row', td: 'cell', th: 'columnheader', dl: 'descriptionList',
    dt: 'term', dd: 'definition', aside: 'complementary', nav: 'navigation', li: 'listitem',
    ul: 'list', ol: 'list', section: 'region', header: 'banner', footer: 'contentinfo',
  };
  const clean = s => s?.replace(/\s+/g, ' ').trim() || '';
  const ids = new Set();
  const mapped = new Map();
  const counters = new Map();
  const controls = [], elements = [];
  const visible = e => {
    if (e.closest('[hidden],script,style,template,option,svg')) return false;
    for (let p = e; p; p = p.parentElement) {
      if (p.localName === 'details' && !p.open && e !== p) {
        const summary = [...p.children].find(child => child.localName === 'summary');
        if (!summary?.contains(e)) return false;
      }
      const css = getComputedStyle(p);
      if (css.display === 'none' || css.visibility === 'hidden' || css.visibility === 'collapse' || css.contentVisibility === 'hidden') return false;
    }
    return true;
  };
  for (const e of all) {
    if (!visible(e)) continue;
    const tag = e.localName;
    const native = supported.has(tag);
    const direct = clean([...e.childNodes].filter(n => n.nodeType === Node.TEXT_NODE).map(n => n.textContent).join(' '));
    const explicit = e.getAttribute('role');
    const panel = panels.has(tag) || ['dialog', 'menu', 'menuitem', 'region', 'tabpanel', 'group', 'treegrid', 'list'].includes(explicit);
    if (!native && !explicit && !direct && !e.id && e !== root) continue;
    if (!native && !explicit && e.closest('button, label, summary, p, td, dd, dt, h1, h2, h3, h4, h5, h6')) continue;
    let parent = e.parentElement;
    while (parent && !mapped.has(parent)) parent = parent.parentElement;
    const parentId = mapped.get(parent) ?? null;
    const stable = e.id || e.dataset.id || e.dataset.field || e.dataset.pane || e.dataset.undock || e.dataset.configuredLimit || e.dataset.focus || e.dataset.direction || e.dataset.limitDirection || e.dataset.series;
    const slot = parentId ? parentId + '/' : '';
    const role = explicit || roleFor[tag] || (/^h[1-6]$/.test(tag) ? 'heading' : native ? tag : direct ? 'text' : 'group');
    const basis = e.id || (stable ? slot + tag + ':' + encodeURIComponent(stable) : slot + role);
    const sequence = (counters.get(basis) ?? 0) + 1;
    counters.set(basis, sequence);
    let id = sequence === 1 ? basis : basis + '#' + sequence;
    while (ids.has(id)) id += '#';
    ids.add(id);
    if (panel || e === root) mapped.set(e, id);
    const text = tag === 'select' ? clean(e.selectedOptions[0]?.label)
      : tag === 'input' ? (['checkbox', 'radio', 'range'].includes(e.type) ? '' : clean(e.value || e.placeholder))
        : tag === 'textarea' ? clean(e.value || e.placeholder)
          : panel ? direct
            : [...e.children].some(child => child.matches('button,input,select,a,summary')) ? direct
              : clean(e.innerText ?? direct);
    const control = { id, parentId, role, text };
    if (['select', 'input', 'textarea', 'output', 'meter', 'progress'].includes(tag) &&
        !['checkbox', 'radio'].includes(e.type)) control.value = e.type === 'password' ? null : e.value;
    if (e.type === 'password') control.text = '';
    if (e.matches('button,input,select,textarea,summary,a[href],[role^="menuitem"],[role=button]') || e.hasAttribute('aria-disabled'))
      control.enabled = !e.matches(':disabled') && e.getAttribute('aria-disabled') !== 'true' && !e.closest('[inert]');
    if (e.matches('input[type=checkbox], input[type=radio]')) control.checked = e.indeterminate ? 'mixed' : e.checked;
    for (const [attribute, key] of [['aria-checked', 'checked'], ['aria-expanded', 'expanded'], ['aria-selected', 'selected'], ['aria-pressed', 'checked']]) {
      const value = e.getAttribute(attribute);
      if (value !== null) control[key] = value === 'mixed' && key === 'checked' ? 'mixed' : value === 'true';
    }
    if (tag === 'details') control.expanded = e.open;
    if (tag === 'summary' && e.parentElement.localName === 'details') control.expanded = e.parentElement.open;
    controls.push(control);
    elements.push(e);
  }
  const active = document.activeElement;
  const localNetwork = document.querySelector('#rows tr[data-id="network:local"]');
  const tooltip = document.querySelector('#flowgateTooltip:popover-open');
  const tooltipTargets = Object.fromEntries(
    ['firewallMenuStatus', 'extendedBadge', 'allowForAWhile', 'expand'].flatMap(id => {
      const element = document.getElementById(id);
      if (!element || !visible(element)) return [];
      const ariaDescribedBy = element.getAttribute('aria-describedby');
      return [[id, {
        focused: element === active && document.hasFocus(),
        focusVisible: element.matches(':focus-visible'),
        hovered: element.matches(':hover'),
        ariaDescribedBy,
        describesTooltip: (ariaDescribedBy || '').split(/\s+/).includes('flowgateTooltip'),
      }]];
    }),
  );
  const observation = {
    renderedAtMs: Date.now(),
    documentFocused: document.hasFocus(),
    visibility: document.visibilityState,
    focusedControlId: controls[elements.indexOf(active)]?.id ?? active?.id ?? null,
    localNetworkFocusWithin: localNetwork?.matches(':focus-within') ?? null,
    localNetworkHovered: localNetwork?.matches(':hover') ?? null,
    tooltipText: tooltip ? clean(tooltip.innerText) : null,
    tooltipTargets,
    tooltipTransition: window.finishInventoryTooltip?.(),
  };
  return { controls, elements, observation };
}

const desktopAccountFields = new Map([
  ['group', ['text', 1]], ['app', ['text', 1]],
  ['rows/tr:overview', ['accessibleName', 3]],
  ['rows/tr:overview/cell', ['accessibleName', 2]],
  ...['rows/tr:overview/button', 'rows/tr:overview/cell#4', 'rows/tr:overview/group']
    .map(id => [id, ['accessibleName', 1]]),
]);

// Preserve every byte outside occurrences of the independently measured account.
// In particular, no fallback accepts a different syntactically valid user@host.
export function bindDesktopAccount(controls, label, requireAll = false) {
  const fields = [];
  const escaped = label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const token = new RegExp('(?<![\\w.@-])' + escaped + '(?![\\w.@-])', 'g');
  const overview = controls.some(control => control.id === 'rows/tr:overview');
  if (!overview && !requireAll) return fields;
  for (const control of controls) {
    const [key, occurrences] = desktopAccountFields.get(control.id) ?? [];
    const displayed = key && control[key];
    if (typeof displayed !== 'string') continue;
    if ([...displayed.matchAll(token)].length !== occurrences) continue;
    fields.push({ id: control.id, field: key, displayed });
  }
  if (requireAll && fields.length !== desktopAccountFields.size)
    throw Error('Desktop account does not match independently measured identity in all seven overview fields');
  for (const { id, field, displayed } of fields) {
    controls.find(control => control.id === id)[field] = displayed.replace(token, '{desktop-user@host}');
  }
  return fields;
}
