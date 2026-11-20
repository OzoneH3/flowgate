// These fields explain how FlowGate established identity or measured traffic.
// Scope, stale observations, permission actions and warnings stay in Overview.
const diagnosticFields = new Set([
  'Application identity', 'Caller evidence', 'Evidence', 'Executable', 'Fast path',
  'Identity', 'Incoming rule scopes', 'Launch provenance', 'Measurement', 'Measurements',
  'Observed processes', 'Outgoing rule scopes', 'Ownership evidence category',
  'Recorded attribution category', 'Recorded caller', 'Recorded caller paths',
  'Recorded executable', 'Request history', 'Rule identity', 'Rule inventory',
  'Running application', 'Running revisions', 'Script', 'Socket identity', 'Totals',
  'Unix socket holder', 'Windows ownership',
]);

export function setupInspectorTabs(info: HTMLElement) {
  const overview = info.closest<HTMLElement>('.info-scroll')!;
  const tabs = document.createElement('div');
  tabs.className = 'inspector-tabs';
  tabs.setAttribute('role', 'tablist');
  tabs.setAttribute('aria-label', 'App details');
  const diagnostics = document.createElement('div');
  diagnostics.className = 'info-scroll';
  const evidence = document.createElement('dl');
  evidence.className = 'inspector-evidence';
  diagnostics.append(evidence);
  overview.before(tabs);
  overview.after(diagnostics);

  const panels = [overview, diagnostics];
  const buttons = panels.map((panel, index) => {
    const name = index === 0 ? 'Overview' : 'Diagnostics';
    const tab = document.createElement('button');
    tab.type = 'button';
    tab.id = 'inspectorTab' + name;
    tab.textContent = name;
    tab.setAttribute('role', 'tab');
    panel.id = 'inspector' + name;
    panel.tabIndex = 0;
    panel.setAttribute('role', 'tabpanel');
    panel.setAttribute('aria-labelledby', tab.id);
    tab.setAttribute('aria-controls', panel.id);
    tab.onclick = () => select(index);
    tab.onkeydown = (event) => {
      const next = { ArrowRight: 1 - index, ArrowLeft: 1 - index, Home: 0, End: 1 }[event.key];
      if (next === undefined) return;
      event.preventDefault();
      select(next);
      buttons[next].focus();
    };
    tabs.append(tab);
    return tab;
  });
  function select(index: number) {
    panels.forEach((panel, i) => {
      panel.hidden = i !== index;
      buttons[i].tabIndex = i === index ? 0 : -1;
      buttons[i].setAttribute('aria-selected', String(i === index));
    });
  }
  select(0);

  let lastSelection: string | undefined;
  return (fields: HTMLElement, selection: string) => {
    const technical = document.createElement('dl');
    for (const term of Array.from(fields.children)) {
      if (term.tagName !== 'DT' || !diagnosticFields.has(term.textContent || '')) continue;
      const value = term.nextElementSibling;
      if (value?.tagName === 'DD') technical.append(term, value);
    }
    const changed = lastSelection !== selection;
    if (changed || info.textContent !== fields.textContent)
      info.replaceChildren(...Array.from(fields.childNodes));
    if (changed || evidence.textContent !== technical.textContent)
      evidence.replaceChildren(...Array.from(technical.childNodes));
    lastSelection = selection;
    if (changed || !evidence.childElementCount) {
      select(0);
      if (changed) overview.scrollTop = diagnostics.scrollTop = 0;
    }
    tabs.hidden = evidence.childElementCount === 0;
  };
}
