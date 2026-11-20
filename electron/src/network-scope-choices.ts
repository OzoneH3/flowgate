export type EditorNetworkScope = 'all' | 'internet' | 'local';

export function networkScopeChoices(
  id: string,
  selected: EditorNetworkScope,
  choose: (scope: EditorNetworkScope) => void,
) {
  const group = document.createElement('fieldset');
  group.id = id;
  group.className = 'quick-editor-scopes';
  const legend = document.createElement('legend');
  legend.textContent = 'Network scope';
  group.append(legend);
  const choices = document.createElement('div');
  for (const [scope, title] of [['all', 'Any'], ['internet', 'Internet'], ['local', 'Local']] as const) {
    const label = document.createElement('label');
    const input = document.createElement('input');
    input.type = 'radio';
    input.name = id;
    input.value = scope;
    input.dataset.focus = id + ':' + scope;
    input.checked = scope === selected;
    input.onchange = () => { if (input.checked) choose(scope); };
    const caption = document.createElement('span');
    caption.textContent = title;
    label.append(input, caption);
    choices.append(label);
  }
  group.append(choices);
  return group;
}
