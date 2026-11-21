export type EditorNetworkScope = 'all' | 'internet' | 'local';

export function networkScopeChoices(
  id: string,
  selected: EditorNetworkScope,
  choose: (scope: EditorNetworkScope) => void,
) {
  return editorChoices(id, 'Network scope', [
    ['all', 'Any'], ['internet', 'Internet'], ['local', 'Local'],
  ], selected, choose);
}

export function editorChoices<T extends string>(
  id: string,
  title: string,
  options: readonly (readonly [T, string])[],
  selected: T,
  choose: (value: T) => void,
) {
  const group = document.createElement('fieldset');
  group.id = id;
  group.className = 'quick-editor-scopes';
  const legend = document.createElement('legend');
  legend.textContent = title;
  group.append(legend);
  const choices = document.createElement('div');
  for (const [value, labelText] of options) {
    const label = document.createElement('label');
    const input = document.createElement('input');
    input.type = 'radio';
    input.name = id;
    input.value = value;
    input.dataset.focus = id + ':' + value;
    input.checked = value === selected;
    input.onchange = () => { if (input.checked) choose(value); };
    const caption = document.createElement('span');
    caption.textContent = labelText;
    label.append(input, caption);
    choices.append(label);
  }
  group.append(choices);
  return group;
}
