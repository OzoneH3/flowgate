import type { DecisionTimeoutEdit, DecisionTimeoutView } from './decision-timeout';

export function setupDecisionTimeout(menu: HTMLDetailsElement) {
  const section = document.createElement('fieldset');
  section.id = 'decisionTimeoutSettings';
  section.innerHTML = `<legend>Permission popup</legend>
    <label for="decisionTimeoutSeconds">Decision timeout (seconds)
      <input id="decisionTimeoutSeconds" type="number" min="2" max="60" step="1" required disabled>
    </label>
    <p>Choose 2–60 seconds for new permission requests on this machine. Unanswered requests are blocked at the deadline.</p>
    <button type="button" id="decisionTimeoutRefresh">Refresh</button>
    <button type="button" id="decisionTimeoutSave" disabled>Save</button>
    <p id="decisionTimeoutStatus" role="status"></p>`;
  menu.querySelector('.menu-panel')!.append(section);
  const input = section.querySelector('input')!;
  const [refresh, save] = section.querySelectorAll('button');
  const status = section.querySelector('[role=status]')!;
  let settings: DecisionTimeoutView | undefined;
  let busy = false;
  const updateSave = () => {
    save.disabled = busy || !settings?.writable || !input.validity.valid || input.valueAsNumber === settings.seconds;
  };
  const run = async (edit?: DecisionTimeoutEdit) => {
    if (busy) return;
    busy = input.disabled = refresh.disabled = true;
    updateSave();
    status.textContent = edit ? 'Saving…' : 'Reading current timeout…';
    try {
      settings = await window.flowgate.decisionTimeout(edit);
      input.value = String(settings.seconds);
      input.disabled = !settings.writable;
      status.textContent = !settings.writable ? 'Only administrators can change this setting.' : edit ? 'Saved for new requests.' : '';
    } catch (error) {
      settings = undefined;
      status.textContent = (error instanceof Error ? error.message : String(error))
        + (edit ? ' Refresh to check the saved value.' : '');
    } finally {
      busy = refresh.disabled = false;
      updateSave();
    }
  };
  input.oninput = updateSave;
  refresh.onclick = () => void run();
  save.onclick = () => {
    if (!settings?.writable || !input.reportValidity()) return;
    void run({ seconds: input.valueAsNumber, generation: settings.generation, expectedRevision: settings.revision });
  };
  menu.addEventListener('toggle', () => { if (menu.open) void run(); });
}
