import { contextBridge, ipcRenderer } from 'electron';
let ruleContext: { selection: string; generation: string } | undefined;
const operation = (op: string, value: unknown) =>
  ipcRenderer.invoke('pane:rule-operation', op, value, ruleContext);
const api = {
  ruleDraft: async (source: unknown) => {
    const frame = await ipcRenderer.invoke('pane:snapshot');
    ruleContext = {
      selection: frame.presentation.selection,
      generation: frame.presentation.generation,
    };
    return operation('draft', source);
  },
  rulePreview: (value: unknown) => operation('preview', value),
  ruleSave: (value: unknown) => operation('save', value),
  ruleReconcile: (value: unknown) => operation('reconcile', value),
  ruleContext: () => ipcRenderer.invoke('rule:context'),
  applicationMetadata: (keys: unknown) => ipcRenderer.invoke('application:metadata', keys),
  applicationIcons: (keys: unknown) => ipcRenderer.invoke('application:icons', keys),
  graph: (value: unknown) => ipcRenderer.invoke('graph', value),
  paneSnapshot: () => ipcRenderer.invoke('pane:snapshot'),
  paneUpdate: (value: unknown) => ipcRenderer.invoke('pane:update', value),
  paneControl: (kind: unknown, action: unknown) => ipcRenderer.invoke('pane:control', kind, action),
  paneRule: (action: unknown) => ipcRenderer.invoke('pane:rule', action),
  onPaneFrame: (fn: (frame: unknown) => void) => {
    const listener = (_e: unknown, frame: unknown) => fn(frame);
    ipcRenderer.on('pane:frame', listener);
    return () => ipcRenderer.removeListener('pane:frame', listener);
  },
};
contextBridge.exposeInMainWorld('flowgate', Object.freeze(api));
