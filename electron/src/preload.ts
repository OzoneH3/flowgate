import { contextBridge, ipcRenderer } from 'electron';
import type { Bridge, ClientState, Decision } from './protocol';
const api: Bridge = {
  applicationIcons: (keys) => ipcRenderer.invoke('application:icons', keys),
  graph: (value) => ipcRenderer.invoke('graph', value),
  backgroundStatus: () => ipcRenderer.invoke('background:status'),
  quit: () => ipcRenderer.invoke('app:quit'),
  onNavigate: (fn) => {
    const listener = (_e: unknown, value: { tab: 'requests'; message: string }) => fn(value);
    ipcRenderer.on('navigate', listener);
    return () => ipcRenderer.removeListener('navigate', listener);
  },
  extended: (a) => ipcRenderer.invoke('extended:action', a),
  extendedState: () => ipcRenderer.invoke('extended:state'),
  ruleDraft: (v) => ipcRenderer.invoke('rule:draft', v),
  rulePreview: (v) => ipcRenderer.invoke('rule:preview', v),
  ruleSave: (v) => ipcRenderer.invoke('rule:save', v),
  ruleDelete: (v) => ipcRenderer.invoke('rule:delete', v),
  evaluation: (a, p) => ipcRenderer.invoke('evaluation:action', a, p),
  evaluationState: () => ipcRenderer.invoke('evaluation:state'),
  preferences: (v) => ipcRenderer.invoke('preferences', v),
  snapshot: () => ipcRenderer.invoke('snapshot'),
  subscribe: (fn) => {
    const listener = (_event: unknown, state: ClientState) => fn(state);
    ipcRenderer.on('state', listener);
    return () => ipcRenderer.removeListener('state', listener);
  },
  decide: (d: Decision) => ipcRenderer.invoke('decide', d),
  openPrompt: (id: string) => ipcRenderer.invoke('prompt:open', id),
  dismissPrompt: () => ipcRenderer.invoke('prompt:dismiss'),
};
contextBridge.exposeInMainWorld('flowgate', Object.freeze(api));
