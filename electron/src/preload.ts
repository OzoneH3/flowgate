import { contextBridge, ipcRenderer } from 'electron';
import type { Bridge, ClientState, Decision } from './protocol';
const api: Bridge = {
  essentialState: () => ipcRenderer.invoke('essential:state'),
  essential: (action, value) => ipcRenderer.invoke('essential:action', action, value),
  paneSnapshot: () => ipcRenderer.invoke('pane:snapshot'),
  paneUpdate: (value) => ipcRenderer.invoke('pane:update', value),
  paneControl: (kind, action) => ipcRenderer.invoke('pane:control', kind, action),
  paneRule: (action) => ipcRenderer.invoke('pane:rule', action),
  onPaneFrame: (fn) => {
    const listener = (_e: unknown, frame: import('./pane-model').PaneFrame) => fn(frame);
    ipcRenderer.on('pane:frame', listener);
    return () => ipcRenderer.removeListener('pane:frame', listener);
  },
  onPaneRule: (fn) => {
    const listener = (_e: unknown, action: import('./pane-model').PaneRuleAction) => fn(action);
    ipcRenderer.on('pane:rule-open', listener);
    return () => ipcRenderer.removeListener('pane:rule-open', listener);
  },
  ruleContext: () => ipcRenderer.invoke('rule:context'),
  applicationMetadata: (keys: unknown) => ipcRenderer.invoke('application:metadata', keys),
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
  ruleReconcile: (v) => ipcRenderer.invoke('rule:reconcile', v),
  ruleDelete: (v) => ipcRenderer.invoke('rule:delete', v),
  evaluation: (a, p) => ipcRenderer.invoke('evaluation:action', a, p),
  protection: (a, t) => ipcRenderer.invoke('protection:action', a, t),
  protectionState: () => ipcRenderer.invoke('protection:state'),
  evaluationState: () => ipcRenderer.invoke('evaluation:state'),
  preferences: (v) => ipcRenderer.invoke('preferences', v),
  snapshot: () => ipcRenderer.invoke('snapshot'),
  subscribe: (fn) => {
    const listener = (_event: unknown, state: ClientState) => fn(state);
    ipcRenderer.on('state', listener);
    return () => ipcRenderer.removeListener('state', listener);
  },
  onClock: (fn) => {
    const listener = (
      _e: unknown,
      clock: { generation: string; serverNow: number; publication?: number },
    ) => fn(clock);
    ipcRenderer.on('state:clock', listener);
    return () => ipcRenderer.removeListener('state:clock', listener);
  },
  decide: (d: Decision) => ipcRenderer.invoke('decide', d),
  decisionPreview: (d) => ipcRenderer.invoke('decision:preview', d),
  decisionReconcile: (d) => ipcRenderer.invoke('decision:reconcile', d),
  openPrompt: (id: string) => ipcRenderer.invoke('prompt:open', id),
  promptLayout: (value) => ipcRenderer.invoke('prompt:layout', value),
  dismissPrompt: () => ipcRenderer.invoke('prompt:dismiss'),
  decisionLog: () => ipcRenderer.invoke('log:state'),
  decisionLogVisible: (v) => ipcRenderer.invoke('log:visible', v),
  decisionLogFilter: (v) => ipcRenderer.invoke('log:filter', v),
  decisionLogOlder: () => ipcRenderer.invoke('log:older'),
  decisionLogLive: (v) => ipcRenderer.invoke('log:live', v),
  decisionLogDetail: (id) => ipcRenderer.invoke('log:detail', id),
  decisionLogCopy: (id, endpoint) =>
    ipcRenderer.invoke('log:copy', endpoint ? { id, endpoint } : id),
};
contextBridge.exposeInMainWorld('flowgate', Object.freeze(api));
