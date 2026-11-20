import type { ClientState } from './protocol';
import { evaluationLabel } from './evaluation-model';
export const PROTECTION_CAPABILITY = 'continuous-firewall-v1';
export type ProtectionProfile = 'incoming' | 'both';
export interface ProtectionStatus {
  id: string;
  request_id: string;
  desired_mode: 'monitoring' | ProtectionProfile;
  state: 'stopped' | 'starting' | 'active' | 'stopping' | 'failed' | 'degraded';
  profile: ProtectionProfile;
  cleanup: 'not_needed' | 'pending' | 'confirmed' | 'unconfirmed';
  reason_code: string;
  reason: string;
  readiness: {
    state: 'not_checked' | 'checking' | 'ready' | 'blocked';
    checked_at: string;
    checks: { id: string; status: string; code: string; detail: string; next: string }[];
  };
  existing_connections: string;
  failure_policy: string;
  gui_required: false;
}
export interface ProtectionTokens {
  generation: string;
  protectionId: string;
  profile: ProtectionProfile;
}
export interface ProtectionView {
  supported: boolean;
  label: string;
  message: string;
  connected: boolean;
  status?: ProtectionStatus;
  tokens?: ProtectionTokens;
  busy: boolean;
  canCheck: boolean;
  canStart: boolean;
  canStop: boolean;
}
const text = (v: unknown, limit = 4096) => (typeof v === 'string' ? v.slice(0, limit) : '');
export function parseProtection(raw: unknown): ProtectionStatus | undefined {
  const p = raw as ProtectionStatus;
  if (
    !p ||
    typeof p !== 'object' ||
    Array.isArray(p) ||
    !['monitoring', 'incoming', 'both'].includes(p.desired_mode) ||
    !['stopped', 'starting', 'active', 'stopping', 'failed', 'degraded'].includes(p.state) ||
    !['incoming', 'both'].includes(p.profile) ||
    !['not_needed', 'pending', 'confirmed', 'unconfirmed'].includes(p.cleanup) ||
    !p.readiness ||
    !['not_checked', 'checking', 'ready', 'blocked'].includes(p.readiness.state) ||
    (p.readiness.checks != null && !Array.isArray(p.readiness.checks)) ||
    (p.readiness.checks?.length || 0) > 128 ||
    typeof p.id !== 'string' ||
    (p.id !== '' && !/^[a-f0-9]{32}$/.test(p.id)) ||
    typeof p.request_id !== 'string' ||
    (p.request_id !== '' && !/^[a-f0-9]{32}$/.test(p.request_id)) ||
    p.gui_required !== false
  )
    return;
  return {
    id: p.id,
    request_id: p.request_id,
    desired_mode: p.desired_mode,
    state: p.state,
    profile: p.profile,
    cleanup: p.cleanup,
    reason_code: text(p.reason_code, 128),
    reason: text(p.reason),
    existing_connections: text(p.existing_connections),
    failure_policy: text(p.failure_policy),
    gui_required: false,
    readiness: {
      state: p.readiness.state,
      checked_at: text(p.readiness.checked_at, 64),
      checks: (p.readiness.checks || []).map((c) => ({
        id: text(c?.id, 128),
        status: text(c?.status, 64),
        code: text(c?.code, 128),
        detail: text(c?.detail),
        next: text(c?.next),
      })),
    },
  };
}
export function protectionTokens(raw: unknown): ProtectionTokens {
  const p = raw as ProtectionTokens;
  if (
    !p ||
    typeof p !== 'object' ||
    Object.keys(p).sort().join(',') !== 'generation,profile,protectionId' ||
    typeof p.generation !== 'string' ||
    !p.generation ||
    p.generation.length > 128 ||
    typeof p.protectionId !== 'string' ||
    (p.protectionId !== '' && !/^[a-f0-9]{32}$/.test(p.protectionId)) ||
    !['incoming', 'both'].includes(p.profile)
  )
    throw Error('Invalid protection session');
  return { ...p };
}
export function protectionLabel(p: ProtectionStatus | undefined, connected: boolean) {
  if (!connected) return 'Protection · disconnected / unknown';
  if (!p) return 'Protection · status unavailable';
  if (p.state === 'active')
    return p.profile === 'both'
      ? 'Incoming + outgoing protection · active'
      : 'Incoming protection · active';
  if (p.state === 'stopped' && ['confirmed', 'not_needed'].includes(p.cleanup))
    return p.desired_mode === 'monitoring'
      ? 'Monitoring only · protection stopped'
      : 'Protection stopped · restart requested';
  return `Protection · ${p.state === 'stopped' ? 'cleanup unconfirmed' : p.state}`;
}
export function stateProtection(state: ClientState) {
  const source = state.control.capabilities?.includes(PROTECTION_CAPABILITY)
    ? state.control
    : state.observation;
  return protectionLabel(source.protection, source.connected);
}

export function firewallPresentation(control?: ClientState['control']) {
  let status = 'Connecting';
  let detail = 'Waiting for the firewall controller.';
  let countdown = '';
  if (control?.connected) {
    const p = control.protection;
    const e = control.enforcement;
    const evaluation = !e?.state || control.evaluation?.state === e.state
      ? control.evaluation : undefined;
    const current = p?.state || e?.state || evaluation?.state;
    if (current === 'active') {
      const profile = p?.profile || evaluation?.profile || e?.profile;
      status = profile === 'both' ? 'Both' : profile === 'incoming' ? 'Incoming' : 'Active';
    } else if (current === 'stopped') {
      const cleanup = p?.cleanup || evaluation?.cleanup;
      status = cleanup === 'unconfirmed' || cleanup === 'pending' ? 'Check cleanup' : 'Off';
    } else if (current && current !== 'unknown') {
      status = current.charAt(0).toUpperCase() + current.slice(1);
    } else {
      status = 'Unavailable';
    }
    if (p) {
      detail = [protectionLabel(p, true), p.reason].filter(Boolean).join('\n');
    } else if (evaluation) {
      const remaining = Date.parse(evaluation.stops_at) - (control.serverNow ?? Date.now());
      detail = evaluationLabel(evaluation, remaining);
      if (evaluation.state === 'active') {
        const seconds = Math.ceil(remaining / 1000);
        countdown = seconds > 0
          ? `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, '0')}`
          : 'confirming expiry';
      }
    } else if (e) {
      detail = [status === 'Off' ? 'Firewall is off.' : 'Firewall status: ' + status, e.detail].filter(Boolean).join('\n');
    } else {
      detail = 'Connected to the daemon, but no enforcement status was reported.';
    }
  } else if (control) {
    status = 'Offline';
    detail = 'The firewall controller is disconnected. Current enforcement could not be confirmed.';
  }
  return { status, detail, menu: 'Firewall · ' + (countdown || status) };
}

/**
 * Is FlowGate currently blocking (protection/enforcement active and confirmed)?
 * Drives the icon: blue shield when active, red when stopped, failed, starting
 * or unknown (disconnected) — "no blocks active" is never shown as protected.
 */
export function protectionActive(state: ClientState): boolean {
  if (state.control.capabilities?.includes(PROTECTION_CAPABILITY))
    return state.control.connected && state.control.protection?.state === 'active';
  return state.control.connected && state.control.enforcement?.state === 'active';
}
