import type { ClientState, Rule } from './protocol';

export const ENDPOINT_CAPABILITY = 'network-endpoint-policy-v1';
export const ENDPOINT_SCOPE = 'All users and programs, including unidentified and kernel traffic. This is not a kernel-only, application, CIFS-service or share permission.';
export const ENDPOINT_PRECEDENCE = 'Endpoint Deny wins over endpoint Allow. Endpoint rules run before application rules; Endpoint Allow overrides application Deny and Ask.';
export const ENDPOINT_LIFETIME = 'Removal or expiry affects new admissions and reconnects. Already admitted TCP connections may continue. Same-host traffic retains the existing localhost policy.';
export const ENDPOINT_ZERO_EXPIRY = '0001-01-01T00:00:00Z';
export interface EndpointDraft {
  action: 'allow' | 'block';
  remote_address: string;
  remote_port: number;
  expires: string;
}
export interface EndpointPreview {
  token: string;
  expires_at: string;
  rule: Rule;
  scope_preview: string;
  enforcement: { state: string; covered: boolean; reason: string };
}
export interface EndpointReview {
  receipt: string;
  rule: Rule;
  scope: string;
  enforcement: EndpointPreview['enforcement'];
  expiresAt: number;
}
export function canManageEndpoints(c: ClientState['control']): boolean {
  return c.connected && !c.readOnly && c.permissions?.can_manage_rules === true &&
    c.permissions.can_manage_machine_rules === true && !!c.capabilities?.includes(ENDPOINT_CAPABILITY);
}
export function endpointAddress(raw: unknown): string {
  if (typeof raw !== 'string' || !raw || raw.length > 64 || raw !== raw.trim() || /[\s%/\[\]]/.test(raw))
    throw Error('Enter one non-loopback unicast IP address; hostnames, ranges and zone IDs are unavailable.');
  let address: string;
  if (raw.includes(':')) {
    if (!/^[0-9a-fA-F:.]+$/.test(raw)) throw Error('Invalid IP address');
    try { address = new URL('http://[' + raw + ']/').hostname.slice(1, -1); }
    catch { throw Error('Invalid IP address'); }
    if (/^::ffff:[0-9a-f]+:[0-9a-f]+$/.test(address)) {
      const tail = address.split(':').slice(-2).map(x => parseInt(x, 16));
      address = [tail[0] >> 8, tail[0] & 255, tail[1] >> 8, tail[1] & 255].join('.');
    }
  } else {
    const parts = raw.split('.');
    if (parts.length !== 4 || parts.some(x => !/^(0|[1-9][0-9]{0,2})$/.test(x) || Number(x) > 255)) throw Error('Invalid IP address');
    address = raw;
  }
  if (address.includes(':')) {
    const first = parseInt(address.split(':')[0] || '0', 16);
    if (address === '::' || address === '::1' || (first & 0xff00) === 0xff00 || (first & 0xffc0) === 0xfe80)
      throw Error('Loopback, unspecified, multicast and link-local endpoints are unavailable.');
  } else {
    const p = address.split('.').map(Number);
    if (p[0] === 127 || (p[0] >= 224 && p[0] <= 239) || address === '0.0.0.0' || address === '255.255.255.255' || (p[0] === 169 && p[1] === 254))
      throw Error('Loopback, unspecified, multicast and link-local endpoints are unavailable.');
  }
  return address;
}
export function validateEndpointDraft(raw: unknown, now: number): EndpointDraft {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw Error('Invalid endpoint draft');
  const d = raw as Record<string, unknown>;
  if (Object.keys(d).sort().join(',') !== 'action,expires,remote_address,remote_port' ||
    !['allow', 'block'].includes(String(d.action)) || !Number.isSafeInteger(d.remote_port) || Number(d.remote_port) < 1 || Number(d.remote_port) > 65535 ||
    typeof d.expires !== 'string' || (d.expires !== ENDPOINT_ZERO_EXPIRY && (!Number.isFinite(Date.parse(d.expires)) || Date.parse(d.expires) <= now || Date.parse(d.expires) > now + 365 * 86400000)))
    throw Error('Choose Allow/Deny, one IP and TCP port, and an explicit future expiry within 365 days or No expiry.');
  return { action: d.action as EndpointDraft['action'], remote_address: endpointAddress(d.remote_address), remote_port: Number(d.remote_port), expires: d.expires === ENDPOINT_ZERO_EXPIRY ? ENDPOINT_ZERO_EXPIRY : new Date(d.expires).toISOString() };
}
const record = (v: unknown): Record<string, unknown> => v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : {};
export function validateEndpointRule(raw: unknown): void {
  const r = record(raw), f = record(r.filter);
  const allowed = ['application', 'revision', 'uid', 'all_programs', 'all_uids', 'direction', 'protocol', 'remote_address', 'remote_port'];
  if (r.schema !== 7 || r.network_endpoint !== true || !['allow','block'].includes(String(r.action)) ||
    r.priority !== 100 || typeof r.disabled !== 'boolean' || typeof r.id !== 'string' || !r.id || r.id.length > 256 ||
    !Number.isSafeInteger(r.version) || Number(r.version) < 1 || !Number.isFinite(Date.parse(String(r.created))) || !Number.isFinite(Date.parse(String(r.expires))) ||
    Object.keys(r).some(k => !['id','version','schema','network_endpoint','executable','created','priority','disabled','action','expires','filter','follows_updates'].includes(k)) ||
    (r.follows_updates !== undefined && r.follows_updates !== false) ||
    (r.executable !== undefined && r.executable !== '') || Object.keys(f).some(k => !allowed.includes(k)) ||
    f.application !== '' || f.revision !== '' || f.uid !== 0 || f.all_programs !== true || f.all_uids !== true || f.direction !== 'outgoing' || f.protocol !== 'tcp' ||
    !Number.isSafeInteger(f.remote_port) || Number(f.remote_port) < 1 || Number(f.remote_port) > 65535 || endpointAddress(f.remote_address) !== f.remote_address)
    throw Error('Unsupported network endpoint rule scope');
}
export function sameEndpointRule(a: Rule, b: Rule): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}
