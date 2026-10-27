import type { Row } from './model';
import type { ClientState } from './protocol';
export const UPLOAD_CAPABILITY = 'experimental-native-upload-v1';
export interface UploadTarget { uid: number; application: string; label?: string; revision?: string }
export interface UploadCap extends UploadTarget { bits_per_second: number }
export interface UploadSnapshot {
  version: number; applied_version: number; enabled: boolean; interface: string; status: string;
  configured_caps: UploadCap[]; last_error?: string; coverage_snapshot_expired?: boolean; coverage_valid_for_ms?: number;
  kernel?: { valid_for_ms?: number; covered_bindings?: number; bindings?: {app: string; covered?: boolean}[]; limitations?: string[]; fault?: string };
}
export interface UploadView { supported: boolean; writable: boolean; generation?: string; snapshot?: UploadSnapshot; message: string }
export interface UploadCleanup { generation: string; expected_version: number; cleanup_only: true }
export interface UploadEdit { generation: string; expected_version: number; target: UploadTarget; bits_per_second: number | null }
export function uploadTarget(row: Row, state: ClientState): UploadTarget | undefined {
  if (!state.observation?.connected) return;
  if (row.displayApplication || row.runtimeApplication || row.applicationZone || row.inactive || !['application','process'].includes(row.kind)) return;
  const p = row.process;
  if (!p || p.application.kind !== 'native' || p.application.hosted || !p.application.key || !p.application.revision) return;
  return {uid:p.uid, application:p.application.key, revision:p.application.revision, label:row.label};
}
export function parseUpload(raw: unknown): UploadSnapshot {
  const r = raw as UploadSnapshot;
  if (r && r.configured_caps === null) r.configured_caps = [];
  if (!r || !Number.isSafeInteger(r.version) || r.version < 1 || !Number.isSafeInteger(r.applied_version) || typeof r.enabled !== 'boolean' || !Array.isArray(r.configured_caps) || r.configured_caps.length > 16 || !['Disabled','Applying','Active','Partial','Unsupported'].includes(r.status)) throw Error('Invalid upload-limit status');
  for (const c of r.configured_caps) validateCap(c);
  return r;
}
export function validateCap(c: UploadCap) {
  if (!c || !Number.isSafeInteger(c.uid) || c.uid < 0 || typeof c.application !== 'string' || !c.application || c.application.length > 4096 || !Number.isSafeInteger(c.bits_per_second) || c.bits_per_second < 1000000 || c.bits_per_second > 1000000000) throw Error('Use a native application and a rate from 1 to 1000 Mbit/s');
}
export function replaceCap(s: UploadSnapshot, edit: UploadEdit): UploadCap[] {
  if (!edit || !Number.isSafeInteger(edit.expected_version) || edit.expected_version < 1 || (edit.bits_per_second !== null && !Number.isSafeInteger(edit.bits_per_second))) throw Error("Invalid upload configuration draft");
  if (s.version !== edit.expected_version) throw Error('Configuration changed. Refresh and review the draft before saving.');
  const cap = {...edit.target, bits_per_second: edit.bits_per_second ?? 1000000}; validateCap(cap);
  const caps = s.configured_caps.filter(c => c.uid !== cap.uid || c.application !== cap.application);
  if (edit.bits_per_second !== null) caps.push({uid:cap.uid, application:cap.application, bits_per_second:cap.bits_per_second});
  if (caps.length > 16) throw Error('The experimental controller supports 16 configured applications');
  return caps;
}
export function uploadSummary(v: UploadView, t?: UploadTarget): string {
  if (!v.supported || !v.snapshot) return 'Unsupported';
  const s=v.snapshot, c=t && s.configured_caps.find(c=>c.uid===t.uid && c.application===t.application);
  if (s.status==='Unsupported') return 'Unsupported';
  if (s.status==='Applying' || s.applied_version!==s.version) return 'Pending';
  if (!c) return 'Off';
  return `${c.bits_per_second/1000000} Mbit/s · Partial`;
}
