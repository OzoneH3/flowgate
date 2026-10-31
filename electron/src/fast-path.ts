import type { SocketRow } from './protocol';
// Presentation only: an Allow, a connected socket, or global fast hits cannot
// establish this connection's acceleration state.
export function fastPathIndicator(row: SocketRow) {
  const h=row.fast_path;
  const sampled=h?.sampled_at ? Date.parse(h.sampled_at) : NaN;
  if (h && (!Number.isFinite(sampled) || Date.now()-sampled>3000 || sampled>Date.now()+1000)) return {label:'Fast path ?',className:'unknown',title:'Fast-path status is stale or undated; current use is unknown.'};
  const detail=h ? h.reason+' Snapshot: '+h.sampled_at : ''; 
  if (!h) return {label:'Fast path ?', className:'unknown',title:'This backend does not report per-connection fast-path status. No inference is made from Allow or traffic totals.'};
  if (h.state==='authorized') return {label:'Fast grant',className:'authorized',title:detail};
  if (h.state==='unsupported') return {label:'Fast path unsupported',className:'unsupported',title:detail};
  if (h.state==='inactive') return {label:'Fast path off',className:'inactive',title:detail};
  return {label:'Fast path ?',className:'unknown',title:detail};
}
