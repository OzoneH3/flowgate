import type { SocketRow } from './protocol';
// Presentation only: an Allow, a connected socket, or global fast hits cannot
// establish this connection's acceleration state.
export function fastPathIndicator(row: SocketRow) {
  const h=row.fast_path;
  const sampled=h?.sampled_at ? Date.parse(h.sampled_at) : NaN;
  if (h && (!Number.isFinite(sampled) || Date.now()-sampled>3000 || sampled>Date.now()+1000)) return {label:'Fast path ?',className:'unknown',title:'Fast-path status is stale or undated; current use is unknown.'};
  const detail=h ? h.reason+' Snapshot: '+h.sampled_at : ''; 
  if (!h) return {label:'Fast path ?', className:'unknown',title:'This backend does not report per-connection fast-path status. No inference is made from Allow or traffic totals.'};
  if (h.state==='in_use') return {label:'UDP fast path in use',className:'in-use',title:detail};
  if (h.state==='authorized') return {label:'Fast grant',className:'authorized',title:detail};
  if (h.state==='unsupported') return {label:'Fast path unsupported',className:'unsupported',title:detail};
  if (h.state==='inactive') return {label:'Fast path off',className:'inactive',title:detail};
  return {label:'Fast path ?',className:'unknown',title:detail};
}

// Executable-level observation from UID-projected socket rows. Never infer hits
// from permission, a running process, TCP activity or machine-wide counters.
export function appFastPathIndicator(rows: SocketRow[]) {
 const udp=rows.filter(r=>r.socket.protocol==='udp');
 if (!udp.length) return undefined;
 const views=udp.map(r=>({row:r,view:fastPathIndicator(r)}));
 const active=views.find(x=>x.view.className==='in-use');
 const idle=views.find(x=>x.view.className==='authorized');
 const unknown=views.find(x=>x.view.className==='unknown');
 const selected=active||idle||unknown||views[0];
 const state=active?'in-use':idle?'idle':unknown?'unknown':views.every(x=>x.view.className==='unsupported')?'unsupported':'normal';
 const title=active?'UDP fast path in use: recent kernel hits were observed for this application. Other destinations may still use normal checking.':idle?'UDP fast grant, idle: grants exist, but no recent fast-path hits were observed.':unknown?'UDP fast-path use is unknown.':state==='unsupported'?'This UDP traffic is outside the accelerator scope.':'UDP normal path: no fast-path grant was observed for these sockets; ordinary policy checking applies.';
 return {state,glyph:state==='in-use'?'↯':state==='idle'?'◇':state==='normal'?'•':state==='unsupported'?'–':'?',title:title+' '+selected.view.title,sampledAt:selected.row.fast_path?.sampled_at||''};
}
