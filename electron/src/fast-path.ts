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
export function appFastPathDetails(rows: SocketRow[]) {
 const udp=rows.filter(r=>r.socket.protocol==='udp');
 if (!udp.length) return undefined;
 const views=udp.map(r=>({row:r,view:fastPathIndicator(r)}));
 const active=views.find(x=>x.view.className==='in-use');
 const idle=views.find(x=>x.view.className==='authorized');
 const unknown=views.find(x=>x.view.className==='unknown');
 const selected=active||idle||unknown||views[0];
 const state=active?'in-use':idle?'idle':unknown?'unknown':views.every(x=>x.view.className==='unsupported')?'unsupported':'normal';
 const title=active?'UDP fast path in use: recent kernel hits were observed for this application. Other destinations may still use normal checking.':idle?'UDP fast grant, idle: grants exist, but no recent fast-path hits were observed.':unknown?'UDP fast-path use is unknown.':state==='unsupported'?'This UDP traffic is outside the accelerator scope.':'UDP normal path: no fast-path grant was observed for these sockets; ordinary policy checking applies.';
 const at=Date.parse(selected.row.fast_path?.sampled_at||'');
 const fresh=Number.isFinite(at)&&Date.now()-at<=3000&&at<=Date.now()+1000;
 const reason=fresh?selected.row.fast_path?.reason||selected.view.title:selected.view.title;
 return {state,title:title+' '+reason,sampledAt:selected.row.fast_path?.sampled_at||''};
}

// Decorative fast-path symbols are limited to observed grants. Other UDP apps
// keep their ordinary connected-peer dot; explanation remains in Info.
export function appFastPathIndicator(rows: SocketRow[]) {
 const details=appFastPathDetails(rows);
 return details && (details.state==='in-use'||details.state==='idle') ? details : undefined;
}
export function statusIconMarkup(state: 'in-use'|'idle'|'on'|'off') {
 const shape=state==='in-use'?'<path d="M9 1 3 9h4l-1 6 7-9H9z"/>':state==='idle'?'<path d="m8 2 6 6-6 6-6-6z" fill="none" stroke="currentColor" stroke-width="1.5"/>':'<circle cx="8" cy="8" r="4"/>';
 return '<svg viewBox="0 0 16 16" aria-hidden="true" focusable="false">'+shape+'</svg>';
}
