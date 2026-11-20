import type { Row } from './model';
import { hasObservedConnection } from './model';
import { appFastPathIndicator,appFastPathDetails,statusIconMarkup } from './fast-path';

export function updateConnectionStatus(slot: HTMLElement, row: Row) {
  const fast=row.kind==='application'&&!row.applicationZone?appFastPathIndicator(row.rows):undefined;
  const mode=fast?.state || (hasObservedConnection(row)?'on':'off');
  const markup=statusIconMarkup(mode as 'in-use'|'idle'|'on'|'off');
  if(slot.dataset.statusShape!==mode) {slot.innerHTML=markup;slot.dataset.statusShape=mode;}
  slot.className='connection-status-slot '+mode;
  const details=appFastPathDetails(row.rows);
  const detail=details?.title||'Connected-peer observation; no UDP fast-path evidence.';
  slot.title=mode==='in-use'?'Recent UDP fast-path activity'
    :mode==='idle'?'UDP fast grant, idle'
    :details?.state==='normal'?'UDP uses normal checking'
    :details?.state==='unsupported'?'UDP fast path unsupported'
    :details?.state==='unknown'?'UDP fast-path status unknown'
    :mode==='on'?'Connected peer observed':'No connected peer observed';
  if (row.kind==='application'&&!row.applicationZone) slot.setAttribute('aria-label','Open Info: '+detail);
}

