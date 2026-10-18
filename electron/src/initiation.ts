import type { SocketRow } from './protocol';
export function initiationPresentation(row: SocketRow) {
  const i = row.initiation;
  if (i?.state === 'known' && ['incoming', 'outgoing'].includes(i.direction || '')) {
    const incoming = i.direction === 'incoming';
    return {
      state: 'known',
      direction: i.direction!,
      label: incoming ? 'Incoming' : 'Outgoing',
      glyph: incoming ? '←' : '→',
      className: incoming ? 'connection-incoming' : 'connection-outgoing',
      title: `${incoming ? 'Incoming: accepted an initiation' : 'Outgoing: initiated the connection'}\n${i.reason}\nEvidence: ${i.source}${i.observed_at ? ' · observed ' + i.observed_at : ''}\nInitiation is independent of upload/download; this is not a firewall verdict.`,
    };
  }
  // Older daemons may explicitly report initiation, but no ports/traffic inference is made.
  const legacy = row.direction?.toLowerCase();
  if (!i && ['incoming', 'outgoing'].includes(legacy))
    return {
      state: 'known',
      direction: legacy,
      label: legacy === 'incoming' ? 'Incoming' : 'Outgoing',
      glyph: legacy === 'incoming' ? '←' : '→',
      className: legacy === 'incoming' ? 'connection-incoming' : 'connection-outgoing',
      title: `Backend-reported ${legacy} initiation (legacy format). Not byte-flow direction or a verdict.`,
    };
  const state =
    i?.state ||
    (row.socket.protocol === 'tcp' && row.socket.state === 10 ? 'listening' : 'unknown');
  const label =
    state === 'listening'
      ? 'Listening'
      : state === 'unconnected'
        ? 'Unconnected UDP'
        : state === 'ambiguous'
          ? 'Ambiguous initiation'
          : 'Unknown initiation';
  return {
    state,
    direction: '',
    label,
    glyph:
      state === 'listening'
        ? '·'
        : state === 'unconnected'
          ? '○'
          : state === 'ambiguous'
            ? '↔'
            : '?',
    className: state === 'listening' ? 'connection-listening' : 'connection-neutral',
    title: `${label}\n${i?.reason || 'No trustworthy initiation observation supplied.'}${i?.source ? '\nEvidence: ' + i.source : ''}\nNo direction is inferred from endpoints or traffic.`,
  };
}
