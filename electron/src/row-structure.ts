import type { Row } from './model';
import type { SocketRow } from './protocol';
// Traffic has a separate, live cell-update path. Every identity, ownership, endpoint,
// direction and state field remains in the structural key; this is not authority.
const structure = (r: SocketRow) => {
  const { traffic: _traffic, fast_path: _fastPath, runtime_application: runtime, ...rest } = r;
  // Sampling timestamps/status and retained-vs-fresh display provenance have
  // an in-place update path; they do not change the socket/application identity.
  if (!runtime) return rest;
  const { display_source: _source, ...identity } = runtime;
  return { ...rest, runtime_application: identity };
};
export function rowStructure(r: Row, depth: number, selected: boolean, expanded: boolean) {
  return JSON.stringify([
    r.kind,
    r.program,
    r.applicationZone,
    r.label,
    r.presentationLabel,
    r.identityNote,
    r.pid,
    r.rows.map(structure),
    r.socket && structure(r.socket),
    r.process,
    r.displayApplication,
    r.inactive,
    r.requestEvent && [r.requestEvent.id, r.requestEvent.state],
    r.children.map((c) => c.id),
    depth,
    selected,
    expanded,
  ]);
}
