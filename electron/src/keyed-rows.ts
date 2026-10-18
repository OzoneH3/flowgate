// Replace an invalidated row before the ordering pass. Keeping its old node in
// the parent offsets every later sibling and turns one change into a full move.
export function replaceKeyedRow(previous: Pick<ChildNode, 'replaceWith'> | undefined, next: Node) {
  previous?.replaceWith(next);
}
