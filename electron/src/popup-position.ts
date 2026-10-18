// Viewport coordinates: never transfer an anchor between renderer windows.
export function popupPosition(
  anchor: { left: number; top: number; bottom: number },
  width: number,
  height: number,
  viewport: { width: number; height: number },
) {
  const margin = 6;
  const left = Math.max(margin, Math.min(anchor.left, viewport.width - width - margin));
  const below = anchor.bottom + 4;
  const preferred = below + height + margin <= viewport.height ? below : anchor.top - height - 4;
  return { left, top: Math.max(margin, Math.min(preferred, viewport.height - height - margin)) };
}
