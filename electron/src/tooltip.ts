export function setupTooltips() {
  const tooltip = document.createElement('div');
  tooltip.id = 'flowgateTooltip';
  tooltip.className = 'ui-readout';
  tooltip.setAttribute('popover', 'manual');
  tooltip.setAttribute('role', 'tooltip');
  document.body.append(tooltip);
  let anchor: HTMLElement | undefined;
  let title = '';
  let point: { x: number; y: number } | undefined;

  function position() {
    if (!anchor) return;
    const bounds = anchor.getBoundingClientRect();
    const { width, height } = tooltip.getBoundingClientRect();
    const x = point ? point.x + 12 : bounds.left;
    const below = point ? point.y + 16 : bounds.bottom + 6;
    const above = (point ? point.y - 10 : bounds.top - 6) - height;
    tooltip.style.left = Math.max(8, Math.min(x, innerWidth - width - 8)) + 'px';
    tooltip.style.top =
      Math.max(8, Math.min(below + height + 8 <= innerHeight ? below : above, innerHeight - height - 8)) + 'px';
  }

  const watchTitle = new MutationObserver(() => {
    const next = anchor?.getAttribute('title');
    if (!next?.trim()) return hide(false);
    if (point) {
      anchor!.title = '';
      watchTitle.takeRecords();
    }
    if (next === title) return;
    title = next;
    tooltip.textContent = title;
    position();
  });
  const watchAnchor = new MutationObserver(() => { if (anchor && !anchor.isConnected) hide(); });

  function hide(restoreTitle = true) {
    if (!anchor) return;
    watchTitle.disconnect();
    watchAnchor.disconnect();
    if (restoreTitle && point && anchor.getAttribute('title') === '') anchor.title = title;
    const description = (anchor.getAttribute('aria-describedby') || '')
      .split(/\s+/).filter((id) => id && id !== tooltip.id).join(' ');
    if (description) anchor.setAttribute('aria-describedby', description);
    else anchor.removeAttribute('aria-describedby');
    anchor = undefined;
    tooltip.hidePopover();
  }

  function show(target: EventTarget | null, pointer?: typeof point) {
    const next = target instanceof Element ? target.closest('[title]') : null;
    if (next === anchor && Boolean(pointer) === Boolean(point)) return;
    hide();
    if (!(next instanceof HTMLElement) || !next.title.trim()) return;
    anchor = next;
    title = next.title;
    point = pointer;
    tooltip.textContent = title;
    if (point) next.title = '';
    next.setAttribute('aria-describedby', [next.getAttribute('aria-describedby'), tooltip.id].filter(Boolean).join(' '));
    watchTitle.observe(next, { attributes: true, attributeFilter: ['title'] });
    watchAnchor.observe(document.body, { childList: true, subtree: true });
    tooltip.showPopover();
    position();
  }

  document.addEventListener('pointerover', (event) => {
    if (event.pointerType !== 'touch') show(event.target, { x: event.clientX, y: event.clientY });
  });
  document.addEventListener('pointerout', (event) => {
    if (point && anchor && (!(event.relatedTarget instanceof Node) || !anchor.contains(event.relatedTarget)))
      hide();
  });
  document.addEventListener('focusin', (event) => {
    if (event.target instanceof HTMLElement && event.target.matches(':focus-visible')) show(event.target);
  });
  document.addEventListener('focusout', () => { if (!point) hide(); });
  document.addEventListener('pointerdown', () => hide(), true);
  document.addEventListener('keydown', (event) => { if (event.key === 'Escape') hide(); });
  document.addEventListener('scroll', () => hide(), true);
  window.addEventListener('resize', () => hide());
  window.addEventListener('blur', () => hide());
}
