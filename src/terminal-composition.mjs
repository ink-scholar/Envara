// xterm 6 anchors IME preedit to min(cursorX, cols - 1). That can put it
// inside a wide character or on the last character of a pending-wrap line.
// Adjust only the two DOM helpers: the buffer and PTY input stay with xterm.
export function attachTerminalComposition(terminal) {
  const element = terminal.element;
  const textarea = terminal.textarea;
  const screen = element?.querySelector('.xterm-screen');
  const view = element?.querySelector('.composition-view');
  if (!textarea || !screen || !view) return () => {};

  const win = element.ownerDocument.defaultView;
  let disposed = false, scheduled = false, positioned = false;
  const style = (target, property, value) => {
    const current = target.style[property];
    // CSS serializes fractional pixels with its own precision. Do not turn
    // harmless rounding into an endless MutationObserver/microtask cycle.
    if (current === value || (current.endsWith('px') && value.endsWith('px') && Math.abs(Number.parseFloat(current) - Number.parseFloat(value)) < 0.001)) return;
    target.style[property] = value;
  };
  const geometry = () => {
    const dimensions = win.getComputedStyle(screen);
    const width = Number.parseFloat(dimensions.width);
    const height = Number.parseFloat(dimensions.height);
    if (!(width > 0 && height > 0 && terminal.cols > 0 && terminal.rows > 0)) return null;
    const buffer = terminal.buffer.active;
    return { width, cellWidth: width / terminal.cols, cellHeight: height / terminal.rows,
      buffer, cursorRow: buffer.baseY + buffer.cursorY - buffer.viewportY };
  };
  const restoreTextarea = () => {
    const current = geometry();
    if (!current) return;
    const { buffer, cellWidth, cellHeight, cursorRow } = current;
    const column = Math.min(buffer.cursorX, terminal.cols - 1);
    const cell = buffer.getLine(buffer.baseY + buffer.cursorY)?.getCell(column);
    style(textarea, 'left', `${column * cellWidth}px`);
    style(textarea, 'top', `${cursorRow * cellHeight}px`);
    style(textarea, 'width', `${Math.max(1, cellWidth * (cell?.getWidth() ?? 1))}px`);
    style(textarea, 'height', `${cellHeight}px`);
    style(textarea, 'lineHeight', `${cellHeight}px`);
  };

  const sync = () => {
    scheduled = false;
    if (disposed) return;
    if (!view.classList.contains('active')) {
      if (positioned) {
        positioned = false;
        view.classList.remove('terminal-composition-floating');
        style(view, 'maxWidth', '');
        style(view, 'visibility', '');
        view.scrollLeft = 0;
        // xterm normally restores this on cursor movement. Composition can
        // end without any output, so restore it from the current public buffer.
        restoreTextarea();
      }
      return;
    }

    const current = geometry();
    if (!current) return;
    const { width, cellWidth, cellHeight, buffer, cursorRow } = current;
    positioned = true;
    // An output update can leave the cursor outside a scrolled viewport.
    // Avoid displaying stale preedit over unrelated scrollback content.
    if (cursorRow < 0 || cursorRow >= terminal.rows) {
      style(view, 'visibility', 'hidden');
      return;
    }
    style(view, 'visibility', '');

    let column = buffer.cursorX;
    const line = buffer.getLine(buffer.baseY + buffer.cursorY);
    while (column < terminal.cols && line?.getCell(column)?.getWidth() === 0) column++;
    let row = cursorRow;
    if (column >= terminal.cols) { column = 0; row++; }

    style(view, 'fontFamily', terminal.options.fontFamily);
    style(view, 'fontSize', `${terminal.options.fontSize}px`);
    style(view, 'height', `${cellHeight}px`);
    style(view, 'lineHeight', `${cellHeight}px`);
    style(view, 'maxWidth', `${width}px`);
    // Use the fractional CSS width, not scrollWidth's integer rounding: a
    // preview that fits exactly at the edge must not jump to another row.
    const previewWidth = Math.min(width, Math.max(1, Number.parseFloat(win.getComputedStyle(view).width) || 0));
    let left = column * cellWidth;
    const floating = row >= terminal.rows || left + previewWidth > width;
    if (floating) {
      // Keep the current input row readable. At the bottom, show a bounded
      // preedit popup above it instead of shifting left over committed text.
      row = cursorRow + 1 < terminal.rows ? cursorRow + 1 : Math.max(0, cursorRow - 1);
      left = Math.min(left, Math.max(0, width - previewWidth));
    }
    view.classList.toggle('terminal-composition-floating', floating);
    const top = row * cellHeight;
    for (const target of [view, textarea]) {
      style(target, 'left', `${left}px`);
      style(target, 'top', `${top}px`);
    }
    style(textarea, 'width', `${previewWidth}px`);
    style(textarea, 'height', `${cellHeight}px`);
    style(textarea, 'lineHeight', `${cellHeight}px`);
    view.scrollLeft = Math.max(0, view.scrollWidth - view.clientWidth);
  };
  const schedule = () => {
    if (disposed || scheduled) return;
    scheduled = true;
    win.queueMicrotask(sync);
  };

  // xterm rewrites these helpers during composition updates and renders.
  // A microtask keeps our correction before paint, including its delayed
  // update, without accessing a private xterm service or polling every frame.
  const observer = new win.MutationObserver(schedule);
  observer.observe(view, { attributes: true, attributeFilter: ['style', 'class'], childList: true, characterData: true, subtree: true });
  observer.observe(textarea, { attributes: true, attributeFilter: ['style'] });
  observer.observe(screen, { attributes: true, attributeFilter: ['style'] });
  const subscriptions = [terminal.onRender(schedule), terminal.onCursorMove(schedule), terminal.onResize(schedule), terminal.onScroll(schedule)];
  const events = ['compositionstart', 'compositionupdate', 'compositionend'];
  for (const event of events) textarea.addEventListener(event, schedule);
  return () => {
    disposed = true;
    observer.disconnect();
    for (const subscription of subscriptions) subscription.dispose();
    for (const event of events) textarea.removeEventListener(event, schedule);
    view.classList.remove('terminal-composition-floating');
    style(view, 'maxWidth', '');
    style(view, 'visibility', '');
  };
}
