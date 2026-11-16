import { TERMINAL_ATTACHMENT_LIMITS as limits, TERMINAL_ATTACHMENT_MESSAGES as messages } from '../shared/terminal-attachments.mjs';

/** File events are intercepted before xterm's text-paste listener. The caller
 * also checks busy in onData, including IME/programmatic input paths. */
export function attachTerminalAttachments({ container, sessionId, upload, call, isAvailable, beforeTransfer, insert, onError, onBusyChange = () => {} }) {
  let disposed = false, current = null;
  const available = record => !disposed && current === record && !record.cancelled && isAvailable();
  const cancel = () => {
    const record = current;
    if (!record) return;
    record.cancelled = true; current = null;
    onBusyChange(false);
    void call('cancelTerminalAttachments', { sessionId, transferId: record.id }).catch(() => {});
  };
  const transfer = async files => {
    if (disposed || current || !isAvailable()) return;
    const record = { id: crypto.randomUUID().replaceAll('-', ''), cancelled: false };
    current = record; onBusyChange(true);
    try {
      if (typeof upload !== 'function') throw new Error(messages.TERMINAL_ATTACHMENT_UNSUPPORTED);
      if (!files.length || files.length > limits.count || files.some(file => !Number.isSafeInteger(file.size) || file.size < 0 || file.size > limits.fileBytes) || files.reduce((total, file) => total + file.size, 0) > limits.totalBytes) throw new Error(messages.TERMINAL_ATTACHMENT_LIMIT);
      await beforeTransfer();
      if (!available(record)) return;
      const result = await upload({ sessionId, transferId: record.id }, files);
      if (!available(record)) return;
      if (result?.transferId !== record.id || typeof result.quotedPaths !== 'string' || !result.quotedPaths || result.quotedPaths.length > 32768 || /[\x00-\x1f\x7f]/.test(result.quotedPaths)) throw new Error(messages.TERMINAL_ATTACHMENT_INVALID);
      // Keep the input lock until the path itself is accepted. Never append CR.
      await insert(result.quotedPaths, record.id);
      if (available(record)) { current = null; onBusyChange(false); }
    } catch (error) {
      if (available(record)) onError(messages[error?.code] ?? (Object.values(messages).includes(error?.message) ? error.message : messages.TERMINAL_ATTACHMENT_STORAGE));
    } finally { if (current === record) cancel(); else if (record.cancelled) void call('cancelTerminalAttachments', { sessionId, transferId: record.id }).catch(() => {}); }
  };
  const filesIn = data => Array.from(data?.files ?? []);
  const intercept = event => {
    const files = filesIn(event.clipboardData ?? event.dataTransfer);
    if (!files.length) return;
    event.preventDefault(); event.stopImmediatePropagation();
    if (current) return;
    void transfer(files);
  };
  const dragover = event => { if (Array.from(event.dataTransfer?.types ?? []).includes('Files')) { event.preventDefault(); if (event.dataTransfer) event.dataTransfer.dropEffect = isAvailable() ? 'copy' : 'none'; } };
  const block = event => { if (current) { event.preventDefault(); event.stopImmediatePropagation(); if (event.type === 'keydown' && event.key === 'Escape') cancel(); } };
  container.addEventListener('paste', intercept, true);
  container.addEventListener('drop', intercept, true);
  container.addEventListener('dragover', dragover, true);
  container.addEventListener('keydown', block, true);
  container.addEventListener('beforeinput', block, true);
  return {
    get busy() { return current !== null; }, cancel,
    dispose() { disposed = true; cancel(); container.removeEventListener('paste', intercept, true); container.removeEventListener('drop', intercept, true); container.removeEventListener('dragover', dragover, true); container.removeEventListener('keydown', block, true); container.removeEventListener('beforeinput', block, true); },
  };
}
