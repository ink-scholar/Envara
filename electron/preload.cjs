const { contextBridge, ipcRenderer, webUtils } = require('electron');
const args = typeof process === 'object' && Array.isArray(process.argv) ? process.argv : [];
const argument = name => args.find(value => value.startsWith(`--${name}=`))?.split('=')[1];
const validAppearance = value => value && ['system', 'light', 'dark'].includes(value.preference) && ['light', 'dark'].includes(value.effective);
let appearance = { preference: argument('envara-appearance'), effective: argument('envara-theme') };
if (!validAppearance(appearance)) appearance = null;
const appearanceListeners = new Set();
const attachmentUploads = new Map();
async function invoke(method, args) {
  const result = await ipcRenderer.invoke('envara:call', { method, args });
  if (!result.ok) throw { name: 'Error', message: result.error.message, code: result.error.code, keychainDiagnostic: result.error.keychainDiagnostic };
  return result.value;
}
ipcRenderer.on('envara:appearance', (_event, value) => {
  if (!validAppearance(value)) return;
  appearance = Object.freeze({ preference: value.preference, effective: value.effective });
  for (const listener of appearanceListeners) listener(appearance);
});

contextBridge.exposeInMainWorld('envara', Object.freeze({
  isDesktop: true,
  getAppearance: () => appearance,
  onAppearance: listener => {
    if (typeof listener !== 'function') throw new TypeError('外观监听器必须是函数。');
    appearanceListeners.add(listener);
    if (appearance) listener(appearance);
    return () => appearanceListeners.delete(listener);
  },
  call: async (method, args = {}) => {
    if (method === 'stageTerminalAttachments') throw new Error('附件必须来自粘贴或拖入的文件。');
    if (method === 'cancelTerminalAttachments') { const pending = attachmentUploads.get(args.transferId); if (pending) pending.cancelled = true; }
    return invoke(method, args);
  },
  stageTerminalAttachments: async ({ sessionId, transferId }, files) => {
    if (!Array.isArray(files) || !files.length || files.length > 8) throw new Error('每次最多添加 8 个文件，单个不超过 20 MB，总计不超过 50 MB。');
    if (attachmentUploads.has(transferId) || attachmentUploads.size >= 8) throw new Error('正在处理附件，请稍候再输入。');
    const pending = { cancelled: false }; attachmentUploads.set(transferId, pending);
    try {
    let total = 0; const selected = [];
    for (const file of files) {
      // webUtils rejects synthetic objects. The renderer never supplies a path.
      const source = webUtils.getPathForFile(file);
      if (!Number.isSafeInteger(file.size) || file.size < 0 || file.size > 20 * 1024 * 1024 || (total += file.size) > 50 * 1024 * 1024) throw new Error('每次最多添加 8 个文件，单个不超过 20 MB，总计不超过 50 MB。');
      selected.push(source ? { name: file.name, path: source } : { name: file.name || 'screenshot.png', bytes: new Uint8Array(await file.arrayBuffer()) });
      if (pending.cancelled) throw new Error('附件传输已取消。');
    }
    return await invoke('stageTerminalAttachments', { sessionId, transferId, files: selected });
    } finally { attachmentUploads.delete(transferId); }
  },
  subscribe: (listener) => {
    const handler = (_event, snapshot) => listener(snapshot);
    ipcRenderer.on('envara:snapshot', handler);
    return () => ipcRenderer.removeListener('envara:snapshot', handler);
  },
  /* Where a link from an environment went, so the page can say so. */
  onLinkEvent: (listener) => {
    if (typeof listener !== 'function') throw new TypeError('链接监听器必须是函数。');
    const handler = (_event, message) => listener(message);
    ipcRenderer.on('envara:link-event', handler);
    return () => ipcRenderer.removeListener('envara:link-event', handler);
  },
  onTerminalEvent: (listener) => {
    if (typeof listener !== 'function') throw new TypeError('终端监听器必须是函数。');
    const handler = (_event, message) => listener(message);
    ipcRenderer.on('envara:terminal-event', handler);
    return () => ipcRenderer.removeListener('envara:terminal-event', handler);
  },
}));
