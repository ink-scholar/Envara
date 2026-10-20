const { contextBridge, ipcRenderer } = require('electron');
const args = typeof process === 'object' && Array.isArray(process.argv) ? process.argv : [];
const argument = name => args.find(value => value.startsWith(`--${name}=`))?.split('=')[1];
const validAppearance = value => value && ['system', 'light', 'dark'].includes(value.preference) && ['light', 'dark'].includes(value.effective);
let appearance = { preference: argument('envara-appearance'), effective: argument('envara-theme') };
if (!validAppearance(appearance)) appearance = null;
const appearanceListeners = new Set();
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
    const result = await ipcRenderer.invoke('envara:call', { method, args });
    if (!result.ok) {
      // contextBridge copies Error.message/stack but drops custom properties.
      // Carry a plain failure across worlds; the renderer restores its Error.
      throw { name: 'Error', message: result.error.message, code: result.error.code };
    }
    return result.value;
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
