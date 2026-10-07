const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('envara', Object.freeze({
  isDesktop: true,
  call: async (method, args = {}) => {
    const result = await ipcRenderer.invoke('envara:call', { method, args });
    if (!result.ok) {
      const error = new Error(result.error.message);
      error.code = result.error.code;
      throw error;
    }
    return result.value;
  },
  subscribe: (listener) => {
    const handler = (_event, snapshot) => listener(snapshot);
    ipcRenderer.on('envara:snapshot', handler);
    return () => ipcRenderer.removeListener('envara:snapshot', handler);
  },
  onTerminalEvent: (listener) => {
    if (typeof listener !== 'function') throw new TypeError('终端监听器必须是函数。');
    const handler = (_event, message) => listener(message);
    ipcRenderer.on('envara:terminal-event', handler);
    return () => ipcRenderer.removeListener('envara:terminal-event', handler);
  },
}));
