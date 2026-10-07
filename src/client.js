const now = new Date().toISOString();
const initialProfiles = [
  { id: 'preview-1', name: '日常工作 · 独立空间', group: '工作', notes: '', engine: 'cloakbrowser', platform: 'macos', seed: 482731, locale: 'zh-CN', timezone: 'Asia/Shanghai', width: 1440, height: 900, startUrl: 'https://example.com', proxyId: null, createdAt: now, updatedAt: now, lastLaunchedAt: null, status: 'stopped', dataBytes: 0, cpuPercent: null, memoryBytes: null },
  { id: 'preview-2', name: '海外站点测试', group: '测试', notes: '', engine: 'cloakbrowser', platform: 'macos', seed: 827194, locale: 'en-US', timezone: 'America/New_York', width: 1920, height: 1080, startUrl: 'https://example.com', proxyId: 'preview-proxy', createdAt: now, updatedAt: now, lastLaunchedAt: null, status: 'stopped', dataBytes: 0, cpuPercent: null, memoryBytes: null },
];
let state;
try { state = JSON.parse(localStorage.getItem('envara.preview.v1')); } catch {}
state ||= { profiles: initialProfiles, proxies: [{ id: 'preview-proxy', name: '本地代理', protocol: 'socks5', host: '127.0.0.1', port: 1080, username: '', password: '' }], settings: { closeBrowsersOnExit: true }, events: [] };
const listeners = new Set();
const snapshot = () => structuredClone({ ...state, engine: { installed: false, installing: false, version: null, progress: null, error: null }, system: { platform: 'darwin', appVersion: '0.1.0', dataDir: '桌面 App 中查看本地数据目录' } });
function commit() {
  localStorage.setItem('envara.preview.v1', JSON.stringify(state));
  const value = snapshot();
  listeners.forEach(listener => listener(value));
  return value;
}
function download(data, filename) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
  const link = document.createElement('a');
  link.href = url; link.download = filename; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
const preview = {
  isDesktop: false,
  subscribe(listener) { listeners.add(listener); return () => listeners.delete(listener); },
  async call(method, args = {}) {
    const p = state.profiles.find(item => item.id === args.id);
    const stamp = new Date().toISOString();
    switch (method) {
      case 'snapshot': return snapshot();
      case 'createProfile': state.profiles.push({ ...args.profile, id: crypto.randomUUID(), seed: args.profile.seed || Math.floor(Math.random() * 2147483646) + 1, engine: 'cloakbrowser', createdAt: stamp, updatedAt: stamp, status: 'stopped', dataBytes: 0, lastLaunchedAt: null, cpuPercent: null, memoryBytes: null }); break;
      case 'updateProfile': if (!p) throw new Error('环境不存在'); Object.assign(p, args.profile, { updatedAt: stamp }); break;
      case 'cloneProfile': if (!p) throw new Error('环境不存在'); state.profiles.push({ ...p, id: crypto.randomUUID(), name: `${p.name} · 副本`, seed: Math.floor(Math.random() * 2147483646) + 1, createdAt: stamp, updatedAt: stamp }); break;
      case 'deleteProfile': state.profiles = state.profiles.filter(item => item.id !== args.id); break;
      case 'clearProfile': if (p) p.dataBytes = 0; break;
      case 'saveProxy': {
        const proxy = { ...args.proxy, port: Number(args.proxy.port), id: args.proxy.id || crypto.randomUUID() };
        const existing = state.proxies.findIndex(item => item.id === proxy.id);
        if (existing >= 0) state.proxies[existing] = proxy; else state.proxies.push(proxy);
        break;
      }
      case 'deleteProxy':
        if (state.profiles.some(item => item.proxyId === args.id)) throw new Error('请先解除使用此代理的环境绑定');
        state.proxies = state.proxies.filter(item => item.id !== args.id); break;
      case 'saveSettings': Object.assign(state.settings, args.settings); break;
      case 'exportProfiles': {
        const rows = args.id ? state.profiles.filter(item => item.id === args.id) : state.profiles;
        const profiles = rows.map(({ name, group, notes, engine, platform, seed, locale, timezone, width, height, startUrl }) => ({ name, group, notes, engine, platform, seed, locale, timezone, width, height, startUrl, proxyId: null }));
        download({ schema: 'envara.profiles', version: 1, profiles }, 'envara-profiles.json');
        return { canceled: false };
      }
      case 'importProfiles': throw new Error('请在桌面 App 中导入环境配置');
      case 'openDocumentation': {
        const urls = { project: 'https://github.com/ink-scholar/Envara', 'runtime-license': 'https://github.com/CloakHQ/CloakBrowser/blob/main/BINARY-LICENSE.md' };
        if (!Object.hasOwn(urls, args.target)) throw new Error('无效文档链接');
        window.open(urls[args.target], '_blank', 'noopener,noreferrer');
        return { ok: true };
      }
      case 'installEngine': case 'startProfile': case 'stopProfile': case 'focusProfile': case 'checkProxy': case 'openDataDirectory':
        throw new Error('当前是界面预览，请打开 Envara 桌面 App 使用浏览器与本地功能');
      default: throw new Error('不支持的操作');
    }
    return commit();
  },
};
export const api = window.envara || preview;
