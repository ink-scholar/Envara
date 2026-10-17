import { isInterfaceLanguage } from '../shared/interface-languages.mjs';
import { isAppearancePreference, workspaceAppearance } from '../shared/appearance.mjs';
import { parseGoogleMapsLocation } from '../shared/network-location.mjs';

const now = new Date().toISOString();
const catalogNotice = '内核目录为界面预览样例；当前预览未安装或连接任何浏览器内核。';
const sharedCapabilities = { supports_native_proxy: true, supports_webrtc_masking: true, supports_persistent_context: true, supports_playwright_bind: true, requires_external_binary: true };
const engines = [
  { id: 'cloakbrowser', displayName: 'CloakBrowser', family: 'chromium', experimental: false, capabilities: { ...sharedCapabilities, supports_seed_fingerprint: true, supports_structured_config: false, supports_agent_web_sessions: true } },
  { id: 'browseforge-chromium', displayName: 'BrowseForge Chromium', family: 'chromium', experimental: true, capabilities: { ...sharedCapabilities, supports_seed_fingerprint: true, supports_structured_config: true, supports_agent_web_sessions: true } },
  { id: 'camoufox', displayName: 'Camoufox', family: 'firefox', experimental: false, capabilities: { ...sharedCapabilities, supports_seed_fingerprint: false, supports_structured_config: true, supports_agent_web_sessions: false } },
].map(engine => ({ ...engine, supported: true, installed: false, installing: false, enabled: false, version: null, progress: null, error: null, notice: catalogNotice }));
const supportsSeed = engineId => engines.find(engine => engine.id === engineId)?.capabilities.supports_seed_fingerprint === true;
function newSeed(previous) {
  let value;
  do { value = Math.floor(Math.random() * 2147483646) + 1; } while (value === Number(previous));
  return value;
}
const profileFields = ['name', 'group', 'notes', 'engine', 'platform', 'seed', 'locale', 'timezone', 'width', 'height', 'startUrl', 'proxyId', 'privacy'];
function profileConfig(profile = {}) {
  return Object.fromEntries(profileFields.filter(key => Object.hasOwn(profile, key)).map(key => [key, profile[key]]));
}
const initialProfiles = [
  { id: 'preview-1', name: '日常工作 · 独立空间', group: '工作', notes: '', engine: 'cloakbrowser', platform: 'macos', seed: 482731, locale: 'zh-CN', timezone: 'Asia/Shanghai', width: 1440, height: 900, startUrl: 'https://example.com', proxyId: null, createdAt: now, updatedAt: now, lastLaunchedAt: null, status: 'stopped', dataBytes: 0, cpuPercent: null, memoryBytes: null },
  { id: 'preview-2', name: '海外站点测试', group: '测试', notes: '', engine: 'cloakbrowser', platform: 'macos', seed: 827194, locale: 'en-US', timezone: 'America/New_York', width: 1920, height: 1080, startUrl: 'https://example.com', proxyId: 'preview-proxy', createdAt: now, updatedAt: now, lastLaunchedAt: null, status: 'stopped', dataBytes: 0, cpuPercent: null, memoryBytes: null },
];
let state;
try { state = JSON.parse(localStorage.getItem('envara.preview.v1')); } catch {}
if (state) state.settings = { ...state.settings, appearance: workspaceAppearance(state.settings) };
state ||= { profiles: initialProfiles, proxies: [{ id: 'preview-proxy', name: '本地代理', protocol: 'socks5', host: '127.0.0.1', port: 1080, username: '', password: '' }], settings: { closeBrowsersOnExit: true, appearance: 'system' }, events: [] };
state.applications ||= [];
const listeners = new Set();
const snapshot = () => structuredClone({ ...state, applicationRouting: { ready: false, installed: false, authorized: false, status: 'unavailable', message: '本地软件需要桌面应用。' }, engines, engine: engines[0], runtime: { message: catalogNotice }, system: { platform: 'darwin', appVersion: '0.5.0', dataDir: '桌面 App 中查看本地数据目录', preview: true } });
function commit(next = state) {
  localStorage.setItem('envara.preview.v1', JSON.stringify(next));
  state = next;
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
  onTerminalEvent() { return () => {}; },
  onLinkEvent() { return () => {}; },
  subscribe(listener) { listeners.add(listener); return () => listeners.delete(listener); },
  async call(method, args = {}) {
    const p = state.profiles.find(item => item.id === args.id);
    const stamp = new Date().toISOString();
    switch (method) {
      case 'snapshot': return snapshot();
      case 'createProfile': {
        const engine = args.profile.engine || 'cloakbrowser';
        state.profiles.push({ ...profileConfig(args.profile), id: crypto.randomUUID(), seed: supportsSeed(engine) ? Number(args.profile.seed) || newSeed() : null, engine, createdAt: stamp, updatedAt: stamp, status: 'stopped', dataBytes: 0, lastLaunchedAt: null, lastError: null, cpuPercent: null, memoryBytes: null }); break;
      }
      case 'updateProfile':
        if (!p) throw new Error('环境不存在');
        if (args.profile.engine != null && args.profile.engine !== p.engine) throw new Error('已有环境不能直接切换内核，请创建新环境。');
        if (p.seed != null && args.profile.seed != null && Number(args.profile.seed) !== Number(p.seed)) throw new Error('现有环境的指纹种子不可修改；请克隆以生成新指纹。');
        Object.assign(p, profileConfig(args.profile), { seed: supportsSeed(p.engine) ? args.profile.seed ?? p.seed : null, updatedAt: stamp }); break;
      case 'cloneProfile':
        if (!p) throw new Error('环境不存在');
        state.profiles.push({ ...profileConfig(p), id: crypto.randomUUID(), name: `${p.name} · 副本`, seed: supportsSeed(p.engine) ? newSeed(p.seed) : null, createdAt: stamp, updatedAt: stamp, status: 'stopped', dataBytes: 0, lastLaunchedAt: null, lastError: null, cpuPercent: null, memoryBytes: null }); break;
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
      case 'saveSettings':
        if (args.settings?.language != null && !isInterfaceLanguage(args.settings.language)) throw new Error('界面语言无效。');
        if (args.settings && Object.hasOwn(args.settings, 'appearance') && !isAppearancePreference(args.settings.appearance)) throw new Error('无法保存外观，请重试。');
        return commit({ ...state, settings: { ...state.settings, ...args.settings } });
      case 'exportProfiles': {
        const rows = args.id ? state.profiles.filter(item => item.id === args.id) : state.profiles;
        const profiles = rows.map(({ name, group, notes, engine, platform, seed, locale, timezone, width, height, startUrl, privacy }) => ({ name, group, notes, engine, platform, seed, locale, timezone, width, height, startUrl, privacy, proxyId: null }));
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
      case 'openNetworkLocationMap': {
        const location = parseGoogleMapsLocation(args.url);
        if (!location) throw new Error('请先选择网络位置。');
        window.open(location.mapsUrl, '_blank', 'noopener,noreferrer');
        return { ok: true };
      }
      case 'terminalSnapshot': case 'chooseWorkspaceDirectory': case 'openTerminal': case 'writeTerminal': case 'resizeTerminal': case 'closeTerminal': case 'duplicateTerminal': case 'openTerminalWindow':
        throw new Error('内置终端与本地工作目录需要境舱桌面应用。');
      case 'pickApplication': case 'saveApplication': case 'startApplication': case 'stopApplication': case 'deleteApplication': case 'getApplicationRoutingStatus': case 'setupApplicationRouting':
        throw new Error('本地软件与网络接管需要境舱桌面应用。');
      case 'listLocalApplications':
        return { applications: [], platform: 'preview', available: false, scanComplete: true, truncated: false };
      case 'checkEnvironmentNetwork': case 'previewProxyNetwork':
        throw new Error('真实网络出口检测需要境舱桌面应用。');
      case 'installEngine': case 'startProfile': case 'stopProfile': case 'focusProfile': case 'checkProxy': case 'openDataDirectory':
        throw new Error('当前是界面预览，未安装或连接浏览器内核；请打开 Envara 桌面 App 使用浏览器与本地功能。');
      default: throw new Error('不支持的操作');
    }
    return commit();
  },
};
export const api = window.envara || preview;
