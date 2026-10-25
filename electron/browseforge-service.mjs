import { createHash, randomInt, randomUUID } from 'node:crypto';
import { access, cp, lstat, mkdir, readFile, readdir, realpath, rm, stat, writeFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { EnvaraStore } from './store.mjs';
import { ProxyNetworkProbe, proxyFingerprint } from './proxy-network.mjs';
import { AddressGeocoder, addressQuery } from './address-geocoder.mjs';
import { normalizePrivacy } from './privacy-policy.mjs';
import { localeForCountry } from './workspace-context.mjs';
import { isInterfaceLanguage } from '../shared/interface-languages.mjs';
import { isAppearancePreference } from '../shared/appearance.mjs';
import { browseForgeRegionFor } from '../shared/engine-choice.mjs';
import { assertHttpProxyUsername } from '../shared/proxy-auth.mjs';
import { assertNetworkLocationMatchesEgress, confirmNetworkLocation, networkLocationGeolocation, normalizeNetworkLocation, recommendNetworkLocation } from '../shared/network-location.mjs';
import { browserContextSignature } from './terminal-browser-broker.mjs';
import { PROVIDER_DEFAULT_DEVICE_PROFILE_ID, applyBrowserDeviceProfile, deviceProfileFingerprint, deviceProfileReplacedFields, getBrowserDeviceProfile, validateBrowserDeviceProfileIdentity, validateBrowserDeviceProfileInput } from '../shared/browser-device-profile.mjs';

/** A link an environment's browser will load: web only, never credentials. */
function linkURL(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 4096 || /[\0\r\n]/.test(value)) throw error('链接无效。', 'LINK_INVALID');
  let url;
  try { url = new URL(value); } catch { throw error('链接无效。', 'LINK_INVALID'); }
  if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password) throw error('链接仅支持不含凭据的网页地址。', 'LINK_INVALID');
  return url.href;
}
const PROFILE_KEYS = new Set(['name', 'group', 'notes', 'engine', 'platform', 'seed', 'locale', 'timezone', 'width', 'height', 'startUrl', 'proxyId', 'tags', 'fingerprint', 'fingerprintGeneration', 'privacy', 'deviceProfileId']);
const BOUND_BROWSER_ARGUMENTS = Object.freeze({ form_fill: ['fields'], press_key: ['key'], select_option: ['selector', 'values', 'timeout'], check: ['selector', 'checked', 'timeout'], list_tabs: [], new_tab: ['url'], switch_tab: ['index'], close_tab: ['index'] });
function browserProfileSignature(profile) {
  const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
  return createHash('sha256').update(JSON.stringify(canonical(Object.fromEntries(['runtime_id', 'fingerprint_seed', 'fingerprint_generation', 'identity', 'fingerprint', 'launch_overrides', 'group', 'proxy', 'managed_proxy_required'].map(key => [key, profile?.[key] ?? null]))))).digest('hex');
}
// Private launch-route contract shared with browser.SessionRouteDigest. It is
// never included in snapshots or exports and contains no plaintext credentials.
function launchRouteDigest(proxy) {
  // Unicode case conversion differs across Go and JavaScript. Fold ASCII only
  // for this private digest; preserve the actual proxy host and Unicode bytes.
  const host = proxy?.host.replace(/^\[|\]$/g, '').replace(/[A-Z]/g, letter => letter.toLowerCase());
  const fields = proxy ? [(proxy.protocol ?? proxy.type).toLowerCase(), host, String(proxy.port), proxy.username ?? '', proxy.password ?? ''] : ['direct', '', '0', '', ''];
  const digest = createHash('sha256').update('envara-browser-route-v1\0');
  for (const field of fields) digest.update(`${Buffer.byteLength(field)}:`).update(field);
  return digest.digest('hex');
}
function boundBrowserArguments(name, args) {
  const keys = Object.hasOwn(BOUND_BROWSER_ARGUMENTS, name) ? BOUND_BROWSER_ARGUMENTS[name] : null;
  const invalid = () => { throw error('浏览器操作参数无效。', 'CLAUDE_BROWSER_INVALID_ARGUMENT'); };
  if (!keys) throw error('此浏览器操作不属于当前终端。', 'CLAUDE_BROWSER_UNKNOWN_TOOL');
  if (!args || typeof args !== 'object' || Array.isArray(args) || Object.keys(args).some(key => key !== 'profile_id' && !keys.includes(key))) invalid();
  const input = Object.fromEntries(keys.filter(key => Object.hasOwn(args, key)).map(key => [key, args[key]]));
  const string = (value, max = 10000, empty = false) => typeof value === 'string' && (empty || value.length > 0) && value.length <= max && !value.includes('\0');
  if (name === 'form_fill' && (!Array.isArray(input.fields) || !input.fields.length || input.fields.length > 100 || input.fields.some(field => !field || typeof field !== 'object' || Array.isArray(field) || Object.keys(field).some(key => !['selector', 'text', 'clear'].includes(key)) || !string(field.selector) || !string(field.text, 64000, true) || field.clear != null && typeof field.clear !== 'boolean'))) invalid();
  if (name === 'press_key' && !string(input.key, 200)) invalid();
  if (['select_option', 'check'].includes(name) && !string(input.selector)) invalid();
  if (name === 'select_option' && (!Array.isArray(input.values) || !input.values.length || input.values.length > 100 || input.values.some(value => !string(value, 10000, true)))) invalid();
  if (name === 'check' && typeof input.checked !== 'boolean') invalid();
  if (input.timeout != null && (!Number.isSafeInteger(input.timeout) || input.timeout < 0 || input.timeout > 45000)) invalid();
  if (['switch_tab', 'close_tab'].includes(name) && (!Number.isSafeInteger(input.index) || input.index < 0 || input.index > 10000)) invalid();
  if (name === 'new_tab' && input.url != null) input.url = linkURL(input.url);
  return structuredClone(input);
}
const now = () => new Date().toISOString();
const unwrap = (response) => response?.data;
const array = (response) => Array.isArray(unwrap(response)) ? unwrap(response) : [];
const encoded = (value) => encodeURIComponent(identifier(value));
function error(message, code = 'VALIDATION_ERROR') { return Object.assign(new Error(message), { code }); }
function identifier(value) { if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{1,96}$/.test(value)) throw error('无效的环境标识。'); return value; }
function object(value, label) { if (!value || typeof value !== 'object' || Array.isArray(value)) throw error(`${label}必须是对象。`); return value; }
function fingerprintConfig(value) {
  object(value, '指纹');
  const validate = (entry) => {
    if (entry && typeof entry === 'object') for (const [key, child] of Object.entries(entry)) {
      if (['__proto__', 'constructor', 'prototype'].includes(key) || /password|username|credential|token|secret/i.test(key)) throw error('指纹配置不能包含凭据或保留字段。');
      validate(child);
    }
    else if (entry != null && !['string', 'number', 'boolean'].includes(typeof entry)) throw error('指纹配置必须是 JSON 数据。');
  };
  if (JSON.stringify(value).length > 200000) throw error('指纹配置过大。');
  validate(value);
  return structuredClone(value);
}
function fingerprintGenerationConfig(value, provider) {
  if (value == null) return null;
  object(value, '指纹生成记录');
  if (Object.keys(value).some(key => !['provider', 'version', 'tuple_id', 'generated_fields'].includes(key)) || value.provider !== provider || value.version !== 1 || typeof value.tuple_id !== 'string' || !/^[A-Za-z0-9_-]{1,100}$/.test(value.tuple_id)) throw error('指纹生成记录无效。');
  return { provider, version: 1, tuple_id: value.tuple_id, generated_fields: fingerprintConfig(value.generated_fields) };
}
function text(value, label, maximum = 100, optional = false) {
  if (optional && value == null) return '';
  if (typeof value !== 'string' || value.includes('\0') || value.length > maximum || (!optional && !value.trim())) throw error(`${label}格式无效。`);
  return value.trim();
}
function number(value, label, minimum, maximum) { if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw error(`${label}必须为 ${minimum} 至 ${maximum} 的整数。`); return value; }
function proxyConfig(input) {
  object(input, '网络出口');
  const protocol = input.protocol ?? input.type;
  if (!['http', 'https', 'socks5', 'anytls'].includes(protocol)) throw error('代理协议仅支持 HTTP、HTTPS、SOCKS5 和 AnyTLS。');
  if (typeof input.host === 'string' && /[\x00-\x1f\x7f]/.test(input.host)) throw error('代理主机不能包含控制字符。');
  let host = text(input.host, '代理主机', 253);
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  if (/[\\/@\s?#\x00-\x1f\x7f]/.test(host) || (host.includes(':') && net.isIP(host) !== 6)) throw error('代理主机仅填写域名或 IP。');
  if (typeof input.port !== 'number' && !(typeof input.port === 'string' && /^\d+$/.test(input.port))) throw error('代理端口必须为整数。');
  const port = Number(input.port);
  number(port, '代理端口', 1, 65535);
  for (const key of ['username', 'password']) if (input[key] != null && (typeof input[key] !== 'string' || input[key].length > 2048 || /[\x00-\x1f\x7f]/.test(input[key]))) throw error('代理凭据格式无效。');
  if (typeof input.region === 'string' && /[\x00-\x1f\x7f]/.test(input.region)) throw error('代理地域不能包含控制字符。');
  const region = text(input.region ?? '', '代理地域', 64, true);
  const config = { protocol, host, port, username: input.username ?? '', password: input.password ?? '', region };
  if (protocol === 'anytls') {
    if (config.username || !config.password) throw error('AnyTLS 使用密码认证，请填写密码并将用户名留空。');
    if (typeof input.serverName === 'string' && /[\x00-\x1f\x7f]/.test(input.serverName)) throw error('TLS 服务器名称不能包含控制字符。');
    const serverName = text(input.serverName ?? '', 'TLS 服务器名称', 253, true);
    if (serverName && (/[\\/@\s?#\x00-\x1f\x7f]/.test(serverName) || (serverName.includes(':') && net.isIP(serverName) !== 6))) throw error('TLS 服务器名称仅填写域名或 IP。');
    if (input.skipCertVerify != null && typeof input.skipCertVerify !== 'boolean') throw error('证书校验选项格式无效。');
    const clientFingerprint = input.clientFingerprint ?? 'chrome';
    if (!['chrome', 'firefox', 'safari', 'ios', 'android', 'edge', 'random', 'randomized'].includes(clientFingerprint)) throw error('TLS 客户端指纹无效。');
    const alpn = input.alpn ?? [];
    if (!Array.isArray(alpn) || alpn.length > 8 || alpn.some((entry) => typeof entry !== 'string' || !/^[\x21-\x7e]{1,64}$/.test(entry)) || new Set(alpn).size !== alpn.length) throw error('ALPN 必须包含至多 8 个不同的可打印 ASCII 协议名称。');
    if (input.udp != null && typeof input.udp !== 'boolean') throw error('UDP 选项格式无效。');
    if (region && !/^[A-Za-z0-9](?:[A-Za-z0-9_-]*[A-Za-z0-9])?$/.test(region)) throw error('AnyTLS 地域标签只支持字母、数字、横线和下划线。');
    Object.assign(config, { serverName, skipCertVerify: input.skipCertVerify ?? false, clientFingerprint, alpn: [...alpn], udp: input.udp ?? true });
  }
  return config;
}
const upstreamProxy = (proxy) => { if (!proxy) return null; assertHttpProxyUsername(proxy.protocol, proxy.username); const region = browseForgeRegionFor(proxy); return { type: proxy.protocol, host: proxy.host, port: proxy.port, username: proxy.username, password: proxy.password, ...(region ? { region } : {}) }; };
const sameProxy = (a, b) => JSON.stringify(proxyConfig(a)) === JSON.stringify(proxyConfig(b));
const usesManagedProxy = (proxy) => ['http', 'https', 'anytls'].includes(proxy?.protocol ?? proxy?.type);
// Explicit IDs keep saved nodes distinct even when their endpoint fields match.
const proxyMatchesBinding = (proxy, boundId, inline) => boundId ? boundId === proxy.id : inline && sameProxy(inline, proxy);
const rawProxyFingerprint = (proxy) => proxy?.protocol === 'anytls' ? createHash('sha256').update(JSON.stringify(proxyConfig(proxy))).digest('hex') : proxyFingerprint(proxy);
function event(workspace, type, message, profileId) { workspace.events.unshift({ id: randomUUID(), time: now(), type, message, ...(profileId ? { profileId } : {}) }); workspace.events.length = Math.min(200, workspace.events.length); }
function isClosed(errorValue) { return /(?:target|page|browser|context|connection).*(?:has been closed|is closed)|TargetClosed|session not found/i.test(errorValue?.message ?? ''); }
const metric = (value) => typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null;
const configured = (value) => value != null && value !== '';
function profileGeoField(profile, field) {
  const overrides = profile.launch_overrides ?? {};
  if (Object.hasOwn(overrides, field)) return overrides[field] ?? null;
  return profile.fingerprint?.[field === 'locale' ? 'navigator.language' : field] ?? null;
}
function manualTimezone(value) {
  if (!configured(value)) return null;
  if (typeof value !== 'string' || value.length > 128 || /[\x00-\x1f\x7f]/.test(value)) throw error('手动时区无效，请检查环境或旧指纹中的时区配置。', 'INVALID_MANUAL_TIMEZONE');
  try { return new Intl.DateTimeFormat('en', { timeZone: value }).resolvedOptions().timeZone; }
  catch { throw error('手动时区无效，请检查环境或旧指纹中的时区配置。', 'INVALID_MANUAL_TIMEZONE'); }
}
async function dataSize(directory) {
  try {
    let size = 0;
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      if (entry.isDirectory()) { const part = await dataSize(path.join(directory, entry.name)); if (part === null) return null; size += part; }
      else if (entry.isFile()) size += (await stat(path.join(directory, entry.name))).size;
    }
    return size;
  } catch (value) { return value.code === 'ENOENT' ? 0 : null; }
}

/** Native manager for the pinned BrowseForge HTTP contract. Legacy files are never opened for writing. */
export class BrowseForgeService {
  constructor(dataDir, client, system = {}, onChange = () => {}, options = {}) {
    if (!path.isAbsolute(dataDir)) throw error('应用数据目录必须是绝对路径。');
    this.dataDir = path.resolve(dataDir);
    this.client = client;
    this.system = { platform: process.platform, appVersion: '0.2.0', ...system, dataDir: this.dataDir };
    this.options = options;
    this.networkProbe = options.networkProbe ?? new ProxyNetworkProbe();
    this.addressGeocoder = options.addressGeocoder ?? new AddressGeocoder();
    this.workspaceContexts = new Map();
    this.browserLaunchReceipts = new Map();
    this.proxyWires = new Map();
    this.managedProxyRevisions = new Map();
    this.locationPreviews = new Map();
    if (options.profilesDir && !path.isAbsolute(options.profilesDir)) throw error('BrowseForge 资料目录必须是绝对路径。');
    this.profilesDir = path.resolve(options.profilesDir ?? path.join(this.dataDir, 'browseforge', 'profiles'));
    const legacyProfilesDir = path.join(this.dataDir, 'profiles');
    if (this.profilesDir === legacyProfilesDir || this.profilesDir.startsWith(`${legacyProfilesDir}${path.sep}`)) throw error('BrowseForge 必须使用新的资料目录，不能覆盖旧环境。');
    this.store = new EnvaraStore(path.join(this.dataDir, 'browseforge-manager'));
    this.onChange = onChange;
    this.queue = Promise.resolve();
    this.profileQueues = new Map();
    this.installingEngine = null;
    this.starting = new Set();
    this.lastErrors = new Map();
    this.previews = new Map();
    this.previewAttempts = new Map();
    this.previewCapturedAt = new Map();
    this.previewInFlight = new Map();
    this.closed = false;
    this.ready = this.store.ready;
  }

  changed() { try { Promise.resolve(this.onChange()).catch(() => {}); } catch {} }
  request(method, route, body, options) { return this.client.request(method, route, body, options); }
  serialize(operation) { const result = this.queue.then(operation); this.queue = result.catch(() => {}); return result; }
  serializeMutation(operation) { return this.serialize(() => { if (this.closed) throw error('应用正在退出。', 'APP_CLOSING'); if (this.installingEngine) throw error('内核安装期间暂时无法修改工作区。', 'ENGINE_INSTALL_BUSY'); return operation(); }); }
  profileSerialize(profileId, operation) {
    identifier(profileId);
    const result = (this.profileQueues.get(profileId) ?? Promise.resolve()).then(operation);
    const settled = result.catch(() => {});
    this.profileQueues.set(profileId, settled);
    settled.then(() => { if (this.profileQueues.get(profileId) === settled) this.profileQueues.delete(profileId); });
    return result;
  }
  async remote() {
    const results = await Promise.all([this.request('GET', '/api/profiles'), this.request('GET', '/api/sessions'), this.request('GET', '/api/runtimes'), this.request('GET', '/api/groups')]);
    return { profiles: array(results[0]), sessions: array(results[1]), descriptors: array(results[2]), defaultEngine: results[2].default_runtime_id ?? null, groups: array(results[3]) };
  }
  directory(profile) {
    const target = path.join(this.profilesDir, identifier(profile.id));
    if (profile.profile_dir && path.resolve(profile.profile_dir) !== target) throw error('环境资料目录不属于境舱管理的 BrowseForge 目录。', 'UNSAFE_PROFILE_PATH');
    return target;
  }
  async checkedDirectory(profile) {
    const target = this.directory(profile);
    const root = await realpath(this.profilesDir);
    let legacyRoot;
    try { legacyRoot = await realpath(path.join(this.dataDir, 'profiles')); } catch (value) { if (value.code !== 'ENOENT') throw value; }
    if (legacyRoot && (root === legacyRoot || root.startsWith(`${legacyRoot}${path.sep}`))) throw error('新的 BrowseForge 目录不能链接到旧浏览资料。', 'UNSAFE_PROFILE_PATH');
    const info = await lstat(target);
    if (!info.isDirectory() || info.isSymbolicLink() || await realpath(target) !== path.join(root, profile.id)) throw error('环境资料目录包含不安全的链接，操作已取消。', 'UNSAFE_PROFILE_PATH');
    return target;
  }
  async health(session) {
    try {
      const response = await this.request('POST', `/api/sessions/${encoded(session.session_id)}/eval`, { script: '({url:location.href,language:navigator.language,timezone:Intl.DateTimeFormat().resolvedOptions().timeZone,width:screen.width,height:screen.height,platform:navigator.platform})' });
      return { alive: true, observed: unwrap(response) };
    } catch (value) { return { alive: isClosed(value) ? false : null, error: value.message }; }
  }
  async engines(descriptors) {
    const managed = await this.options.getEngineStates?.() ?? {};
    return Promise.all(descriptors.map(async (descriptor) => {
      let installed = false;
      const state = Array.isArray(managed) ? managed.find((item) => item.id === descriptor.id) ?? {} : managed[descriptor.id] ?? {};
      const binaryPath = state.binaryPath ?? descriptor.binary_path;
      if (binaryPath && path.isAbsolute(binaryPath)) { try { const info = await stat(binaryPath); await access(binaryPath, process.platform === 'win32' ? constants.F_OK : constants.X_OK); installed = info.isFile(); } catch {} }
      return { id: descriptor.id, displayName: descriptor.display_name, family: descriptor.family, enabled: !!descriptor.enabled, supported: !!descriptor.platform_supported, installed, installing: !!state.installing, version: installed ? state.version ?? null : null, progress: state.progress ?? null, experimental: descriptor.id === 'browseforge-chromium', capabilities: descriptor.capabilities ?? {}, error: state.error ?? descriptor.unsupported_reason ?? null, binaryPath: installed ? binaryPath : null };
    }));
  }
  proxies(workspace, remote) {
    const result = [...workspace.proxies];
    const networkFor = (proxy) => usesManagedProxy(proxy) ? (this.proxyWires.has(proxy.id) ? this.networkProbe.peek(this.proxyWires.get(proxy.id)) : null) : this.networkProbe.peek(proxy);
    const isBoundProjection = (inline, boundId) => {
      const saved = boundId && workspace.proxies.find((proxy) => proxy.id === boundId);
      if (!saved || saved.protocol === 'anytls') return false;
      // Native copies include the derived region; they do not create a new saved node.
      try { return sameProxy(upstreamProxy({ ...saved, network: networkFor(saved) }), inline); }
      catch { return false; } // Legacy values must remain readable for repair.
    };
    for (const profile of remote.profiles) if (profile.proxy && !result.some((proxy) => sameProxy(proxy, profile.proxy)) && !isBoundProjection(profile.proxy, workspace.profiles.find((item) => item.id === profile.id)?.proxyId)) result.push({ id: `inline_${profile.id}`, name: `${profile.name} · 配置内代理`, ...proxyConfig(profile.proxy), source: 'profile', profileId: profile.id });
    for (const group of remote.groups) if (group.proxy && !result.some((proxy) => sameProxy(proxy, group.proxy)) && !isBoundProjection(group.proxy, workspace.groups?.find((item) => item.name === group.name)?.proxyId)) result.push({ id: `group_${Buffer.from(group.name).toString('hex').slice(0, 70)}`, name: `${group.name} · 分组代理`, ...proxyConfig(group.proxy), source: 'group', groupName: group.name });
    return result.map((proxy) => ({ ...proxy, network: networkFor(proxy), compatibility: this.options?.proxyCore?.compatibilitySnapshot?.(proxy.id) ?? null }));
  }
  groups(workspace, remoteGroups) {
    const groups = remoteGroups.map((group) => ({ ...group }));
    for (const local of workspace.groups ?? []) {
      let group = groups.find((item) => item.name === local.name);
      if (!group) { group = { name: local.name }; groups.push(group); }
      const proxy = workspace.proxies.find((item) => item.id === local.proxyId);
      if (!proxy && group.proxy) continue;
      if (!proxy) throw error('分组绑定的网络出口不存在，不能切换为直接连接。', 'PROXY_NOT_FOUND');
      Object.assign(group, { proxyId: local.proxyId, proxy_mode: local.proxyMode ?? group.proxy_mode ?? 'default', proxy });
    }
    return groups;
  }
  profileProxy(profile, workspace, explicitProxyId) {
    const binding = explicitProxyId === undefined ? workspace?.profiles.find((item) => item.id === profile.id)?.proxyId : explicitProxyId;
    if (binding) {
      const proxy = workspace.proxies.find((item) => item.id === binding);
      if (!proxy && profile.proxy) return profile.proxy;
      if (!proxy) throw error('环境绑定的网络出口不存在，不能切换为直接连接。', 'PROXY_NOT_FOUND');
      return proxy;
    }
    return profile.proxy ?? null;
  }
  effectiveProxy(profile, groups, workspace = { profiles: [], proxies: [] }, explicitProxyId) {
    const group = this.groups(workspace, groups).find((item) => item.name === profile.group);
    const own = this.profileProxy(profile, workspace, explicitProxyId);
    if (group?.proxy_mode === 'enforced' && group.proxy) return { proxy: group.proxy, source: 'group', mode: 'enforced' };
    if (own) return { proxy: own, source: 'profile', mode: group?.proxy_mode ?? 'default' };
    return { proxy: group?.proxy ?? null, source: group?.proxy ? 'group' : 'direct', mode: group?.proxy_mode ?? 'default' };
  }
  async snapshot() {
    await this.ready;
    const trace = (stage, operation) => this.options.diagnostics ? this.options.diagnostics.step(stage, operation) : operation();
    const [workspace, remote] = await Promise.all([trace('snapshot.store', () => this.store.read()), trace('snapshot.remote', () => this.remote())]);
    const proxies = this.proxies(workspace, remote);
    const engines = await trace('snapshot.engines', () => this.engines(remote.descriptors));
    const knownIds = new Set(remote.profiles.map((profile) => profile.id));
    for (const profileId of new Set([...this.previews.keys(), ...this.previewInFlight.keys(), ...this.previewAttempts.keys(), ...this.previewCapturedAt.keys()])) if (!knownIds.has(profileId)) this.resetPreview(profileId);
    let measurements = {};
    try { measurements = await trace('snapshot.metrics', () => this.options.getMetrics?.(remote.profiles)) ?? {}; } catch { /* Unavailable OS measurements remain unknown. */ }
    const profiles = await trace('snapshot.profiles', () => Promise.all(remote.profiles.map(async (profile) => {
      const metadata = workspace.profiles.find((item) => item.id === profile.id) ?? {};
      const session = remote.sessions.find((item) => item.profile_id === profile.id);
      const health = session ? await trace('snapshot.health', () => this.health(session)) : null;
      const effective = this.effectiveProxy(profile, remote.groups, workspace);
      const ownProxy = this.profileProxy(profile, workspace);
      const proxyId = effective.proxy ? proxies.find((proxy) => proxy.id === effective.proxy.id)?.id ?? proxies.find((proxy) => sameProxy(proxy, effective.proxy))?.id ?? null : null;
      const fingerprint = profile.fingerprint ?? {};
      const launchOverrides = profile.launch_overrides ?? {};
      const locale = profileGeoField(profile, 'locale');
      const timezone = profileGeoField(profile, 'timezone');
      const selectedNetworkLocation = effective.proxy?.location?.confirmed === true ? normalizeNetworkLocation(effective.proxy.location) : null;
      const networkTimezone = selectedNetworkLocation?.timezone ?? selectedNetworkLocation?.egressTimezone ?? null;
      let fixedTimezone = null;
      try { fixedTimezone = manualTimezone(timezone); } catch { /* Keep invalid legacy input editable without claiming a resolved timezone. */ }
      const context = this.workspaceContexts.get(profile.id);
      const currentContext = context?.signature === this.contextSignature(profile, effective) ? context : null;
      const status = this.starting.has(profile.id) ? 'starting' : session && health?.alive === true ? 'running' : session && health?.alive === null ? 'error' : this.lastErrors.has(profile.id) ? 'error' : 'stopped';
      const measurement = status === 'running' ? measurements[profile.id] ?? {} : {};
      if (status === 'running') await trace('snapshot.capture', () => this.capture(profile.id, session.session_id, { force: false }));
      else this.resetPreview(profile.id);
      let bytes = null;
      try {
        const directory = await trace('snapshot.directory', () => this.checkedDirectory(profile));
        bytes = await trace('snapshot.data-size', () => dataSize(path.join(directory, 'browser-data')));
      } catch {}
      return { id: profile.id, name: profile.name, group: profile.group ?? '', tags: profile.tags ?? [], notes: metadata.notes ?? '', engine: profile.runtime_id, deviceProfileId: metadata.deviceProfileId ?? PROVIDER_DEFAULT_DEVICE_PROFILE_ID, platform: launchOverrides.target_os || profile.identity?.target_os || null, seed: profile.fingerprint_seed || null, fingerprintGeneration: profile.fingerprint_generation ?? null, locale, timezone, localeMode: configured(locale) ? 'fixed' : 'auto', timezoneMode: configured(timezone) ? 'fixed' : 'auto', launchOverrides, resolvedTimezone: currentContext ? currentContext.timezone ?? null : networkTimezone ?? fixedTimezone, timezoneSource: currentContext ? currentContext.timezoneSource ?? null : networkTimezone ? 'proxy-egress' : configured(timezone) ? 'manual' : null, timezoneOrigin: currentContext?.timezoneOrigin ?? (networkTimezone ? 'network-environment' : null), network: currentContext?.network ?? null, networkLastError: currentContext?.networkLastError ?? null, width: fingerprint['screen.width'] ?? null, height: fingerprint['screen.height'] ?? null, fingerprint, privacy: normalizePrivacy(metadata.privacy), privacyProtection: session?.privacy ?? null, geolocation: currentContext?.geolocation ?? null, selectedLocation: currentContext?.selectedLocation ?? selectedNetworkLocation, locationSource: currentContext?.locationSource ?? effective.proxy?.location?.source ?? null, resolvedLocale: currentContext?.locale ?? null, startUrl: metadata.startUrl ?? 'about:blank', proxyId, profileProxyId: ownProxy ? proxies.find((proxy) => proxy.id === ownProxy.id)?.id ?? proxies.find((proxy) => sameProxy(proxy, ownProxy))?.id ?? null : null, proxySource: effective.source, proxyMode: effective.mode, createdAt: metadata.createdAt ?? profile.created_at, updatedAt: metadata.updatedAt ?? profile.created_at, lastLaunchedAt: metadata.lastLaunchedAt ?? null, status, lastError: health?.alive === null ? health.error : this.lastErrors.get(profile.id) ?? null, dataBytes: bytes, cpuPercent: metric(measurement.cpuPercent), memoryBytes: metric(measurement.memoryBytes), observed: health?.observed ?? null, ...(this.previews.has(profile.id) && status === 'running' ? { screenshot: this.previews.get(profile.id), screenshotCapturedAt: this.previewCapturedAt.get(profile.id) } : {}) };
    })));
    let legacyMigration;
    try { const migration = await trace('snapshot.migration', () => this.previewLegacyMigration()); legacyMigration = { available: migration.detected && migration.profiles.some((profile) => !profile.migrated), count: migration.profiles.filter((profile) => !profile.migrated).length, migrated: migration.profiles.filter((profile) => profile.migrated).length, ...migration }; }
    catch (value) { legacyMigration = { available: false, count: 0, migrated: 0, error: value.message }; }
    const connection = await trace('snapshot.connection', () => this.options.getConnectionInfo?.()) ?? {};
    const publicConnection = Object.fromEntries(['apiUrl', 'mcpUrl', 'status', 'version', 'sourceCommit'].filter((key) => Object.hasOwn(connection, key)).map((key) => [key, connection[key]]));
    return { profiles: profiles.sort((a, b) => (a.createdAt ?? '').localeCompare(b.createdAt ?? '')), proxies, groups: this.groups(workspace, remote.groups).map((group) => ({ ...group, proxyId: group.proxy ? proxies.find((proxy) => proxy.id === group.proxy.id)?.id ?? proxies.find((proxy) => sameProxy(proxy, group.proxy))?.id ?? null : null, proxy: undefined })), engines, engine: engines.find((item) => item.id === remote.defaultEngine) ?? engines[0] ?? {}, settings: { ...workspace.settings, defaultEngine: remote.defaultEngine }, events: workspace.events, legacyMigration, system: this.system, integration: { backup: { configExport: true, browserDataExport: false, credentialExport: false }, mcp: { supported: true, authentication: 'bearer', ...publicConnection } } };
  }
  find(remote, profileId) { identifier(profileId); const profile = remote.profiles.find((item) => item.id === profileId); if (!profile) throw error('环境不存在。', 'PROFILE_NOT_FOUND'); return profile; }
  async assertStopped(remote, profileId) {
    if (this.starting.has(profileId)) throw error('请先停止环境。', 'PROFILE_RUNNING');
    const session = remote.sessions.find((item) => item.profile_id === profileId);
    if (session) { if ((await this.health(session)).alive !== false) throw error('请先停止环境。', 'PROFILE_RUNNING'); await this.request('DELETE', `/api/sessions/${encoded(session.session_id)}`); }
  }
  deviceProfileInput(input, descriptor, { existing } = {}) {
    object(input, '环境配置');
    if (Object.hasOwn(input, 'deviceProfileId')) {
      getBrowserDeviceProfile(input.deviceProfileId);
      return { ...input };
    }
    // A new environment delegates its device defaults to its selected provider.
    // Existing labels and custom/imported fields stay unchanged; only an explicit
    // selection applies one of Envara's fixed device specifications.
    return { ...input, deviceProfileId: existing?.deviceProfileId ?? PROVIDER_DEFAULT_DEVICE_PROFILE_ID };
  }
  normalize(input, descriptor, workspace, remote, existing = null, { preserveIdentity = false } = {}) {
    object(input, '环境配置');
    if (Object.hasOwn(input, 'privacy')) normalizePrivacy(input.privacy);
    for (const key of Object.keys(input)) if (!PROFILE_KEYS.has(key)) throw error(`不支持的环境字段：${key}`);
    const name = text(input.name ?? existing?.name, '环境名称');
    const group = text(input.group ?? existing?.group ?? '', '分组', 100, true);
    if (!descriptor || !descriptor.platform_supported) throw error('当前平台不支持所选浏览器内核。', 'UNSUPPORTED_ENGINE');
    const deviceProfile = validateBrowserDeviceProfileInput(input, descriptor, this.system.platform, { requireComplete: preserveIdentity });
    const previousDeviceProfileId = workspace.profiles.find(item => item.id === existing?.id)?.deviceProfileId ?? PROVIDER_DEFAULT_DEVICE_PROFILE_ID;
    const applyDeviceProfile = deviceProfile && !preserveIdentity && (!existing || input.deviceProfileId !== previousDeviceProfileId);
    if (applyDeviceProfile && existing) validateBrowserDeviceProfileIdentity(deviceProfile.id, descriptor, existing, { requireKnownOrigin: true });
    const payload = { name, group, runtime_id: descriptor.id };
    let generation = Object.hasOwn(input, 'fingerprintGeneration')
      ? fingerprintGenerationConfig(input.fingerprintGeneration, descriptor.id)
      : structuredClone(existing?.fingerprint_generation ?? null);
    const launchOverrides = { ...(existing?.launch_overrides ?? {}) };
    if (input.tags != null) { if (!Array.isArray(input.tags) || input.tags.length > 30) throw error('标签格式无效。'); payload.tags = input.tags.map((tag) => text(tag, '标签', 60)); }
    const platform = deviceProfile?.platform ?? input.platform ?? existing?.identity?.target_os;
    if (platform != null) { if (!['macos', 'windows', 'linux'].includes(platform)) throw error('指纹平台无效。'); payload.identity = { ...(existing?.identity ?? {}), target_os: platform }; launchOverrides.target_os = platform; }
    let fingerprint = { ...(existing?.fingerprint ?? {}) };
    if (input.fingerprint != null) Object.assign(fingerprint, fingerprintConfig(input.fingerprint));
    // Imports and ordinary edits retain their complete saved identity. Only a
    // newly selected fixed specification replaces provider-specific geometry.
    if (applyDeviceProfile) fingerprint = applyBrowserDeviceProfile(fingerprint, deviceProfile.id, descriptor);
    // Null explicitly restores provider-managed geometry; an omitted field is
    // an unrelated edit and must retain the user's existing configuration.
    // A fixed specification continues to own its dimensions even for null.
    if (!deviceProfile) {
      if (Object.hasOwn(input, 'width') && input.width === null) {
        delete fingerprint['screen.width']; delete fingerprint['screen.availWidth'];
      }
      if (Object.hasOwn(input, 'height') && input.height === null) {
        delete fingerprint['screen.height']; delete fingerprint['screen.availHeight'];
      }
    }
    if (input.locale === '') {
      launchOverrides.locale = '';
      for (const key of ['navigator.language', 'navigator.languages', 'locale:language', 'locale:region']) delete fingerprint[key];
    } else if (input.locale != null) { let locale; try { locale = Intl.getCanonicalLocales(input.locale)[0]; } catch { throw error('语言代码无效。'); } if (!locale) throw error('语言代码无效。'); fingerprint['navigator.language'] = locale; fingerprint['navigator.languages'] = [...new Set([locale, locale.split('-')[0]])]; const parts = locale.split('-'); fingerprint['locale:language'] = parts[0]; if (parts[1]) fingerprint['locale:region'] = parts[1]; launchOverrides.locale = locale; }
    if (input.timezone === '') { launchOverrides.timezone = ''; delete fingerprint.timezone; }
    else if (input.timezone != null) { try { new Intl.DateTimeFormat('en', { timeZone: input.timezone }); } catch { throw error('时区无效。'); } fingerprint.timezone = input.timezone; launchOverrides.timezone = input.timezone; }
    if (Object.keys(launchOverrides).length) payload.launch_overrides = launchOverrides;
    if (input.width != null) fingerprint['screen.width'] = number(input.width, '屏幕宽度', 800, 7680);
    if (input.height != null) fingerprint['screen.height'] = number(input.height, '屏幕高度', 600, 4320);
    if (Object.keys(fingerprint).length || existing?.fingerprint != null || input.fingerprint != null) payload.fingerprint = fingerprint;
    if (generation && existing && !preserveIdentity) {
      // An explicit selection owns even a value equal to the generated value.
      // Cloning must keep that choice instead of mistaking it for an automatic one.
      const owned = new Set(Object.keys(input.fingerprint ?? {}));
      if (applyDeviceProfile) for (const key of [...Object.keys(deviceProfileFingerprint(deviceProfile.id, descriptor)), ...deviceProfileReplacedFields(descriptor)]) owned.add(key);
      if (Object.hasOwn(input, 'width') && input.width !== (existing.fingerprint?.['screen.width'] ?? null)) { owned.add('screen.width'); owned.add('screen.availWidth'); }
      if (Object.hasOwn(input, 'height') && input.height !== (existing.fingerprint?.['screen.height'] ?? null)) { owned.add('screen.height'); owned.add('screen.availHeight'); }
      for (const key of owned) delete generation.generated_fields[key];
    }
    if (existing || Object.hasOwn(input, 'fingerprintGeneration')) payload.fingerprint_generation = generation;
    if (descriptor.capabilities?.supports_seed_fingerprint) payload.fingerprint_seed = input.seed != null ? number(input.seed, '指纹种子', 1, 4294967295) : existing ? existing.fingerprint_seed ?? 0 : preserveIdentity ? 0 : randomInt(1, 4294967295);
    else if (input.seed != null) throw error('所选内核使用结构化指纹，不支持种子参数。', 'UNSUPPORTED_CAPABILITY');
    if (existing && input.seed != null && payload.fingerprint_seed !== existing.fingerprint_seed) throw error('现有环境种子不可修改，请克隆新环境。');
    let proxy = existing?.proxy ?? null;
    if (Object.hasOwn(input, 'proxyId')) { if (input.proxyId === null || input.proxyId === '') proxy = null; else { const selected = this.proxies(workspace, remote).find((item) => item.id === input.proxyId); if (!selected) throw error('指定代理不存在，不能自动切换为直接连接。', 'PROXY_NOT_FOUND'); proxy = selected.protocol === 'anytls' ? null : upstreamProxy(selected); } payload.proxy = proxy; }
    const effective = this.effectiveProxy({ ...existing, ...payload, proxy }, remote.groups, workspace, Object.hasOwn(input, 'proxyId') ? input.proxyId : undefined);
    if (descriptor.id === 'browseforge-chromium' && effective.proxy && !browseForgeRegionFor(effective.proxy)) throw error('BrowseForge Chromium 需要有效的地区预设。请先检测并确认网络出口位置，或在高级设置中填写支持的地区代码。', 'INVALID_PROXY_REGION');
    payload.managed_proxy_required = effective.proxy?.protocol === 'anytls';
    return payload;
  }
  metadata(input, profileId, existing = {}) {
    const startUrl = input.startUrl ?? existing.startUrl ?? 'about:blank';
    if (startUrl !== 'about:blank') { let url; try { url = new URL(startUrl); } catch { throw error('启动网址无效。'); } if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) throw error('启动网址仅支持不含凭据的 HTTP 或 HTTPS。'); }
    return { ...existing, id: profileId, deviceProfileId: input.deviceProfileId ?? existing.deviceProfileId ?? PROVIDER_DEFAULT_DEVICE_PROFILE_ID, ...(Object.hasOwn(input, 'proxyId') ? { proxyId: input.proxyId || null } : {}), privacy: normalizePrivacy(input.privacy ?? existing.privacy), notes: text(input.notes ?? existing.notes ?? '', '备注', 4000, true), startUrl, updatedAt: now() };
  }
  async call(method, args = {}) {
    await this.ready;
    if (this.closed) throw error('应用正在退出。', 'APP_CLOSING');
    object(args, '操作参数');
    if (['snapshot', 'getSnapshot'].includes(method)) return this.snapshot();
    const direct = new Set(['checkProxy', 'previewProxyNetwork', 'searchNetworkAddress', 'exportProfiles', 'previewLegacyMigration']);
    const mutations = new Set(['createProfile', 'updateProfile', 'cloneProfile', 'deleteProfile', 'clearProfile', 'startProfile', 'stopProfile', 'focusProfile', 'saveProxy', 'deleteProxy', 'saveGroup', 'deleteGroup', 'clearGroupProxy', 'bulkProfiles', 'importProfiles', 'migrateLegacy', 'saveSettings', 'installEngine']);
    if (!direct.has(method) && !mutations.has(method)) throw error('不支持的操作。', 'UNKNOWN_METHOD');
    if (direct.has(method)) return this[method](args);
    if (this.installingEngine && method !== 'installEngine') throw error('内核安装期间暂时无法修改工作区。', 'ENGINE_INSTALL_BUSY');
    const lifecycle = ['startProfile', 'stopProfile', 'focusProfile'].includes(method);
    const result = lifecycle ? await this.profileSerialize(args.id, () => this[method](args)) : ['installEngine', 'bulkProfiles'].includes(method) ? await this[method](args) : await this.serializeMutation(() => this[method](args));
    this.changed();
    const snapshot = await this.snapshot();
    if (result) snapshot.actionResult = result;
    return snapshot;
  }
  async createProfile({ profile }) {
    const [workspace, remote] = await Promise.all([this.store.read(), this.remote()]);
    if (remote.profiles.length >= 500) throw error('最多支持 500 个环境。');
    const descriptor = remote.descriptors.find((item) => item.id === (profile?.engine ?? remote.defaultEngine));
    profile = this.deviceProfileInput(profile, descriptor);
    const metadata = this.metadata(profile, null);
    const payload = this.normalize(profile, descriptor, workspace, remote);
    const created = unwrap(await this.request('POST', '/api/profiles', payload));
    try { await this.store.transaction((next) => { next.profiles.push({ ...metadata, id: created.id }); event(next, 'profile', `创建环境「${created.name}」`, created.id); }); }
    catch (value) { await this.request('DELETE', `/api/profiles/${encoded(created.id)}`).catch(() => {}); throw value; }
    return { createdId: created.id };
  }
  async updateProfile({ id: profileId, profile }) {
    const [workspace, remote] = await Promise.all([this.store.read(), this.remote()]);
    const existing = this.find(remote, profileId);
    await this.assertStopped(remote, profileId);
    const engineId = profile?.engine ?? existing.runtime_id;
    if (engineId !== existing.runtime_id) throw error('已有资料不能直接切换内核，请创建新环境。', 'ENGINE_CHANGE_REQUIRES_NEW_PROFILE');
    const oldMetadata = workspace.profiles.find((item) => item.id === profileId) ?? {};
    profile = this.deviceProfileInput(profile, remote.descriptors.find(item => item.id === engineId), { existing: oldMetadata, preserve: true });
    const metadata = this.metadata(profile, profileId, oldMetadata);
    const payload = this.normalize(profile, remote.descriptors.find((item) => item.id === engineId), workspace, remote, existing);
    await this.request('PUT', `/api/profiles/${encoded(profileId)}`, payload);
    await this.store.transaction((next) => { next.profiles = next.profiles.filter((item) => item.id !== profileId); next.profiles.push(metadata); event(next, 'profile', `更新环境「${payload.name}」`, profileId); });
    this.workspaceContexts.delete(profileId);
  }
  async cloneProfile({ id: profileId }) {
    const [workspace, remote] = await Promise.all([this.store.read(), this.remote()]);
    const original = this.find(remote, profileId);
    const descriptor = remote.descriptors.find((item) => item.id === original.runtime_id);
    if (!descriptor?.platform_supported) throw error('当前平台不支持原环境的内核。');
    const old = workspace.profiles.find(item => item.id === profileId) ?? {};
    validateBrowserDeviceProfileInput({ deviceProfileId: old.deviceProfileId ?? PROVIDER_DEFAULT_DEVICE_PROFILE_ID }, descriptor, this.system.platform);
    // Native creation owns identity generation for desktop, REST and MCP.
    // Duplicate preserves user constraints and gives the copy a fresh identity.
    const created = unwrap(await this.request('POST', `/api/profiles/${encoded(profileId)}/duplicate`, { name: `${original.name.slice(0, 90)} 副本` }));
    try { await this.store.transaction((next) => { next.profiles.push(this.metadata(old, created.id)); event(next, 'profile', `克隆环境「${original.name}」`, created.id); }); }
    catch (value) { await this.request('DELETE', `/api/profiles/${encoded(created.id)}`).catch(() => {}); throw value; }
    return { createdId: created.id };
  }
  async deleteProfile({ id: profileId }) { const remote = await this.remote(); const profile = this.find(remote, profileId); await this.assertStopped(remote, profileId); await this.checkedDirectory(profile); await this.request('DELETE', `/api/profiles/${encoded(profileId)}`); await this.store.transaction((next) => { next.profiles = next.profiles.filter((item) => item.id !== profileId); event(next, 'profile', `删除环境「${profile.name}」`, profileId); }); this.lastErrors.delete(profileId); this.workspaceContexts.delete(profileId); this.resetPreview(profileId); }
  async clearProfile({ id: profileId }) { const remote = await this.remote(); const profile = this.find(remote, profileId); await this.assertStopped(remote, profileId); const directory = await this.checkedDirectory(profile); await rm(path.join(directory, 'browser-data'), { recursive: true, force: true }); await rm(path.join(directory, 'cookies-backup.json'), { force: true }); await mkdir(path.join(directory, 'browser-data'), { recursive: true, mode: 0o700 }); await this.store.transaction((next) => event(next, 'profile', `清理环境「${profile.name}」的完整浏览资料，保留下载文件`, profileId)); this.lastErrors.delete(profileId); this.resetPreview(profileId); }
  // A new tab preserves the user's current page. If it fails, leave that page
  // intact and let the caller handle the refusal instead of navigating it.
  linkNetworkSelection(profile, workspace) {
    const proxy = profile.proxyId ? workspace.proxies.find(item => item.id === profile.proxyId) : null;
    if (profile.proxyId && !proxy) throw error('链接所属的网络不可用。', 'LINK_BROWSER_CHANGED');
    return { group: profile.group ?? '', proxyId: profile.proxyId ?? null, signature: rawProxyFingerprint(proxy) };
  }
  async openProfileLink({ id: profileId, url, sourceProfileId = profileId, expectedNetwork }) {
    const target = linkURL(url);
    await this.ready;
    // Serialize configuration only until a launch and its exact route are bound.
    // Navigation happens afterwards, so a slow page cannot prevent Stop.
    const selected = await this.profileSerialize(profileId, () => this.serializeMutation(async () => {
      let remote = await this.remote();
      const workspace = await this.store.read();
      const network = (id, native, local) => {
        const profile = this.find(native, id);
        const effective = this.effectiveProxy(profile, native.groups, local);
        const proxies = this.proxies(local, native);
        const proxyId = effective.proxy ? proxies.find(proxy => proxy.id === effective.proxy.id)?.id ?? proxies.find(proxy => sameProxy(proxy, effective.proxy))?.id ?? null : null;
        return { group: profile.group ?? '', proxyId, signature: rawProxyFingerprint(effective.proxy) };
      };
      const source = network(sourceProfileId, remote, workspace), destination = network(profileId, remote, workspace);
      if (expectedNetwork && (source.group !== expectedNetwork.group || source.proxyId !== expectedNetwork.proxyId
          || expectedNetwork.signature != null && source.signature !== expectedNetwork.signature)
          || source.group !== destination.group || source.proxyId !== destination.proxyId || source.signature !== destination.signature) {
        throw error('链接所属的网络已改变，请重新打开链接。', 'LINK_BROWSER_CHANGED');
      }
      const reservation = await this.reserveProfileStart(profileId);
      if (!reservation.focus) await this.launchReservedProfile(reservation);
      remote = await this.remote();
      // REST clients bypass the desktop queue: re-read the stored selections,
      // then bind the live launch's own nonce and actual route at the backend.
      const currentWorkspace = await this.store.read();
      const currentSource = network(sourceProfileId, remote, currentWorkspace), currentTarget = network(profileId, remote, currentWorkspace);
      if ([currentSource, currentTarget].some(current => current.group !== source.group || current.proxyId !== source.proxyId || current.signature !== source.signature)) {
        throw error('链接所属的网络已改变，请重新打开链接。', 'LINK_BROWSER_CHANGED');
      }
      const context = await this.resolveWorkspaceContext(profileId, { remote });
      const bound = await this.assertBoundBrowserReceipt(profileId, context, remote);
      const receipt = this.browserLaunchReceipts.get(profileId);
      return { profileId, profile: this.find(remote, profileId).name, sessionId: bound.session_id, instanceId: receipt.instanceId, routeDigest: launchRouteDigest(context.proxy) };
    }));
    await this.request('POST', `/api/sessions/${encoded(selected.sessionId)}/open-link`, { url: target, instance_id: selected.instanceId, route_digest: selected.routeDigest }, { timeoutMs: 20000 });
    return { profileId, profile: selected.profile, opened: 'tab', url: target };
  }
  async startProfile({ id: profileId }) {
    const reservation = await this.serialize(() => this.reserveProfileStart(profileId));
    if (reservation.focus) return this.focusProfile({ id: profileId });
    return this.launchReservedProfile(reservation);
  }
  async reserveProfileStart(profileId) {
    if (this.closed) throw error('应用正在退出。', 'APP_CLOSING');
    if (this.installingEngine) throw error('内核正在安装，请稍后启动。', 'ENGINE_INSTALL_BUSY');
    const remote = await this.remote(); const profile = this.find(remote, profileId); const previous = remote.sessions.find((item) => item.profile_id === profileId);
    const metadata = (await this.store.read()).profiles.find(item => item.id === profileId) ?? {};
    const deviceProfileId = metadata.deviceProfileId ?? PROVIDER_DEFAULT_DEVICE_PROFILE_ID;
    validateBrowserDeviceProfileInput({ ...profile, deviceProfileId, platform: profile.launch_overrides?.target_os ?? profile.identity?.target_os },
    profile.runtime_id, this.system.platform, { requireComplete: true });
    if (previous && (await this.health(previous)).alive === true) return { profile, focus: true };
    const engine = (await this.engines(remote.descriptors)).find((item) => item.id === profile.runtime_id);
    if (!engine?.installed || !engine.enabled) throw error('请先安装并启用该环境的浏览器内核。', 'ENGINE_NOT_INSTALLED');
    this.starting.add(profileId); this.lastErrors.delete(profileId); this.resetPreview(profileId);
    return { profile, remote };
  }
  async launchReservedProfile(reservation) {
    const { profile } = reservation, profileId = profile.id;
    this.changed();
    try {
      const context = await this.resolveWorkspaceContext(profileId, { remote: reservation.remote, force: true });
      const session = unwrap(await this.request('POST', '/api/sessions', { profile_id: profileId, launch_overrides: { timezone: context.timezone, ...(context.locale ? { locale: context.locale } : {}), ...(context.network?.countryCode ? { country_code: context.network.countryCode } : {}), privacy: context.privacy, geolocation: context.geolocation, ...(context.managedProxy ? { proxy: upstreamProxy(context.proxy) } : {}) } }, { timeoutMs: 180000 }));
      // Only a launch issued here can establish the route receipt. Existing
      // sessions discovered from REST are never retroactively called verified.
      this.browserLaunchReceipts.delete(profileId);
      try {
        // LaunchSession may reuse a healthy backend browser even when its active
        // page failed our health check. That is not proof of a fresh launch.
        if (reservation.remote.sessions.some(item => item.profile_id === profileId)) throw error('浏览器启动来源尚未确认。', 'CLAUDE_BROWSER_ROUTE_UNVERIFIED');
        const identity = await this.browserSessionIdentity(session, context);
        const endpoint = await this.boundBrowserEndpoint(session);
        this.browserLaunchReceipts.set(profileId, { sessionId: session.session_id, runtimeId: session.runtime_id, instanceId: identity.instance_id, endpoint,
          profileSignature: browserProfileSignature(profile),
          signature: browserContextSignature(context), context: structuredClone({ proxyId: context.proxyId, timezone: context.timezone, locale: context.locale, geolocation: context.geolocation, network: context.network }) });
      } catch { /* Normal browser launch remains usable; bound automation refuses. */ }
      const metadata = (await this.store.read()).profiles.find((item) => item.id === profileId);
      if (metadata?.startUrl && metadata.startUrl !== 'about:blank') { try { await this.request('POST', `/api/sessions/${encoded(session.session_id)}/navigate`, { url: metadata.startUrl, wait_until: 'domcontentloaded' }); } catch (value) { this.lastErrors.set(profileId, `页面未加载完成：${value.message}`); } }
      await this.store.transaction((next) => { const metadata = next.profiles.find((item) => item.id === profileId); if (metadata) metadata.lastLaunchedAt = now(); event(next, 'browser', `启动环境「${profile.name}」`, profileId); });
      await this.capture(profileId, session.session_id);
    } catch (value) { this.lastErrors.set(profileId, value.message); await this.store.transaction((next) => event(next, 'error', `环境「${profile.name}」启动失败：${value.message}`, profileId)); throw value; }
    finally { this.starting.delete(profileId); this.changed(); }
  }
  async stopProfile({ id: profileId }) { const remote = await this.remote(); const profile = this.find(remote, profileId); const session = remote.sessions.find((item) => item.profile_id === profileId); if (session) await this.request('DELETE', `/api/sessions/${encoded(session.session_id)}`); this.browserLaunchReceipts.delete(profileId); this.resetPreview(profileId); this.lastErrors.delete(profileId); await this.store.transaction((next) => event(next, 'browser', `停止环境「${profile.name}」`, profileId)); }
  async browserSessionIdentity(session, context) {
    const identity = unwrap(await this.request('GET', `/api/sessions/${encoded(session.session_id)}/identity`));
    if (!/^[a-f0-9]{32}$/.test(session.instance_id ?? '') || identity?.instance_id !== session.instance_id || identity?.route_digest !== launchRouteDigest(context.proxy)) {
      throw error('当前浏览器的实际启动线路已改变，请停止后重新启动。', 'CLAUDE_BROWSER_ROUTE_UNVERIFIED');
    }
    return identity;
  }
  async boundBrowserEndpoint(session) {
    const endpoints = array(await this.request('GET', '/api/playwright/endpoint'));
    const endpoint = endpoints.find(item => item.profile_id === session.profile_id && item.session_id === session.session_id && item.runtime_id === session.runtime_id)?.endpoint;
    if (typeof endpoint !== 'string' || !endpoint) throw error('当前浏览器缺少启动凭据，请在境舱中停止后重新启动。', 'CLAUDE_BROWSER_ROUTE_UNVERIFIED');
    return createHash('sha256').update(endpoint).digest('hex');
  }
  async assertBoundBrowserReceipt(profileId, context, remote) {
    const session = remote.sessions.find(item => item.profile_id === profileId);
    const receipt = this.browserLaunchReceipts.get(profileId);
    if (!session || !receipt || receipt.sessionId !== session.session_id || receipt.runtimeId !== session.runtime_id
      || receipt.profileSignature !== browserProfileSignature(remote.profiles.find(item => item.id === profileId))
      || receipt.signature !== browserContextSignature(context) || receipt.instanceId !== session.instance_id
      || receipt.endpoint !== await this.boundBrowserEndpoint(session)) {
      throw error('当前浏览器的网络启动凭据不匹配，请在境舱中停止后重新启动。', 'CLAUDE_BROWSER_ROUTE_UNVERIFIED');
    }
    await this.browserSessionIdentity(session, context);
    if ((await this.health(session)).alive !== true) throw error('当前浏览器没有响应，未改用其他浏览器。', 'CLAUDE_BROWSER_UNAVAILABLE');
    return { session_id: session.session_id, profile_id: profileId };
  }
  /** Main-process only. Not part of call()/IPC and never returns Bind endpoints. */
  async ensureBoundBrowser({ profileId, expectedContext }) {
    await this.ready;
    identifier(profileId);
    if (expectedContext?.id !== profileId || !expectedContext.proxy || !expectedContext.proxyId || expectedContext.network?.ok !== true) throw error('请先确认此浏览器所属的境舱网络。', 'CLAUDE_BROWSER_NETWORK_REQUIRED');
    return this.profileSerialize(profileId, async () => {
      if (this.closed) throw error('应用正在退出。', 'APP_CLOSING');
      let remote = await this.remote();
      let context = await this.resolveWorkspaceContext(profileId, { remote });
      const expectedSignature = browserContextSignature(expectedContext);
      if (context.network?.ok !== true || browserContextSignature(context) !== expectedSignature) throw error('浏览器的境舱网络已改变，请重新创建 Claude Code 会话。', 'CLAUDE_BROWSER_BINDING_CHANGED');
      if (!remote.sessions.some(item => item.profile_id === profileId)) {
        // startProfile uses the global reservation queue, not profileSerialize.
        await this.startProfile({ id: profileId });
        remote = await this.remote();
        context = await this.resolveWorkspaceContext(profileId, { remote });
        if (context.network?.ok !== true || browserContextSignature(context) !== expectedSignature) throw error('浏览器启动期间境舱网络已改变，请重新创建 Claude Code 会话。', 'CLAUDE_BROWSER_BINDING_CHANGED');
      }
      return this.assertBoundBrowserReceipt(profileId, context, remote);
    });
  }
  /** The broker may call only page operations; another profile is never accepted. */
  async callBoundBrowserTool(profileId, name, args = {}) {
    await this.ready;
    identifier(profileId);
    const input = boundBrowserArguments(name, args);
    return this.profileSerialize(profileId, async () => {
      if (this.closed) throw error('应用正在退出。', 'APP_CLOSING');
      const remote = await this.remote();
      const context = await this.resolveWorkspaceContext(profileId, { remote });
      if (context.network?.ok !== true || !context.proxy || !context.proxyId) throw error('当前境舱网络不可用，未执行浏览器操作。', 'CLAUDE_BROWSER_NETWORK_REQUIRED');
      await this.assertBoundBrowserReceipt(profileId, context, remote);
      if (typeof this.client.callMcpTool !== 'function') throw error('浏览器操作通道不可用。', 'CLAUDE_BROWSER_UNAVAILABLE');
      return this.client.callMcpTool(name, { ...input, profile_id: profileId });
    });
  }
  async focusProfile({ id: profileId }) { const remote = await this.remote(); const profile = this.find(remote, profileId); const session = remote.sessions.find((item) => item.profile_id === profileId); if (!session || (await this.health(session)).alive !== true) throw error('环境尚未运行。', 'PROFILE_NOT_RUNNING'); const workspace = await this.store.read(); if (usesManagedProxy(this.effectiveProxy(profile, remote.groups, workspace).proxy) || profile.managed_proxy_required) await this.resolveWorkspaceContext(profileId, { remote, force: true }); if (this.options.focusSession) await this.options.focusSession(session); else await this.request('POST', `/api/sessions/${encoded(session.session_id)}/focus`); await this.capture(profileId, session.session_id); }
  resetPreview(profileId) { this.previews.delete(profileId); this.previewAttempts.delete(profileId); this.previewCapturedAt.delete(profileId); this.previewInFlight.delete(profileId); }
  async capture(profileId, sessionId, { force = true } = {}) {
    const pending = this.previewInFlight.get(profileId);
    if (pending) return pending.promise;
    const timestamp = this.options.nowMs?.() ?? Date.now();
    if (!force && this.previewAttempts.has(profileId) && timestamp - this.previewAttempts.get(profileId) < 10000) return;
    this.previewAttempts.set(profileId, timestamp);
    const operation = { promise: null };
    this.previewInFlight.set(profileId, operation);
    operation.promise = (async () => {
      try {
        const image = await this.request('GET', `/api/sessions/${encoded(sessionId)}/screenshot`, undefined, { responseType: 'arraybuffer' });
        if (!image?.byteLength) return;
        if (!this.closed && this.previewInFlight.get(profileId) === operation) {
          this.previews.set(profileId, `data:image/png;base64,${Buffer.from(image).toString('base64')}`);
          this.previewCapturedAt.set(profileId, new Date(this.options.nowMs?.() ?? Date.now()).toISOString());
        }
      } catch { /* Preserve the last successful image and its original capture time. */ }
      finally { if (this.previewInFlight.get(profileId) === operation) this.previewInFlight.delete(profileId); }
    })();
    return operation.promise;
  }
  async saveProxy({ proxy, locationPreviewToken }) {
    const config = { ...proxyConfig(proxy), name: text(proxy.name, '代理名称') };
    assertHttpProxyUsername(config.protocol, config.username);
    const [workspace, remote] = await Promise.all([this.store.read(), this.remote()]);
    const existing = proxy.id ? this.proxies(workspace, remote).find((item) => item.id === proxy.id) : null;
    if (proxy.id && !existing) throw error('网络出口不存在。', 'PROXY_NOT_FOUND');
    const sameRoute = existing && rawProxyFingerprint(existing) === rawProxyFingerprint(config);
    const requestedLocation = Object.hasOwn(proxy, 'location') ? normalizeNetworkLocation(proxy.location) : undefined;
    const previousLocation = sameRoute && existing.location?.confirmed === true ? normalizeNetworkLocation(existing.location) : null;
    // Legacy callers can keep a saved selection, but changing the route clears
    // it. A new/changed confirmed location must match a private recent probe.
    const unchangedLocation = requestedLocation != null && previousLocation != null && JSON.stringify(requestedLocation) === JSON.stringify(previousLocation);
    if (requestedLocation && (!unchangedLocation || locationPreviewToken != null)) {
      const preview = this.locationPreviews.get(locationPreviewToken);
      if (!preview || preview.expiresAt <= Date.now() || preview.fingerprint !== rawProxyFingerprint(config)) throw error('请先检测当前代理，再确认这个网络环境的位置。', 'NETWORK_LOCATION_NOT_VERIFIED');
      config.location = confirmNetworkLocation(proxy.location, preview.network, undefined, preview.referenceLocation);
    } else if (requestedLocation === null) config.location = null;
    else if (requestedLocation || previousLocation) config.location = requestedLocation ?? previousLocation;
    const savedId = workspace.proxies.some((item) => item.id === proxy.id) ? proxy.id : randomUUID();
    const users = existing ? remote.profiles.filter(profile => proxyMatchesBinding(existing, workspace.profiles.find(item => item.id === profile.id)?.proxyId, profile.proxy)) : [];
    const groups = existing ? this.groups(workspace, remote.groups).filter(group => proxyMatchesBinding(existing, group.proxy?.id, group.proxy)) : [];
    const affected = remote.profiles.filter((profile) => users.includes(profile) || groups.some((group) => group.name === profile.group));
    for (const profile of affected) await this.assertStopped(remote, profile.id);
    for (const profile of affected) if (profile.runtime_id === 'browseforge-chromium' && !browseForgeRegionFor(config)) throw error('BrowseForge Chromium 需要有效的地区预设。请先检测并确认网络出口位置，或在高级设置中填写支持的地区代码。', 'INVALID_PROXY_REGION');
    if (groups.length && config.protocol === 'https') throw error('BrowseForge 分组代理仅支持 HTTP、SOCKS5 或托管 AnyTLS。', 'UNSUPPORTED_GROUP_PROXY');
    const staged = structuredClone(workspace);
    staged.proxies = staged.proxies.filter((item) => item.id !== savedId);
    staged.proxies.push({ id: savedId, ...config });
    for (const profile of users) {
      let metadata = staged.profiles.find((item) => item.id === profile.id);
      if (!metadata) { metadata = { id: profile.id }; staged.profiles.push(metadata); }
      metadata.proxyId = savedId;
    }
    staged.groups = staged.groups ?? [];
    for (const group of groups) { staged.groups = staged.groups.filter((item) => item.name !== group.name); staged.groups.push({ name: group.name, proxyId: savedId, proxyMode: group.proxy_mode ?? 'default' }); }
    const markers = new Map(affected.map((profile) => [profile.id, this.effectiveProxy(profile, remote.groups, staged).proxy?.protocol === 'anytls']));
    const applied = [], appliedGroups = [];
    try {
      for (const profile of users) { await this.request('PUT', `/api/profiles/${encoded(profile.id)}`, { proxy: config.protocol === 'anytls' ? null : upstreamProxy(config), managed_proxy_required: markers.get(profile.id) }); applied.push(profile); }
      for (const profile of affected.filter((item) => !users.includes(item) && markers.get(item.id))) { await this.request('PUT', `/api/profiles/${encoded(profile.id)}`, { managed_proxy_required: true }); applied.push(profile); }
      for (const group of groups) { await this.applyGroupProxy(group.name, config, group.proxy_mode); appliedGroups.push(group); }
      for (const profile of affected.filter((item) => !users.includes(item) && !markers.get(item.id))) { await this.request('PUT', `/api/profiles/${encoded(profile.id)}`, { managed_proxy_required: false }); applied.push(profile); }
      await this.store.transaction((next) => {
        next.proxies = next.proxies.filter((item) => item.id !== savedId);
        next.proxies.push({ id: savedId, ...config });
        for (const profile of users) {
          let metadata = next.profiles.find((item) => item.id === profile.id);
          if (!metadata) { metadata = this.metadata({}, profile.id); next.profiles.push(metadata); }
          metadata.proxyId = savedId;
        }
        next.groups = next.groups ?? [];
        for (const group of groups) { next.groups = next.groups.filter((item) => item.name !== group.name); next.groups.push({ name: group.name, proxyId: savedId, proxyMode: group.proxy_mode ?? 'default' }); }
        event(next, 'proxy', `保存网络出口「${config.name}」`);
      });
    } catch (value) {
      const failures = [];
      for (const profile of applied) { try { await this.request('PUT', `/api/profiles/${encoded(profile.id)}`, { proxy: profile.proxy ?? null, managed_proxy_required: !!profile.managed_proxy_required }); } catch { failures.push(profile.id); } }
      for (const group of appliedGroups) { try { const oldRemote = remote.groups.find((item) => item.name === group.name); if (oldRemote?.proxy) await this.applyGroupProxy(group.name, oldRemote.proxy, oldRemote.proxy_mode); else await this.request('DELETE', `/api/groups/${encodeURIComponent(group.name)}/proxy`); } catch { failures.push(`分组 ${group.name}`); } }
      if (failures.length) value.message += `；以下绑定恢复未完成：${failures.join(', ')}`;
      throw value;
    }
    if (existing) await this.releaseProxy(existing);
    if (locationPreviewToken) this.locationPreviews.delete(locationPreviewToken);
    for (const profile of affected) this.workspaceContexts.delete(profile.id);
  }
  async deleteProxy({ id: proxyId }) {
    const [workspace, remote] = await Promise.all([this.store.read(), this.remote()]);
    const proxy = this.proxies(workspace, remote).find((item) => item.id === proxyId);
    if (!proxy) throw error('网络出口不存在。');
    if (remote.profiles.some(profile => proxyMatchesBinding(proxy, workspace.profiles.find(item => item.id === profile.id)?.proxyId, profile.proxy)) || this.groups(workspace, remote.groups).some(group => proxyMatchesBinding(proxy, group.proxy?.id, group.proxy))) throw error('请先解除环境和分组对该代理的引用。', 'PROXY_IN_USE');
    await this.store.transaction((next) => { next.proxies = next.proxies.filter((item) => item.id !== proxyId); event(next, 'proxy', `删除网络出口「${proxy.name}」`); });
    await this.releaseProxy(proxy);
  }
  async prepareProxy(proxy, { requireManagedRoute = false } = {}) {
    if (!proxy && requireManagedRoute) throw error('托管网络出口绑定缺失，请先选择代理节点。', 'MANAGED_PROXY_BINDING_MISSING');
    if (!proxy) return { wire: null, managed: false };
    assertHttpProxyUsername(proxy.protocol ?? proxy.type, proxy.username);
    if (!usesManagedProxy(proxy) && !requireManagedRoute) return { wire: { ...proxyConfig(proxy), region: browseForgeRegionFor(proxy) ?? '' }, managed: false };
    if (!this.options.proxyCore?.ensure) throw error('内置代理网络内核尚未就绪。', 'PROXY_CORE_UNAVAILABLE');
    let candidate;
    try { candidate = await this.options.proxyCore.ensure({ ...proxyConfig(proxy), id: identifier(proxy.id) }); }
    catch (value) {
      this.invalidateManagedProxy(proxy.id);
      let message = String(value?.message ?? '未知错误');
      for (const secret of [proxy.password, proxy.username]) if (secret) message = message.split(secret).join('[redacted]');
      throw error(`代理网络内核启动失败：${message}`, value?.code ?? 'PROXY_CORE_FAILED');
    }
    const wire = proxyConfig(candidate);
    if (wire.protocol !== 'http' || wire.host !== '127.0.0.1' || !wire.username || !wire.password) throw error('内置代理网络入口无效，已阻止直接连接。', 'INVALID_PROXY_CORE');
    wire.region = browseForgeRegionFor(proxy) ?? '';
    if (this.closed) { await this.options.proxyCore.release?.(proxy.id); throw error('应用正在退出。', 'APP_CLOSING'); }
    this.proxyWires.set(proxy.id, wire);
    return { wire, managed: true };
  }
  invalidateManagedProxy(proxyId) {
    identifier(proxyId);
    this.managedProxyRevisions.set(proxyId, (this.managedProxyRevisions.get(proxyId) ?? 0) + 1);
    const wire = this.proxyWires.get(proxyId);
    if (wire) this.networkProbe.invalidate(wire);
    this.proxyWires.delete(proxyId);
    for (const context of this.workspaceContexts.values()) if (context.managedProxyId === proxyId) {
      context.timezone = null; context.timezoneSource = null;
      context.geolocation = null; context.locale = null;
      context.networkLastError = '代理网络内核已停止，请重试以恢复连接。';
      context.network = { ok: false, scope: 'egress', ip: null, timezone: null, errorCode: 'PROXY_CORE_STOPPED', message: context.networkLastError, checkedAt: now() };
    }
    this.changed();
  }
  async releaseProxy(proxy) {
    if (proxy.protocol !== 'anytls') this.networkProbe.invalidate(proxy);
    const wire = this.proxyWires.get(proxy.id);
    if (wire) this.networkProbe.invalidate(wire);
    this.proxyWires.delete(proxy.id);
    await this.options.proxyCore?.release?.(proxy.id);
  }
  async checkProxy({ id: proxyId, proxy: draft } = {}, afterProbe) {
    const prepare = async () => {
      if (this.closed) throw error('应用正在退出。', 'APP_CLOSING');
      let proxy;
      if (draft != null) { if (proxyId != null) throw error('请选择已保存代理或草稿，不能同时提供。'); proxy = { ...proxyConfig(draft), id: `draft_${randomUUID()}` }; }
      else { const [workspace, remote] = await Promise.all([this.store.read(), this.remote()]); proxy = this.proxies(workspace, remote).find((item) => item.id === proxyId); if (!proxy) throw error('网络出口不存在。', 'PROXY_NOT_FOUND'); }
      const revision = this.managedProxyRevisions.get(proxy.id) ?? 0;
      try { return { proxy, revision, ...(await this.prepareProxy(proxy)) }; }
      catch (value) { if (draft != null && usesManagedProxy(proxy)) await this.releaseProxy(proxy); throw value; }
    };
    const { proxy, wire, revision, managed } = draft == null ? await this.serialize(prepare) : await prepare();
    try {
      const result = await this.networkProbe.probe(wire, { force: true });
      if (managed && revision !== (this.managedProxyRevisions.get(proxy.id) ?? 0)) throw error('代理网络内核在检测期间中断，请重试。', 'PROXY_CORE_STOPPED');
      // Main-only callback keeps optional map context on the exact verified
      // wire until the owned draft is released. IPC cannot supply this callback.
      if (afterProbe) await afterProbe(result, wire);
      if (managed && revision !== (this.managedProxyRevisions.get(proxy.id) ?? 0)) throw error('代理网络内核在检测期间中断，请重试。', 'PROXY_CORE_STOPPED');
      if (draft == null) this.changed();
      return result;
    } finally { if (draft != null && managed) await this.releaseProxy(proxy); }
  }
  async previewProxyNetwork({ proxy, language = 'en' }) {
    await this.ready;
    const config = proxyConfig(proxy);
    let referenceLocation = null;
    const network = await this.checkProxy({ proxy: config }, async (network, wire) => {
      if (recommendNetworkLocation(network)?.latitude != null) try {
        referenceLocation = await this.addressGeocoder.reverse({ coordinates: network.geolocation, proxy: wire, language, routeKey: rawProxyFingerprint(config) });
      } catch { /* Nearby map context is optional; the measured egress stays intact. */ }
    });
    const locationRecommendation = recommendNetworkLocation(network);
    if (this.closed) throw error('应用正在退出。', 'APP_CLOSING');
    let locationPreviewToken = null;
    if (locationRecommendation) {
      for (const [token, preview] of this.locationPreviews) if (preview.expiresAt <= Date.now()) this.locationPreviews.delete(token);
      if (this.locationPreviews.size >= 128) this.locationPreviews.delete(this.locationPreviews.keys().next().value);
      locationPreviewToken = randomUUID();
      this.locationPreviews.set(locationPreviewToken, { fingerprint: rawProxyFingerprint(config), network: structuredClone(network), referenceLocation: structuredClone(referenceLocation), expiresAt: Date.now() + 15 * 60 * 1000 });
    }
    return { network, locationRecommendation, referenceLocation, locationPreviewToken };
  }
  async searchNetworkAddress({ proxy, locationPreviewToken, query, language }) {
    await this.ready;
    if (this.closed) throw error('应用正在退出。', 'APP_CLOSING');
    const config = proxyConfig(proxy);
    const preview = this.locationPreviews.get(locationPreviewToken);
    if (!preview || preview.expiresAt <= Date.now() || preview.fingerprint !== rawProxyFingerprint(config)) throw error('请先检测当前代理，再查询地址。', 'ADDRESS_NETWORK_NOT_VERIFIED');
    addressQuery(query);
    const draft = { ...config, id: `draft_${randomUUID()}` };
    const revision = this.managedProxyRevisions.get(draft.id) ?? 0;
    try {
      const { wire, managed } = await this.prepareProxy(draft);
      const result = await this.addressGeocoder.search({ query, language, proxy: wire, routeKey: rawProxyFingerprint(config), bias: preview.network.geolocation });
      if (managed && revision !== (this.managedProxyRevisions.get(draft.id) ?? 0)) throw error('代理网络内核在地址查询期间中断，请重试。', 'PROXY_CORE_STOPPED');
      return result;
    } finally { if (usesManagedProxy(draft)) await this.releaseProxy(draft); }
  }
  contextSignature(profile, effective) { return `${profile.id}:${JSON.stringify(profile.launch_overrides ?? {})}:${JSON.stringify({ timezone: profileGeoField(profile, 'timezone'), locale: profileGeoField(profile, 'locale') })}:${rawProxyFingerprint(effective.proxy)}:${JSON.stringify(effective.proxy?.location ?? null)}`; }
  /** Main-process only: this returns proxy credentials and is deliberately absent from call()/IPC. */
  async resolveWorkspaceContext(profileId, { remote: providedRemote, force = false, requireManagedRoute = false } = {}) {
    await this.ready;
    if (this.closed) throw error('应用正在退出。', 'APP_CLOSING');
    const remote = providedRemote ?? await this.remote(), profile = this.find(remote, profileId);
    const workspace = await this.store.read();
    const effective = this.effectiveProxy(profile, remote.groups, workspace);
    if (effective.proxy && !effective.proxy.id) {
      const listed = this.proxies(workspace, remote).find((proxy) => sameProxy(proxy, effective.proxy));
      if (listed) effective.proxy = { ...effective.proxy, id: listed.id, protocol: listed.protocol };
    }
    if (profile.managed_proxy_required && effective.proxy?.protocol !== 'anytls') throw error('托管网络出口绑定缺失，请重新选择 AnyTLS 节点后再启动。', 'MANAGED_PROXY_BINDING_MISSING');
    if (effective.proxy?.protocol === 'anytls' && !profile.managed_proxy_required) { await this.request('PUT', `/api/profiles/${encoded(profileId)}`, { managed_proxy_required: true }); profile.managed_proxy_required = true; }
    const revision = this.managedProxyRevisions.get(effective.proxy?.id) ?? 0;
    const { wire, managed } = await this.prepareProxy(effective.proxy, { requireManagedRoute });
    const signature = this.contextSignature(profile, effective);
    const selectedLocation = effective.proxy?.location?.confirmed === true ? normalizeNetworkLocation(effective.proxy.location) : null;
    const confirmedTimezone = selectedLocation?.timezone ?? selectedLocation?.egressTimezone ?? null;
    const fixedTimezone = confirmedTimezone ? null : manualTimezone(profileGeoField(profile, 'timezone'));
    let resolvedTimezone, timezoneSource, networkLastError = null;
    const network = await this.networkProbe.probe(wire, { force: force || !!selectedLocation });
    if (managed && revision !== (this.managedProxyRevisions.get(effective.proxy.id) ?? 0)) throw error('代理网络内核在检测期间中断，请重试。', 'PROXY_CORE_STOPPED');
    if (selectedLocation) {
      try { assertNetworkLocationMatchesEgress(selectedLocation, network); }
      catch (value) {
        this.workspaceContexts.set(profileId, { signature, managedProxyId: managed ? effective.proxy.id : null, timezone: null, timezoneSource: null, selectedLocation, geolocation: null, network, networkLastError: value.message });
        this.changed();
        throw value;
      }
    }
    if (confirmedTimezone) { resolvedTimezone = confirmedTimezone; timezoneSource = 'proxy-egress'; }
    else if (fixedTimezone) { resolvedTimezone = fixedTimezone; timezoneSource = 'manual'; }
    else if (network.ok) { resolvedTimezone = network.timezone; timezoneSource = effective.proxy ? 'proxy' : 'direct'; }
    else {
      networkLastError = network.message;
      if (effective.proxy) { this.workspaceContexts.set(profileId, { signature, managedProxyId: managed ? effective.proxy.id : null, timezone: null, timezoneSource: null, network, networkLastError }); this.changed(); throw error(`自动时区匹配失败：${network.message} 可保留或选择手动时区后重试。`, 'AUTO_TIMEZONE_FAILED'); }
      resolvedTimezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
      timezoneSource = 'local';
    }
    if (!network.ok) networkLastError = network.message;
    // A confirmed text-only address remains a label: never silently use the IP
    // centre as though that address was geocoded. The actual probe stays intact.
    const geolocation = network.ok ? selectedLocation ? networkLocationGeolocation(selectedLocation) : network.geolocation ?? null : null;
    const fixedLocale = profileGeoField(profile, 'locale');
    const locale = configured(fixedLocale) ? fixedLocale : network.ok ? localeForCountry(network.countryCode) : null;
    const metadata = workspace.profiles.find(item => item.id === profileId) ?? {};
    const privacy = normalizePrivacy(metadata.privacy);
    const udp = ['anytls', 'socks5'].includes(effective.proxy?.protocol) && effective.proxy.udp !== false;
    const applicationRoute = managed ? { ...wire, protocol: 'socks5', udp, udpPolicy: udp ? 'proxy' : 'block' } : null;
    const ownedRoute = managed ? this.options.proxyCore?.routingIdentity?.(effective.proxy.id) : null;
    if (requireManagedRoute && !ownedRoute) throw error('内置代理网络身份无效，已阻止启动软件。', 'INVALID_PROXY_CORE');
    const managedRoute = ownedRoute ? { ...ownedRoute, profileId } : null;
    const timezoneOrigin = confirmedTimezone ? 'network-environment' : null;
    this.workspaceContexts.set(profileId, { signature, managedProxyId: managed ? effective.proxy.id : null, timezone: resolvedTimezone, timezoneSource, timezoneOrigin, locale, geolocation, selectedLocation, locationSource: selectedLocation?.source ?? network.locationSource ?? null, privacy, network, networkLastError });
    this.changed();
    return { id: profileId, profileId, name: profile.name, timezone: resolvedTimezone, timezoneSource, timezoneOrigin, locale, geolocation, selectedLocation, locationSource: selectedLocation?.source ?? network.locationSource ?? null, privacy, network, networkLastError,
      proxy: wire, proxyEndpoint: applicationRoute, applicationRoute, managedRoute, proxyId: effective.proxy?.id ?? null, proxyName: typeof effective.proxy?.name === 'string' ? effective.proxy.name.slice(0, 100) : null, managedProxy: managed, proxySource: effective.source, proxyMode: effective.mode };
  }
  async stoppedGroup(name) { const remote = await this.remote(); for (const profile of remote.profiles.filter((item) => item.group === name)) await this.assertStopped(remote, profile.id); }
  async applyGroupProxy(name, proxy, proxyMode = 'default') {
    if ((proxy.protocol ?? proxy.type) === 'anytls') return this.request('DELETE', `/api/groups/${encodeURIComponent(name)}/proxy`);
    return this.request('PUT', `/api/groups/${encodeURIComponent(name)}`, { proxy_mode: proxyMode, proxy: upstreamProxy({ ...proxy, ...proxyConfig(proxy) }) });
  }
  async saveGroup({ name, proxyId, proxyMode = 'default' }) {
    name = text(name, '分组名称');
    if (!['default', 'enforced'].includes(proxyMode)) throw error('分组代理策略无效。');
    const [workspace, remote] = await Promise.all([this.store.read(), this.remote()]);
    const proxy = this.proxies(workspace, remote).find((item) => item.id === proxyId);
    if (!proxy) throw error('请选择分组代理。');
    if (proxy.protocol === 'https') throw error('BrowseForge 的分组代理仅支持 HTTP、SOCKS5 或托管 AnyTLS，请使用环境专属 HTTPS 代理。', 'UNSUPPORTED_GROUP_PROXY');
    const members = remote.profiles.filter((item) => item.group === name);
    for (const profile of members) { await this.assertStopped(remote, profile.id); if (profile.runtime_id === 'browseforge-chromium' && !browseForgeRegionFor(proxy)) throw error('BrowseForge Chromium 需要有效的地区预设。请先检测并确认网络出口位置，或在高级设置中填写支持的地区代码。', 'INVALID_PROXY_REGION'); }
    const staged = { ...workspace, groups: [...(workspace.groups ?? []).filter((item) => item.name !== name), { name, proxyId, proxyMode }] };
    const markers = new Map(members.map((profile) => [profile.id, this.effectiveProxy(profile, remote.groups, staged).proxy?.protocol === 'anytls']));
    const previous = remote.groups.find((item) => item.name === name), applied = [];
    let result, groupApplied = false;
    try {
      // Mark new managed routes before clearing their old native group policy.
      for (const profile of members.filter((item) => markers.get(item.id))) { await this.request('PUT', `/api/profiles/${encoded(profile.id)}`, { managed_proxy_required: true }); applied.push(profile); }
      result = unwrap(await this.applyGroupProxy(name, proxy, proxyMode)); groupApplied = true;
      for (const profile of members.filter((item) => !markers.get(item.id))) { await this.request('PUT', `/api/profiles/${encoded(profile.id)}`, { managed_proxy_required: false }); applied.push(profile); }
      await this.store.transaction((next) => { next.groups = staged.groups; });
    } catch (value) {
      const failures = [];
      if (groupApplied) { try { if (previous?.proxy) await this.applyGroupProxy(name, previous.proxy, previous.proxy_mode); else await this.request('DELETE', `/api/groups/${encodeURIComponent(name)}/proxy`); } catch { failures.push('分组策略'); } }
      for (const profile of applied) { try { await this.request('PUT', `/api/profiles/${encoded(profile.id)}`, { managed_proxy_required: !!profile.managed_proxy_required }); } catch { failures.push(profile.id); } }
      if (failures.length) value.message += `；以下配置恢复未完成：${failures.join(', ')}`;
      throw value;
    }
    return { restartRequired: !!result?.restart_required };
  }
  async removeGroup({ name }, deleting) {
    name = text(name, '分组名称');
    const [workspace, remote] = await Promise.all([this.store.read(), this.remote()]);
    const members = remote.profiles.filter((item) => item.group === name);
    for (const profile of members) await this.assertStopped(remote, profile.id);
    const staged = { ...workspace, groups: (workspace.groups ?? []).filter((item) => item.name !== name) };
    const groups = remote.groups.filter((item) => item.name !== name);
    const markers = new Map(members.map((profile) => [profile.id, this.effectiveProxy({ ...profile, ...(deleting ? { group: '' } : {}) }, groups, staged).proxy?.protocol === 'anytls']));
    const previous = remote.groups.find((item) => item.name === name), applied = [];
    let groupApplied = false;
    try {
      for (const profile of members.filter((item) => markers.get(item.id))) { await this.request('PUT', `/api/profiles/${encoded(profile.id)}`, { managed_proxy_required: true }); applied.push(profile); }
      await this.request('DELETE', `/api/groups/${encodeURIComponent(name)}${deleting ? '' : '/proxy'}`); groupApplied = true;
      for (const profile of members.filter((item) => !markers.get(item.id))) { await this.request('PUT', `/api/profiles/${encoded(profile.id)}`, { managed_proxy_required: false }); applied.push(profile); }
      await this.store.transaction((next) => { next.groups = staged.groups; });
    } catch (value) {
      const failures = [];
      if (groupApplied) { try { if (previous?.proxy) await this.applyGroupProxy(name, previous.proxy, previous.proxy_mode); } catch { failures.push('分组策略'); } }
      const rollback = deleting ? members : applied;
      for (const profile of rollback) { try { await this.request('PUT', `/api/profiles/${encoded(profile.id)}`, { ...(deleting ? { group: name } : {}), managed_proxy_required: !!profile.managed_proxy_required }); } catch { failures.push(profile.id); } }
      if (failures.length) value.message += `；以下配置恢复未完成：${failures.join(', ')}`;
      throw value;
    }
  }
  async deleteGroup(args) { return this.removeGroup(args, true); }
  async clearGroupProxy(args) { return this.removeGroup(args, false); }
  async bulkProfiles({ action, ids, group }) {
    if (!Array.isArray(ids) || ids.length === 0 || ids.length > 500 || new Set(ids).size !== ids.length) throw error('请选择 1 至 500 个不同环境。');
    ids.forEach(identifier);
    if (!['start', 'stop', 'delete', 'clear', 'move'].includes(action)) throw error('不支持的批量操作。');
    const results = new Array(ids.length); let next = 0;
    const worker = async () => {
      while (next < ids.length) {
        const index = next++, profileId = ids[index];
        try {
          if (action === 'move') await this.serializeMutation(() => this.updateProfile({ id: profileId, profile: { group } }));
          else if (['start', 'stop'].includes(action)) await this.profileSerialize(profileId, () => this[`${action}Profile`]({ id: profileId }));
          else await this.serializeMutation(() => this[`${action}Profile`]({ id: profileId }));
          results[index] = { id: profileId, ok: true };
        } catch (value) { results[index] = { id: profileId, ok: false, code: value.code, message: value.message }; }
      }
    };
    await Promise.all(Array.from({ length: Math.min(3, ids.length) }, worker));
    return { results };
  }
  async saveSettings({ settings }) {
    object(settings, '设置');
    if (settings.closeBrowsersOnExit === false) throw error('当前版本退出会关闭托管会话。');
    if (Object.keys(settings).some((key) => !['closeBrowsersOnExit', 'language', 'appearance'].includes(key))) throw error('不支持的设置。');
    if (settings.language != null && !isInterfaceLanguage(settings.language)) throw error('界面语言无效。');
    if (Object.hasOwn(settings, 'appearance') && !isAppearancePreference(settings.appearance)) throw error('无法保存外观，请重试。');
    await this.store.transaction((next) => { next.settings.closeBrowsersOnExit = true; if (settings.language != null) next.settings.language = settings.language; if (settings.appearance != null) next.settings.appearance = settings.appearance; });
  }
  async installEngine({ id: engineId, engine, runtimeId }) {
    const selected = runtimeId ?? engineId ?? engine;
    if (!this.options.installEngine) throw error('本机内核安装服务尚未就绪。', 'ENGINE_INSTALL_UNAVAILABLE');
    await this.serialize(async () => {
      if (this.closed) throw error('应用正在退出。', 'APP_CLOSING');
      if (this.installingEngine || this.starting.size) throw error('请等待内核安装或浏览器启动完成。', 'ENGINE_INSTALL_BUSY');
      const remote = await this.remote();
      if (!remote.descriptors.some((item) => item.id === selected && item.platform_supported)) throw error('当前平台不支持所选内核。', 'UNSUPPORTED_ENGINE');
      for (const session of remote.sessions) { if ((await this.health(session)).alive !== false) throw error('安装内核会重启本地服务，请先停止所有浏览器会话。', 'PROFILE_RUNNING'); await this.request('DELETE', `/api/sessions/${encoded(session.session_id)}`); }
      this.installingEngine = selected;
    });
    this.pendingInstall = Promise.resolve().then(() => this.options.installEngine(selected));
    try { return await this.pendingInstall; } finally { this.pendingInstall = null; this.installingEngine = null; this.changed(); }
  }
  async exportProfiles({ id: profileId } = {}) {
    const snapshot = await this.snapshot(); const selected = profileId ? [snapshot.profiles.find((item) => item.id === profileId)] : snapshot.profiles;
    if (selected.some((item) => !item)) throw error('环境不存在。');
    const proxyIds = new Set(selected.map((profile) => profile.proxyId).filter(Boolean));
    return { schema: 'envara.profiles', version: 2, profiles: selected.map((profile) => ({ ...Object.fromEntries([...PROFILE_KEYS].map((key) => [key, profile[key]])), fingerprint: fingerprintConfig(profile.fingerprint) })), proxies: snapshot.proxies.filter((proxy) => proxyIds.has(proxy.id)).map(({ id, name, protocol, host, port, region, username, password, serverName, skipCertVerify, clientFingerprint, alpn, udp }) => ({ id, name, protocol, host, port, region, ...(protocol === 'anytls' ? { serverName, skipCertVerify, clientFingerprint, alpn, udp } : {}), requiresCredentials: !!(username || password) })), notice: '包含完整指纹配置与代理引用；不包含登录凭据、Cookie 或浏览资料。导入时需要明确代理映射。' };
  }
  async importProfiles({ document, profiles, proxyMap = {} }) {
    const rows = document?.profiles ?? profiles;
    if (!Array.isArray(rows) || !rows.length || rows.length > 500) throw error('导入文件须包含 1 至 500 个环境。');
    const [workspace, remote] = await Promise.all([this.store.read(), this.remote()]);
    const candidates = rows.map((row) => {
      const config = Object.fromEntries(Object.entries(object(row, '导入环境')).filter(([key]) => PROFILE_KEYS.has(key)));
      if (!Object.hasOwn(config, 'deviceProfileId')) config.deviceProfileId = PROVIDER_DEFAULT_DEVICE_PROFILE_ID;
      if (row.proxyId) { const mapped = proxyMap[row.proxyId]; if (!mapped) throw error(`环境「${row.name}」的代理尚未映射，导入已取消。`, 'PROXY_MAPPING_REQUIRED'); config.proxyId = mapped; }
      else if (Object.hasOwn(row, 'proxy') && row.proxy) throw error('原始代理配置需要先建立明确映射。', 'PROXY_MAPPING_REQUIRED');
      if (Object.keys(row).some((key) => !PROFILE_KEYS.has(key) && !['id', 'createdAt', 'updatedAt', 'lastLaunchedAt'].includes(key))) throw error('导入配置包含不支持的字段。');
      const descriptor = remote.descriptors.find((item) => item.id === (config.engine ?? remote.defaultEngine));
      return { payload: { ...this.normalize(config, descriptor, workspace, remote, null, { preserveIdentity: true }), identity_mode: 'preserve' }, metadata: this.metadata(config, null) };
    });
    const created = [];
    try {
      for (const candidate of candidates) { const profile = unwrap(await this.request('POST', '/api/profiles', candidate.payload)); created.push({ profile, metadata: { ...candidate.metadata, id: profile.id } }); }
      await this.store.transaction((next) => { next.profiles.push(...created.map((item) => item.metadata)); event(next, 'profile', `导入 ${created.length} 个环境配置`); });
    } catch (value) { const failures = []; for (const item of created) { try { await this.request('DELETE', `/api/profiles/${encoded(item.profile.id)}`); } catch { failures.push(item.profile.id); } } if (failures.length) value.message += `；以下新环境回滚未完成：${failures.join(', ')}`; throw value; }
    return { importedCount: created.length, createdIds: created.map((item) => item.profile.id) };
  }
  async legacy() {
    let workspace; try { workspace = JSON.parse(await readFile(path.join(this.dataDir, 'workspace.json'), 'utf8')); } catch (value) { if (value.code === 'ENOENT') return null; throw value; }
    if (workspace.schema !== 'envara.workspace' || workspace.version !== 1 || !Array.isArray(workspace.profiles) || !Array.isArray(workspace.proxies)) throw error('旧工作区格式无法识别，原文件已保留。');
    return workspace;
  }
  async previewLegacyMigration() { const workspace = await this.legacy(); const migrated = (await this.store.read()).profiles.map((item) => item.legacyId).filter(Boolean); return { detected: !!workspace, profiles: workspace?.profiles.map((profile) => ({ id: profile.id, name: profile.name, engine: profile.engine, migrated: migrated.includes(profile.id), hasProxy: !!profile.proxyId })) ?? [], proxyCount: workspace?.proxies.length ?? 0, originalDataDir: this.dataDir, destinationDir: this.profilesDir, notice: '迁移会备份并复制旧配置与选定浏览资料，旧文件保留。代理绑定和凭据会在本机保留。' }; }
  async migrateLegacy({ ids, copyBrowserData = true } = {}) {
    if (typeof copyBrowserData !== 'boolean' || (ids != null && (!Array.isArray(ids) || !ids.length || ids.some((profileId) => typeof profileId !== 'string')))) throw error('迁移选项格式无效。');
    if (!this.options.assertLegacyStopped || !await this.options.assertLegacyStopped()) throw error('必须先确认旧版本的所有浏览器会话已停止，才能复制资料。', 'LEGACY_SESSIONS_NOT_CONFIRMED_STOPPED');
    const legacy = await this.legacy(); if (!legacy) throw error('没有发现旧工作区。');
    const existing = await this.store.read(); const migrated = new Set(existing.profiles.map((item) => item.legacyId).filter(Boolean));
    const selected = legacy.profiles.filter((profile) => (!ids || ids.includes(profile.id)) && !migrated.has(profile.id));
    if (!selected.length) throw error('没有需要迁移的环境。');
    const remote = await this.remote(); const descriptor = remote.descriptors.find((item) => item.id === 'cloakbrowser');
    const importedProxies = legacy.proxies.map((proxy) => ({ ...proxyConfig(proxy), name: text(proxy.name, '旧代理名称'), id: randomUUID(), legacyId: proxy.id }));
    const stagedWorkspace = { ...existing, proxies: [...existing.proxies, ...importedProxies] };
    const candidates = selected.map((profile) => { if (!/^[0-9a-f-]{36}$/i.test(profile.id)) throw error('旧环境 ID 无效，迁移取消。'); const proxyId = profile.proxyId ? importedProxies.find((proxy) => proxy.legacyId === profile.proxyId)?.id : null; if (profile.proxyId && !proxyId) throw error('旧代理绑定缺失，不能改为直接连接。', 'PROXY_MAPPING_REQUIRED'); const config = Object.fromEntries([...PROFILE_KEYS].filter((key) => Object.hasOwn(profile, key)).map((key) => [key, profile[key]])); config.proxyId = proxyId; config.deviceProfileId ??= PROVIDER_DEFAULT_DEVICE_PROFILE_ID; return { old: profile, payload: { ...this.normalize(config, descriptor, stagedWorkspace, remote, null, { preserveIdentity: true }), identity_mode: 'preserve' }, metadata: this.metadata(config, null) }; });
    const backupDir = path.join(this.dataDir, 'migration-backups', `${Date.now()}-${randomUUID()}`);
    await mkdir(backupDir, { recursive: true, mode: 0o700 });
    await cp(path.join(this.dataDir, 'workspace.json'), path.join(backupDir, 'workspace.json'), { errorOnExist: true, force: false });
    for (const candidate of candidates) {
      const source = path.join(this.dataDir, 'profiles', candidate.old.id);
      let info;
      try { info = await lstat(source); } catch (value) { if (value.code === 'ENOENT') continue; throw value; }
      if (!info.isDirectory()) throw error('旧资料目录不是普通目录。');
      await cp(source, path.join(backupDir, 'profiles', candidate.old.id), { recursive: true, force: false, errorOnExist: true });
    }
    const created = [];
    try {
      for (const candidate of candidates) {
        const profile = unwrap(await this.request('POST', '/api/profiles', candidate.payload)); created.push({ profile, metadata: { ...candidate.metadata, id: profile.id, legacyId: candidate.old.id, migrationBackup: backupDir, createdAt: candidate.old.createdAt, lastLaunchedAt: candidate.old.lastLaunchedAt } });
        if (copyBrowserData) {
          const source = path.join(backupDir, 'profiles', candidate.old.id);
          let exists = true;
          try { await access(source); } catch (value) { if (value.code === 'ENOENT') exists = false; else throw value; }
          if (exists) await cp(source, path.join(await this.checkedDirectory(profile), 'browser-data'), { recursive: true, force: false, errorOnExist: true, filter: (entry) => !['SingletonLock', 'SingletonSocket', 'SingletonCookie', 'DevToolsActivePort'].includes(path.basename(entry)) });
        }
      }
      await writeFile(path.join(backupDir, 'migration-result.json'), JSON.stringify({ completedAt: now(), profiles: created.map((item) => ({ legacyId: item.metadata.legacyId, newId: item.profile.id })), copyBrowserData }, null, 2), { mode: 0o600 });
      await this.store.transaction((next) => { next.proxies.push(...importedProxies); next.profiles.push(...created.map((item) => item.metadata)); event(next, 'migration', `复制迁移 ${created.length} 个旧环境，原资料与备份均保留`); });
    } catch (value) { const failures = []; for (const item of created) { try { await this.request('DELETE', `/api/profiles/${encoded(item.profile.id)}`); } catch { failures.push(item.profile.id); } } value.message += `；原资料未修改，备份位于 ${backupDir}${failures.length ? `；新环境回滚未完成：${failures.join(', ')}` : ''}`; throw value; }
    return { migratedCount: created.length, backupDir, createdIds: created.map((item) => item.profile.id) };
  }
  async shutdown() { await this.ready; this.closed = true; this.locationPreviews.clear(); this.networkProbe.close?.(); this.addressGeocoder.close?.(); await this.options.cancelInstall?.(); await Promise.allSettled([this.queue, ...this.profileQueues.values(), ...(this.pendingInstall ? [this.pendingInstall] : [])]); try { if (this.options.shutdown) await this.options.shutdown(); else await this.request('POST', '/api/shutdown'); } finally { await this.options.proxyCore?.close?.(); this.proxyWires.clear(); } }
}

export default BrowseForgeService;
