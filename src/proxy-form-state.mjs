import { httpProxyUsernameError } from '../shared/proxy-auth.mjs';

export const proxyFields = ['id', 'name', 'protocol', 'host', 'port', 'username', 'password', 'region', 'serverName', 'skipCertVerify', 'clientFingerprint', 'alpn', 'udp'];

function alpnEntries(value) {
  if (value == null || value === '') return [];
  if (Array.isArray(value)) return [...value];
  if (typeof value === 'string') return value.split(',').map(item => item.trim()).filter(Boolean);
  return null;
}

export function initialProxyForm(proxy = {}) {
  return {
    name: '', protocol: 'http', host: '', port: '', username: '', password: '', region: '',
    serverName: '', skipCertVerify: false, clientFingerprint: 'chrome', alpn: [], udp: true,
    ...Object.fromEntries(Object.entries(proxy || {}).filter(([key]) => proxyFields.includes(key))),
  };
}

export function proxyConfig(proxy) {
  const host = String(proxy.host || '').trim();
  const config = {
    ...(proxy.id ? { id: proxy.id } : {}),
    name: String(proxy.name || '').trim(),
    protocol: proxy.protocol,
    host,
    port: Number(proxy.port),
    password: proxy.password || '',
    region: String(proxy.region || '').trim(),
  };
  return proxy.protocol === 'anytls'
    ? { ...config, serverName: String(proxy.serverName || '').trim() || host, skipCertVerify: proxy.skipCertVerify === true, clientFingerprint: proxy.clientFingerprint ?? 'chrome', alpn: alpnEntries(proxy.alpn), udp: proxy.udp !== false }
    : { ...config, username: proxy.username || '' };
}

export function proxyFormError(proxy) {
  if (!String(proxy.host || '').trim() || !Number.isInteger(Number(proxy.port)) || Number(proxy.port) < 1 || Number(proxy.port) > 65535) {
    return '请先填写服务器地址和有效端口。';
  }
  const usernameError = httpProxyUsernameError(proxy.protocol, proxy.username);
  if (usernameError) return usernameError;
  if (proxy.protocol === 'anytls' && !proxy.password) return '请填写 AnyTLS 节点密码。';
  if (proxy.protocol === 'anytls') {
    const alpn = alpnEntries(proxy.alpn);
    if (!alpn || alpn.length > 8 || alpn.some(value => typeof value !== 'string' || !/^[\x21-\x7e]{1,64}$/.test(value))) {
      return 'ALPN 最多 8 项，每项需为 1–64 个无空格 ASCII 字符，请用英文逗号分隔。';
    }
  }
  return '';
}
