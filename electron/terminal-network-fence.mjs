// macOS process-tree network fence for an Envara terminal with a network route.
// Proxy variables alone let a tool that ignores them leave through the host
// network, and CFNetwork tools follow the macOS system proxy instead. Inside
// this Seatbelt profile those connections fail at connect(): only loopback,
// which includes the environment's authenticated route, stays reachable. Loopback
// ports of host proxy clients and local DNS are refused and the DNS-SD resolver
// is unavailable, so external names resolve only at the bridge's remote end.
// Seatbelt network filters accept only "*" or "localhost" as the host, so a
// remote HTTP(S) upstream cannot be allowlisted; callers fence loopback routes.
import { execFile } from 'node:child_process';
import { lstat } from 'node:fs/promises';
import { promisify } from 'node:util';
import path from 'node:path';

export const TERMINAL_FENCE_EXECUTABLE = '/usr/bin/sandbox-exec';
// Default local listeners of common proxy clients (Clash/mihomo and Clash Verge,
// Shadowsocks/V2RayU, v2rayN, Surge, v2rayA) and local DNS forwarders. A tool
// configured to use one of them would otherwise leave through that client.
export const KNOWN_LOCAL_PROXY_PORTS = Object.freeze([53, 853, 1053, 1080, 1081, 1086, 1087, 5353, 6152, 6153,
  7890, 7891, 7892, 7893, 7895, 7897, 7898, 7899, 10808, 10809, 20170, 20171, 20172]);
// DNS-SD client endpoints from Apple's dnssd_ipc.h and mDNSResponder.sb; the
// Notion launch profile denies the same set.
const DNSSD_SOCKETS = Object.freeze(['/private/var/run/mDNSResponder', '/var/run/mDNSResponder', '/private/var/tmp/mDNSResponder', '/var/tmp/mDNSResponder']);
const fail = message => Object.assign(new Error(message), { code: 'TERMINAL_NETWORK_FENCE_UNAVAILABLE' });
const deviceRestrictionFailure = () => Object.assign(new Error('设备标识读取限制不可用，未启动终端。'), { code: 'TERMINAL_DEVICE_IDENTIFIERS_UNAVAILABLE' });
const sshProtectionFailure = () => Object.assign(new Error('SSH 私钥读取保护不可用，未启动终端。'), { code: 'TERMINAL_SSH_PROTECTION_UNAVAILABLE' });
const validPort = value => { const number = Number(value); return Number.isInteger(number) && number >= 1 && number <= 65535 ? number : null; };
const loopback = host => ['localhost', '::1', '[::1]'].includes(host) || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);

/** Loopback proxy ports the host has configured, from `scutil --proxy` output. */
export function systemProxyPorts(text) {
  if (typeof text !== 'string') throw new TypeError('System proxy settings must be text.');
  const fields = new Map();
  for (const line of text.split('\n')) {
    const match = /^\s*([A-Za-z]+)\s*:\s*(.*?)\s*$/.exec(line);
    if (match) fields.set(match[1], match[2]);
  }
  const ports = new Set();
  for (const kind of ['HTTP', 'HTTPS', 'SOCKS', 'FTP', 'RTSP', 'Gopher']) {
    const host = fields.get(`${kind}Proxy`)?.toLowerCase(), port = validPort(fields.get(`${kind}Port`));
    if (host && port && loopback(host)) ports.add(port);
  }
  // A local PAC server could name any proxy; refusing it leaves CFNetwork with
  // its direct fallback, which the fence already refuses.
  try {
    const pac = new URL(fields.get('ProxyAutoConfigURLString'));
    const port = validPort(pac.port || (pac.protocol === 'https:' ? 443 : 80));
    if (port && loopback(pac.hostname.toLowerCase())) ports.add(port);
  } catch {}
  return ports;
}

/** Loopback proxy ports named by this app's own inherited proxy variables. */
export function environmentProxyPorts(environment = {}) {
  const ports = new Set();
  for (const [key, value] of Object.entries(environment ?? {})) {
    if (!/^(?:https?|all|ftp|rsync|socks)_proxy$/i.test(key) || typeof value !== 'string' || !value.trim()) continue;
    try {
      const url = new URL(/^[a-z][a-z\d+.-]*:\/\//i.test(value) ? value : `http://${value}`);
      const port = validPort(url.port || ({ 'http:': 80, 'https:': 443 }[url.protocol] ?? 1080));
      if (port && loopback(url.hostname.toLowerCase())) ports.add(port);
    } catch {}
  }
  return ports;
}

function sshProtectionRules(value) {
  if (value == null) return [];
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw sshProtectionFailure();
  const checkedPath = name => {
    if (typeof name !== 'string' || !path.isAbsolute(name) || path.normalize(name) !== name || name === '/'
      || name.length > 4096 || /[\x00-\x1f\x7f]/.test(name)) throw sshProtectionFailure();
    return name;
  };
  const paths = field => {
    const items = value[field] ?? [];
    if (!Array.isArray(items) || items.length > 256) throw sshProtectionFailure();
    return [...new Set(items.map(checkedPath))];
  };
  const protectedPaths = paths('protectedPaths'), readablePaths = paths('readablePaths');
  const readOnlyPaths = paths('readOnlyPaths'), deniedAgentSockets = paths('deniedAgentSockets');
  const agentRoot = checkedPath(value.agentRoot);
  const agentSocket = value.agentSocket == null ? null : checkedPath(value.agentSocket);
  const allowedSockets = [...new Set([...paths('allowedSockets'), ...(agentSocket ? [agentSocket] : [])])];
  const inside = filename => filename.startsWith(`${agentRoot}/`);
  if (!protectedPaths.includes(agentRoot) || readablePaths.some(filename => !inside(filename))
      || allowedSockets.length > 32 || allowedSockets.some(filename => !inside(filename) || deniedAgentSockets.includes(filename))) throw sshProtectionFailure();
  const filter = (kind, filename) => `(${kind} ${JSON.stringify(filename)})`;
  const rules = [
    `(deny file-read* file-write* ${protectedPaths.map(filename => filter('subpath', filename)).join(' ')})`,
    `(deny network-outbound (remote unix-socket ${filter('subpath', agentRoot)})${deniedAgentSockets.map(filename => ` (remote unix-socket ${filter('literal', filename)})`).join(' ')})`,
  ];
  // Only public session configuration is readable. The store, key files and
  // other sessions' agents remain inaccessible to this process tree.
  const traversalPaths = new Set();
  for (const filename of [...readablePaths, ...allowedSockets]) {
    for (let parent = path.dirname(filename); parent === agentRoot || inside(parent); parent = path.dirname(parent)) traversalPaths.add(parent);
  }
  // The helper verifies every ancestor with lstat before opening its public
  // target file. Permit metadata for those exact directories, not listing or
  // reading their contents or another session's files.
  if (traversalPaths.size) rules.push(`(allow file-read-metadata ${[...traversalPaths].map(filename => filter('literal', filename)).join(' ')})`);
  if (readablePaths.length) rules.push(`(allow file-read* ${readablePaths.map(filename => filter('subpath', filename)).join(' ')})`);
  if (readOnlyPaths.length) {
    rules.push(`(deny file-write* ${readOnlyPaths.map(filename => filter('subpath', filename)).join(' ')})`);
    // A trusted runtime cannot be replaced by renaming one of its ancestors.
    // Literal ancestor rules leave sibling projects and their contents writable.
    const ancestors = new Set();
    for (const filename of readOnlyPaths) {
      for (let parent = path.dirname(filename); ; parent = path.dirname(parent)) {
        ancestors.add(parent);
        if (path.dirname(parent) === parent) break;
      }
    }
    rules.push(`(deny file-write* ${[...ancestors].map(filename => filter('literal', filename)).join(' ')})`);
  }
  for (const socket of allowedSockets) {
    rules.push(`(allow file-read* file-write-data ${filter('literal', socket)})`,
      `(allow network-outbound (remote unix-socket ${filter('literal', socket)}))`);
  }
  return rules;
}

export function terminalFenceProfile({ deniedLoopbackPorts = [], restrictDeviceIdentifiers = false, sshProtection = null } = {}) {
  if (typeof restrictDeviceIdentifiers !== 'boolean') throw deviceRestrictionFailure();
  const denied = [...new Set([...KNOWN_LOCAL_PROXY_PORTS, ...deniedLoopbackPorts].map(validPort).filter(Boolean))].sort((a, b) => a - b);
  // Later Seatbelt rules take precedence, so each refusal follows its allowance.
  return ['(version 1)', '(allow default)',
    '(deny network-outbound)',
    '(allow network-outbound (remote unix-socket))',
    '(allow network-outbound (remote ip "localhost:*"))',
    `(deny network-outbound ${denied.map(port => `(remote ip "localhost:${port}")`).join(' ')})`,
    '(deny mach-lookup (global-name "com.apple.dnssd.service"))',
    `(deny file-read* file-write* ${DNSSD_SOCKETS.map(socket => `(literal "${socket}")`).join(' ')})`,
    `(deny network-outbound ${DNSSD_SOCKETS.map(socket => `(remote unix-socket (literal "${socket}"))`).join(' ')})`,
    // Restrict the named reads, including batch/recursive IOKit queries. These
    // rules do not return simulated values or replace the machine's hardware.
    ...(restrictDeviceIdentifiers ? [
      '(deny iokit-get-properties (iokit-property "IOPlatformSerialNumber" "IOPlatformUUID"))',
      '(deny syscall-unix (syscall-number SYS_gethostuuid))',
      '(deny sysctl-read (sysctl-name "kern.uuid"))',
    ] : []),
    ...sshProtectionRules(sshProtection),
  ].join('\n');
}

export class TerminalNetworkFence {
  constructor({ platform = process.platform, execute = promisify(execFile), inspect = lstat, environment = process.env } = {}) {
    this.platform = platform; this.execute = execute; this.inspect = inspect; this.environment = environment;
  }
  /** Wraps a shell launch; refuses rather than starting an unfenced shell. */
  async wrap(shell, { routePort, restrictDeviceIdentifiers = false, sshProtection = null } = {}) {
    if (typeof restrictDeviceIdentifiers !== 'boolean') throw deviceRestrictionFailure();
    if (this.platform !== 'darwin') throw fail('此系统没有终端网络围栏，未启动终端。');
    const allowed = validPort(routePort);
    if (!allowed || !shell?.executable || !Array.isArray(shell.args)) throw fail('终端网络通道无效，未启动终端。');
    let info;
    try { info = await this.inspect(TERMINAL_FENCE_EXECUTABLE); } catch { throw fail('系统网络围栏组件不可用，未启动终端。'); }
    if (!info.isFile() || info.isSymbolicLink() || info.uid !== 0 || (info.mode & 0o022)) throw fail('系统网络围栏组件不可信，未启动终端。');
    let text;
    try { ({ stdout: text } = await this.execute('/usr/sbin/scutil', ['--proxy'], { timeout: 5000, maxBuffer: 65536, env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin' } })); }
    catch { throw fail('无法读取系统代理设置，未启动终端。'); }
    const denied = new Set([...KNOWN_LOCAL_PROXY_PORTS, ...systemProxyPorts(text), ...environmentProxyPorts(this.environment)]);
    if (denied.has(allowed)) throw fail('终端网络通道与本机代理端口冲突，未启动终端。');
    const profile = terminalFenceProfile({ deniedLoopbackPorts: [...denied], restrictDeviceIdentifiers, sshProtection });
    if (restrictDeviceIdentifiers || sshProtection != null) {
      // Validate this OS's interpreter before returning launch authority. This
      // disposable child is separate from the shell; the shell gets one fence.
      try {
        await this.execute(TERMINAL_FENCE_EXECUTABLE, ['-p', profile, '/usr/bin/true'], {
          timeout: 5000, maxBuffer: 4096, env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', LC_ALL: 'C' },
        });
      } catch { throw sshProtection != null ? sshProtectionFailure() : deviceRestrictionFailure(); }
    }
    return { executable: TERMINAL_FENCE_EXECUTABLE, args: ['-p', profile, shell.executable, ...shell.args],
      environment: shell.environment, deniedLoopbackPorts: [...denied].sort((a, b) => a - b), deviceIdentifierRestrictions: restrictDeviceIdentifiers,
      ...(sshProtection != null ? { sshPrivateKeyProtection: true } : {}) };
  }
}
