import path from 'node:path';
import { constants } from 'node:fs';
import { chmod, lstat, mkdir, open, readFile, realpath, rename, rm, writeFile } from 'node:fs/promises';
import { randomBytes, randomUUID } from 'node:crypto';
import { execFile, spawn as spawnChild } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { validateSshProxyUrl, validateSshTarget } from './terminal-ssh-proxy.mjs';
import { describeSshSession, SSH_SESSION_SCHEMA, SSH_SESSION_VERSION } from './terminal-ssh-command.mjs';
import { createPasswordSshBroker } from './terminal-ssh-broker.mjs';
import { createSshDirectTransport } from './terminal-ssh-direct.mjs';
import { parseSshPublicKey as publicKey } from './terminal-ssh-key.mjs';
import { normalizeSshRoute, sameSshRoute } from './terminal-ssh-route.mjs';
import { openSshRouteSocket } from './terminal-ssh-route-socket.mjs';
import { probeSshHostKey } from './terminal-ssh-host-key-probe.mjs';

const STORE_SCHEMA = 'envara.terminal-ssh';
const MAX_STORE_BYTES = 1024 * 1024;
const MAX_PUBLIC_BYTES = 16 * 1024;
const MAX_CONNECTIONS = 20;
const MAX_TOTAL_CONNECTIONS = 128;
const TOKEN_TTL = 30 * 60 * 1000;
const PRIVATE_MODE = 0o600;
const fail = (code, message) => Object.assign(new Error(message), { code });
const invalid = () => fail('SSH_INVALID_INPUT', 'SSH 连接信息无效。');
const unsafe = () => fail('SSH_UNSAFE_PATH', 'SSH 文件路径、所有者或权限不符合保护要求。');
const storageInvalid = () => fail('SSH_STORAGE_INVALID', 'SSH 连接配置无法安全读取。');
const identityChanged = () => fail('SSH_IDENTITY_CHANGED', '选定密钥或已信任的服务器身份已改变，请重新选择并核对。');
const uid = () => process.getuid?.();
const id = value => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{1,96}$/.test(value)) throw invalid();
  return value;
};
const connectionId = value => {
  if (typeof value !== 'string' || !/^ssh_[a-f0-9]{32}$/.test(value)) throw invalid();
  return value;
};
const label = value => {
  if (typeof value !== 'string' || !value.trim() || value.trim().length > 80 || /[\x00-\x1f\x7f]/.test(value)) throw invalid();
  return value.trim();
};
const nameKey = value => value.normalize('NFKC').toLocaleLowerCase('en-US');
const absolute = value => {
  if (typeof value !== 'string' || !path.isAbsolute(value) || path.resolve(value) !== value || /[\x00-\x1f\x7f]/.test(value)) throw unsafe();
  return value;
};
const target = ({ host, port, user }) => {
  let checked;
  try { checked = validateSshTarget(host, port); } catch { throw invalid(); }
  if (typeof user !== 'string' || !/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(user)) throw invalid();
  return { ...checked, user };
};
const keyIdentity = info => ({ dev: info.dev, ino: info.ino, size: info.size, mtimeMs: info.mtimeMs, ctimeMs: info.ctimeMs });
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const endpoint = ({ host, port }) => port === 22 ? host : `[${host}]:${port}`;
const authType = record => record.authType ?? 'publickey';
const trustSource = record => record.trustSource ?? 'host-known-hosts';
const routeActive = context => { try { return context.isActive() === true; } catch { return false; } };
const passwordBytes = value => {
  if (typeof value !== 'string' || !value.length || Buffer.byteLength(value) > 1024 || /[\x00\r\n]/.test(value)) throw fail('SSH_PASSWORD_INVALID', '请输入有效的 SSH 密码。');
  return Buffer.from(value, 'utf8');
};
const publicConnection = (value, passwordReady = false) => ({ id: value.id, name: value.name, alias: value.alias, host: value.host, port: value.port,
  user: value.user, authType: authType(value), passwordReady, route: normalizeSshRoute(value.route, { legacy: true }), trustSource: trustSource(value),
  ...(authType(value) === 'publickey' ? { keyLabel: value.keyLabel, keyFingerprint: value.keyFingerprint } : {}),
  hostFingerprints: [...value.hostFingerprints] });
const shellQuote = value => `'${value.replaceAll("'", "'\\''")}'`;
const configQuote = value => `"${value.replaceAll('\\', '\\\\').replaceAll('"', '\\"')}"`;
const runtimeRoot = filename => {
  const components = filename.split(path.sep);
  const bundle = components.findIndex((component, index) => component.endsWith('.app') && components[index + 1] === 'Contents');
  return bundle >= 0 ? components.slice(0, bundle + 1).join(path.sep) : path.dirname(filename);
};
const moduleCodeRoot = runtimeRoot(fileURLToPath(import.meta.url));

function nativeExecute(command, args, options) {
  return new Promise((resolve, reject) => {
    const child = execFile(command, args, options, (error, stdout, stderr) => error ? reject(error) : resolve({ stdout, stderr }));
    // No inherited terminal or passphrase stream is supplied to ssh-add.
    child.stdin?.end();
  });
}

/** Check every component, including the leaf. Never follow a caller's link. */
async function checkedPath(filename) {
  absolute(filename);
  let current = path.parse(filename).root;
  const parts = filename.slice(current.length).split(path.sep).filter(Boolean);
  let info = await lstat(current);
  for (const part of parts) {
    current = path.join(current, part);
    info = await lstat(current);
    if (info.isSymbolicLink()) throw unsafe();
    if (current !== filename && !info.isDirectory()) throw unsafe();
  }
  if (await realpath(filename) !== filename) throw unsafe();
  return info;
}

async function checkedDirectory(directory, { privateMode = false } = {}) {
  const info = await checkedPath(directory);
  if (!info.isDirectory() || uid() !== undefined && info.uid !== uid() || info.mode & 0o022
    || privateMode && (info.mode & 0o777) !== 0o700) throw unsafe();
  return info;
}

async function privateDirectory(parent, name) {
  await checkedDirectory(parent);
  const directory = path.join(parent, name);
  try { await mkdir(directory, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
  await checkedDirectory(directory, { privateMode: true });
  return directory;
}

async function checkedPrivateKey(filename) {
  const info = await checkedPath(filename);
  if (!info.isFile() || info.nlink !== 1 || uid() !== undefined && info.uid !== uid()
    || (info.mode & 0o777) !== PRIVATE_MODE || info.size < 1 || info.size > MAX_STORE_BYTES) throw unsafe();
  return keyIdentity(info);
}

/** Only public material and the private metadata store use this reader. */
async function safeRead(filename, limit, { privateMode = false } = {}) {
  const info = await checkedPath(filename);
  if (!info.isFile() || info.nlink !== 1 || uid() !== undefined && info.uid !== uid() || info.size > limit
    || info.mode & 0o022 || privateMode && (info.mode & 0o777) !== PRIVATE_MODE) throw unsafe();
  const handle = await open(filename, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const before = await handle.stat();
    if (!same(keyIdentity(before), keyIdentity(info))) throw unsafe();
    const buffer = Buffer.alloc(limit + 1);
    let length = 0;
    while (length < buffer.length) {
      const { bytesRead } = await handle.read(buffer, length, buffer.length - length, null);
      if (!bytesRead) break;
      length += bytesRead;
    }
    if (length > limit || length !== before.size || !same(keyIdentity(before), keyIdentity(await handle.stat()))) throw unsafe();
    return buffer.toString('utf8', 0, length);
  } finally { await handle.close(); }
}


function trustedHostKeys(output) {
  const result = new Map();
  for (const line of String(output).split('\n')) {
    const value = line.trim();
    if (!value || value.startsWith('#')) continue;
    const fields = value.split(/\s+/);
    // Revocation and CA entries are not silently converted into plain trust.
    if (fields[0].startsWith('@')) throw fail('SSH_HOST_UNTRUSTED', '此服务器需要普通的已确认主机密钥，不能自动采用证书或撤销记录。');
    if (fields.length < 3) throw fail('SSH_HOST_UNTRUSTED', '服务器主机密钥记录无效。');
    let key;
    try { key = publicKey(`${fields[1]} ${fields[2]}`); } catch { throw fail('SSH_HOST_UNTRUSTED', '服务器主机密钥记录不受支持。'); }
    result.set(key.fingerprint, key.text);
  }
  if (!result.size) throw fail('SSH_HOST_UNTRUSTED', '宿主已知主机记录中没有此地址和端口的可信密钥；请先确认服务器身份。');
  return [...result].sort(([a], [b]) => a.localeCompare(b)).map(([fingerprint, text]) => ({ fingerprint, text }));
}

function launchScript(config, manifest, passwordBroker, { adHocConfigPath, configuredConnections, childEnvironment } = {}) {
  return `import { runSshCommand } from './terminal-ssh-command.mjs';
// This manifest and configuration are fixed when the session starts. Discovery
// and expiry never read caller-controlled environment overrides or renew keys.
const manifest = ${JSON.stringify(manifest)};
process.exitCode = await runSshCommand({ argv: process.argv.slice(3), entry: process.argv[2], manifest, configPath: ${JSON.stringify(config)}${passwordBroker ? `, passwordBroker: ${JSON.stringify(passwordBroker)}` : ''}${adHocConfigPath ? `, adHocConfigPath: ${JSON.stringify(adHocConfigPath)}` : ''}, configuredConnections: ${JSON.stringify(configuredConnections ?? [])}, childEnvironment: { ...${JSON.stringify(childEnvironment)}, proxyUrl: process.env.ENVARA_SSH_PROXY_URL } });
`;
}

function configuration(records, files, nodeExecutable) {
  return records.map(record => [
    `Host ${record.alias}`, `  HostName ${record.host}`, `  Port ${record.port}`, `  User ${record.user}`,
    `  HostKeyAlias ${record.alias}`,
    ...(authType(record) === 'password' ? ['  IdentityFile none', '  IdentityAgent none', '  IdentitiesOnly yes']
      : [`  IdentityFile ${configQuote(files.publicKeys.get(record.id))}`, `  IdentityAgent ${configQuote(files.socket)}`, '  IdentitiesOnly yes']),
    `  UserKnownHostsFile ${configQuote(files.knownHosts)}`, '  GlobalKnownHostsFile /dev/null',
    '  StrictHostKeyChecking yes', '  VerifyHostKeyDNS no', '  UpdateHostKeys no',
    ...(authType(record) === 'password'
      ? ['  PreferredAuthentications password', '  PubkeyAuthentication no', '  PasswordAuthentication yes', '  KbdInteractiveAuthentication no', '  BatchMode no', '  NumberOfPasswordPrompts 1']
      : ['  PreferredAuthentications publickey', '  PasswordAuthentication no', '  KbdInteractiveAuthentication no', '  BatchMode yes', '  NumberOfPasswordPrompts 0']),
    '  ConnectTimeout 15', '  ConnectionAttempts 1',
    '  AddKeysToAgent no', '  UseKeychain no', '  PKCS11Provider none',
    '  ForwardAgent no', '  ForwardX11 no', '  ClearAllForwardings yes',
    '  ControlMaster no', '  ControlPath none', '  ControlPersist no', '  CanonicalizeHostname no',
    '  PermitLocalCommand no', '  EnableEscapeCommandline no', '  EscapeChar none',
    '  ServerAliveInterval 30', '  ServerAliveCountMax 3',
    `  ProxyCommand ${shellQuote(nodeExecutable).replaceAll('%', '%%')} ${shellQuote(files.direct).replaceAll('%', '%%')} --alias ${record.alias}`, '',
  ].join('\n')).join('\n');
}

function adHocConfiguration(files, nodeExecutable, knownHosts) {
  const proxy = `${shellQuote(nodeExecutable).replaceAll('%', '%%')} ${shellQuote(files.proxy).replaceAll('%', '%%')} --host '%h' --port '%p' --environment-targets`;
  return ['Host *', `  UserKnownHostsFile ${configQuote(knownHosts)}`, '  GlobalKnownHostsFile /dev/null',
    '  StrictHostKeyChecking ask', '  VerifyHostKeyDNS no', '  UpdateHostKeys no',
    '  IdentityFile none', '  IdentityAgent none', '  IdentitiesOnly yes', '  AddKeysToAgent no', '  UseKeychain no', '  PKCS11Provider none',
    '  ForwardAgent no', '  ForwardX11 no', '  ClearAllForwardings yes', '  ControlMaster no', '  ControlPath none', '  ControlPersist no',
    '  CanonicalizeHostname no', '  PermitLocalCommand no', '  EnableEscapeCommandline no', '  EscapeChar none',
    '  ConnectTimeout 15', '  ConnectionAttempts 1', '  ServerAliveInterval 30', '  ServerAliveCountMax 3', `  ProxyCommand ${proxy}`, ''].join('\n');
}

async function adHocTrustFile(directories) {
  // Older injected consumers may only provide home. Production passes the
  // main-created environment config directory; no renderer-selected path enters.
  if (directories?.config == null) return null;
  await checkedDirectory(absolute(directories.config), { privateMode: true });
  const filename = path.join(directories.config, 'ssh-known_hosts');
  let handle;
  try { handle = await open(filename, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), PRIVATE_MODE); }
  catch (error) { if (error.code !== 'EEXIST') throw error; }
  finally { await handle?.close(); }
  await safeRead(filename, MAX_STORE_BYTES, { privateMode: true });
  return filename;
}

/** Private-key references stay outside the exported profile tree. Only native
 * ssh-add reads private bytes, into an owned destination-constrained agent.
 * File modes and unpredictable sockets do not isolate hostile same-UID host
 * processes; new terminal fences protect the returned paths and sockets. */
export class TerminalSshManager {
  #passwordGrants = new Map();
  constructor({ dataDir, hostHome, nodeExecutable, platform = process.platform, execute = nativeExecute, spawn = spawnChild,
    now = Date.now, agentRoot = platform === 'darwin' ? `/private/tmp/envara-ssh-${uid() ?? 'unsupported'}`
      : path.join(dataDir ?? '', 'terminal', 'ssh-access-runtime'),
    createPasswordBroker = createPasswordSshBroker, createDirectTransport = createSshDirectTransport,
    resolveRoute = null, probeHost = probeSshHostKey } = {}) {
    this.dataDir = absolute(dataDir); this.hostHome = absolute(hostHome);
    this.nodeExecutable = nodeExecutable == null ? null : absolute(nodeExecutable);
    this.root = path.join(this.dataDir, 'terminal', 'ssh-access'); this.filename = path.join(this.root, 'connections.json');
    this.agentRoot = absolute(agentRoot); this.platform = platform; this.execute = execute; this.spawn = spawn; this.now = now;
    this.createPasswordBroker = createPasswordBroker;
    this.createDirectTransport = createDirectTransport;
    this.resolveRoute = resolveRoute; this.probeHost = probeHost; this.preparations = new Set(); this.retainedRoutes = new Set();
    this.profiles = new Map(); this.pending = new Map(); this.sessions = new Map(); this.queue = Promise.resolve();
    this.closed = false; this.supported = false; this.ready = this.initialize();
  }
  nativeEnvironment(home, socket) {
    return { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', HOME: home, LANG: 'C', LC_ALL: 'C',
      SSH_ASKPASS_REQUIRE: 'never', SSH_ASKPASS: '/usr/bin/false', ...(socket ? { SSH_AUTH_SOCK: socket } : {}) };
  }
  nativeOptions(home, socket) {
    return { env: this.nativeEnvironment(home, socket), timeout: 5000, maxBuffer: MAX_STORE_BYTES, encoding: 'utf8', windowsHide: true };
  }
  async initialize() {
    // Unsupported systems must keep their ordinary terminals working. The
    // macOS SSH feature must not impose POSIX file modes on a Windows store.
    if (this.platform !== 'darwin') return;
    await checkedDirectory(this.dataDir);
    const terminal = await privateDirectory(this.dataDir, 'terminal');
    await privateDirectory(terminal, 'ssh-access');
    try {
      const document = JSON.parse(await safeRead(this.filename, MAX_STORE_BYTES, { privateMode: true }));
      if (document?.schema !== STORE_SCHEMA || document.version !== 1 || !Array.isArray(document.profiles) || document.profiles.length > 512) throw storageInvalid();
      const connectionIds = new Set();
      for (const profile of document.profiles) {
        const profileId = id(profile?.id);
        if (this.profiles.has(profileId) || !Array.isArray(profile.connections) || profile.connections.length > MAX_CONNECTIONS) throw storageInvalid();
        const names = new Set(), ids = new Set(), aliases = new Set();
        const records = profile.connections.map(record => {
          const value = this.validateRecord(record);
          if (names.has(nameKey(value.name)) || ids.has(value.id) || aliases.has(value.alias) || connectionIds.has(value.id)) throw storageInvalid();
          connectionIds.add(value.id);
          names.add(nameKey(value.name)); ids.add(value.id); aliases.add(value.alias); return value;
        });
        this.profiles.set(profileId, records);
      }
      if ([...this.profiles.values()].reduce((sum, records) => sum + records.length, 0) > MAX_TOTAL_CONNECTIONS) throw storageInvalid();
    } catch (error) {
      if (error.code !== 'ENOENT') { this.profiles.clear(); throw storageInvalid(); }
    }
    if (this.platform === 'darwin') {
      try {
        const value = await this.execute('/usr/bin/ssh', ['-V'], this.nativeOptions(this.hostHome));
        const match = /OpenSSH_(\d+)\.(\d+)/.exec(`${value.stdout ?? ''} ${value.stderr ?? ''}`);
        this.supported = Boolean(match && (Number(match[1]) > 8 || Number(match[1]) === 8 && Number(match[2]) >= 9));
      } catch { this.supported = false; }
    }
  }
  validateRecord(record) {
    const checkedTarget = target(record ?? {}), authentication = authType(record ?? {});
    if (!['publickey', 'password'].includes(authentication)) throw storageInvalid();
    if (authentication === 'password') {
      const allowed = new Set(['id', 'name', 'alias', 'host', 'port', 'user', 'authType', 'hostKeys', 'hostFingerprints', 'route', 'trustSource']);
      if (Object.keys(record).some(key => !allowed.has(key))) throw storageInvalid();
    }
    const key = authentication === 'publickey' ? publicKey(record?.publicKey) : null;
    const value = { id: connectionId(record?.id), name: label(record?.name), alias: record?.alias, ...checkedTarget,
      authType: authentication, route: normalizeSshRoute(record.route, { legacy: true }), trustSource: trustSource(record),
      ...(key ? { keyPath: absolute(record?.keyPath), keyStat: record?.keyStat, publicKey: key.text,
        keyLabel: label(record?.keyLabel), keyFingerprint: key.fingerprint } : {}), hostKeys: record?.hostKeys };
    if (!['host-known-hosts', 'probe'].includes(value.trustSource)
      || value.route.kind === 'environment' && value.trustSource !== 'probe'
      || !/^envara-[a-f0-9]{12}$/.test(value.alias ?? '')
      || key && (!same(record.keyFingerprint, value.keyFingerprint) || !value.keyStat
        || Object.keys(value.keyStat).sort().join(',') !== 'ctimeMs,dev,ino,mtimeMs,size'
        || Object.values(value.keyStat).some(number => !Number.isFinite(number) || number < 0))
      || !Array.isArray(value.hostKeys) || !value.hostKeys.length || value.hostKeys.length > 32) throw storageInvalid();
    value.hostKeys = value.hostKeys.map(item => { const key = publicKey(item?.text); if (key.fingerprint !== item.fingerprint) throw storageInvalid(); return { fingerprint: key.fingerprint, text: key.text }; });
    value.hostKeys.sort((a, b) => a.fingerprint.localeCompare(b.fingerprint));
    value.hostFingerprints = value.hostKeys.map(item => item.fingerprint);
    if (new Set(value.hostFingerprints).size !== value.hostFingerprints.length || !same(record.hostFingerprints, value.hostFingerprints)) throw storageInvalid();
    return value;
  }
  assertOpen() { if (this.closed) throw fail('SSH_SESSION_CLOSED', 'SSH 通道已关闭，请重新打开境舱。'); }
  assertSupported() { this.assertOpen(); if (!this.supported) throw fail('SSH_UNSUPPORTED', '此系统未提供所需的受约束 OpenSSH 代理。'); }
  async list({ id: profileId }) {
    id(profileId); await this.ready;
    return { supported: this.supported, connections: (this.profiles.get(profileId) ?? [])
      .map(record => publicConnection(record, Boolean(this.passwordGrant(record.id)))) };
  }
  passwordGrant(selectedId) {
    return this.#passwordGrants.get(selectedId);
  }
  clearPassword(selectedId) {
    const grant = this.#passwordGrants.get(selectedId);
    if (grant) { grant.secret.fill(0); this.#passwordGrants.delete(selectedId); }
  }
  grantPassword(selectedId, secret) {
    this.clearPassword(selectedId);
    // This authorization exists only in this manager's memory. App shutdown or
    // explicit revocation erases it; elapsed time does not end a live session.
    const grant = { secret, expiresAt: null };
    this.#passwordGrants.set(selectedId, grant);
  }
  async readTrust(checkedTarget) {
    const filename = path.join(this.hostHome, '.ssh', 'known_hosts');
    let before;
    try { before = await safeRead(filename, MAX_STORE_BYTES); } catch { throw fail('SSH_HOST_UNTRUSTED', '无法读取此地址和端口的已有可信主机密钥。'); }
    let result;
    try { result = await this.execute('/usr/bin/ssh-keygen', ['-F', endpoint(checkedTarget), '-f', filename], this.nativeOptions(this.hostHome)); }
    catch { throw fail('SSH_HOST_UNTRUSTED', '宿主已知主机记录中没有此地址和端口的可信密钥；请先确认服务器身份。'); }
    try { if (before !== await safeRead(filename, MAX_STORE_BYTES)) throw identityChanged(); } catch { throw identityChanged(); }
    return trustedHostKeys(result.stdout);
  }
  async identity(keyPath) {
    keyPath = absolute(keyPath);
    let keyStat;
    try { keyStat = await checkedPrivateKey(keyPath); } catch (error) { if (error.code?.startsWith('SSH_')) throw error; throw unsafe(); }
    let publicText;
    try { publicText = await safeRead(`${keyPath}.pub`, MAX_PUBLIC_BYTES); }
    catch (error) { if (error.code === 'ENOENT') throw fail('SSH_PUBLIC_KEY_REQUIRED', '所选私钥需要同目录的 .pub 公钥文件。'); if (error.code?.startsWith('SSH_')) throw error; throw unsafe(); }
    const key = publicKey(publicText);
    try { if (!same(keyStat, await checkedPrivateKey(keyPath))) throw identityChanged(); } catch { throw identityChanged(); }
    const keyLabel = path.basename(keyPath).slice(0, 80);
    return { keyPath, keyStat, keyLabel: label(keyLabel), publicKey: key.text, keyFingerprint: key.fingerprint };
  }
  async routeContext(profileId, route, sessionId, signal) {
    this.assertOpen();
    let context;
    if (typeof this.resolveRoute === 'function') context = await this.resolveRoute({ ownerProfileId: profileId, route, sessionId, signal });
    else if (route.kind === 'host') context = { route, routeIdentity: 'host', isActive: () => !this.closed, dispose: async () => {} };
    else throw fail('SSH_ROUTE_UNAVAILABLE', 'SSH 所选网络不可用，未切换其他路线。');
    try {
      if (!context || !sameSshRoute(context.route, route) || typeof context.routeIdentity !== 'string'
        || !context.routeIdentity || context.routeIdentity.length > 256 || /[\x00-\x1f\x7f]/.test(context.routeIdentity)
        || typeof context.isActive !== 'function' || typeof context.dispose !== 'function') throw invalid();
      if (route.kind === 'environment') validateSshProxyUrl(context.proxyUrl);
      else if (context.proxyUrl != null) throw invalid();
      if (this.closed || signal?.aborted || !routeActive(context)) throw fail('SSH_ROUTE_CHANGED', 'SSH 所选网络已改变，请重新读取指纹或新建终端。');
      return context;
    } catch (error) {
      if (typeof context?.dispose === 'function') {
        try { await context.dispose(); } catch { this.retainedRoutes.add(context); throw fail('SSH_ROUTE_CLEANUP_FAILED', 'SSH 网络资源清理尚未确认。'); }
      }
      throw error.code === 'SSH_ROUTE_CHANGED' ? error : fail('SSH_ROUTE_UNAVAILABLE', 'SSH 所选网络不可用，未切换其他路线。');
    }
  }
  async releaseRoute(context) {
    try { await context.dispose(); this.retainedRoutes.delete(context); }
    catch { this.retainedRoutes.add(context); throw fail('SSH_ROUTE_CLEANUP_FAILED', 'SSH 网络资源清理尚未确认。'); }
  }
  async releasePreparation(operation) {
    if (operation.probeCleanup) { await operation.probeCleanup(); operation.probeCleanup = null; }
    if (operation.context) { await this.releaseRoute(operation.context); operation.context = null; }
    this.preparations.delete(operation);
  }
  async withRoute(profileId, route, prefix, callback, signal) {
    const controller = new AbortController();
    const abort = () => controller.abort();
    signal?.addEventListener('abort', abort, { once: true });
    if (signal?.aborted) abort();
    let finish;
    const operation = { controller, context: null, probeCleanup: null, finished: new Promise(resolve => { finish = resolve; }) };
    this.preparations.add(operation);
    let value, failure;
    try {
      operation.context = await this.routeContext(profileId, route, `${prefix}_${randomBytes(12).toString('hex')}`, controller.signal);
      value = await callback(operation.context, controller.signal);
    } catch (error) {
      failure = error;
      if (typeof error.sshCleanup === 'function') operation.probeCleanup = error.sshCleanup;
    } finally {
      if (!operation.probeCleanup) try { await this.releasePreparation(operation); }
      catch (error) { failure = error; }
      signal?.removeEventListener('abort', abort); finish();
    }
    if (failure) throw failure;
    return value;
  }
  async preparedTrust(profileId, checkedTarget, requestedRoute, signal) {
    if (requestedRoute === undefined) return { route: { kind: 'host' }, trustSource: 'host-known-hosts', hostKeys: await this.readTrust(checkedTarget) };
    const route = normalizeSshRoute(requestedRoute);
    return this.withRoute(profileId, route, 'sshprep', async (context, probeSignal) => {
      const parent = await checkedPath(path.dirname(this.agentRoot));
      if (!parent.isDirectory()) throw unsafe();
      try { await mkdir(this.agentRoot, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
      await checkedDirectory(this.agentRoot, { privateMode: true });
      const result = await this.probeHost({ target: checkedTarget, routeBinding: context.routeIdentity,
        isActive: () => !this.closed && routeActive(context), signal: probeSignal, nodeExecutable: this.nodeExecutable,
        root: this.agentRoot, hostHome: this.hostHome,
        connector: request => {
          if (!request || !same(validateSshTarget(request.host, request.port), validateSshTarget(checkedTarget.host, checkedTarget.port))
            || request.allowHalfOpen !== true) throw invalid();
          return openSshRouteSocket({ target: checkedTarget, routeContext: context, signal: request.signal ?? probeSignal });
        } });
      if (!result || result.routeBinding !== context.routeIdentity || result.unverified !== true
        || !Array.isArray(result.hostKeys) || !result.hostKeys.length || result.hostKeys.length > 32 || !routeActive(context))
        throw fail('SSH_HOST_PROBE_FAILED', '无法核验所选线路返回的主机指纹。');
      const hostKeys = result.hostKeys.map(value => {
        const key = publicKey(value?.text);
        if (key.fingerprint !== value.fingerprint) throw fail('SSH_HOST_PROBE_FAILED', '无法核验所选线路返回的主机指纹。');
        return { fingerprint: key.fingerprint, text: key.text };
      }).sort((a, b) => a.fingerprint.localeCompare(b.fingerprint));
      if (new Set(hostKeys.map(key => key.fingerprint)).size !== hostKeys.length) throw fail('SSH_HOST_PROBE_FAILED', '无法核验所选线路返回的主机指纹。');
      return { route, trustSource: 'probe', routeIdentity: context.routeIdentity, hostKeys };
    }, signal);
  }
  async prepareIdentity({ id: profileId, host, port, user, keyPath, route, signal }) {
    id(profileId); await this.ready; this.assertSupported();
    const checkedTarget = target({ host, port, user });
    const identity = await this.identity(keyPath), trust = await this.preparedTrust(profileId, checkedTarget, route, signal);
    const { hostKeys } = trust;
    this.assertOpen();
    for (const [token, item] of this.pending) if (item.expiresAt <= this.now()) this.pending.delete(token);
    if (this.pending.size >= 64) throw fail('SSH_CONNECTION_LIMIT', '待确认的 SSH 密钥过多，请稍后重试。');
    const selectionToken = `sshsel_${randomBytes(24).toString('hex')}`;
    const value = { profileId, ...checkedTarget, authType: 'publickey', ...identity, ...trust,
      hostFingerprints: hostKeys.map(item => item.fingerprint), expiresAt: this.now() + TOKEN_TTL };
    this.pending.set(selectionToken, value);
    return { selectionToken, ...checkedTarget, route: trust.route, trustSource: trust.trustSource,
      authType: 'publickey', keyLabel: identity.keyLabel, keyFingerprint: identity.keyFingerprint, hostFingerprints: [...value.hostFingerprints] };
  }
  async preparePassword({ id: profileId, host, port, user, route, signal }) {
    id(profileId); await this.ready; this.assertSupported();
    const checkedTarget = target({ host, port, user }), trust = await this.preparedTrust(profileId, checkedTarget, route, signal);
    const { hostKeys } = trust;
    this.assertOpen();
    for (const [token, item] of this.pending) if (item.expiresAt <= this.now()) this.pending.delete(token);
    if (this.pending.size >= 64) throw fail('SSH_CONNECTION_LIMIT', '待确认的 SSH 密钥过多，请稍后重试。');
    const selectionToken = `sshsel_${randomBytes(24).toString('hex')}`;
    const value = { profileId, ...checkedTarget, authType: 'password', ...trust,
      hostFingerprints: hostKeys.map(item => item.fingerprint), expiresAt: this.now() + TOKEN_TTL };
    this.pending.set(selectionToken, value);
    return { selectionToken, ...checkedTarget, route: trust.route, trustSource: trust.trustSource,
      authType: 'password', hostFingerprints: [...value.hostFingerprints] };
  }
  async revalidate(record, { trust = false } = {}) {
    if (authType(record) === 'publickey') {
      let current;
      try { current = await this.identity(record.keyPath); } catch { throw identityChanged(); }
      if (!same(current.keyStat, record.keyStat) || current.publicKey !== record.publicKey) throw identityChanged();
    }
    if (trust && trustSource(record) === 'host-known-hosts' && !same(await this.readTrust(record), record.hostKeys)) throw identityChanged();
  }
  mutate(operation) {
    const task = this.queue.then(async () => { await this.ready; this.assertOpen(); return operation(); });
    this.queue = task.catch(() => {}); return task;
  }
  async persist(profiles) {
    const source = JSON.stringify({ schema: STORE_SCHEMA, version: 1, profiles: [...profiles]
      .map(([id, connections]) => ({ id, connections: connections.map(record => this.validateRecord(record)) })) });
    if (Buffer.byteLength(source) > MAX_STORE_BYTES) throw storageInvalid();
    await checkedDirectory(this.root, { privateMode: true });
    try { await safeRead(this.filename, MAX_STORE_BYTES, { privateMode: true }); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    const temporary = path.join(this.root, `${randomUUID()}.tmp`);
    try {
      const handle = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
      try { await handle.writeFile(source); await handle.sync(); } finally { await handle.close(); }
      await rename(temporary, this.filename);
    } catch (error) {
      if (error.code?.startsWith('SSH_')) throw error;
      throw fail('SSH_STORAGE_UNAVAILABLE', 'SSH 连接配置未保存，请检查应用数据目录。');
    } finally { await rm(temporary, { force: true }); }
  }
  save({ id: profileId, name, selectionToken, password, hostKeyConfirmed }) {
    id(profileId); name = label(name);
    return this.mutate(async () => {
      this.assertSupported();
      if (hostKeyConfirmed !== true) throw fail('SSH_HOST_KEY_CONFIRMATION_REQUIRED', '请核对并确认主机指纹后再保存连接。');
      const selected = this.pending.get(selectionToken);
      if (!selected || selected.expiresAt <= this.now()) { this.pending.delete(selectionToken); throw fail('SSH_SELECTION_EXPIRED', '密钥选择已失效，请重新选择并核对。'); }
      if (selected.profileId !== profileId) throw fail('SSH_SELECTION_MISMATCH', '密钥选择不属于此境舱。');
      if (authType(selected) === 'password' && [...this.sessions.values()].some(session => session.profileId === profileId)) throw fail('SSH_CONNECTION_IN_USE', '请先结束使用此 SSH 连接的终端会话。');
      const previous = this.profiles.get(profileId) ?? [];
      if (previous.length >= MAX_CONNECTIONS) throw fail('SSH_CONNECTION_LIMIT', '一个境舱最多保存 20 个 SSH 连接。');
      if ([...this.profiles.values()].reduce((sum, records) => sum + records.length, 0) >= MAX_TOTAL_CONNECTIONS) throw fail('SSH_CONNECTION_LIMIT', '已保存的 SSH 连接数量达到上限。');
      if (previous.some(record => nameKey(record.name) === nameKey(name))) throw fail('SSH_NAME_EXISTS', '此境舱已存在同名 SSH 连接。');
      const retain = async () => {
        await this.revalidate(selected, { trust: true });
        let secret;
        if (authType(selected) === 'password') secret = passwordBytes(password);
        else if (password !== undefined) throw invalid();
        const uuid = randomUUID().replaceAll('-', '');
        const { profileId: ignored, expiresAt, routeIdentity: ignoredBinding, ...identity } = selected;
        const record = { id: `ssh_${uuid}`, name, alias: `envara-${uuid.slice(0, 12)}`, ...structuredClone(identity) };
        const next = new Map(this.profiles); next.set(profileId, [...previous, record]);
        try { await this.persist(next); } catch (error) { secret?.fill(0); throw error; }
        this.profiles = next; this.pending.delete(selectionToken);
        if (this.closed) { secret?.fill(0); this.assertOpen(); }
        if (secret) this.grantPassword(record.id, secret);
        return publicConnection(record, Boolean(secret));
      };
      if (trustSource(selected) !== 'probe') return retain();
      return this.withRoute(profileId, normalizeSshRoute(selected.route), 'sshsave', async context => {
        if (context.routeIdentity !== selected.routeIdentity || !routeActive(context))
          throw fail('SSH_ROUTE_CHANGED', 'SSH 所选网络已改变，请重新读取指纹并确认。');
        return retain();
      });
    });
  }
  setPassword({ id: profileId, connectionId: selectedId, password }) {
    id(profileId); connectionId(selectedId);
    return this.mutate(async () => {
      this.assertSupported();
      const record = (this.profiles.get(profileId) ?? []).find(record => record.id === selectedId);
      if (!record) throw fail('SSH_CONNECTION_NOT_FOUND', '此 SSH 连接已不存在。');
      if (authType(record) !== 'password') throw invalid();
      if ([...this.sessions.values()].some(session => session.profileId === profileId)) throw fail('SSH_CONNECTION_IN_USE', '请先结束使用此 SSH 连接的终端会话。');
      await this.revalidate(record, { trust: true });
      this.assertOpen();
      this.grantPassword(selectedId, passwordBytes(password));
      return publicConnection(record, true);
    });
  }
  remove({ id: profileId, connectionId: selectedId }) {
    id(profileId); connectionId(selectedId);
    return this.mutate(async () => {
      const previous = this.profiles.get(profileId) ?? [];
      const record = previous.find(record => record.id === selectedId);
      if (!record) throw fail('SSH_CONNECTION_NOT_FOUND', '此 SSH 连接已不存在。');
      if ([...this.sessions.values()].some(session => session.records.some(record => record.id === selectedId)
        || authType(record) === 'password' && session.profileId === profileId)) throw fail('SSH_CONNECTION_IN_USE', '请先结束使用此 SSH 连接的终端会话。');
      const next = new Map(this.profiles); next.set(profileId, previous.filter(record => record.id !== selectedId));
      await this.persist(next); this.profiles = next; this.clearPassword(selectedId); return { removed: true };
    });
  }
  removeProfile({ id: profileId }) {
    id(profileId);
    return this.mutate(async () => {
      if ([...this.sessions.values()].some(session => session.profileId === profileId)) throw fail('SSH_CONNECTION_IN_USE', '请先结束此境舱的终端会话。');
      const previousRecords = this.profiles.get(profileId) ?? [];
      const next = new Map(this.profiles); next.delete(profileId);
      if (this.profiles.has(profileId)) { await this.persist(next); this.profiles = next; }
      for (const record of previousRecords) this.clearPassword(record.id);
      for (const [token, selected] of this.pending) if (selected.profileId === profileId) this.pending.delete(token);
      return { removed: true };
    });
  }
  protection(records = [], nodeExecutable = this.nodeExecutable) {
    // A newly launched environment also protects keys selected for other
    // environments, including references outside the host's .ssh directory.
    const privateKeys = [...this.profiles.values()].flat().concat(records, [...this.pending.values()]).map(record => record.keyPath).filter(Boolean);
    const readOnlyPaths = this.platform === 'darwin' ? [...new Set([moduleCodeRoot,
      ...[this.nodeExecutable, nodeExecutable].filter(Boolean).map(filename => runtimeRoot(absolute(filename)))])] : [];
    return { protectedPaths: [...new Set([path.join(this.hostHome, '.ssh'), this.root, this.agentRoot, ...privateKeys])],
      readablePaths: [], readOnlyPaths, runtimeReadOnlyPaths: readOnlyPaths,
      agentSocket: null, allowedAgentSocket: null, agentRoot: this.agentRoot };
  }
  async createSession({ profileId, sessionId, directories, proxyUrl, nodeExecutable = this.nodeExecutable, signal } = {}) {
    id(profileId); id(sessionId); await this.ready; await this.queue; this.assertOpen();
    const allRecords = structuredClone(this.profiles.get(profileId) ?? []), base = this.protection(allRecords, nodeExecutable);
    // Unsupported platforms remain unaffected. Supported fenced sessions always
    // receive discovery/refusal shims, including when no connection was saved.
    if (!this.supported && !allRecords.length) return { ...base, environment: {}, binDirectory: null, dispose: async () => {} };
    this.assertSupported();
    if (this.sessions.has(sessionId)) throw fail('SSH_SESSION_EXISTS', 'SSH 终端会话标识已被使用。');
    try { validateSshProxyUrl(proxyUrl); } catch { throw fail('SSH_PROXY_REQUIRED', 'SSH 需要此会话的已认证境舱代理通道。'); }
    nodeExecutable = absolute(nodeExecutable);
    const nodeInfo = await checkedPath(nodeExecutable);
    if (!nodeInfo.isFile() || !(nodeInfo.mode & 0o111)) throw unsafe();
    if (directories?.home != null) absolute(directories.home);
    const grants = new Map(allRecords.filter(record => authType(record) === 'password')
      .map(record => [record.id, this.passwordGrant(record.id)]).filter(([, grant]) => grant));
    const candidates = allRecords.filter(record => authType(record) === 'publickey' || grants.has(record.id));
    let records = [], keyRecords = [], manifest;
    const passwords = new Map(), controller = new AbortController();
    const abort = () => controller.abort();
    signal?.addEventListener('abort', abort, { once: true });
    if (signal?.aborted) abort();
    let settleSetup;
    const lease = { profileId, sessionId, records, revoked: false, child: null, directory: null, directoryIdentity: null,
      publicDirectory: null, publicIdentity: null, binIdentity: null, processError: false, stopped: false, cleanup: null,
      passwords, passwordBroker: null, directTransport: null, routeContexts: new Map(), controller,
      detachSignal: () => signal?.removeEventListener('abort', abort),
      setup: new Promise(resolve => { settleSetup = resolve; }) };
    // Every new binding uses the current application lifetime. Null is an
    // explicit v2 authorization scope, not an extended numeric timeout.
    const check = () => { this.assertOpen(); if (lease.revoked || controller.signal.aborted) throw fail('SSH_SESSION_CLOSED', 'SSH 会话已取消。'); };
    // Object identity prevents a later grant from resurrecting a revoked lease.
    const passwordGrantsActive = () => [...grants].every(([selectedId, grant]) => this.passwordGrant(selectedId) === grant);
    const connectionActive = alias => {
      if (lease.revoked || this.closed || controller.signal.aborted) return false;
      const record = records.find(value => value.alias === alias);
      if (!record || !routeActive(lease.routeContexts.get(alias))) return false;
      if (authType(record) === 'password') return this.passwordGrant(record.id) === grants.get(record.id);
      return !!lease.child?.pid && !lease.processError && !lease.stopped && lease.child.exitCode == null && lease.child.signalCode == null;
    };
    const dispose = () => this.disposeSession(lease);
    this.sessions.set(sessionId, lease);
    let result, failure;
    try {
      for (const record of candidates) {
        check();
        let context;
        try { context = await this.routeContext(profileId, normalizeSshRoute(record.route, { legacy: true }), sessionId, controller.signal); }
        catch (error) {
          // An unavailable saved route stays in configuredConnections below,
          // so the shim refuses it rather than treating it as an unknown host.
          check();
          if (['SSH_ROUTE_UNAVAILABLE', 'SSH_ROUTE_UNCONFIGURED', 'SSH_ROUTE_CHANGED'].includes(error.code)) continue;
          throw error;
        }
        lease.routeContexts.set(record.alias, context); check(); records.push(record);
      }
      lease.records = records;
      keyRecords = records.filter(record => authType(record) === 'publickey');
      for (const record of records.filter(record => authType(record) === 'password')) passwords.set(record.alias, Buffer.from(grants.get(record.id).secret));
      manifest = { schema: SSH_SESSION_SCHEMA, version: SSH_SESSION_VERSION, expiresAt: null,
        connections: records.map(record => ({ id: record.id, name: record.name, alias: record.alias,
          host: record.host, port: record.port, user: record.user, route: normalizeSshRoute(record.route, { legacy: true }),
          authType: authType(record), expiresAt: null })) };
      describeSshSession(manifest, this.now());
      for (const record of records) { await this.revalidate(record, { trust: true }); check(); }
      // The stable parent is short enough for macOS Unix-domain socket paths.
      const parent = path.dirname(this.agentRoot);
      const parentInfo = await checkedPath(parent);
      if (!parentInfo.isDirectory()) throw unsafe();
      try { await mkdir(this.agentRoot, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
      await checkedDirectory(this.agentRoot, { privateMode: true }); check();
      lease.directory = await privateDirectory(this.agentRoot, randomUUID().replaceAll('-', ''));
      lease.directoryIdentity = keyIdentity(await lstat(lease.directory));
      lease.publicDirectory = await privateDirectory(lease.directory, 'public');
      lease.publicIdentity = keyIdentity(await lstat(lease.publicDirectory));
      const binDirectory = await privateDirectory(lease.publicDirectory, 'bin');
      lease.binIdentity = keyIdentity(await lstat(binDirectory));
      const socket = keyRecords.length ? path.join(lease.directory, 'agent.sock') : null;
      if (socket && Buffer.byteLength(socket) > 100) throw fail('SSH_UNSAFE_PATH', 'SSH 代理通道路径过长。');
      const files = { socket, knownHosts: path.join(lease.publicDirectory, 'known_hosts'),
        config: path.join(lease.publicDirectory, 'config'), targets: path.join(lease.publicDirectory, 'targets.json'),
        direct: path.join(lease.publicDirectory, 'terminal-ssh-direct.mjs'), adHocConfig: path.join(lease.publicDirectory, 'environment-ssh-config'),
        manifest: path.join(lease.publicDirectory, 'connections.json'), command: path.join(lease.publicDirectory, 'terminal-ssh-command.mjs'),
        proxy: path.join(lease.publicDirectory, 'terminal-ssh-proxy.mjs'), launcher: path.join(lease.publicDirectory, 'launch.mjs'), publicKeys: new Map() };
      for (const record of keyRecords) {
        const file = path.join(lease.publicDirectory, `${record.id}.pub`); files.publicKeys.set(record.id, file);
        await writeFile(file, `${record.publicKey}\n`, { mode: 0o400, flag: 'wx' }); check();
      }
      const hostKeys = records.flatMap(record => record.hostKeys.map(key => `${record.alias} ${key.text}`)).join('\n') + '\n';
      await writeFile(files.knownHosts, hostKeys, { mode: 0o400, flag: 'wx' });
      const targets = [...new Map(records.map(record => [`${record.host}:${record.port}`, { host: record.host, port: record.port }])).values()];
      await writeFile(files.targets, JSON.stringify(targets), { mode: 0o400, flag: 'wx' });
      await writeFile(files.proxy, await readFile(fileURLToPath(new URL('./terminal-ssh-proxy.mjs', import.meta.url))), { mode: 0o400, flag: 'wx' });
      await writeFile(files.direct, await readFile(fileURLToPath(new URL('./terminal-ssh-direct.mjs', import.meta.url))), { mode: 0o400, flag: 'wx' });
      await writeFile(files.command, await readFile(fileURLToPath(new URL('./terminal-ssh-command.mjs', import.meta.url))), { mode: 0o400, flag: 'wx' });
      await writeFile(path.join(lease.publicDirectory, 'terminal-ssh-route.mjs'), await readFile(fileURLToPath(new URL('./terminal-ssh-route.mjs', import.meta.url))), { mode: 0o400, flag: 'wx' });
      await writeFile(path.join(lease.publicDirectory, 'terminal-ssh-client.mjs'), await readFile(fileURLToPath(new URL('./terminal-ssh-client.mjs', import.meta.url))), { mode: 0o400, flag: 'wx' });
      await writeFile(files.manifest, JSON.stringify(manifest), { mode: 0o400, flag: 'wx' });
      await writeFile(files.config, configuration(records, files, nodeExecutable), { mode: 0o400, flag: 'wx' });
      const knownHosts = await adHocTrustFile(directories); check();
      const adHocConfigPath = knownHosts ? files.adHocConfig : null;
      if (adHocConfigPath) await writeFile(adHocConfigPath, adHocConfiguration(files, nodeExecutable, knownHosts), { mode: 0o400, flag: 'wx' });
      if (records.length) {
        try {
          lease.directTransport = await this.createDirectTransport({ directory: lease.directory,
            connections: records.map(record => ({ alias: record.alias, host: record.host, port: record.port })), isActive: connectionActive,
            openConnection: ({ alias, target: requested, signal: connectionSignal }) => {
              const record = records.find(value => value.alias === alias), context = lease.routeContexts.get(alias);
              if (!record || !connectionActive(alias) || !same(requested, validateSshTarget(record.host, record.port)))
                throw fail('SSH_ROUTE_UNAVAILABLE', 'SSH 所选网络不可用，未切换其他路线。');
              return openSshRouteSocket({ target: { host: record.host, port: record.port }, routeContext: context, signal: connectionSignal });
            } });
        } catch (error) {
          if (typeof error.sshCleanup === 'function') lease.directTransport = { dispose: error.sshCleanup };
          throw error;
        }
        if (lease.directTransport?.socket !== path.join(lease.directory, 'transport.sock')
          || typeof lease.directTransport.token !== 'string' || !/^[a-f0-9]{64}$/.test(lease.directTransport.token)
          || typeof lease.directTransport.dispose !== 'function') throw unsafe();
        const directSocket = await checkedPath(lease.directTransport.socket);
        if (!directSocket.isSocket() || uid() !== undefined && directSocket.uid !== uid() || directSocket.mode & 0o077) throw unsafe();
        check();
      }
      if (passwords.size) {
        try {
          lease.passwordBroker = await this.createPasswordBroker({ directory: lease.directory, publicDirectory: lease.publicDirectory,
            nodeExecutable, configPath: files.config, proxyUrl, targetsPath: files.targets, manifest, passwords,
            transportSocket: lease.directTransport.socket, directToken: lease.directTransport.token,
            runtimeReadOnlyPaths: base.readOnlyPaths,
            now: this.now, expiresAt: manifest.expiresAt, isActive: () => !lease.revoked && !this.closed && passwordGrantsActive(),
            isConnectionActive: connectionActive });
        } catch (error) {
          if (typeof error.sshCleanup === 'function') lease.passwordBroker = { dispose: error.sshCleanup };
          throw error;
        } finally {
          // The broker owns its own memory-only copy after construction. The
          // per-lease transfer buffers are never retained for the session.
          for (const secret of passwords.values()) secret.fill(0);
        }
        if (lease.passwordBroker?.socket !== path.join(lease.directory, 'command.sock')
          || Buffer.byteLength(lease.passwordBroker.socket) > 100 || typeof lease.passwordBroker.dispose !== 'function') throw unsafe();
        const commandSocket = await checkedPath(lease.passwordBroker.socket);
        if (!commandSocket.isSocket() || uid() !== undefined && commandSocket.uid !== uid() || commandSocket.mode & 0o077) throw unsafe();
        check();
      }
      const passwordBroker = lease.passwordBroker ? { socket: lease.passwordBroker.socket, aliases: [...passwords.keys()] } : undefined;
      const configuredConnections = allRecords.map(record => ({ id: record.id, name: record.name, alias: record.alias,
        host: record.host, port: record.port, user: record.user, route: normalizeSshRoute(record.route, { legacy: true }), authType: authType(record) }));
      const childEnvironment = { home: lease.publicDirectory, targetsPath: files.targets,
        ...(lease.directTransport ? { directSocket: lease.directTransport.socket, directToken: lease.directTransport.token } : {}) };
      await writeFile(files.launcher, launchScript(files.config, manifest, passwordBroker, { adHocConfigPath, configuredConnections, childEnvironment }), { mode: 0o400, flag: 'wx' });
      for (const name of ['ssh', 'envara-ssh']) await writeFile(path.join(binDirectory, name), `#!/bin/sh\nexec ${shellQuote(nodeExecutable)} ${shellQuote(files.launcher)} ${shellQuote(name)} "$@"\n`, { mode: 0o500, flag: 'wx' });
      check();
      if (keyRecords.length) {
      lease.child = this.spawn('/usr/bin/ssh-agent', ['-D', '-a', socket, '-P', ''],
        { env: this.nativeEnvironment(lease.publicDirectory), stdio: ['ignore', 'ignore', 'pipe'], windowsHide: true });
      lease.child.stderr?.resume();
      lease.child.once('error', () => { lease.processError = true; if (!lease.child.pid) lease.stopped = true; });
      lease.child.once('exit', () => { lease.stopped = true; });
      const deadline = Date.now() + 3000;
      while (true) {
        check();
        if (lease.processError || lease.stopped) throw fail('SSH_AGENT_FAILED', '受保护的 SSH 签名代理无法启动。');
        try {
          const info = await lstat(socket);
          if (!info.isSocket() || info.isSymbolicLink() || uid() !== undefined && info.uid !== uid() || info.mode & 0o077) throw unsafe();
          break;
        } catch (error) { if (error.code !== 'ENOENT') throw error; }
        if (Date.now() >= deadline) throw fail('SSH_AGENT_FAILED', '受保护的 SSH 签名代理启动超时。');
        await delay(20);
      }
      const groups = new Map();
      for (const record of keyRecords) { const group = groups.get(record.keyFingerprint) ?? []; group.push(record); groups.set(record.keyFingerprint, group); }
      for (const group of groups.values()) {
        const record = group[0];
        await this.revalidate(record); check();
        const constraints = group.flatMap(item => ['-h', `${item.user}@${item.alias}`]);
        try { await this.execute('/usr/bin/ssh-add', ['-q', '-k', '-H', files.knownHosts, ...constraints, record.keyPath], this.nativeOptions(lease.publicDirectory, socket)); }
        catch { throw fail('SSH_KEY_LOCKED', '私钥未解锁或无法受约束加载；没有读取钥匙串，也没有改用其他密钥。'); }
        await this.revalidate(record); check();
      }
      let loaded;
      try { const value = await this.execute('/usr/bin/ssh-add', ['-L'], this.nativeOptions(lease.publicDirectory, socket)); loaded = value.stdout.trim().split('\n').map(publicKey); }
      catch { throw fail('SSH_AGENT_FAILED', '无法核对 SSH 签名代理中的密钥。'); }
      const expected = [...groups.keys()].sort(), actual = loaded.map(key => key.fingerprint).sort();
      if (!same(expected, actual)) throw identityChanged();
      check();
      }
      await chmod(binDirectory, 0o500); await chmod(lease.publicDirectory, 0o500);
      check();
      result = { ...base, environment: { ENVARA_SSH_CONFIG: files.config, ENVARA_SSH_CONNECTIONS: files.manifest,
        ...(socket ? { SSH_AUTH_SOCK: socket } : {}),
        ...(records.length || adHocConfigPath ? { ENVARA_SSH_PROXY_URL: proxyUrl, ENVARA_SSH_TARGETS: files.targets } : {}),
        ...(lease.directTransport ? { ENVARA_SSH_DIRECT_SOCKET: lease.directTransport.socket, ENVARA_SSH_DIRECT_TOKEN: lease.directTransport.token } : {}) },
        binDirectory, readablePaths: [lease.publicDirectory], readOnlyPaths: [...new Set([lease.publicDirectory, ...base.readOnlyPaths])],
        agentSocket: socket, allowedAgentSocket: socket,
        allowedSockets: [socket, lease.passwordBroker?.socket, lease.directTransport?.socket].filter(Boolean), dispose,
        describe: () => {
          const now = this.now(), passwordsActive = passwordGrantsActive();
          const keysUnavailable = keyRecords.length > 0 && (!lease.child?.pid || lease.processError || lease.stopped
            || lease.child.exitCode != null || lease.child.signalCode != null);
          return describeSshSession(manifest, now, { closed: lease.revoked || this.closed,
            unavailableAliases: records.filter(record => !routeActive(lease.routeContexts.get(record.alias))
              || (authType(record) === 'password' ? !passwordsActive : keysUnavailable))
              .map(record => record.alias) });
        } };
    } catch (error) {
      failure = error.code?.startsWith('SSH_') ? error : fail('SSH_AGENT_FAILED', '受保护的 SSH 通道未能创建。');
    } finally { settleSetup(); }
    if (failure) {
      try { await dispose(); }
      catch { failure.sshCleanup = dispose; failure.sshCleanupError = 'SSH_CLEANUP_FAILED'; }
      throw failure;
    }
    return result;
  }
  disposeSession(lease) {
    lease.revoked = true;
    lease.controller?.abort();
    if (lease.cleanup) return lease.cleanup;
    lease.cleanup = (async () => {
      await lease.setup;
      let failure;
      if (lease.directTransport) {
        try { await lease.directTransport.dispose(); lease.directTransport = null; }
        catch { failure = fail('SSH_CLEANUP_FAILED', 'SSH 直连通道清理尚未确认，请重试结束会话。'); }
      }
      for (const secret of lease.passwords?.values() ?? []) secret.fill(0);
      if (lease.passwordBroker) {
        try { await lease.passwordBroker.dispose(); lease.passwordBroker = null; }
        catch { failure = fail('SSH_CLEANUP_FAILED', 'SSH 临时资料清理尚未确认，请重试结束会话。'); }
      }
      if (lease.child && !lease.stopped && lease.child.exitCode == null && lease.child.signalCode == null) {
        const wait = async milliseconds => {
          const deadline = Date.now() + milliseconds;
          while (!lease.stopped && lease.child.exitCode == null && lease.child.signalCode == null && Date.now() < deadline) await delay(20);
          return lease.stopped || lease.child.exitCode != null || lease.child.signalCode != null;
        };
        try {
          lease.child.kill('SIGTERM');
          if (!await wait(1500)) { lease.child.kill('SIGKILL'); if (!await wait(1500)) throw new Error(); }
        } catch { failure = fail('SSH_CLEANUP_FAILED', 'SSH 签名代理清理尚未确认，请重试结束会话。'); }
      }
      if (!failure && lease.directory) {
        try {
          const info = await checkedPath(lease.directory);
          if (!info.isDirectory() || info.dev !== lease.directoryIdentity?.dev || info.ino !== lease.directoryIdentity?.ino || uid() !== undefined && info.uid !== uid()) throw unsafe();
          if (lease.publicDirectory) {
            const publicInfo = await checkedDirectory(lease.publicDirectory);
            if (publicInfo.dev !== lease.publicIdentity?.dev || publicInfo.ino !== lease.publicIdentity?.ino) throw unsafe();
            await chmod(lease.publicDirectory, 0o700);
            try {
              const bin = path.join(lease.publicDirectory, 'bin'), binInfo = await checkedDirectory(bin);
              if (binInfo.dev !== lease.binIdentity?.dev || binInfo.ino !== lease.binIdentity?.ino) throw unsafe();
              await chmod(bin, 0o700);
            } catch (error) { if (error.code !== 'ENOENT') throw error; }
          }
          await rm(lease.directory, { recursive: true });
        } catch (error) { if (error.code !== 'ENOENT') failure = fail('SSH_CLEANUP_FAILED', 'SSH 临时资料清理尚未确认，请重试结束会话。'); }
      }
      // The route dependency remains live until every owned transport and
      // native process has been confirmed closed. A failed disposal is retried.
      if (!failure) for (const [alias, context] of lease.routeContexts ?? []) {
        try { await this.releaseRoute(context); lease.routeContexts.delete(alias); }
        catch (error) { failure = error; }
      }
      if (failure) throw failure;
      lease.detachSignal?.();
      this.sessions.delete(lease.sessionId);
    })();
    void lease.cleanup.catch(() => { lease.cleanup = null; });
    return lease.cleanup;
  }
  async close() {
    this.closed = true; this.pending.clear();
    for (const operation of this.preparations) operation.controller.abort();
    for (const selectedId of this.#passwordGrants.keys()) this.clearPassword(selectedId);
    const preparations = [...this.preparations].map(async operation => { await operation.finished; await this.releasePreparation(operation); });
    const results = await Promise.allSettled([...preparations, ...[...this.sessions.values()].map(session => this.disposeSession(session))]);
    const retained = await Promise.allSettled([...this.retainedRoutes].map(context => this.releaseRoute(context)));
    const first = [...results, ...retained].find(result => result.status === 'rejected');
    if (first) throw first.reason;
  }
}
