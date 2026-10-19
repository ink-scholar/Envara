import path from 'node:path';
import { constants } from 'node:fs';
import { chmod, lstat, mkdir, open, readFile, realpath, rename, rm, writeFile } from 'node:fs/promises';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { execFile, spawn as spawnChild } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { validateSshProxyUrl, validateSshTarget } from './terminal-ssh-proxy.mjs';

const STORE_SCHEMA = 'envara.terminal-ssh';
const MAX_STORE_BYTES = 1024 * 1024;
const MAX_PUBLIC_BYTES = 16 * 1024;
const MAX_CONNECTIONS = 20;
const MAX_TOTAL_CONNECTIONS = 128;
const TOKEN_TTL = 30 * 60 * 1000;
const PRIVATE_MODE = 0o600;
const KEY_TYPES = new Set(['ssh-ed25519', 'ssh-rsa', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521']);
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
const fingerprint = blob => `SHA256:${createHash('sha256').update(blob).digest('base64').replace(/=+$/, '')}`;
const keyIdentity = info => ({ dev: info.dev, ino: info.ino, size: info.size, mtimeMs: info.mtimeMs, ctimeMs: info.ctimeMs });
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const endpoint = ({ host, port }) => port === 22 ? host : `[${host}]:${port}`;
const publicConnection = value => ({ id: value.id, name: value.name, alias: value.alias, host: value.host, port: value.port,
  user: value.user, keyLabel: value.keyLabel, keyFingerprint: value.keyFingerprint, hostFingerprints: [...value.hostFingerprints] });
const shellQuote = value => `'${value.replaceAll("'", "'\\''")}'`;
const configQuote = value => `"${value.replaceAll('\\', '\\\\').replaceAll('"', '\\"')}"`;

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

function publicKey(text) {
  if (typeof text !== 'string' || text.length > MAX_PUBLIC_BYTES || /[\x00\r]/.test(text)) throw fail('SSH_KEY_INVALID', 'SSH 公钥格式不受支持。');
  const lines = text.trim().split('\n');
  const match = lines.length === 1 && /^(\S+)\s+([A-Za-z0-9+/]+={0,2})(?:\s+[^\n]*)?$/.exec(lines[0]);
  if (!match || !KEY_TYPES.has(match[1])) throw fail('SSH_KEY_INVALID', 'SSH 公钥格式不受支持。');
  const blob = Buffer.from(match[2], 'base64');
  if (blob.length > MAX_PUBLIC_BYTES || blob.toString('base64').replace(/=+$/, '') !== match[2].replace(/=+$/, '')) throw fail('SSH_KEY_INVALID', 'SSH 公钥格式不受支持。');
  let offset = 0;
  const field = () => {
    if (offset + 4 > blob.length) throw fail('SSH_KEY_INVALID', 'SSH 公钥格式不受支持。');
    const length = blob.readUInt32BE(offset); offset += 4;
    if (length < 1 || offset + length > blob.length) throw fail('SSH_KEY_INVALID', 'SSH 公钥格式不受支持。');
    const value = blob.subarray(offset, offset + length); offset += length; return value;
  };
  if (field().toString() !== match[1]) throw fail('SSH_KEY_INVALID', 'SSH 公钥格式不受支持。');
  if (match[1] === 'ssh-ed25519') { if (field().length !== 32) throw fail('SSH_KEY_INVALID', 'SSH 公钥格式不受支持。'); }
  else if (match[1] === 'ssh-rsa') { field(); field(); }
  else { if (field().toString() !== match[1].slice('ecdsa-sha2-'.length)) throw fail('SSH_KEY_INVALID', 'SSH 公钥格式不受支持。'); field(); }
  if (offset !== blob.length) throw fail('SSH_KEY_INVALID', 'SSH 公钥格式不受支持。');
  return { text: `${match[1]} ${blob.toString('base64')}`, fingerprint: fingerprint(blob) };
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

function launchScript(config, aliases) {
  return `import { spawn } from 'node:child_process';
const args = process.argv.slice(2), flags = [];
const refuse = () => { process.stderr.write('Envara SSH: use ssh [-T|-t|-v|-vv|-vvv] saved-alias [command...]. Custom connection options are not allowed.\\n'); process.exit(2); };
while (args.length && args[0].startsWith('-')) {
  if (!['-T','-t','-v','-vv','-vvv'].includes(args[0])) refuse();
  flags.push(args.shift());
}
const alias = args.shift();
if (!${JSON.stringify(aliases)}.includes(alias)) refuse();
const child = spawn('/usr/bin/ssh', ['-F', ${JSON.stringify(config)}, ...flags, '--', alias, ...args], { stdio: 'inherit', env: { ...process.env, SSH_ASKPASS_REQUIRE: 'never', SSH_ASKPASS: '/usr/bin/false' } });
for (const signal of ['SIGTERM','SIGINT','SIGHUP']) process.on(signal, () => { try { child.kill(signal); } catch {} });
child.once('error', () => { process.stderr.write('Envara SSH: the protected client could not start.\\n'); process.exitCode = 1; });
child.once('exit', (code, signal) => { if (signal) { process.exitCode = 1; } else process.exitCode = Number.isInteger(code) ? code : 1; });
`;
}

function configuration(records, files, nodeExecutable) {
  const proxy = `${shellQuote(nodeExecutable).replaceAll('%', '%%')} ${shellQuote(files.proxy).replaceAll('%', '%%')} --host '%h' --port '%p'`;
  return records.map(record => [
    `Host ${record.alias}`, `  HostName ${record.host}`, `  Port ${record.port}`, `  User ${record.user}`,
    `  HostKeyAlias ${record.alias}`, `  IdentityFile ${configQuote(files.publicKeys.get(record.id))}`,
    `  IdentityAgent ${configQuote(files.socket)}`, '  IdentitiesOnly yes',
    `  UserKnownHostsFile ${configQuote(files.knownHosts)}`, '  GlobalKnownHostsFile /dev/null',
    '  StrictHostKeyChecking yes', '  VerifyHostKeyDNS no', '  UpdateHostKeys no',
    '  PreferredAuthentications publickey', '  PasswordAuthentication no', '  KbdInteractiveAuthentication no',
    '  BatchMode yes', '  NumberOfPasswordPrompts 0', '  ConnectTimeout 15', '  ConnectionAttempts 1',
    '  AddKeysToAgent no', '  UseKeychain no', '  PKCS11Provider none',
    '  ForwardAgent no', '  ForwardX11 no', '  ClearAllForwardings yes',
    '  ControlMaster no', '  ControlPath none', '  ControlPersist no', '  CanonicalizeHostname no',
    '  ServerAliveInterval 30', '  ServerAliveCountMax 3', `  ProxyCommand ${proxy}`, '',
  ].join('\n')).join('\n');
}

/** Private-key references stay outside the exported profile tree. Only native
 * ssh-add reads private bytes, into an owned destination-constrained agent.
 * File modes and unpredictable sockets do not isolate hostile same-UID host
 * processes; new terminal fences protect the returned paths and sockets. */
export class TerminalSshManager {
  constructor({ dataDir, hostHome, nodeExecutable, platform = process.platform, execute = nativeExecute, spawn = spawnChild,
    now = Date.now, agentRoot = platform === 'darwin' ? `/private/tmp/envara-ssh-${uid() ?? 'unsupported'}`
      : path.join(dataDir ?? '', 'terminal', 'ssh-access-runtime'), agentLifetimeSeconds = 3600 } = {}) {
    this.dataDir = absolute(dataDir); this.hostHome = absolute(hostHome);
    this.nodeExecutable = nodeExecutable == null ? null : absolute(nodeExecutable);
    this.root = path.join(this.dataDir, 'terminal', 'ssh-access'); this.filename = path.join(this.root, 'connections.json');
    this.agentRoot = absolute(agentRoot); this.platform = platform; this.execute = execute; this.spawn = spawn; this.now = now;
    if (!Number.isInteger(agentLifetimeSeconds) || agentLifetimeSeconds < 60 || agentLifetimeSeconds > 86400) throw invalid();
    this.agentLifetimeSeconds = agentLifetimeSeconds;
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
      for (const profile of document.profiles) {
        const profileId = id(profile?.id);
        if (this.profiles.has(profileId) || !Array.isArray(profile.connections) || profile.connections.length > MAX_CONNECTIONS) throw storageInvalid();
        const names = new Set(), ids = new Set(), aliases = new Set();
        const records = profile.connections.map(record => {
          const value = this.validateRecord(record);
          if (names.has(nameKey(value.name)) || ids.has(value.id) || aliases.has(value.alias)) throw storageInvalid();
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
    const checkedTarget = target(record ?? {}), key = publicKey(record?.publicKey);
    const value = { id: connectionId(record?.id), name: label(record?.name), alias: record?.alias, ...checkedTarget,
      keyPath: absolute(record?.keyPath), keyStat: record?.keyStat, publicKey: key.text,
      keyLabel: label(record?.keyLabel), keyFingerprint: key.fingerprint, hostKeys: record?.hostKeys };
    if (!/^envara-[a-f0-9]{12}$/.test(value.alias ?? '') || !same(record.keyFingerprint, value.keyFingerprint)
      || !value.keyStat || Object.keys(value.keyStat).sort().join(',') !== 'ctimeMs,dev,ino,mtimeMs,size'
      || Object.values(value.keyStat).some(number => !Number.isFinite(number) || number < 0)
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
    return { supported: this.supported, connections: (this.profiles.get(profileId) ?? []).map(publicConnection) };
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
  async prepareIdentity({ id: profileId, host, port, user, keyPath }) {
    id(profileId); await this.ready; this.assertSupported();
    const checkedTarget = target({ host, port, user });
    const identity = await this.identity(keyPath), hostKeys = await this.readTrust(checkedTarget);
    this.assertOpen();
    for (const [token, item] of this.pending) if (item.expiresAt <= this.now()) this.pending.delete(token);
    if (this.pending.size >= 64) throw fail('SSH_CONNECTION_LIMIT', '待确认的 SSH 密钥过多，请稍后重试。');
    const selectionToken = `sshsel_${randomBytes(24).toString('hex')}`;
    const value = { profileId, ...checkedTarget, ...identity, hostKeys,
      hostFingerprints: hostKeys.map(item => item.fingerprint), expiresAt: this.now() + TOKEN_TTL };
    this.pending.set(selectionToken, value);
    return { selectionToken, ...checkedTarget, keyLabel: identity.keyLabel, keyFingerprint: identity.keyFingerprint, hostFingerprints: [...value.hostFingerprints] };
  }
  async revalidate(record, { trust = false } = {}) {
    let current;
    try { current = await this.identity(record.keyPath); } catch { throw identityChanged(); }
    if (!same(current.keyStat, record.keyStat) || current.publicKey !== record.publicKey) throw identityChanged();
    if (trust && !same(await this.readTrust(record), record.hostKeys)) throw identityChanged();
  }
  mutate(operation) {
    const task = this.queue.then(async () => { await this.ready; this.assertOpen(); return operation(); });
    this.queue = task.catch(() => {}); return task;
  }
  async persist(profiles) {
    const source = JSON.stringify({ schema: STORE_SCHEMA, version: 1, profiles: [...profiles].map(([id, connections]) => ({ id, connections })) });
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
  save({ id: profileId, name, selectionToken }) {
    id(profileId); name = label(name);
    return this.mutate(async () => {
      this.assertSupported();
      const selected = this.pending.get(selectionToken);
      if (!selected || selected.expiresAt <= this.now()) { this.pending.delete(selectionToken); throw fail('SSH_SELECTION_EXPIRED', '密钥选择已失效，请重新选择并核对。'); }
      if (selected.profileId !== profileId) throw fail('SSH_SELECTION_MISMATCH', '密钥选择不属于此境舱。');
      const previous = this.profiles.get(profileId) ?? [];
      if (previous.length >= MAX_CONNECTIONS) throw fail('SSH_CONNECTION_LIMIT', '一个境舱最多保存 20 个 SSH 连接。');
      if ([...this.profiles.values()].reduce((sum, records) => sum + records.length, 0) >= MAX_TOTAL_CONNECTIONS) throw fail('SSH_CONNECTION_LIMIT', '已保存的 SSH 连接数量达到上限。');
      if (previous.some(record => nameKey(record.name) === nameKey(name))) throw fail('SSH_NAME_EXISTS', '此境舱已存在同名 SSH 连接。');
      await this.revalidate(selected, { trust: true });
      const uuid = randomUUID().replaceAll('-', '');
      const { profileId: ignored, expiresAt, ...identity } = selected;
      const record = { id: `ssh_${uuid}`, name, alias: `envara-${uuid.slice(0, 12)}`, ...structuredClone(identity) };
      const next = new Map(this.profiles); next.set(profileId, [...previous, record]);
      await this.persist(next); this.profiles = next; this.pending.delete(selectionToken);
      return publicConnection(record);
    });
  }
  remove({ id: profileId, connectionId: selectedId }) {
    id(profileId); connectionId(selectedId);
    return this.mutate(async () => {
      const previous = this.profiles.get(profileId) ?? [];
      if (!previous.some(record => record.id === selectedId)) throw fail('SSH_CONNECTION_NOT_FOUND', '此 SSH 连接已不存在。');
      if ([...this.sessions.values()].some(session => session.records.some(record => record.id === selectedId))) throw fail('SSH_CONNECTION_IN_USE', '请先结束使用此 SSH 连接的终端会话。');
      const next = new Map(this.profiles); next.set(profileId, previous.filter(record => record.id !== selectedId));
      await this.persist(next); this.profiles = next; return { removed: true };
    });
  }
  removeProfile({ id: profileId }) {
    id(profileId);
    return this.mutate(async () => {
      if ([...this.sessions.values()].some(session => session.profileId === profileId)) throw fail('SSH_CONNECTION_IN_USE', '请先结束此境舱的终端会话。');
      const next = new Map(this.profiles); next.delete(profileId);
      if (this.profiles.has(profileId)) { await this.persist(next); this.profiles = next; }
      for (const [token, selected] of this.pending) if (selected.profileId === profileId) this.pending.delete(token);
      return { removed: true };
    });
  }
  protection(records = []) {
    // A newly launched environment also protects keys selected for other
    // environments, including references outside the host's .ssh directory.
    const privateKeys = [...this.profiles.values()].flat().concat(records, [...this.pending.values()]).map(record => record.keyPath);
    return { protectedPaths: [...new Set([path.join(this.hostHome, '.ssh'), this.root, this.agentRoot, ...privateKeys])],
      readablePaths: [], readOnlyPaths: [], agentSocket: null, allowedAgentSocket: null, agentRoot: this.agentRoot };
  }
  async createSession({ profileId, sessionId, directories, proxyUrl, nodeExecutable = this.nodeExecutable } = {}) {
    id(profileId); id(sessionId); await this.ready; await this.queue; this.assertOpen();
    const records = structuredClone(this.profiles.get(profileId) ?? []), base = this.protection(records);
    if (!records.length) return { ...base, environment: {}, binDirectory: null, dispose: async () => {} };
    this.assertSupported();
    if (this.sessions.has(sessionId)) throw fail('SSH_SESSION_EXISTS', 'SSH 终端会话标识已被使用。');
    try { validateSshProxyUrl(proxyUrl); } catch { throw fail('SSH_PROXY_REQUIRED', 'SSH 需要此会话的已认证境舱代理通道。'); }
    nodeExecutable = absolute(nodeExecutable);
    const nodeInfo = await checkedPath(nodeExecutable);
    if (!nodeInfo.isFile() || !(nodeInfo.mode & 0o111)) throw unsafe();
    if (directories?.home != null) absolute(directories.home);
    let settleSetup;
    const lease = { profileId, sessionId, records, revoked: false, child: null, directory: null, directoryIdentity: null,
      publicDirectory: null, publicIdentity: null, binIdentity: null, processError: false, stopped: false, cleanup: null,
      setup: new Promise(resolve => { settleSetup = resolve; }) };
    const check = () => { this.assertOpen(); if (lease.revoked) throw fail('SSH_SESSION_CLOSED', 'SSH 会话已取消。'); };
    const dispose = () => this.disposeSession(lease);
    this.sessions.set(sessionId, lease);
    let result, failure;
    try {
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
      const socket = path.join(lease.directory, 'agent.sock');
      if (Buffer.byteLength(socket) > 100) throw fail('SSH_UNSAFE_PATH', 'SSH 代理通道路径过长。');
      const files = { socket, knownHosts: path.join(lease.publicDirectory, 'known_hosts'),
        config: path.join(lease.publicDirectory, 'config'), targets: path.join(lease.publicDirectory, 'targets.json'),
        proxy: path.join(lease.publicDirectory, 'proxy.mjs'), launcher: path.join(lease.publicDirectory, 'launch.mjs'), publicKeys: new Map() };
      for (const record of records) {
        const file = path.join(lease.publicDirectory, `${record.id}.pub`); files.publicKeys.set(record.id, file);
        await writeFile(file, `${record.publicKey}\n`, { mode: 0o400, flag: 'wx' }); check();
      }
      const hostKeys = records.flatMap(record => record.hostKeys.map(key => `${record.alias} ${key.text}`)).join('\n') + '\n';
      await writeFile(files.knownHosts, hostKeys, { mode: 0o400, flag: 'wx' });
      const targets = [...new Map(records.map(record => [`${record.host}:${record.port}`, { host: record.host, port: record.port }])).values()];
      await writeFile(files.targets, JSON.stringify(targets), { mode: 0o400, flag: 'wx' });
      await writeFile(files.proxy, await readFile(fileURLToPath(new URL('./terminal-ssh-proxy.mjs', import.meta.url))), { mode: 0o400, flag: 'wx' });
      await writeFile(files.config, configuration(records, files, nodeExecutable), { mode: 0o400, flag: 'wx' });
      await writeFile(files.launcher, launchScript(files.config, records.map(record => record.alias)), { mode: 0o400, flag: 'wx' });
      for (const name of ['ssh', 'envara-ssh']) await writeFile(path.join(binDirectory, name), `#!/bin/sh\nexec ${shellQuote(nodeExecutable)} ${shellQuote(files.launcher)} "$@"\n`, { mode: 0o500, flag: 'wx' });
      check();
      lease.child = this.spawn('/usr/bin/ssh-agent', ['-D', '-a', socket, '-P', '', '-t', String(this.agentLifetimeSeconds)],
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
      for (const record of records) { const group = groups.get(record.keyFingerprint) ?? []; group.push(record); groups.set(record.keyFingerprint, group); }
      for (const group of groups.values()) {
        const record = group[0];
        await this.revalidate(record); check();
        const constraints = group.flatMap(item => ['-h', `${item.user}@${item.alias}`]);
        try { await this.execute('/usr/bin/ssh-add', ['-q', '-k', '-t', String(this.agentLifetimeSeconds), '-H', files.knownHosts, ...constraints, record.keyPath], this.nativeOptions(lease.publicDirectory, socket)); }
        catch { throw fail('SSH_KEY_LOCKED', '私钥未解锁或无法受约束加载；没有读取钥匙串，也没有改用其他密钥。'); }
        await this.revalidate(record); check();
      }
      let loaded;
      try { const value = await this.execute('/usr/bin/ssh-add', ['-L'], this.nativeOptions(lease.publicDirectory, socket)); loaded = value.stdout.trim().split('\n').map(publicKey); }
      catch { throw fail('SSH_AGENT_FAILED', '无法核对 SSH 签名代理中的密钥。'); }
      const expected = [...groups.keys()].sort(), actual = loaded.map(key => key.fingerprint).sort();
      if (!same(expected, actual)) throw identityChanged();
      check();
      await chmod(binDirectory, 0o500); await chmod(lease.publicDirectory, 0o500);
      check();
      result = { ...base, environment: { SSH_AUTH_SOCK: socket, ENVARA_SSH_PROXY_URL: proxyUrl, ENVARA_SSH_TARGETS: files.targets },
        binDirectory, readablePaths: [lease.publicDirectory], readOnlyPaths: [lease.publicDirectory],
        agentSocket: socket, allowedAgentSocket: socket, dispose };
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
    if (lease.cleanup) return lease.cleanup;
    lease.cleanup = (async () => {
      await lease.setup;
      let failure;
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
      if (failure) throw failure;
      this.sessions.delete(lease.sessionId);
    })();
    void lease.cleanup.catch(() => { lease.cleanup = null; });
    return lease.cleanup;
  }
  async close() {
    this.closed = true; this.pending.clear();
    const results = await Promise.allSettled([...this.sessions.values()].map(session => this.disposeSession(session)));
    const first = results.find(result => result.status === 'rejected');
    if (first) throw first.reason;
  }
}
