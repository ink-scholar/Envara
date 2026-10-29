import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const executeFile = promisify(execFile);
const nativeCodes = new Set(['INVALID_ARGUMENT', 'UNSAFE_PATH', 'BUSY', 'MISSING', 'LOCKED', 'UNAVAILABLE',
  'EXISTING_SELECTION', 'PREPARATION_FAILED', 'HOST_CHANGED', 'HOST_CHECK_FAILED', 'CLEANUP_FAILED'].map(value => `CLAUDE_KEYCHAIN_${value}`));
const stages = new Set(['arguments', 'lock', 'scoped-query', 'host-query', 'stage', 'select', 'publish', 'verify', 'host-verify', 'cleanup']);
const failure = (code = 'CLAUDE_KEYCHAIN_UNAVAILABLE') => Object.assign(new Error('Claude 登录凭据存储暂不可用，请检查钥匙串后重试。'), { code });
const incompleteCheck = 'Claude 钥匙串准备的收尾检查未通过。请保留现有资料并联系维护者处理。';
const absolute = value => typeof value === 'string' && path.isAbsolute(value) && path.resolve(value) === value
  && value !== path.parse(value).root && value.length <= 4096 && !/[\x00-\x1f\x7f]/.test(value);
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const digest = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const sameFile = (a, b) => a.dev === b.dev && a.ino === b.ino && a.size === b.size && a.mtimeMs === b.mtimeMs
  && a.mode === b.mode && a.uid === b.uid && a.nlink === b.nlink;

async function resourceFile(filename, limit, executable = false) {
  const before = await lstat(filename);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.mode & 0o022
    || ![0, process.getuid?.()].includes(before.uid) || before.size < 1 || before.size > limit
    || executable && !(before.mode & 0o111) || await realpath(filename) !== filename) throw failure('CLAUDE_KEYCHAIN_RESOURCE_INVALID');
  const handle = await open(filename, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    if (!sameFile(before, await handle.stat())) throw failure('CLAUDE_KEYCHAIN_RESOURCE_INVALID');
    const bytes = await handle.readFile();
    if (!sameFile(before, await handle.stat()) || bytes.length !== before.size) throw failure('CLAUDE_KEYCHAIN_RESOURCE_INVALID');
    return { info: before, bytes };
  } finally { await handle.close(); }
}

/** Inspect only bundled helper bytes. Never queries a Keychain or creates a HOME. */
export async function inspectClaudeKeychainResource({ resourcesDir, architecture = process.arch } = {}) {
  try {
    if (!absolute(resourcesDir) || !['arm64', 'x64'].includes(architecture)) throw failure('CLAUDE_KEYCHAIN_RESOURCE_INVALID');
    const directory = path.join(resourcesDir, `darwin-${architecture}`);
    const executable = path.join(directory, 'envara-claude-keychain');
    const manifestFile = path.join(directory, 'manifest.json');
    const metadata = await resourceFile(manifestFile, 8192);
    const manifest = JSON.parse(metadata.bytes.toString('utf8'));
    if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest) || manifest.schemaVersion !== 1
      || manifest.platform !== 'darwin' || manifest.architecture !== architecture || manifest.executable !== path.basename(executable)
      || !digest(manifest.sha256) || !digest(manifest.sourceSha256) || !digest(manifest.builderSha256)) throw failure('CLAUDE_KEYCHAIN_RESOURCE_INVALID');
    const binary = await resourceFile(executable, 4 * 1024 * 1024, true);
    if (binary.bytes.length < 32 || binary.bytes.readUInt32LE(0) !== 0xfeedfacf
      || binary.bytes.readUInt32LE(4) !== ({ arm64: 0x0100000c, x64: 0x01000007 })[architecture]
      || sha256(binary.bytes) !== manifest.sha256) throw failure('CLAUDE_KEYCHAIN_RESOURCE_INVALID');
    return { executable, manifest, identity: binary.info, manifestIdentity: metadata.info, manifestFile };
  } catch { throw failure('CLAUDE_KEYCHAIN_RESOURCE_INVALID'); }
}

export function parseClaudeKeychainReply(text, succeeded) {
  try {
    if (typeof text !== 'string' || Buffer.byteLength(text) > 4096 || !text.trim()) throw new Error();
    const value = JSON.parse(text);
    if (!value || Array.isArray(value) || value.schemaVersion !== 1) throw new Error();
    if (succeeded && value.status === 'ready' && typeof value.changed === 'boolean'
      && Object.keys(value).every(key => ['schemaVersion', 'status', 'changed'].includes(key))) return value;
    if (!succeeded && value.status === 'error' && nativeCodes.has(value.code) && stages.has(value.stage)
      && (value.osStatus === null || Number.isSafeInteger(value.osStatus) && value.osStatus >= -2147483648 && value.osStatus <= 2147483647)
      && (value.cleanupCode === undefined || value.cleanupCode === 'CLAUDE_KEYCHAIN_CLEANUP_FAILED')
      && (value.hostCheckCode === undefined || ['CLAUDE_KEYCHAIN_HOST_CHANGED', 'CLAUDE_KEYCHAIN_HOST_CHECK_FAILED'].includes(value.hostCheckCode))
      && Object.keys(value).every(key => ['schemaVersion', 'status', 'code', 'stage', 'osStatus', 'cleanupCode', 'hostCheckCode'].includes(key))) return value;
    throw new Error();
  } catch { throw failure('CLAUDE_KEYCHAIN_PROTOCOL_ERROR'); }
}

/** Explicit session preparation. Keychain contents remain owned by the official CLI. */
export class ClaudeKeychainManager {
  constructor({ resourcesDir = path.join(process.resourcesPath ?? path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../build'), 'claude-keychain'),
    platform = process.platform, architecture = process.arch, execute = executeFile } = {}) {
    this.resourcesDir = resourcesDir;
    this.platform = platform;
    this.architecture = architecture;
    this.execute = execute;
    this.pending = new Map();
  }
  async prepare({ home, hostHome } = {}) {
    if (this.platform !== 'darwin') return { schemaVersion: 1, status: 'not-required', changed: false };
    if (!absolute(home) || !absolute(hostHome) || home === hostHome) throw failure('CLAUDE_KEYCHAIN_UNSAFE_PATH');
    // Duplicates share the environment HOME. Serialize preparations, then query
    // again: a previously ready Keychain may have locked since the last session.
    const previous = this.pending.get(home) ?? Promise.resolve();
    const task = previous.catch(() => {}).then(() => this.prepareOne(home, hostHome));
    this.pending.set(home, task);
    try { return await task; }
    finally { if (this.pending.get(home) === task) this.pending.delete(home); }
  }
  async prepareOne(home, hostHome) {
    const resource = await inspectClaudeKeychainResource({ resourcesDir: this.resourcesDir, architecture: this.architecture });
    if (!sameFile(resource.identity, await lstat(resource.executable)) || !sameFile(resource.manifestIdentity, await lstat(resource.manifestFile)))
      throw failure('CLAUDE_KEYCHAIN_RESOURCE_INVALID');
    let result, succeeded = false;
    try {
      result = await this.execute(resource.executable, ['prepare', '--home', home, '--host-home', hostHome], {
        env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', HOME: hostHome, LANG: 'C', LC_ALL: 'C' },
        cwd: '/', timeout: 30000, maxBuffer: 4096, encoding: 'utf8', windowsHide: true,
      });
      succeeded = true;
    } catch (error) {
      // Node's native error includes argv and stderr, both private. Never retain
      // it as a cause or forward it into public terminal errors or diagnostics.
      if (error?.killed || error?.signal) throw Object.assign(failure('CLAUDE_KEYCHAIN_TIMEOUT'), { keychainPreparationIncomplete: true, cleanupError: incompleteCheck });
      if (!Number.isInteger(error?.code)) throw failure();
      result = { stdout: error.stdout };
    }
    let reply;
    try { reply = parseClaudeKeychainReply(result?.stdout, succeeded); }
    catch (error) {
      // A child that ran but did not return a valid completion frame may have
      // prepared files. Keep that uncertainty in the session's cleanup history.
      throw Object.assign(error, { keychainPreparationIncomplete: true, cleanupError: incompleteCheck });
    }
    if (reply.status !== 'ready') {
      const error = failure(reply.code);
      if (reply.cleanupCode || reply.code === 'CLAUDE_KEYCHAIN_CLEANUP_FAILED') {
        error.keychainPreparationIncomplete = true;
        error.cleanupError = 'Claude 钥匙串准备的临时资料未能完成清理。请保留现有资料并联系维护者处理。';
      }
      if (reply.hostCheckCode || reply.code === 'CLAUDE_KEYCHAIN_HOST_CHECK_FAILED' || reply.code === 'CLAUDE_KEYCHAIN_HOST_CHANGED') {
        error.keychainPreparationIncomplete = true;
        error.cleanupError = incompleteCheck;
      }
      throw error;
    }
    return reply;
  }
}
