import path from 'node:path';
import { constants } from 'node:fs';
import { access, chmod, copyFile, link, lstat, mkdir, open, readdir, realpath, rm, symlink } from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const invalid = () => Object.assign(new Error('境舱的 Claude 安装无效，请检查其本地安装后重试；未改用本机版本。'), { code: 'CLAUDE_CODE_INSTALLATION_INVALID' });
const unsupported = () => Object.assign(new Error('此安装方式无法初始化境舱，请先在本机安装 Claude Code 官方原生版本。'), { code: 'CLAUDE_CODE_NATIVE_INSTALL_REQUIRED' });
const versionName = value => /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(value);
const locks = new Map();

function layout(home) {
  if (typeof home !== 'string' || !path.isAbsolute(home) || path.resolve(home) !== home || /[\0\r\n]/.test(home) || home.includes(path.delimiter)) throw invalid();
  return { home, entryPath: path.join(home, '.local/bin/claude'), versionsDirectory: path.join(home, '.local/share/claude/versions') };
}

async function directory(filename, create = false) {
  if (create) {
    try { await mkdir(filename, { mode: 0o700 }); }
    catch (error) { if (error.code !== 'EEXIST') throw error; }
  }
  const info = await lstat(filename);
  if (!info.isDirectory() || info.isSymbolicLink() || info.mode & 0o022
    || (process.getuid && info.uid !== process.getuid()) || await realpath(filename) !== filename) throw invalid();
}

async function directories(installation, create = false) {
  await directory(installation.home);
  for (const relative of ['.local', '.local/bin', '.local/share', '.local/share/claude', '.local/share/claude/versions']) {
    await directory(path.join(installation.home, relative), create);
  }
}

// Validate the native file format without starting any host program. A copied
// npm/JS/shell launcher would retain host dependencies, not an isolated install.
async function nativeFile(filename, independent = false) {
  const before = await lstat(filename);
  if (!before.isFile() || before.isSymbolicLink() || before.mode & 0o022 || (independent && (before.nlink !== 1 || (process.getuid && before.uid !== process.getuid())))) throw invalid();
  await access(filename, constants.R_OK | constants.X_OK);
  const handle = await open(filename, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const info = await handle.stat();
    if (info.dev !== before.dev || info.ino !== before.ino) throw invalid();
    const magic = Buffer.alloc(4);
    const { bytesRead } = await handle.read(magic, 0, 4, 0);
    const signature = magic.toString('hex');
    const recognized = process.platform === 'darwin'
      ? ['feedface', 'feedfacf', 'cefaedfe', 'cffaedfe', 'cafebabe', 'bebafeca', 'cafebabf', 'bfbafeca'].includes(signature)
      : process.platform === 'linux' && signature === '7f454c46';
    if (bytesRead !== 4 || !recognized) throw unsupported();
    return info;
  } finally { await handle.close(); }
}

// Recovery is limited to an interrupted bootstrap publication: only this
// private directory's UUID staging names with the exact version inode qualify.
// Any other hard link, inode mismatch or unexpected ownership remains refused.
async function recoverPublication(installation, executable) {
  if (path.dirname(executable) !== installation.versionsDirectory || !versionName(path.basename(executable))) throw invalid();
  const version = await nativeFile(executable);
  if (version.nlink === 1) return;
  if (process.getuid && version.uid !== process.getuid()) throw invalid();
  const owned = [];
  for (const name of await readdir(installation.versionsDirectory)) {
    if (!/^\.envara-bootstrap-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(name)) continue;
    const filename = path.join(installation.versionsDirectory, name), info = await lstat(filename);
    if (info.isFile() && !info.isSymbolicLink() && info.dev === version.dev && info.ino === version.ino && info.uid === version.uid) owned.push(filename);
  }
  if (version.nlink !== owned.length + 1 || !owned.length) throw invalid();
  for (const filename of owned) {
    const current = await lstat(filename);
    if (!current.isFile() || current.dev !== version.dev || current.ino !== version.ino) throw invalid();
    await rm(filename);
  }
  await nativeFile(executable, true);
}

async function fileDigest(filename) {
  const handle = await open(filename, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const hash = createHash('sha256');
    for await (const chunk of handle.createReadStream({ autoClose: false })) hash.update(chunk);
    return hash.digest('hex');
  } finally { await handle.close(); }
}

/** Resolve only the updater-owned entry in this environment, on every call. */
export async function resolveClaudeInstallation({ home } = {}) {
  try {
    const installation = layout(home);
    await directories(installation);
    const entry = await lstat(installation.entryPath);
    if (!entry.isSymbolicLink()) throw invalid();
    const executable = await realpath(installation.entryPath);
    if (path.dirname(executable) !== installation.versionsDirectory || !versionName(path.basename(executable))) throw invalid();
    await nativeFile(executable, true);
    return executable;
  } catch { throw invalid(); }
}

/** Read-only presence check. Missing directories are never initialized here. */
export async function claudeInstallationStatus({ home } = {}) {
  const installation = layout(home);
  try {
    await directory(home);
    let entry;
    try { entry = await lstat(installation.entryPath); }
    catch (error) {
      if (error.code !== 'ENOENT') throw error;
      for (const relative of ['.local', '.local/bin']) {
        try { await directory(path.join(home, relative)); }
        catch (parentError) { if (parentError.code === 'ENOENT') return { installed: false }; throw parentError; }
      }
      return { installed: false };
    }
    if (!entry.isSymbolicLink()) throw invalid();
    await resolveClaudeInstallation(installation);
    return { installed: true };
  } catch (error) {
    return error.code === 'ENOENT' ? { installed: false }
      : { installed: false, errorCode: 'CLAUDE_CODE_INSTALLATION_INVALID' };
  }
}

async function ensureInstallation({ home, findHostExecutable, downloadContext, onProgress, downloadNative, source = 'auto' }) {
  if (!['auto', 'download', 'local'].includes(source)) throw Object.assign(new Error('Claude 安装来源无效，请重新选择。'), { code: 'CLAUDE_CODE_INSTALL_SOURCE_INVALID' });
  const installation = layout(home);
  await directory(home);
  // Check lstat first: a broken or escaping entry is never a missing install.
  let entry;
  try { entry = await lstat(installation.entryPath); }
  catch (error) { if (error.code !== 'ENOENT') throw invalid(); }
  if (entry) {
    await directories(installation);
    if (!entry.isSymbolicLink()) throw invalid();
    try { await recoverPublication(installation, await realpath(installation.entryPath)); }
    catch { throw invalid(); }
    await resolveClaudeInstallation(installation); return installation;
  }
  await directories(installation, true);
  const checkCancelled = () => { if (downloadContext?.signal?.aborted) throw Object.assign(new Error('Claude 下载已取消。'), { code: 'CLAUDE_CODE_DOWNLOAD_CANCELLED' }); };
  checkCancelled();
  let canonical, name, sourceInfo, hostError, expectedChecksum;
  if (source !== 'download' && typeof findHostExecutable === 'function') {
    try {
      const source = await findHostExecutable();
      if (typeof source !== 'string' || !path.isAbsolute(source) || /[\0\r\n]/.test(source)) throw unsupported();
      const found = await realpath(source);
      if (!versionName(path.basename(found))) throw unsupported();
      sourceInfo = await nativeFile(found); canonical = found; name = path.basename(found);
    } catch (error) { hostError = error; }
  }
  if (!canonical && source === 'local') throw Object.assign(new Error('本机未找到可用的 Claude 原生安装，请选择下载独立安装。'), { code: 'CLAUDE_CODE_LOCAL_INSTALL_UNAVAILABLE' });
  if (!downloadContext && source === 'download') throw Object.assign(new Error('请选择可用的境舱网络后下载 Claude Code。'), { code: 'CLAUDE_CODE_DOWNLOAD_ROUTE_REQUIRED' });
  if (!canonical && !downloadContext) throw hostError ?? unsupported();
  const staged = path.join(installation.versionsDirectory, `.envara-bootstrap-${randomUUID()}`);
  try {
    if (canonical) {
      // COPYFILE_FICLONE is an independent-inode COW copy where supported, and
      // falls back to a normal copy. Never link a writable host installation.
      await copyFile(canonical, staged, constants.COPYFILE_EXCL | constants.COPYFILE_FICLONE);
      const after = await lstat(canonical);
      if (after.dev !== sourceInfo.dev || after.ino !== sourceInfo.ino || after.size !== sourceInfo.size || after.mtimeMs !== sourceInfo.mtimeMs) throw invalid();
    } else {
      // Dynamic import keeps the runtime entry checker self-contained: it never
      // imports network dependencies or initiates a download on CLI invocation.
      const downloader = downloadNative ?? (await import('./claude-code-download.mjs')).downloadClaudeNative;
      const release = await downloader({ destination: staged, proxyUrl: downloadContext.proxyUrl, signal: downloadContext.signal, onProgress });
      if (!versionName(release?.version ?? '')) throw invalid();
      name = release.version; expectedChecksum = release.checksum;
    }
    checkCancelled();
    await chmod(staged, 0o700);
    await nativeFile(staged, true);
    const destination = path.join(installation.versionsDirectory, name);
    try { onProgress?.({ phase: 'installing', version: name }); } catch { /* Progress is informational. */ }
    checkCancelled();
    try {
      // Atomic, exclusive publication of the already-complete new inode. This
      // temporary second name is in this environment only, never the host.
      await link(staged, destination);
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
      // Never turn an unrelated pre-existing version file into an entry after
      // validating a different downloaded/staged binary.
      await nativeFile(destination);
      if (await fileDigest(destination) !== (expectedChecksum ?? await fileDigest(staged))) throw invalid();
    }
    await rm(staged, { force: true });
    await recoverPublication(installation, destination);
    const copied = await nativeFile(destination, true);
    if (sourceInfo && copied.dev === sourceInfo.dev && copied.ino === sourceInfo.ino) throw invalid();
    checkCancelled();
    try { await symlink(path.relative(path.dirname(installation.entryPath), destination), installation.entryPath); }
    catch (error) { if (error.code !== 'EEXIST') throw error; }
    await resolveClaudeInstallation(installation);
    return installation;
  } catch (error) {
    // A complete version may already be in use by a racing updater. Never
    // delete persistent versions or rewrite an entry as failure recovery.
    if (error.code?.startsWith('CLAUDE_CODE_')) throw error;
    throw invalid();
  } finally { await rm(staged, { force: true }); }
}

/** Bootstrap once per environment; login/settings data are never accessed. */
export async function ensureClaudeInstallation(options) {
  const { home } = layout(options?.home);
  const previous = locks.get(home) ?? Promise.resolve();
  const next = previous.catch(() => {}).then(() => ensureInstallation(options));
  locks.set(home, next);
  try { return await next; }
  finally { if (locks.get(home) === next) locks.delete(home); }
}

// Copied into the private session runtime for physical Node (outside app.asar).
// stdout is only a validated path; the calling shell execs it, preserving PTY,
// signals and exit status without a resident Node process around the CLI.
if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  try {
    if (process.argv.length !== 4 || process.argv[2] !== '--resolve') throw invalid();
    process.stdout.write(await resolveClaudeInstallation({ home: process.argv[3] }));
  } catch {
    process.stderr.write('envara: CLAUDE_CODE_INSTALLATION_INVALID — 境舱 Claude 安装不可用，未改用本机版本。\n');
    process.exitCode = 126;
  }
}
