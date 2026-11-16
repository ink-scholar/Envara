import path from 'node:path';
import { constants } from 'node:fs';
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, mkdtemp, lstat, realpath, open, rename, rm } from 'node:fs/promises';
import { applicationVersionParts as versionParts, compareApplicationVersions } from '../shared/application-version.mjs';

const RELEASE_API = 'https://api.github.com/repos/ink-scholar/Envara/releases/latest';
const RELEASE_BASE = 'https://github.com/ink-scholar/Envara/releases/download/';
const HOSTS = new Set(['api.github.com', 'github.com', 'release-assets.githubusercontent.com']);
const METADATA_LIMIT = 2 * 1024 * 1024;
const ARCHIVE_LIMIT = 1024 * 1024 * 1024;
const REQUEST_TIMEOUT = 30_000;
const DOWNLOAD_TIMEOUT = 15 * 60_000;

/** Only these codes cross the desktop bridge. Exceptions, URLs and paths do not. */
export const APPLICATION_UPDATE_ERRORS = Object.freeze([
  'APP_UPDATE_SYSTEM_UNSUPPORTED',
  'APP_UPDATE_DEVELOPMENT', 'APP_UPDATE_UNSUPPORTED_PLATFORM', 'APP_UPDATE_INVALID_VERSION',
  'APP_UPDATE_ASSET_UNAVAILABLE', 'APP_UPDATE_METADATA_INVALID', 'APP_UPDATE_NETWORK',
  'APP_UPDATE_TIMEOUT', 'APP_UPDATE_TOO_LARGE', 'APP_UPDATE_HASH_MISMATCH',
  'APP_UPDATE_STORAGE', 'APP_UPDATE_UNSAFE_PATH', 'APP_UPDATE_PREPARE_FAILED',
  'APP_UPDATE_CHECK_REQUIRED', 'APP_UPDATE_BUSY', 'APP_UPDATE_CLEANUP',
  'APP_UPDATE_INSTALL_FAILED', 'APP_UPDATE_CLOSED',
  'APP_UPDATE_LOCATION', 'APP_UPDATE_PACKAGE', 'APP_UPDATE_HELPER', 'APP_UPDATE_HELPER_INVALID',
  'APP_UPDATE_ROLLBACK_FAILED', 'APP_UPDATE_PARENT', 'APP_UPDATE_PROTOCOL', 'APP_UPDATE_APP_RUNNING',
]);
const codes = new Set(APPLICATION_UPDATE_ERRORS);
const failure = code => Object.assign(new Error(code), { code });
const same = (a, b) => a.dev === b.dev && a.ino === b.ino;
const owned = info => !process.getuid || info.uid === process.getuid();
const digest = data => createHash('sha256').update(data).digest('hex');
const safeCode = (error, fallback) => codes.has(error?.code) ? error.code : fallback;
const nativeError = value => {
  if (codes.has(value)) return value;
  if (['APP_UPDATE_ROLLBACK_UNCERTAIN'].includes(value)) return 'APP_UPDATE_ROLLBACK_FAILED';
  if (['APP_UPDATE_PARENT_TIMEOUT', 'APP_UPDATE_PARENT_UNKNOWN'].includes(value)) return 'APP_UPDATE_PARENT';
  if (['APP_UPDATE_CLEANUP_UNCERTAIN'].includes(value)) return 'APP_UPDATE_CLEANUP';
  if (['APP_UPDATE_ARCHITECTURE', 'APP_UPDATE_PATH', 'APP_UPDATE_PREPARATION', 'APP_UPDATE_VALIDATION', 'APP_UPDATE_VERSION'].includes(value)) return 'APP_UPDATE_PACKAGE';
  if (['APP_UPDATE_TOOL_TIMEOUT'].includes(value)) return 'APP_UPDATE_TIMEOUT';
  if (['APP_UPDATE_TOOL_FAILED'].includes(value)) return 'APP_UPDATE_HELPER';
  return 'APP_UPDATE_INSTALL_FAILED';
};
const receiptCodes = new Set([...codes, ...[
  'ARCHITECTURE', 'AUTHORIZATION', 'CANCELLED', 'CLEANUP_UNCERTAIN', 'FAILED', 'PARENT_TIMEOUT',
  'PARENT_UNKNOWN', 'PATH', 'PREPARATION', 'REPLACE_FAILED', 'ROLLBACK_UNCERTAIN', 'ROLLED_BACK',
  'TOOL_FAILED', 'TOOL_TIMEOUT', 'VALIDATION', 'VERSION',
].map(code => `APP_UPDATE_${code}`)]);
const cancelled = () => failure('APP_UPDATE_CANCELLED'); // Internal control flow only.
const newer = (next, current) => compareApplicationVersions(next, current) > 0;

function officialUrl(value, base) {
  let url;
  try { url = new URL(value, base); } catch { throw failure('APP_UPDATE_METADATA_INVALID'); }
  if (url.protocol !== 'https:' || !HOSTS.has(url.hostname) || url.username || url.password || url.port || url.hash) throw failure('APP_UPDATE_METADATA_INVALID');
  return url.href;
}

function assetFor(release, name, maximum) {
  const matches = release.assets.filter(asset => asset?.name === name);
  if (!matches.length) throw failure('APP_UPDATE_ASSET_UNAVAILABLE');
  if (matches.length !== 1) throw failure('APP_UPDATE_METADATA_INVALID');
  const asset = matches[0];
  const expectedUrl = `${RELEASE_BASE}${release.tag_name}/${name}`;
  if (asset.state !== 'uploaded' || !Number.isSafeInteger(asset.id) || asset.id <= 0
    || !Number.isSafeInteger(asset.size) || asset.size <= 0
    || typeof asset.digest !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(asset.digest)
    || asset.browser_download_url !== expectedUrl) throw failure('APP_UPDATE_METADATA_INVALID');
  if (asset.size > maximum) throw failure('APP_UPDATE_TOO_LARGE');
  return { id: asset.id, name, size: asset.size, sha256: asset.digest.slice(7), url: expectedUrl };
}

function releaseSelection(release, currentVersion) {
  if (!release || typeof release !== 'object' || Array.isArray(release)
    || release.draft !== false || release.prerelease !== false
    || typeof release.tag_name !== 'string' || !release.tag_name.startsWith('v')
    || !versionParts(release.tag_name.slice(1))
    || !Number.isSafeInteger(release.id) || release.id <= 0
    || !Array.isArray(release.assets) || release.assets.length > 128) throw failure('APP_UPDATE_METADATA_INVALID');
  const version = release.tag_name.slice(1);
  if (!newer(version, currentVersion)) return { version, current: true };
  return { version, releaseId: release.id,
    archive: assetFor(release, `Envara-${version}-mac-arm64.zip`, ARCHIVE_LIMIT),
    sums: assetFor(release, 'SHA256SUMS.txt', METADATA_LIMIT) };
}

function verifySums(bytes, selection) {
  if (digest(bytes) !== selection.sums.sha256) throw failure('APP_UPDATE_HASH_MISMATCH');
  const entries = new Map();
  for (const line of bytes.toString('utf8').split(/\r?\n/)) {
    if (!line) continue;
    const match = /^([a-f0-9]{64}) [ *]([A-Za-z0-9][A-Za-z0-9._-]{0,200})$/.exec(line);
    if (!match || entries.has(match[2])) throw failure('APP_UPDATE_METADATA_INVALID');
    entries.set(match[2], match[1]);
  }
  if (entries.get(selection.archive.name) !== selection.archive.sha256) throw failure('APP_UPDATE_HASH_MISMATCH');
}

function abortable(promise, signal, onLate) {
  if (signal.aborted) return Promise.reject(cancelled());
  return new Promise((resolve, reject) => {
    let finished = false;
    const aborted = () => { if (!finished) { finished = true; reject(cancelled()); } };
    signal.addEventListener('abort', aborted, { once: true });
    Promise.resolve(promise).then(value => {
      signal.removeEventListener('abort', aborted);
      if (finished) { try { onLate?.(value); } catch {} return; }
      finished = true; resolve(value);
    }, error => {
      signal.removeEventListener('abort', aborted);
      if (!finished) { finished = true; reject(error); }
    });
  });
}

async function consume(response, { signal, maximum, expectedSize, chunk }) {
  if (!response.body?.getReader) throw failure('APP_UPDATE_NETWORK');
  const length = response.headers.get('content-length');
  if (length != null && (!/^\d+$/.test(length) || Number(length) > maximum)) throw failure('APP_UPDATE_TOO_LARGE');
  if (expectedSize != null && length != null && Number(length) !== expectedSize) throw failure('APP_UPDATE_HASH_MISMATCH');
  const reader = response.body.getReader();
  let received = 0;
  try {
    while (true) {
      const item = await abortable(reader.read(), signal);
      if (item.done) break;
      if (!(item.value instanceof Uint8Array)) throw failure('APP_UPDATE_NETWORK');
      received += item.value.byteLength;
      if (received > maximum) throw failure('APP_UPDATE_TOO_LARGE');
      if (expectedSize != null && received > expectedSize) throw failure('APP_UPDATE_HASH_MISMATCH');
      await chunk(item.value, received);
      if (signal.aborted) throw cancelled();
    }
    if (expectedSize != null && received !== expectedSize) throw failure('APP_UPDATE_HASH_MISMATCH');
    return received;
  } finally { void reader.cancel().catch(() => {}); }
}

async function inspectCacheRoot(cacheDir, create = false) {
  if (typeof cacheDir !== 'string' || !path.isAbsolute(cacheDir) || /[\x00-\x1f\x7f]/.test(cacheDir)) throw failure('APP_UPDATE_UNSAFE_PATH');
  if (create) await mkdir(cacheDir, { recursive: true, mode: 0o700 });
  const identity = await lstat(cacheDir);
  if (!identity.isDirectory() || identity.isSymbolicLink() || !owned(identity) || (identity.mode & 0o077)) throw failure('APP_UPDATE_UNSAFE_PATH');
  return { root: await realpath(cacheDir), identity };
}

async function readPrivateJson(filename) {
  const before = await lstat(filename);
  if (!before.isFile() || before.isSymbolicLink() || !owned(before) || (before.mode & 0o077) || before.nlink !== 1 || before.size > 4096) throw failure('APP_UPDATE_PROTOCOL');
  const handle = await open(filename, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    if (!same(before, await handle.stat())) throw failure('APP_UPDATE_PROTOCOL');
    const buffer = Buffer.alloc(4097);
    let offset = 0;
    while (offset < buffer.length) { const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, offset); if (!bytesRead) break; offset += bytesRead; }
    const after = await handle.stat();
    if (offset !== before.size || after.size !== before.size || after.mtimeMs !== before.mtimeMs
      || after.ctimeMs !== before.ctimeMs || !same(before, await lstat(filename))) throw failure('APP_UPDATE_PROTOCOL');
    return JSON.parse(buffer.subarray(0, offset).toString('utf8'));
  } finally { await handle.close(); }
}

/** Main-process only: a read-only startup gate may inspect this private record.
 * No returned path is renderer data or renewed authority to install a package.
 * A missing receipt says nothing about whether the helper is still active. */
export async function readApplicationInstallation({ cacheDir }) {
  let root, pointer;
  try {
    ({ root } = await inspectCacheRoot(cacheDir));
    pointer = await readPrivateJson(path.join(root, 'last-installation.json'));
  } catch (error) { if (error.code === 'ENOENT') return null; throw failure(safeCode(error, 'APP_UPDATE_PROTOCOL')); }
  if (!pointer || pointer.schema !== 'envara.app-update/v1' || !/^update-[A-Za-z0-9]{6}$/.test(pointer.stageName ?? '')
    || !versionParts(pointer.version) || !/^\d{1,30}$/.test(pointer.stageDev ?? '') || !/^\d{1,30}$/.test(pointer.stageIno ?? '')
    || !Number.isSafeInteger(pointer.originatingPid) || pointer.originatingPid <= 0 || pointer.originatingPid > 2147483647
    || !['pending', 'failed'].includes(pointer.outcome) || (pointer.outcome === 'failed' && !codes.has(pointer.error))) throw failure('APP_UPDATE_PROTOCOL');
  const record = { stageRoot: path.join(root, pointer.stageName), version: pointer.version,
    originatingPid: pointer.originatingPid, outcome: pointer.outcome, error: pointer.outcome === 'failed' ? pointer.error : null, receipt: null };
  try {
    let info;
    try { info = await lstat(record.stageRoot); }
    catch (error) { if (error.code === 'ENOENT' && pointer.outcome === 'failed') return { ...record, stageRoot: null }; throw error; }
    if (!info.isDirectory() || info.isSymbolicLink() || !owned(info) || (info.mode & 0o077)
      || String(info.dev) !== pointer.stageDev || String(info.ino) !== pointer.stageIno || await realpath(record.stageRoot) !== record.stageRoot) throw failure('APP_UPDATE_PROTOCOL');
    let result;
    try { result = await readPrivateJson(path.join(record.stageRoot, 'result.json')); }
    catch (error) { if (error.code === 'ENOENT') return record; throw error; }
    if (!result || result.schema !== 'envara.mac-update/v1'
      || (result.backupName != null && !/^\.envara-update-[a-f0-9]{16}$/.test(result.backupName))
      || (result.relaunch != null && !['requested', 'failed'].includes(result.relaunch))) throw failure('APP_UPDATE_PROTOCOL');
    if (result.type === 'installed' && result.version === pointer.version && ['requested', 'failed'].includes(result.relaunch)) {
      record.receipt = { type: 'installed', version: result.version, relaunch: result.relaunch };
    } else if (result.type === 'failed' && receiptCodes.has(result.code)
      && typeof result.committed === 'boolean' && typeof result.replaced === 'boolean'
      && (result.cleanupCode == null || result.cleanupCode === 'APP_UPDATE_CLEANUP_UNCERTAIN')) {
      record.receipt = { type: 'failed', code: result.code, committed: result.committed, replaced: result.replaced,
        ...(result.cleanupCode ? { cleanupCode: result.cleanupCode } : {}), ...(result.relaunch ? { relaunch: result.relaunch } : {}) };
    } else throw failure('APP_UPDATE_PROTOCOL');
    if (result.backupName) record.receipt.backupName = result.backupName;
    return record;
  } catch { throw Object.assign(failure('APP_UPDATE_PROTOCOL'), { version: pointer.version }); }
}

/**
 * App-body updates only. No operation starts before an explicit method call.
 * prepare owns archive inspection/extraction and returns a private handle.
 * install may return { accepted: true, completion: Promise } to acknowledge IPC
 * before quitting. It owns rollback once installation starts. A rejection means
 * the untouched/restored candidate can be retried; success transfers ownership.
 */
export function createApplicationUpdater({ currentVersion, platform, arch, packaged, cacheDir,
  prepare, install: installCandidate, fetch: request = globalThis.fetch, now = Date.now }) {
  const supportError = !packaged ? 'APP_UPDATE_DEVELOPMENT' : platform !== 'darwin' || arch !== 'arm64'
    ? 'APP_UPDATE_UNSUPPORTED_PLATFORM' : !versionParts(currentVersion) ? 'APP_UPDATE_INVALID_VERSION' : null;
  let state = { status: supportError ? 'unsupported' : 'idle', currentVersion: versionParts(currentVersion) ? currentVersion : '',
    latestVersion: null, progress: { percent: 0, received: 0, total: 0 }, error: supportError };
  let selection = null, candidate = null, operation = null, cancelFlight = null, closed = false, lastResult = null, recoveryFlight = null, installationRevision = 0;
  const snapshot = () => ({ ...state, progress: { ...state.progress }, canInstall: !!candidate && !operation && !closed,
    lastResult: lastResult ? { ...lastResult } : null });
  const assertActive = op => { if (closed || op.controller.signal.aborted || operation !== op) throw cancelled(); };
  const resetProgress = () => { state.progress = { percent: 0, received: 0, total: 0 }; };
  const blocked = () => {
    if (closed) return { ...snapshot(), error: 'APP_UPDATE_CLOSED', canInstall: false };
    return supportError ? snapshot() : null;
  };

  async function recover() {
    if (supportError) return;
    const revision = installationRevision;
    try {
      const record = await readApplicationInstallation({ cacheDir });
      if (revision !== installationRevision) return;
      if (!record) return;
      lastResult = { status: record.outcome, version: record.version, error: record.error };
      if (record.receipt?.type === 'installed') lastResult = { status: 'installed', version: record.version,
        error: record.receipt.relaunch === 'failed' ? 'APP_UPDATE_HELPER' : null };
      else if (record.receipt?.type === 'failed') lastResult = { status: 'failed', version: record.version, error: nativeError(record.receipt.code) };
    } catch (error) {
      if (revision !== installationRevision) return;
      if (versionParts(error.version)) lastResult = { status: 'pending', version: error.version, error: 'APP_UPDATE_PROTOCOL' };
      else if (state.status === 'idle') { state.status = 'error'; state.error = 'APP_UPDATE_PROTOCOL'; }
    }
  }
  const ready = Promise.resolve().then(recover).then(snapshot);

  function refreshResult() {
    if (recoveryFlight) return recoveryFlight;
    recoveryFlight = (async () => {
      await ready;
      if (lastResult?.status === 'pending' && !operation) await recover();
      return snapshot();
    })().finally(() => { recoveryFlight = null; });
    return recoveryFlight;
  }

  async function persistInstallation(record, outcome, error = null) {
    installationRevision++;
    await assertStage(record);
    const target = path.join(record.root, 'last-installation.json');
    try {
      const prior = await lstat(target);
      if (!prior.isFile() || prior.isSymbolicLink() || !owned(prior) || prior.nlink !== 1 || (prior.mode & 0o077)) throw failure('APP_UPDATE_UNSAFE_PATH');
    } catch (error) { if (error.code !== 'ENOENT') throw error; }
    const pointer = { schema: 'envara.app-update/v1', stageName: path.basename(record.directory), version: record.version,
      stageDev: String(record.identity.dev), stageIno: String(record.identity.ino), originatingPid: process.pid, outcome, ...(error ? { error } : {}) };
    const temporary = path.join(record.root, `.installation-${randomUUID()}.partial`);
    let handle, temporaryIdentity;
    try {
      handle = await open(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | (constants.O_NOFOLLOW ?? 0), 0o600);
      temporaryIdentity = await handle.stat();
      await handle.writeFile(JSON.stringify(pointer)); await handle.sync(); await handle.close(); handle = null;
      await assertStage(record);
      if (!same(temporaryIdentity, await lstat(temporary))) throw failure('APP_UPDATE_UNSAFE_PATH');
      await rename(temporary, target);
      const directory = await open(record.root, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
      try {
        if (!same(record.rootIdentity, await directory.stat())) throw failure('APP_UPDATE_UNSAFE_PATH');
        await directory.sync();
      } finally { await directory.close(); }
      lastResult = { status: outcome, version: record.version, error };
    } catch (error) { throw failure(safeCode(error, 'APP_UPDATE_STORAGE')); }
    finally {
      await handle?.close();
      try {
        if (temporaryIdentity && same(record.rootIdentity, await lstat(record.root))
          && same(temporaryIdentity, await lstat(temporary))) await rm(temporary);
      } catch {}
    }
  }

  async function fetchResponse(url, op, consumeResponse, timeout = REQUEST_TIMEOUT) {
    const controller = new AbortController();
    let timedOut = false, response;
    const abort = () => controller.abort();
    op.controller.signal.addEventListener('abort', abort, { once: true });
    if (op.controller.signal.aborted) controller.abort();
    const started = now();
    const timer = setTimeout(() => { timedOut = true; controller.abort(); }, timeout);
    timer.unref?.();
    try {
      let target = officialUrl(url);
      for (let redirects = 0; redirects <= 4; redirects++) {
        assertActive(op);
        if (now() - started > timeout) { timedOut = true; throw cancelled(); }
        response = await abortable(request(target, { method: 'GET', redirect: 'manual', credentials: 'omit', cache: 'no-store',
          headers: { Accept: target === RELEASE_API ? 'application/vnd.github+json' : 'application/octet-stream',
            'Accept-Encoding': 'identity', 'User-Agent': 'Envara-Updater', 'X-GitHub-Api-Version': '2022-11-28' }, signal: controller.signal }), controller.signal,
        late => { void late?.body?.cancel?.().catch(() => {}); });
        if (response.redirected) throw failure('APP_UPDATE_METADATA_INVALID');
        if ([301, 302, 303, 307, 308].includes(response.status)) {
          void response.body?.cancel?.().catch(() => {});
          const location = response.headers.get('location');
          if (!location || redirects === 4) throw failure('APP_UPDATE_METADATA_INVALID');
          target = officialUrl(location, target);
          continue;
        }
        if (response.status !== 200) { void response.body?.cancel?.().catch(() => {}); throw failure('APP_UPDATE_NETWORK'); }
        return await consumeResponse(response, controller.signal);
      }
    } catch (error) {
      if (op.controller.signal.aborted || closed) throw cancelled();
      if (timedOut) throw failure('APP_UPDATE_TIMEOUT');
      throw failure(safeCode(error, 'APP_UPDATE_NETWORK'));
    } finally {
      clearTimeout(timer); op.controller.signal.removeEventListener('abort', abort);
      void response?.body?.cancel?.().catch(() => {});
    }
  }

  async function bytes(url, op, expectedSize) {
    return fetchResponse(url, op, async (response, signal) => {
      const chunks = [];
      await consume(response, { signal, maximum: METADATA_LIMIT, expectedSize, chunk: value => { chunks.push(Buffer.from(value)); } });
      return Buffer.concat(chunks);
    });
  }

  async function ownedStage() {
    try {
      const { root, identity: rootInfo } = await inspectCacheRoot(cacheDir, true);
      const directory = await mkdtemp(path.join(root, 'update-'));
      const identity = await lstat(directory);
      if (!same(rootInfo, await lstat(root))) throw failure('APP_UPDATE_UNSAFE_PATH');
      return { directory, identity, root, rootIdentity: rootInfo, committed: false };
    } catch (error) { throw failure(safeCode(error, 'APP_UPDATE_STORAGE')); }
  }

  async function assertStage(record) {
    const info = await lstat(record.directory), rootInfo = await lstat(record.root);
    if (!same(info, record.identity) || info.isSymbolicLink() || !same(rootInfo, record.rootIdentity)
      || rootInfo.isSymbolicLink() || await realpath(record.directory) !== record.directory) throw failure('APP_UPDATE_UNSAFE_PATH');
  }

  async function discard(record) {
    if (!record || record.committed) return;
    try { await assertStage(record); await rm(record.directory, { recursive: true }); }
    catch (error) { if (error.code !== 'ENOENT') throw failure('APP_UPDATE_CLEANUP'); }
  }

  function run(kind, task) {
    const op = { kind, controller: new AbortController(), promise: null };
    operation = op;
    op.promise = Promise.resolve().then(async () => { await ready; assertActive(op); await task(op); }).catch(error => {
      op.errorCode = safeCode(error, 'APP_UPDATE_NETWORK');
      if (operation === op && !op.controller.signal.aborted && !closed) {
        const code = safeCode(error, 'APP_UPDATE_NETWORK');
        state.status = code === 'APP_UPDATE_ASSET_UNAVAILABLE' ? 'unsupported' : 'error'; state.error = code;
      }
    }).finally(() => { if (operation === op) operation = null; }).then(snapshot);
    return op.promise;
  }

  function check() {
    const stop = blocked(); if (stop) return Promise.resolve(stop);
    if (cancelFlight) return cancelFlight;
    if (operation) return operation.kind === 'install' ? Promise.resolve(snapshot()) : operation.promise;
    if (candidate) return Promise.resolve(snapshot());
    selection = null; state = { ...state, status: 'checking', latestVersion: null, error: null }; resetProgress();
    return run('check', async op => {
      let release;
      const payload = await bytes(RELEASE_API, op);
      try { release = JSON.parse(payload.toString('utf8')); } catch { throw failure('APP_UPDATE_METADATA_INVALID'); }
      const result = releaseSelection(release, currentVersion); assertActive(op);
      if (result.current) { state.status = 'current'; state.latestVersion = result.version; }
      else { selection = result; state.status = 'available'; state.latestVersion = result.version; }
    });
  }

  function download() {
    const stop = blocked(); if (stop) return Promise.resolve(stop);
    if (cancelFlight) return cancelFlight;
    if (operation) return operation.kind === 'install' ? Promise.resolve(snapshot()) : operation.promise;
    if (candidate) return Promise.resolve(snapshot());
    if (!selection) { state.status = 'error'; state.error = 'APP_UPDATE_CHECK_REQUIRED'; state.latestVersion = null; return Promise.resolve(snapshot()); }
    const selected = selection;
    state.status = 'downloading'; state.error = null; state.progress = { percent: 0, received: 0, total: selected.archive.size };
    return run('download', async op => {
      let record;
      try {
        verifySums(await bytes(selected.sums.url, op, selected.sums.size), selected); assertActive(op);
        record = await ownedStage(); record.version = selected.version; assertActive(op);
        const partial = path.join(record.directory, 'archive.partial'), archivePath = path.join(record.directory, 'Envara.zip');
        let handle;
        try { handle = await open(partial, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | (constants.O_NOFOLLOW ?? 0), 0o600); }
        catch { throw failure('APP_UPDATE_STORAGE'); }
        const hash = createHash('sha256');
        try {
          await fetchResponse(selected.archive.url, op, async (response, signal) => {
            if (response.headers.get('content-encoding') && response.headers.get('content-encoding') !== 'identity') throw failure('APP_UPDATE_METADATA_INVALID');
            return consume(response, { signal, maximum: ARCHIVE_LIMIT, expectedSize: selected.archive.size, chunk: async (value, received) => {
              assertActive(op); hash.update(value);
              try {
                let offset = 0;
                while (offset < value.byteLength) {
                  const { bytesWritten } = await handle.write(value, offset, value.byteLength - offset);
                  if (!bytesWritten) throw failure('APP_UPDATE_STORAGE'); offset += bytesWritten;
                }
              } catch { throw failure('APP_UPDATE_STORAGE'); }
              assertActive(op);
              state.progress = { received, total: selected.archive.size, percent: Math.floor(received * 100 / selected.archive.size) };
            } });
          }, DOWNLOAD_TIMEOUT);
          if (hash.digest('hex') !== selected.archive.sha256) throw failure('APP_UPDATE_HASH_MISMATCH');
          await handle.sync();
        } finally { await handle.close(); }
        assertActive(op); await assertStage(record); await rename(partial, archivePath);
        state.status = 'verifying';
        try {
          if (typeof prepare !== 'function') throw failure('APP_UPDATE_PREPARE_FAILED');
          record.prepared = await prepare({ archivePath, version: selected.version, sha256: selected.archive.sha256,
            stagingDir: record.directory, signal: op.controller.signal });
          if (record.prepared == null) throw failure('APP_UPDATE_PREPARE_FAILED');
        } catch (error) { throw failure(safeCode(error, 'APP_UPDATE_PREPARE_FAILED')); }
        assertActive(op); await assertStage(record); candidate = record; state.status = 'ready';
      } catch (error) {
        try { await discard(record); } catch (cleanup) { throw cleanup; }
        throw error;
      }
    });
  }

  function install() {
    const stop = blocked(); if (stop) return Promise.resolve(stop);
    if (cancelFlight) return cancelFlight;
    if (operation) return operation.kind === 'install' ? Promise.resolve(snapshot()) : operation.promise;
    if (!candidate) { state.status = 'error'; state.error = 'APP_UPDATE_CHECK_REQUIRED'; return Promise.resolve(snapshot()); }
    const record = candidate, op = { kind: 'install', promise: null };
    operation = op; state.status = 'installing'; state.error = null;
    const finish = async error => {
      if (operation !== op || candidate !== record) return;
      if (error) {
        const code = safeCode(error, 'APP_UPDATE_INSTALL_FAILED');
        await persistInstallation(record, 'failed', code).catch(() => {});
        state.status = 'ready'; state.error = code;
      }
      else { record.committed = true; candidate = null; }
      operation = null;
    };
    op.promise = Promise.resolve().then(async () => {
      await assertStage(record);
      if (typeof installCandidate !== 'function') throw failure('APP_UPDATE_INSTALL_FAILED');
      // The installation dependency may schedule quitting on setImmediate. All
      // persistence must finish before invoking it so IPC can acknowledge first.
      await persistInstallation(record, 'pending');
      const result = await installCandidate(record.prepared);
      if (result?.accepted === true && result.completion && typeof result.completion.then === 'function') {
        void Promise.resolve(result.completion).then(() => finish(), error => finish(error));
      } else if (result == null) await finish();
      else throw failure('APP_UPDATE_PROTOCOL');
    }).catch(finish).then(snapshot);
    return op.promise;
  }

  function cancel() {
    if (operation?.kind === 'install') return Promise.resolve(snapshot());
    if (cancelFlight) return cancelFlight;
    const op = operation;
    op?.controller.abort();
    cancelFlight = (async () => {
      if (op) await op.promise;
      const record = candidate; candidate = null;
      try {
        await discard(record);
        if (op?.errorCode === 'APP_UPDATE_CLEANUP') throw failure('APP_UPDATE_CLEANUP');
        state.status = selection ? 'available' : supportError ? 'unsupported' : 'idle';
        state.error = supportError; resetProgress();
      } catch { state.status = 'error'; state.error = 'APP_UPDATE_CLEANUP'; }
      return snapshot();
    })().finally(() => { cancelFlight = null; });
    return cancelFlight;
  }

  function close() { closed = true; return cancel(); }
  return { ready, snapshot, refreshResult, check, download, cancel, install, close };
}
