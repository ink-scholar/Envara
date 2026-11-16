import { readApplicationInstallation } from './application-updates.mjs';
import { applicationVersionParts, compareApplicationVersions } from '../shared/application-version.mjs';

const version = value => applicationVersionParts(value) !== null;
const older = (current, installed) => compareApplicationVersions(current, installed) < 0;
const failure = code => Object.assign(new Error(code), { code });
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

/** Run before allocating owned services. This module only reads installation
 * evidence and asks a trusted bundled helper for process status. It never
 * deletes a stale marker, signals a process, changes a path or launches Envara.
 * Main must exit on defer-to-installer; waiting in an old loaded entry would
 * hold the single-instance lock and obstruct the helper's final replacement.
 */
export async function waitForApplicationUpdateStartup({ cacheDir, currentVersion, inspectInstaller,
  checkOpen = () => {}, timeoutMs = 120000, intervalMs = 500,
  readInstallation = () => readApplicationInstallation({ cacheDir }),
  now = () => performance.now(), wait = pause } = {}) {
  if (!version(currentVersion)) throw failure('APP_UPDATE_INVALID_VERSION');
  if (![inspectInstaller, readInstallation, checkOpen, now, wait].every(value => typeof value === 'function')
    || !Number.isFinite(timeoutMs) || timeoutMs < 1 || timeoutMs > 300000
    || !Number.isFinite(intervalMs) || intervalMs < 1 || intervalMs > 5000) throw new TypeError('Invalid application update startup options.');
  const deadline = now() + timeoutMs;
  let waitingFor = null;
  const read = async () => {
    checkOpen();
    let value;
    try { value = await readInstallation(); }
    catch { throw failure('APP_UPDATE_PROTOCOL'); }
    checkOpen();
    if (value === null) return null;
    if (!value || !version(value.version) || !Number.isSafeInteger(value.originatingPid) || value.originatingPid <= 1
      || value.originatingPid > 2147483647 || !['pending', 'failed'].includes(value.outcome)
      || value.stageRoot !== null && (typeof value.stageRoot !== 'string' || !value.stageRoot)) throw failure('APP_UPDATE_PROTOCOL');
    return value;
  };
  const completed = value => {
    if (value?.receipt?.type === 'installed') {
      if (value.receipt.version !== value.version) throw failure('APP_UPDATE_PROTOCOL');
      // A retained receipt may predate a manual upgrade. Restart only when the
      // loaded code is older, otherwise that history would cause a relaunch loop.
      return older(currentVersion, value.receipt.version)
        ? { status: 'restart-required', version: value.version }
        : { status: 'ready', result: 'installed', version: value.version };
    }
    if (value?.receipt?.type === 'failed') {
      const receipt = value.receipt;
      if (typeof receipt.committed !== 'boolean' || typeof receipt.replaced !== 'boolean') throw failure('APP_UPDATE_PROTOCOL');
      // A final failure is safe to reopen only when the original application
      // was untouched or definitively restored. Uncertain rollback or cleanup
      // must not let already-loaded code start new environment resources.
      if (receipt.replaced || ['APP_UPDATE_ROLLBACK_UNCERTAIN', 'APP_UPDATE_ROLLBACK_FAILED'].includes(receipt.code)) throw failure('APP_UPDATE_ROLLBACK_FAILED');
      if (receipt.cleanupCode != null || ['APP_UPDATE_CLEANUP_UNCERTAIN', 'APP_UPDATE_CLEANUP'].includes(receipt.code)) throw failure('APP_UPDATE_CLEANUP');
      return { status: 'ready', result: 'failed', version: value.version };
    }
    if (value?.receipt != null) throw failure('APP_UPDATE_PROTOCOL');
    // Main can record a failed, never-committed preparation whose staging was
    // already removed. The private reader distinguishes this from a missing or
    // substituted pending installation, which must be refused.
    if (value?.stageRoot === null) {
      if (value.outcome !== 'failed') throw failure('APP_UPDATE_PROTOCOL');
      return { status: 'ready', result: 'failed', version: value.version };
    }
    return null;
  };
  while (true) {
    const pending = await read();
    if (!pending) {
      if (waitingFor) throw failure('APP_UPDATE_PROTOCOL');
      return { status: 'ready', result: 'none' };
    }
    const identity = `${pending.stageRoot}\n${pending.originatingPid}\n${pending.version}`;
    if (waitingFor && identity !== waitingFor) throw failure('APP_UPDATE_PROTOCOL');
    const result = completed(pending);
    if (result) return result;
    checkOpen();
    let state;
    try { state = await inspectInstaller({ stageRoot: pending.stageRoot, originatingPid: pending.originatingPid }); }
    catch { throw failure('APP_UPDATE_PARENT'); }
    checkOpen();
    if (!state || typeof state.active !== 'boolean' || Object.keys(state).some(key => key !== 'active')) throw failure('APP_UPDATE_PROTOCOL');
    if (!state.active) {
      // The helper may have published its final receipt immediately before
      // exiting. Re-read it rather than starting this already-loaded old entry.
      const final = await read();
      if (!final || `${final.stageRoot}\n${final.originatingPid}\n${final.version}` !== identity) throw failure('APP_UPDATE_PROTOCOL');
      return completed(final) ?? { status: 'ready', result: 'abandoned', version: final.version };
    }
    if (currentVersion !== pending.version) return { status: 'defer-to-installer', version: pending.version };
    waitingFor = identity;
    const remaining = deadline - now();
    if (remaining <= 0) throw failure('APP_UPDATE_TIMEOUT');
    await wait(Math.min(intervalMs, remaining));
    checkOpen();
  }
}
