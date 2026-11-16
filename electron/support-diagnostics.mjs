import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, rename, unlink } from 'node:fs/promises';
import { RUNTIME_DIAGNOSTIC_STAGES } from './runtime-diagnostics.mjs';
import { exportPFNotionTrialDiagnostics } from './macos-pf-notion-trial.mjs';
import { NETWORK_DIAGNOSTIC_ERROR_CODES, sanitizeNetworkDiagnostics } from '../shared/proxy-network-diagnostics.mjs';

export const SUPPORT_DIAGNOSTICS_SCHEMA = 'envara.support-diagnostics/v1';
export const SUPPORT_DIAGNOSTICS_SECTIONS = Object.freeze(['startup', 'runtime', 'network', 'recovery', 'applications']);
const MAX_BYTES = 2 * 1024 * 1024;
const MAX_DURATION = 30 * 24 * 60 * 60 * 1000;
const startupStages = new Set(['main-entry', 'electron-ready', 'ipc-ready', 'window-create-start', 'window-created',
  'window-load', 'renderer-dom-ready', 'workspace-snapshot', 'startup-complete', 'data-directory', 'workspace-store',
  'proxy-initialize', 'sidecar-initialize', 'sidecar-files', 'sidecar-probe', 'sidecar-start', 'sidecar-process-spawn',
  'sidecar-api-ready', 'terminal-link-listen', 'system-link-listen', 'terminal-store', 'link-preferences',
  'pf-installation-verify', 'applications-store', 'application-routing-status']);
const startupCodes = new Set(['STARTUP_FAILED', 'APP_STARTING', 'APP_CLOSING', 'SIDECAR_UNAVAILABLE',
  'SIDECAR_START_FAILED', 'SIDECAR_START_TIMEOUT', 'SIDECAR_API_UNAVAILABLE', 'PROXY_CORE_UNAVAILABLE',
  'PROXY_CORE_START_FAILED', 'PROXY_CORE_START_TIMEOUT', 'PF_HELPER_UNAVAILABLE', 'PF_INSTALLED_CANDIDATE_MISMATCH']);
const runtimeStages = new Set(RUNTIME_DIAGNOSTIC_STAGES);
const networkCodes = new Set([...NETWORK_DIAGNOSTIC_ERROR_CODES, 'PROXY_CORE_STOPPED', 'PROXY_CORE_UNAVAILABLE',
  'PROXY_CORE_FAILED', 'PROXY_CORE_START_FAILED', 'PROXY_CORE_START_TIMEOUT', 'PROXY_CORE_RECOVERY_FAILED']);
const phases = new Set(['idle', 'checking', 'waiting', 'recovered']);
const reasons = new Set(['network-change', 'resume', 'retry', 'manual']);
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const integer = (value, maximum = Number.MAX_SAFE_INTEGER) => Number.isSafeInteger(value) && value >= 0 ? Math.min(value, maximum) : null;
const elapsed = value => integer(value, MAX_DURATION);
const iso = value => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) &&
  Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value ? value : null;
const code = (value, allowed) => value == null ? null : allowed.has(value) ? value : 'OTHER';
const failure = value => Object.assign(new Error('支持诊断导出失败，请重试。'), { code: value });

function startup(value) {
  if (!object(value) || !Array.isArray(value.stages) || elapsed(value.totalMs) === null) return null;
  return { entryUptimeMs: elapsed(value.entryUptimeMs), totalMs: elapsed(value.totalMs), code: code(value.code, startupCodes),
    limited: value.stages.length > 32, stages: value.stages.slice(0, 32).flatMap(item => {
      if (!object(item) || !['started', 'completed', 'failed'].includes(item.status)) return [];
      return [{ stage: startupStages.has(item.name) ? item.name : 'other', status: item.status,
        startedMs: elapsed(item.startedMs), durationMs: elapsed(item.durationMs), code: code(item.code, startupCodes) }];
    }) };
}

function runtime(value) {
  if (!object(value) || value.schema !== 'envara.runtime-diagnostics/v1' || !Array.isArray(value.pending) || !Array.isArray(value.recent)) return null;
  const project = (items, maximum, pending) => items.slice(-maximum).flatMap(item => {
    if (!object(item) || !runtimeStages.has(item.stage) || integer(item.ordinal) === null ||
        !pending && !['completed', 'failed'].includes(item.status)) return [];
    return [{ ordinal: integer(item.ordinal), stage: item.stage, status: pending ? 'pending' : item.status,
      parentOrdinal: integer(item.parentOrdinal), startedMs: elapsed(item.startedMs), elapsedMs: elapsed(item.elapsedMs),
      bytes: integer(item.bytes, MAX_BYTES) }];
  });
  return { elapsedMs: elapsed(value.elapsedMs), dropped: integer(value.dropped),
    limited: value.pending.length > 128 || value.recent.length > 256,
    pending: project(value.pending, 128, true), recent: project(value.recent, 256, false) };
}

function network(value) {
  if (!Array.isArray(value)) return null;
  const records = value.slice(0, 100).flatMap(item => {
    if (!object(item) || typeof item.ok !== 'boolean' || item.scope !== 'egress') return [];
    return [{ outcome: item.ok ? 'success' : 'failure', stale: item.stale === true,
      checkedAt: iso(item.checkedAt), latencyMs: elapsed(item.latencyMs),
      errorCode: item.ok ? null : code(item.errorCode, networkCodes), diagnostics: sanitizeNetworkDiagnostics(item.diagnostics) }];
  });
  return { records, limited: value.length > 100, omitted: Math.min(value.length, 100) - records.length };
}

function recovery(value) {
  if (!object(value) || !phases.has(value.phase) || integer(value.revision) === null || integer(value.attempt) === null) return null;
  return { revision: integer(value.revision), phase: value.phase, reason: reasons.has(value.reason) ? value.reason : null,
    attempt: integer(value.attempt), retryAt: iso(value.retryAt), checkedAt: iso(value.checkedAt) };
}

function applications(value) {
  if (!Array.isArray(value)) return null;
  const records = value.slice(0, 50).flatMap(item => {
    // Reuse the existing fixed native failure vocabulary, then drop all
    // application/run/environment identities and raw session diagnostics.
    const report = exportPFNotionTrialDiagnostics(item);
    if (!report) return [];
    return [{ phase: report.phase, active: report.active, staged: report.staged, resumed: report.resumed,
      cleanupComplete: report.cleanupComplete, cleanupUncertain: report.cleanupUncertain,
      initialFailure: report.initialFailure, cleanupFailure: report.cleanupFailure, events: report.events,
      observation: { pending: report.sessionDiagnostics?.pending === true,
        uncertaintyLatched: report.sessionDiagnostics?.uncertaintyLatched === true,
        polls: integer(report.sessionDiagnostics?.observationPolls), failedPolls: integer(report.sessionDiagnostics?.observationPollFailures) } }];
  });
  return { records, limited: value.length > 50, omitted: Math.min(value.length, 50) - records.length };
}

const projectors = { startup, runtime, network, recovery, applications };

/** Read only the probe's existing result cache. This deliberately avoids a full
 * workspace snapshot, health checks, route preparation and all probe methods.
 * Cache keys and raw results may contain private route data; never return them.
 */
export function existingNetworkDiagnostics(service) {
  const probe = service?.networkProbe;
  if (!(probe?.cache instanceof Map)) return null;
  const records = [];
  const now = typeof probe.nowMs === 'function' ? probe.nowMs() : Date.now();
  for (const entry of probe.cache.values()) {
    const value = entry?.result;
    if (!object(value) || value.scope !== 'egress' || typeof value.ok !== 'boolean') continue;
    records.push({ ok: value.ok, scope: 'egress', checkedAt: iso(value.checkedAt), latencyMs: elapsed(value.latencyMs),
      stale: !Number.isFinite(entry.timestamp) || !Number.isFinite(probe.cacheTtlMs) || now - entry.timestamp >= probe.cacheTtlMs,
      errorCode: value.ok ? null : code(value.errorCode, networkCodes), diagnostics: sanitizeNetworkDiagnostics(value.diagnostics) });
    if (records.length === 100) break;
  }
  return records;
}

async function collectSection(name, reader, timeoutMs) {
  if (typeof reader !== 'function') return { collection: 'missing', reason: 'unavailable' };
  let timer;
  try {
    const expired = Symbol('expired');
    const input = await Promise.race([Promise.resolve().then(reader),
      new Promise(resolve => { timer = setTimeout(() => resolve(expired), timeoutMs); })]);
    if (input === expired) return { collection: 'failed', reason: 'timeout' };
    if (input == null || Array.isArray(input) && input.length === 0) return { collection: 'missing', reason: 'no-records' };
    const data = projectors[name](input);
    if (!data || Array.isArray(data.records) && data.records.length === 0 && data.omitted > 0)
      return { collection: 'failed', reason: 'invalid-record' };
    return { collection: 'success', data };
  } catch { return { collection: 'failed', reason: 'unavailable' }; }
  finally { clearTimeout(timer); }
}

/** Readers return existing snapshots only. This collector never starts probes,
 * opens browsers, traverses profile directories, or reads terminal output.
 */
export async function collectSupportDiagnostics({ readers = {}, appVersion, platform, arch, nowMs = Date.now, timeoutMs = 2000 } = {}) {
  if (!Number.isFinite(timeoutMs) || timeoutMs < 1 || timeoutMs > 5000) throw failure('SUPPORT_DIAGNOSTICS_INVALID_OPTIONS');
  const sections = await Promise.all(SUPPORT_DIAGNOSTICS_SECTIONS.map(async name => [name, await collectSection(name, readers[name], timeoutMs)]));
  return { schema: SUPPORT_DIAGNOSTICS_SCHEMA, createdAt: new Date(nowMs()).toISOString(),
    app: { version: typeof appVersion === 'string' && /^\d{1,6}\.\d{1,6}\.\d{1,6}(?:-(?:alpha|beta|rc)\.\d{1,6})?$/.test(appVersion) ? appVersion : 'unknown',
      platform: ['darwin', 'win32', 'linux'].includes(platform) ? platform : 'unknown',
      arch: ['arm64', 'x64', 'ia32'].includes(arch) ? arch : 'unknown' },
    scope: 'existing-records-only', sections: Object.fromEntries(sections) };
}

function validateRequest(args) {
  if (!object(args) || Object.getPrototypeOf(args) !== Object.prototype || Reflect.ownKeys(args).length)
    throw failure('SUPPORT_DIAGNOSTICS_INVALID_REQUEST');
}

/** Only main-process save-dialog results may supply a destination. Replace an
 * approved regular file atomically; never follow its symlink or retain a partial
 * support package. No selected path is returned to the renderer or put in JSON.
 */
async function saveSupportDiagnostics(filename, document, checkOpen) {
  if (typeof filename !== 'string' || !path.isAbsolute(filename) || /[\0\r\n]/.test(filename)) throw failure('SUPPORT_DIAGNOSTICS_SAVE_FAILED');
  const encoded = JSON.stringify(document, null, 2) + '\n';
  if (Buffer.byteLength(encoded) > MAX_BYTES) throw failure('SUPPORT_DIAGNOSTICS_TOO_LARGE');
  const checkTarget = async () => {
    try {
      const info = await lstat(filename);
      if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || typeof process.getuid === 'function' && info.uid !== process.getuid())
        throw failure('SUPPORT_DIAGNOSTICS_SAVE_FAILED');
    } catch (error) { if (error.code !== 'ENOENT') throw error; }
  };
  let temporary, handle;
  try {
    checkOpen(); await checkTarget(); checkOpen();
    temporary = path.join(path.dirname(filename), `.envara-support-${randomUUID()}.tmp`);
    handle = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    await handle.writeFile(encoded); await handle.sync(); await handle.close(); handle = null;
    checkOpen(); await checkTarget(); checkOpen();
    await rename(temporary, filename); temporary = null;
  } catch (error) {
    if (error?.code === 'APP_CLOSING') throw failure('APP_CLOSING');
    throw failure('SUPPORT_DIAGNOSTICS_SAVE_FAILED');
  } finally { await handle?.close().catch(() => {}); if (temporary) await unlink(temporary).catch(() => {}); }
}

export async function exportSupportDiagnostics({ args = {}, showSaveDialog, checkOpen = () => {}, ...options } = {}) {
  try {
    validateRequest(args);
    if (typeof showSaveDialog !== 'function' || typeof checkOpen !== 'function') throw failure('SUPPORT_DIAGNOSTICS_INVALID_OPTIONS');
    checkOpen();
    const document = await collectSupportDiagnostics(options);
    checkOpen();
    const choice = await showSaveDialog({ title: '导出支持诊断', defaultPath: 'Envara-Support-Diagnostics.json',
      filters: [{ name: 'JSON', extensions: ['json'] }] });
    checkOpen();
    if (choice?.canceled || !choice?.filePath) return { canceled: true };
    await saveSupportDiagnostics(choice.filePath, document, checkOpen);
    return { exported: true };
  } catch (error) {
    const known = ['APP_CLOSING', 'SUPPORT_DIAGNOSTICS_INVALID_REQUEST', 'SUPPORT_DIAGNOSTICS_INVALID_OPTIONS',
      'SUPPORT_DIAGNOSTICS_TOO_LARGE', 'SUPPORT_DIAGNOSTICS_SAVE_FAILED'];
    throw failure(known.includes(error?.code) ? error.code : 'SUPPORT_DIAGNOSTICS_SAVE_FAILED');
  }
}
