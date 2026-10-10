import fs from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { fingerprintProvider, productionIdentity } from '../native/macos-app-routing/provider-reuse.mjs';

export const fixtureRuntimeNamespace = 'owned-fixture-acceptance';
const hostName = 'EnvaraRoutingAcceptance.app';
const helperRelativePath = `${hostName}/Contents/MacOS/EnvaraAppRoutingHelper`;
const providerRelativePath = `${hostName}/Contents/Library/SystemExtensions/${productionIdentity.providerIdentifier}.systemextension`;
const methodSet = new Set(['status', 'setupProfiles', 'activateExtension', 'prepareFixture', 'launchFixture', 'stopFixture', 'revokeFixture']);
const reasons = Object.freeze({
  ACCEPTANCE_BUILD_INVALID: 'The owned fixture build is missing, changed, or incompatible; rebuild it before testing.',
  ACCEPTANCE_ARGUMENT_INVALID: 'Use no argument for status, or exactly one of --setup-profiles, --activate-extension, --run-fixtures.',
  ACCEPTANCE_NOT_READY: 'The signed Mac extension or its profile is not ready for owned fixture acceptance.',
  ACCEPTANCE_OPERATION_REFUSED: 'The owned fixture helper refused the operation.',
  ACCEPTANCE_HELPER_UNAVAILABLE: 'The owned fixture helper could not be started.',
  ACCEPTANCE_HELPER_FAILED: 'The owned fixture helper ended without a valid result.',
  ACCEPTANCE_RESPONSE_INVALID: 'The owned fixture helper returned an invalid response.',
  ACCEPTANCE_HELPER_DEADLINE: 'The owned fixture helper reached its deadline; routing cleanup remains unconfirmed.',
  ACCEPTANCE_HELPER_ABORTED: 'The owned fixture helper was cancelled; routing cleanup remains unconfirmed.',
  ACCEPTANCE_HELPER_EXIT_UNVERIFIED: 'The owned fixture helper exit is unconfirmed; further mutations are blocked.',
  ACCEPTANCE_HELPER_BUSY: 'Another owned fixture helper call is still in progress.',
  ACCEPTANCE_MUTATION_BLOCKED: 'A previous helper exit is unconfirmed; further mutations are blocked.',
  ACCEPTANCE_REQUEST_INVALID: 'The owned fixture request is invalid.',
  ACCEPTANCE_REQUEST_TRANSPORT_FAILED: 'The owned fixture request could not be delivered.',
  ACCEPTANCE_REPORT_FAILED: 'The owned fixture report could not be saved safely.',
});
export function acceptanceFailureReason(error) { return reasons[error?.code] ?? 'Owned Mac fixture acceptance could not complete.'; }
function failed(code, details = {}) { return Object.assign(new Error(reasons[code] ?? reasons.ACCEPTANCE_OPERATION_REFUSED), { code, ...details }); }
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const validHash = hash => typeof hash === 'string' && /^[a-f0-9]{64}$/.test(hash);

async function boundedFile(filename, maximum = 1_048_576) {
  if (await fs.realpath(filename) !== filename) throw failed('ACCEPTANCE_BUILD_INVALID');
  const info = await fs.lstat(filename);
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.size > maximum) throw failed('ACCEPTANCE_BUILD_INVALID');
  const handle = await fs.open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = await handle.stat();
    if (opened.dev !== info.dev || opened.ino !== info.ino || opened.mode !== info.mode || opened.size !== info.size) throw failed('ACCEPTANCE_BUILD_INVALID');
    const bytes = await handle.readFile(), after = await handle.stat();
    if (bytes.length !== opened.size || after.size !== opened.size || after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs) throw failed('ACCEPTANCE_BUILD_INVALID');
    return { bytes, info: opened };
  } finally { await handle.close(); }
}
async function jsonFile(filename, maximum) { return JSON.parse((await boundedFile(filename, maximum)).bytes.toString('utf8')); }
function plistString(bytes, key) {
  const source = bytes.toString('utf8').replace(/<!--[\s\S]*?-->/g, '');
  if (!source.startsWith('<?xml') || !source.includes('<plist')) throw failed('ACCEPTANCE_BUILD_INVALID');
  const entries = [...source.matchAll(new RegExp(`<key>\\s*${key}\\s*</key>\\s*<string>([^<]*)</string>`, 'g'))];
  if (entries.length !== 1) throw failed('ACCEPTANCE_BUILD_INVALID');
  return entries[0][1];
}
async function metadata(bundle, identifier, executable) {
  const { bytes } = await boundedFile(path.join(bundle, 'Contents/Info.plist'));
  if (plistString(bytes, 'CFBundleIdentifier') !== identifier || plistString(bytes, 'CFBundleExecutable') !== executable ||
      plistString(bytes, 'CFBundleVersion') !== '1') throw failed('ACCEPTANCE_BUILD_INVALID');
}
function requireNativeExecutable(file, architecture) {
  if (!(file.info.mode & 0o111) || (file.info.mode & 0o022) || file.bytes.length < 32 ||
      file.bytes.subarray(0, 4).toString('hex') !== 'cffaedfe' ||
      file.bytes.readUInt32LE(4) !== (architecture === 'arm64' ? 0x0100000c : architecture === 'x64' ? 0x01000007 : -1)) throw failed('ACCEPTANCE_BUILD_INVALID');
}
function matchingProviderRecord(record, fingerprint, bundle) {
  return record?.bundle === bundle && record.fingerprintVersion === 1 && validHash(record.binarySHA256) && validHash(record.bundleSHA256) &&
    record.binarySHA256 === fingerprint.binarySHA256 && record.bundleSHA256 === fingerprint.bundleSHA256 &&
    record.files === fingerprint.files && record.bytes === fingerprint.bytes;
}

/** Byte/configuration provenance only; the native helper verifies Apple authority. */
export async function validateAcceptanceBuild(output, { architecture = process.arch } = {}) {
  try {
    output = path.resolve(output);
    if (!['arm64', 'x64'].includes(architecture) || await fs.realpath(output) !== output) throw failed('ACCEPTANCE_BUILD_INVALID');
    const manifest = await jsonFile(path.join(output, 'manifest.json'));
    if (manifest.version !== 1 || manifest.platform !== 'darwin' || manifest.architecture !== architecture ||
        manifest.helper !== helperRelativePath || JSON.stringify(manifest.args) !== '["--acceptance-rpc"]' ||
        manifest.acceptanceOnly !== true || manifest.productionReceiptAllowed !== false ||
        manifest.runtimeNamespace !== fixtureRuntimeNamespace || manifest.reusedProductionProvider !== true ||
        !['unsigned', 'development', 'developer-id'].includes(manifest.signingMode) ||
        manifest.signed !== (manifest.signingMode !== 'unsigned') ||
        (manifest.signed && manifest.profileVerification?.verified !== true) ||
        ['hostIdentifier', 'providerIdentifier', 'applicationGroup'].some(key => manifest[key] !== productionIdentity[key])) throw failed('ACCEPTANCE_BUILD_INVALID');
    const host = path.join(output, hostName), helperPath = path.join(output, helperRelativePath), provider = path.join(output, providerRelativePath);
    const helperFile = await boundedFile(helperPath, 64 * 1024 * 1024); requireNativeExecutable(helperFile, architecture);
    await metadata(host, productionIdentity.hostIdentifier, 'EnvaraAppRoutingHelper');
    await metadata(provider, productionIdentity.providerIdentifier, 'EnvaraAppProxy');
    const fingerprint = await fingerprintProvider(provider);
    if (!matchingProviderRecord(manifest.provider, fingerprint, providerRelativePath)) throw failed('ACCEPTANCE_BUILD_INVALID');
    const reuse = await jsonFile(path.join(host, 'Contents/Resources/provider-reuse.json'), 16384);
    if (reuse.version !== 1 || reuse.providerIdentifier !== productionIdentity.providerIdentifier ||
        reuse.runtimeNamespace !== fixtureRuntimeNamespace || reuse.acceptanceOnly !== true ||
        !matchingProviderRecord(reuse.provider, fingerprint, `${productionIdentity.providerIdentifier}.systemextension`)) throw failed('ACCEPTANCE_BUILD_INVALID');
    const fixtureManifest = await jsonFile(path.join(host, 'Contents/Resources/acceptance-fixtures.json'), 16384);
    if (fixtureManifest.version !== 1 || !fixtureManifest.fixtures || Object.keys(fixtureManifest.fixtures).sort().join('|') !== 'one|two') throw failed('ACCEPTANCE_BUILD_INVALID');
    const fixtures = {};
    for (const slot of ['one', 'two']) {
      const entry = fixtureManifest.fixtures[slot], name = `EnvaraRoutingFixture${slot === 'one' ? 'One' : 'Two'}.app`, identifier = `io.envara.routing.fixture.${slot}`;
      if (Object.keys(entry).sort().join('|') !== 'bundle|identifier|sha256' || entry.identifier !== identifier || entry.bundle !== name || !validHash(entry.sha256)) throw failed('ACCEPTANCE_BUILD_INVALID');
      const bundle = path.join(host, 'Contents/Helpers', name);
      await metadata(bundle, identifier, 'EnvaraRoutingAcceptanceFixture');
      const fixtureFile = await boundedFile(path.join(bundle, 'Contents/MacOS/EnvaraRoutingAcceptanceFixture'), 64 * 1024 * 1024);
      requireNativeExecutable(fixtureFile, architecture);
      if (digest(fixtureFile.bytes) !== entry.sha256) throw failed('ACCEPTANCE_BUILD_INVALID');
      fixtures[slot] = Object.freeze({ identifier, sha256: entry.sha256 });
    }
    try { await fs.lstat(path.join(host, 'Contents/Resources/routing-acceptance.plist')); throw failed('ACCEPTANCE_BUILD_INVALID'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    return Object.freeze({ helperPath, identifiers: Object.freeze(Object.fromEntries(['hostIdentifier', 'providerIdentifier', 'applicationGroup'].map(key => [key, productionIdentity[key]]))),
      runtimeNamespace: fixtureRuntimeNamespace, signed: manifest.signed, signingMode: manifest.signingMode,
      helperSHA256: digest(helperFile.bytes), provider: Object.freeze({ binarySHA256: fingerprint.binarySHA256,
        bundleSHA256: fingerprint.bundleSHA256, files: fingerprint.files, bytes: fingerprint.bytes }), fixtures: Object.freeze(fixtures),
      bytesVerified: true, appleAuthorizationVerified: false });
  } catch { throw failed('ACCEPTANCE_BUILD_INVALID'); }
}

/** A deadline is followed by at most two seconds of explicit terminal teardown. */
export function createAcceptanceRPCTransport({ helperPath, spawnProcess = spawn, killGraceMs = 1000, terminalGraceMs = 1000,
  identifiers = Object.fromEntries(['hostIdentifier', 'providerIdentifier', 'applicationGroup'].map(key => [key, productionIdentity[key]])),
} = {}) {
  if (typeof helperPath !== 'string' || !path.isAbsolute(helperPath) || helperPath.includes('\0') || typeof spawnProcess !== 'function' ||
      !Number.isInteger(killGraceMs) || killGraceMs < 1 || killGraceMs > 1000 ||
      !Number.isInteger(terminalGraceMs) || terminalGraceMs < 1 || terminalGraceMs > 1000) throw failed('ACCEPTANCE_REQUEST_INVALID');
  const expectedIdentifiers = Object.freeze({ ...identifiers }); let busy = false, mutationBlocked = false;
  const call = async (method, params = {}, { timeoutMs = 20000, signal } = {}) => {
    if (!methodSet.has(method) || !params || typeof params !== 'object' || Array.isArray(params) ||
        !Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 20000) throw failed('ACCEPTANCE_REQUEST_INVALID');
    if (mutationBlocked && method !== 'status') throw failed('ACCEPTANCE_MUTATION_BLOCKED', { mutationUncertain: true });
    if (busy) throw failed('ACCEPTANCE_HELPER_BUSY');
    if (signal?.aborted) throw failed('ACCEPTANCE_HELPER_ABORTED', { mutationUncertain: false, helperExitObserved: true, helperCloseObserved: true });
    const id = randomUUID(); let input;
    try { input = JSON.stringify({ protocol: 'envara.routing-acceptance', version: 1, id, method, params }); }
    catch { throw failed('ACCEPTANCE_REQUEST_INVALID'); }
    if (Buffer.byteLength(input) > 65536) throw failed('ACCEPTANCE_REQUEST_INVALID');
    busy = true;
    return await new Promise((resolve, reject) => {
      let child, received = Buffer.alloc(0), exitObserved = false, closeObserved = false, stopping = false, finished = false,
        forcedStreamClose = false, transportError, code, signalCode, operationTimer, killTimer, terminalTimer;
      const details = () => ({ helperExitObserved: exitObserved, helperCloseObserved: closeObserved,
        forcedStreamClose, mutationUncertain: method !== 'status' && Boolean(transportError) });
      const clear = () => { clearTimeout(operationTimer); clearTimeout(killTimer); clearTimeout(terminalTimer); signal?.removeEventListener('abort', abort); };
      const settle = (error, result) => {
        if (finished) return; finished = true; clear(); busy = false;
        if (error) reject(failed(error.code, details()));
        else resolve({ ...result, transport: { helperExitObserved: exitObserved, helperCloseObserved: closeObserved, forcedStreamClose } });
      };
      const ownStreamsClose = () => { forcedStreamClose = true; for (const stream of [child?.stdin, child?.stdout, child?.stderr]) { try { stream?.destroy(); } catch {} } };
      const unverified = () => {
        if (finished || closeObserved) return;
        ownStreamsClose(); if (finished || closeObserved) return;
        mutationBlocked = true; transportError = failed('ACCEPTANCE_HELPER_EXIT_UNVERIFIED'); settle(transportError);
      };
      const beginTerminalWait = () => { if (!finished && !closeObserved) { clearTimeout(terminalTimer); terminalTimer = setTimeout(unverified, terminalGraceMs); } };
      const stop = error => {
        if (finished || stopping) return;
        stopping = true; transportError = error; clearTimeout(operationTimer); signal?.removeEventListener('abort', abort);
        try { child?.stdin?.destroy(); } catch {}
        if (exitObserved) { beginTerminalWait(); return; }
        if (child?.pid !== undefined) { try { child.kill('SIGTERM'); } catch {} }
        killTimer = setTimeout(() => {
          if (finished || closeObserved) return;
          if (!exitObserved && child?.pid !== undefined) { try { child.kill('SIGKILL'); } catch {} }
          beginTerminalWait();
        }, killGraceMs);
      };
      const abort = () => stop(failed('ACCEPTANCE_HELPER_ABORTED'));
      function parse() {
        if (transportError) { settle(transportError); return; }
        try {
          if (code !== 0 || signalCode) throw failed('ACCEPTANCE_HELPER_FAILED');
          const response = JSON.parse(received.toString('utf8'));
          if (!response || response.protocol !== 'envara.routing-acceptance' || response.version !== 1 || response.id !== id ||
              typeof response !== 'object' || Array.isArray(response) || (response.result && response.error)) throw failed('ACCEPTANCE_RESPONSE_INVALID');
          if (response.error) throw failed(response.error.code === 'notReady' ? 'ACCEPTANCE_NOT_READY' : 'ACCEPTANCE_OPERATION_REFUSED');
          const result = response.result;
          if (!result || typeof result !== 'object' || Array.isArray(result) || result.acceptanceOnly !== true || result.ready !== false || result.productionReceiptAllowed !== false) throw failed('ACCEPTANCE_RESPONSE_INVALID');
          if (method === 'status' && (result.runtimeNamespace !== fixtureRuntimeNamespace ||
              Object.entries(expectedIdentifiers).some(([key, value]) => result[key] !== value) ||
              typeof result.authorized !== 'boolean' || typeof result.extensionEnabled !== 'boolean')) throw failed('ACCEPTANCE_RESPONSE_INVALID');
          settle(null, result);
        } catch (error) { settle(failed(reasons[error?.code] ? error.code : 'ACCEPTANCE_RESPONSE_INVALID')); }
      }
      try {
        child = spawnProcess(helperPath, ['--acceptance-rpc'], { env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin' }, stdio: ['pipe', 'pipe', 'ignore'] });
        if (!child?.stdin || !child?.stdout || typeof child.on !== 'function' || typeof child.kill !== 'function') throw failed('ACCEPTANCE_HELPER_UNAVAILABLE');
        child.on('error', () => stop(failed('ACCEPTANCE_HELPER_UNAVAILABLE')));
        child.once('exit', (exitCode, exitSignal) => { exitObserved = true; code = exitCode; signalCode = exitSignal; if (stopping) { clearTimeout(killTimer); beginTerminalWait(); } });
        child.once('close', (exitCode, exitSignal) => {
          closeObserved = true;
          // A failed spawn has no process, but its close is terminal.
          if (child.pid === undefined || exitObserved || exitCode !== null) exitObserved = true;
          code = exitCode; signalCode = exitSignal; parse();
        });
        child.stdout.on('error', () => stop(failed('ACCEPTANCE_REQUEST_TRANSPORT_FAILED')));
        child.stdout.on('data', bytes => {
          if (finished || stopping) return;
          if (!Buffer.isBuffer(bytes) || received.length + bytes.length > 65536) { stop(failed('ACCEPTANCE_RESPONSE_INVALID')); return; }
          received = Buffer.concat([received, bytes]);
        });
        child.stdin.on('error', () => stop(failed('ACCEPTANCE_REQUEST_TRANSPORT_FAILED')));
        operationTimer = setTimeout(() => stop(failed('ACCEPTANCE_HELPER_DEADLINE')), timeoutMs);
        signal?.addEventListener('abort', abort, { once: true });
        if (signal?.aborted) abort(); else child.stdin.end(input);
      } catch {
        if (!child) { exitObserved = true; closeObserved = true; settle(failed('ACCEPTANCE_HELPER_UNAVAILABLE')); }
        else stop(failed('ACCEPTANCE_HELPER_UNAVAILABLE'));
      }
    });
  };
  Object.defineProperties(call, { mutationBlocked: { get: () => mutationBlocked }, inFlight: { get: () => busy }, maximumTeardownGraceMs: { value: killGraceMs + terminalGraceMs } });
  return call;
}
