import path from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { chmod, copyFile, lstat, readFile, realpath, rename, rmdir } from 'node:fs/promises';
import { constants } from 'node:fs';
import { extractApplicationUpdate } from './application-update-archive.mjs';

const execute = promisify(execFile);
const schema = 'envara.mac-update/v1';
const failure = (code = 'APP_UPDATE_INSTALL_FAILED') => Object.assign(new Error('Application update could not complete.'), { code });
const codes = new Set(['APP_UPDATE_LOCATION', 'APP_UPDATE_PACKAGE', 'APP_UPDATE_HELPER', 'APP_UPDATE_TIMEOUT',
  'APP_UPDATE_INSTALL_FAILED', 'APP_UPDATE_ROLLBACK_FAILED', 'APP_UPDATE_PARENT', 'APP_UPDATE_PROTOCOL', 'APP_UPDATE_SYSTEM_UNSUPPORTED',
  'APP_UPDATE_APP_RUNNING', 'APP_UPDATE_CLEANUP']);
const nativeCodes = { APP_UPDATE_ROLLBACK_UNCERTAIN: 'APP_UPDATE_ROLLBACK_FAILED', APP_UPDATE_CLEANUP_UNCERTAIN: 'APP_UPDATE_CLEANUP',
  APP_UPDATE_TOOL_TIMEOUT: 'APP_UPDATE_TIMEOUT', APP_UPDATE_PARENT_UNKNOWN: 'APP_UPDATE_PARENT', APP_UPDATE_AUTHORIZATION: 'APP_UPDATE_PARENT',
  APP_UPDATE_VALIDATION: 'APP_UPDATE_PACKAGE', APP_UPDATE_ARCHITECTURE: 'APP_UPDATE_PACKAGE' };
const safeFailure = error => failure(codes.has(error?.code) ? error.code : 'APP_UPDATE_PACKAGE');
const abort = signal => { if (signal?.aborted) throw failure('APP_UPDATE_CANCELLED'); };

async function regularFile(filename, executable = false) {
  const state = await lstat(filename);
  if (!state.isFile() || state.isSymbolicLink() || state.nlink !== 1 || state.mode & 0o022
    || executable && !(state.mode & 0o111) || await realpath(filename) !== filename) throw failure('APP_UPDATE_PACKAGE');
  return state;
}

/** This adapter never receives a renderer-supplied path. It only prepares an
 * owned staging bundle; the helper cannot replace the app until strict desktop
 * shutdown has granted its private pipe capability and that parent has exited.
 */
export function createMacApplicationUpdateAdapter({ executablePath, currentVersion, helperDirectory,
  parentPid = process.pid, run = execute, spawnHelper = spawn, extract = extractApplicationUpdate } = {}) {
  const currentApp = path.resolve(executablePath, '../../..');
  const handles = new WeakSet();

  async function verifyHelper(signal) {
    const resource = path.join(helperDirectory, 'EnvaraUpdater');
    await regularFile(resource, true);
    await regularFile(path.join(helperDirectory, 'manifest.json'));
    const manifest = JSON.parse(await readFile(path.join(helperDirectory, 'manifest.json'), 'utf8'));
    const helperBytes = await readFile(resource);
    if (manifest.schemaVersion !== 1 || manifest.platform !== 'darwin' || manifest.architecture !== 'arm64'
      || manifest.executable !== 'EnvaraUpdater' || manifest.sha256 !== createHash('sha256').update(helperBytes).digest('hex'))
      throw failure('APP_UPDATE_HELPER');
    await run('/usr/bin/codesign', ['--verify', '--strict', resource], { timeout: 30000, maxBuffer: 65536, signal });
    return { resource, manifest };
  }

  async function verifyBundle(bundle, version, signal) {
    abort(signal);
    const info = await run('/usr/bin/plutil', ['-convert', 'json', '-o', '-', path.join(bundle, 'Contents', 'Info.plist')],
      { timeout: 15000, maxBuffer: 1024 * 1024, signal });
    const plist = JSON.parse(info.stdout);
    if (plist.CFBundleIdentifier !== 'io.envara.desktop' || plist.CFBundleShortVersionString !== version
      || plist.CFBundleExecutable !== 'Envara') throw failure('APP_UPDATE_PACKAGE');
    const requirements = [plist.LSMinimumSystemVersion];
    if (plist.LSMinimumSystemVersionByArchitecture !== undefined) {
      if (!plist.LSMinimumSystemVersionByArchitecture || typeof plist.LSMinimumSystemVersionByArchitecture !== 'object'
        || Array.isArray(plist.LSMinimumSystemVersionByArchitecture)) throw failure('APP_UPDATE_SYSTEM_UNSUPPORTED');
      requirements.push(plist.LSMinimumSystemVersionByArchitecture.arm64);
    }
    if (requirements.some(value => value !== undefined)) {
      const parse = value => {
        if (typeof value !== 'string' || !/^(0|[1-9]\d{0,3})(?:\.(0|[1-9]\d{0,3})){0,2}$/.test(value)) throw failure('APP_UPDATE_SYSTEM_UNSUPPORTED');
        return [...value.split('.').map(Number), 0, 0].slice(0, 3);
      };
      const system = await run('/usr/bin/sw_vers', ['-productVersion'], { timeout: 15000, maxBuffer: 4096, signal });
      const actual = parse(system.stdout.trim());
      const minimum = requirements.filter(value => value !== undefined).map(parse).at(-1);
      for (let index = 0; index < 3; index++) {
        if (actual[index] > minimum[index]) break;
        if (actual[index] < minimum[index]) throw failure('APP_UPDATE_SYSTEM_UNSUPPORTED');
      }
    }
    const binary = path.join(bundle, 'Contents', 'MacOS', 'Envara');
    await regularFile(binary, true);
    const architecture = await run('/usr/bin/lipo', ['-archs', binary], { timeout: 15000, maxBuffer: 65536, signal });
    if (architecture.stdout.trim() !== 'arm64') throw failure('APP_UPDATE_PACKAGE');
    await run('/usr/bin/codesign', ['--verify', '--deep', '--strict', bundle], { timeout: 120000, maxBuffer: 65536, signal });
    abort(signal);
  }

  return {
    async inspectInstaller({ stageRoot, originatingPid }) {
      try {
        if (!Number.isSafeInteger(originatingPid) || originatingPid <= 0 || typeof stageRoot !== 'string'
          || !path.isAbsolute(stageRoot)) throw failure('APP_UPDATE_PROTOCOL');
        const { resource } = await verifyHelper();
        const { stdout } = await run(resource, ['--installer-active', stageRoot, String(originatingPid), currentApp],
          { timeout: 15000, maxBuffer: 8192, env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'en_US.UTF-8' } });
        const result = JSON.parse(stdout);
        if (result?.schema !== schema || result.type !== 'installer-status' || typeof result.active !== 'boolean') throw failure('APP_UPDATE_PROTOCOL');
        return { active: result.active };
      } catch { throw failure('APP_UPDATE_CLEANUP'); }
    },

    async prepare({ archivePath, version, sha256, stagingDir, signal }) {
      try {
        abort(signal);
        if (!currentApp.endsWith('.app') || executablePath !== path.join(currentApp, 'Contents', 'MacOS', 'Envara')
          || await realpath(currentApp) !== currentApp) throw failure('APP_UPDATE_LOCATION');
        const stageRoot = await realpath(stagingDir);
        if (stageRoot === currentApp || stageRoot.startsWith(`${currentApp}${path.sep}`)) throw failure('APP_UPDATE_LOCATION');
        const directory = await lstat(stageRoot);
        if (!directory.isDirectory() || directory.isSymbolicLink() || directory.uid !== process.getuid() || directory.mode & 0o077)
          throw failure('APP_UPDATE_LOCATION');
        const { resource, manifest } = await verifyHelper(signal);
        const destination = path.join(stageRoot, 'content');
        const extracted = await extract({ archivePath, destination, sha256, signal });
        const stagedApp = path.join(stageRoot, 'Envara.app');
        if (extracted !== path.join(destination, 'Envara.app')) throw failure('APP_UPDATE_PACKAGE');
        await rename(extracted, stagedApp);
        await rmdir(destination);
        await verifyBundle(stagedApp, version, signal);
        const helper = path.join(stageRoot, 'EnvaraUpdater');
        await copyFile(resource, helper, constants.COPYFILE_EXCL);
        await chmod(helper, 0o700);
        if (createHash('sha256').update(await readFile(helper)).digest('hex') !== manifest.sha256) throw failure('APP_UPDATE_HELPER');
        abort(signal);
        const handle = Object.freeze({ stageRoot, stagedApp, helper, version });
        handles.add(handle);
        return handle;
      } catch (error) {
        if (signal?.aborted) throw failure('APP_UPDATE_CANCELLED');
        throw safeFailure(error);
      }
    },

    async arm(handle) {
      if (!handles.has(handle)) throw failure('APP_UPDATE_PACKAGE');
      const { helper, stageRoot, stagedApp, version } = handle;
      const capability = randomBytes(32).toString('hex');
      // Detached only changes process-group ownership. The helper still requires
      // this exact live parent and is inert on EOF before authorization.
      const child = spawnHelper(helper, [], { detached: true, stdio: ['pipe', 'pipe', 'ignore'],
        env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'en_US.UTF-8' } });
      let buffer = '', exited = false, committed = false, terminalError = null;
      const pending = new Map();
      const rejectAll = error => {
        terminalError = error;
        for (const entry of pending.values()) { clearTimeout(entry.timer); entry.reject(error); }
        pending.clear();
      };
      const exitPromise = new Promise(resolve => child.once('close', (code, signal) => {
        exited = true;
        rejectAll(failure('APP_UPDATE_INSTALL_FAILED'));
        resolve({ code, signal });
      }));
      child.on('error', () => rejectAll(failure('APP_UPDATE_HELPER')));
      child.stdin.on('error', () => rejectAll(failure('APP_UPDATE_HELPER')));
      child.stdout.on('data', bytes => {
        buffer += bytes.toString('utf8');
        if (buffer.length > 8192) { rejectAll(failure('APP_UPDATE_PROTOCOL')); child.stdin.end(); return; }
        let newline;
        while ((newline = buffer.indexOf('\n')) >= 0) {
          const line = buffer.slice(0, newline); buffer = buffer.slice(newline + 1);
          let frame;
          try { frame = JSON.parse(line); } catch { rejectAll(failure('APP_UPDATE_PROTOCOL')); child.stdin.end(); return; }
          if (frame?.schema !== schema || !['ready', 'authorized', 'failed', 'installed'].includes(frame.type)) {
            rejectAll(failure('APP_UPDATE_PROTOCOL')); child.stdin.end(); return;
          }
          if (frame.type === 'failed') { rejectAll(failure(codes.has(frame.code) ? frame.code
            : Object.hasOwn(nativeCodes, frame.code) ? nativeCodes[frame.code] : 'APP_UPDATE_INSTALL_FAILED')); continue; }
          const waiter = pending.get(frame.type);
          if (waiter) { pending.delete(frame.type); clearTimeout(waiter.timer); waiter.resolve(frame); }
        }
      });
      const waitFor = (type, timeout) => new Promise((resolve, reject) => {
        if (terminalError || exited) { reject(terminalError ?? failure()); return; }
        const timer = setTimeout(() => { pending.delete(type); reject(failure('APP_UPDATE_TIMEOUT')); }, timeout);
        pending.set(type, { resolve, reject, timer });
      });
      const send = frame => new Promise((resolve, reject) => child.stdin.write(`${JSON.stringify(frame)}\n`, error => error ? reject(failure('APP_UPDATE_HELPER')) : resolve()));
      const stopBeforeCommit = async () => {
        if (committed || exited) return;
        child.stdin.end();
        // Let its bounded copy/validation finish and observe pipe EOF. Killing
        // the helper could orphan its owned ditto child during preparation.
        await exitPromise;
      };
      try {
        const ready = waitFor('ready', 180000);
        await Promise.all([send({ schema, currentApp, stagedApp, stageRoot, expectedVersion: version,
          expectedCurrentVersion: currentVersion, parentPid, capability }), ready]);
      } catch (error) { await stopBeforeCommit(); throw error; }
      return {
        async commit() {
          if (committed || exited || terminalError) throw terminalError ?? failure();
          const authorization = waitFor('authorized', 15000);
          await Promise.all([send({ type: 'commit', capability }), authorization]);
          committed = true;
          child.unref(); child.stdin.unref?.(); child.stdout.unref?.();
        },
        abort: stopBeforeCommit,
      };
    },
  };
}
