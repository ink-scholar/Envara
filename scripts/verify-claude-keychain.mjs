/** Opt-in macOS Keychain acceptance using an exclusively owned temporary vault.
 * No real login, account credential, host Keychain item or host default is changed.
 * node scripts/verify-claude-keychain.mjs --helper /absolute/native/helper
 */
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { createServer } from 'node:net';
import { chmod, lstat, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { terminalFenceProfile } from '../electron/terminal-network-fence.mjs';

const sourceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const fixtureSource = path.join(sourceRoot, 'scripts/fixtures/claude-keychain-acceptance.c');
const cleanBase = { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', LC_ALL: 'C' };
const sleep = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
const safeFailure = stage => Object.assign(new Error(`Disposable Keychain acceptance failed at ${stage}.`), { code: 'CLAUDE_KEYCHAIN_ACCEPTANCE_FAILED' });
const isAlive = child => {
  if (!Number.isInteger(child.pid) || child.pid <= 0) return false;
  try { process.kill(-child.pid, 0); return true; } catch (error) { return error.code !== 'ESRCH'; }
};

async function privateDirectory(directory) {
  const canonical = await realpath(directory), info = await lstat(canonical);
  assert(info.isDirectory() && !info.isSymbolicLink() && info.uid === process.getuid() && !(info.mode & 0o077));
  return canonical;
}

/** The optional parent is an already-owned private runtime directory, never an app.
 * Proof objects contain no usernames, Keychain paths, selection hashes or secrets.
 */
export async function verifyClaudeKeychain({ helperPath, temporaryParent = null, outputPath = null } = {}) {
  const proof = { schemaVersion: 1, checkedAt: new Date().toISOString(), platform: `${process.platform}-${process.arch}`,
    passed: false, cleanupComplete: false, hostSelectionUnchanged: null, checks: [],
    limitations: [
      'Synthetic credentials in a temporary Keychain only; no Claude OAuth login or real account persistence is exercised.',
      'The fixed fixture service and distinct config account names test native Keychain separation, not the official CLI service-name derivation.',
      'Network checks use owned loopback listeners; this does not repeat all terminal egress acceptance.',
    ] };
  let stage = 'arguments', temporary, rootIdentity, executable, sourceHome, targetHome, hostHome, fence, hostBefore, failure;
  let canCleanVault = false, cancellation = false, lastDiagnostic = null;
  const children = new Set(), servers = [];
  const check = description => proof.checks.push(description);
  const stop = async child => {
    for (const signal of ['SIGTERM', 'SIGKILL']) {
      if (!isAlive(child)) return;
      try { process.kill(-child.pid, signal); } catch (error) { if (error.code !== 'ESRCH') throw error; }
      const deadline = Date.now() + 1500;
      while (isAlive(child) && Date.now() < deadline) await sleep(25);
    }
    if (isAlive(child)) throw safeFailure('owned-process-cleanup');
  };
  const cancel = () => { cancellation = true; for (const child of children) void stop(child).catch(() => {}); };
  process.on('SIGINT', cancel); process.on('SIGTERM', cancel);

  async function run(command, args, { env, input = '', timeout = 15000, duringCleanup = false } = {}) {
    if (cancellation && !duringCleanup) throw safeFailure('cancelled');
    lastDiagnostic = null;
    return new Promise((resolve, reject) => {
      const child = spawn(command, args, { cwd: temporary, env: env ?? cleanBase, detached: true, stdio: ['pipe', 'pipe', 'pipe'] });
      children.add(child);
      let stdout = '', stderr = '', overflow = false, timedOut = false;
      const timer = setTimeout(() => { timedOut = true; void stop(child).catch(() => {}); }, timeout);
      const collect = (kind, bytes) => {
        if ((kind === 'stdout' ? stdout : stderr).length + bytes.length > 65536) {
          overflow = true; void stop(child).catch(() => {}); return;
        }
        if (kind === 'stdout') stdout += bytes; else stderr += bytes;
      };
      child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
      child.stdout.on('data', value => collect('stdout', value)); child.stderr.on('data', value => collect('stderr', value));
      child.stdin.on('error', () => {}); child.stdin.end(input);
      child.once('error', () => { clearTimeout(timer); children.delete(child); reject(safeFailure(stage)); });
      child.once('close', async (code, signal) => {
        clearTimeout(timer);
        try {
          if (isAlive(child)) await stop(child);
          children.delete(child);
          if (code !== 0 || signal || timedOut || overflow) {
            try {
              const data = JSON.parse(stdout.trim()), diagnostic = {};
              for (const key of ['stage', 'code']) if (typeof data[key] === 'string' && /^[A-Za-z0-9_-]{1,96}$/.test(data[key])) diagnostic[key] = data[key];
              if (Number.isInteger(data.osStatus) || data.osStatus === null) diagnostic.osStatus = data.osStatus;
              if (Object.keys(diagnostic).length) lastDiagnostic = diagnostic;
            } catch {}
            throw safeFailure(stage);
          }
          resolve({ stdout: stdout.trim(), stderr: stderr.trim() });
        } catch { reject(safeFailure(stage)); }
      });
    });
  }

  const environment = home => ({ ...cleanBase, HOME: home, USERPROFILE: home, TMPDIR: `${temporary}/`,
    CLAUDE_CONFIG_DIR: path.join(temporary, home === sourceHome ? 'config-source' : 'config-a') });
  async function fixture(mode, home, { args = [], input = '', restricted = true, duringCleanup = false, config = null } = {}) {
    const command = restricted ? '/usr/bin/sandbox-exec' : executable;
    const argv = [...(restricted ? ['-p', fence, executable] : []), mode, temporary, home, ...args];
    const env = environment(home); if (config) env.CLAUDE_CONFIG_DIR = path.join(temporary, config);
    const result = await run(command, argv, { env, input, duringCleanup });
    const value = JSON.parse(result.stdout); assert.equal(value.ok, true); return value;
  }

  async function snapshot({ duringCleanup = false } = {}) {
    // Selection metadata only; the fixture never queries any credential in this mode.
    const profile = '(version 1)\n(allow default)\n(deny network*)\n(deny file-write*)\n';
    const result = await run('/usr/bin/sandbox-exec', ['-p', profile, executable, 'snapshot'], {
      env: { ...cleanBase, HOME: hostHome, USERPROFILE: hostHome }, duringCleanup,
    });
    const value = JSON.parse(result.stdout);
    assert.equal(value.searchStatus, 0);
    assert([0, -25307].includes(value.defaultStatus));
    return value;
  }

  async function verifyHost({ duringCleanup = false } = {}) {
    const after = await snapshot({ duringCleanup });
    const same = JSON.stringify(after) === JSON.stringify(hostBefore);
    proof.hostSelectionUnchanged = proof.hostSelectionUnchanged === false ? false : same;
    assert.equal(same, true, 'Host selection metadata changed.');
  }

  async function listener() {
    const record = { accepted: 0 };
    const server = createServer(socket => { record.accepted += 1; socket.destroy(); }); servers.push(server);
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
    record.port = server.address().port; return record;
  }

  try {
    assert.equal(process.platform, 'darwin'); assert.notEqual(process.getuid(), 0);
    assert.equal(process.getuid(), process.geteuid()); assert.equal(process.getgid(), process.getegid());
    // A package runner may already use an isolated HOME. Account metadata gives
    // the real host selection context without inheriting that test override.
    const account = os.userInfo(); assert.equal(account.uid, process.getuid());
    hostHome = await realpath(account.homedir);
    const hostInfo = await lstat(hostHome); assert(hostInfo.isDirectory() && hostInfo.uid === process.getuid());
    assert(typeof helperPath === 'string' && path.isAbsolute(helperPath));
    const helper = await realpath(helperPath), helperInfo = await lstat(helper);
    assert(helperInfo.isFile() && !helperInfo.isSymbolicLink() && !(helperInfo.mode & 0o022));
    if (outputPath !== null) assert(path.isAbsolute(outputPath));
    const parent = temporaryParent === null ? await realpath(os.tmpdir()) : await privateDirectory(temporaryParent);
    temporary = await realpath(await mkdtemp(path.join(parent, 'envara-claude-keychain-')));
    await chmod(temporary, 0o700); rootIdentity = await lstat(temporary);
    sourceHome = path.join(temporary, 'source-home'); targetHome = path.join(temporary, 'target-home');
    for (const name of ['source-home', 'target-home', 'vault', 'config-source', 'config-a', 'config-b'])
      await mkdir(path.join(temporary, name), { mode: 0o700 });
    await mkdir(path.join(sourceHome, 'Library'), { mode: 0o700 });
    await mkdir(path.join(sourceHome, 'Library/Preferences'), { mode: 0o700 });
    const helperFingerprint = async () => {
      const before = await lstat(helper);
      assert(before.isFile() && !before.isSymbolicLink() && !(before.mode & 0o022));
      const sha256 = createHash('sha256').update(await readFile(helper)).digest('hex');
      const after = await lstat(helper);
      const identity = info => ({ dev: info.dev, ino: info.ino, size: info.size, uid: info.uid, mode: info.mode,
        mtimeMs: info.mtimeMs, ctimeMs: info.ctimeMs });
      assert.deepEqual(identity(before), identity(after));
      return { ...identity(after), sha256 };
    };
    const helperBefore = await helperFingerprint(); proof.helperSha256 = helperBefore.sha256;
    const verifyHelper = async () => {
      const priorStage = stage; stage = 'helper-binary-stability';
      try { assert.deepEqual(await helperFingerprint(), helperBefore); proof.helperUnchanged = true; }
      catch { proof.helperUnchanged = false; throw safeFailure(stage); }
      stage = priorStage;
    };
    proof.fixtureSha256 = createHash('sha256').update(await readFile(fixtureSource)).digest('hex');
    stage = 'compile-owned-fixture'; executable = path.join(temporary, 'keychain-fixture');
    await run('/usr/bin/xcrun', ['clang', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-deprecated-declarations',
      fixtureSource, '-framework', 'Security', '-framework', 'CoreFoundation', '-o', executable], {
      env: environment(sourceHome), timeout: 30000,
    });
    stage = 'snapshot-host-selection'; hostBefore = await snapshot();
    const allowed = await listener(), refused = await listener();
    fence = `${terminalFenceProfile({ deniedLoopbackPorts: [refused.port], restrictDeviceIdentifiers: true })}\n` +
      `(deny file-write*)\n(allow file-write* (subpath ${JSON.stringify(temporary)}))\n` +
      `(deny file-read-data (subpath ${JSON.stringify(path.join(hostHome, 'Library/Keychains'))}) (subpath "/Library/Keychains"))\n`;
    stage = 'empty-private-home';
    const empty = await fixture('default', targetHome);
    assert.equal(empty.osStatus, -25307); assert.equal(empty.present, false);
    check('A fresh private HOME has no default Keychain.');
    stage = 'network-positive-control';
    const outside = await fixture('network', sourceHome, { restricted: false, args: [String(allowed.port), String(refused.port)] });
    assert.equal(outside.allowedErrno, 0); assert.equal(outside.deniedErrno, 0); await sleep(25);
    assert(allowed.accepted > 0 && refused.accepted > 0);
    const refusedBefore = refused.accepted, allowedBefore = allowed.accepted;
    stage = 'production-network-fence';
    const inside = await fixture('network', sourceHome, { args: [String(allowed.port), String(refused.port)] });
    assert.equal(inside.allowedErrno, 0); assert.equal(inside.deniedErrno, 1); await sleep(25);
    assert(allowed.accepted > allowedBefore); assert.equal(refused.accepted, refusedBefore);
    check('The production fence permits the owned allowed listener and blocks the refused listener, with outside positive controls.');
    const password = randomBytes(32).toString('hex'), firstValue = randomBytes(32).toString('hex'), secondValue = randomBytes(32).toString('hex');
    const suffix = randomBytes(10).toString('hex'), firstAccount = `synthetic-config-a-${suffix}`, secondAccount = `synthetic-config-b-${suffix}`;
    stage = 'create-owned-keychain'; canCleanVault = true;
    const created = await fixture('create', sourceHome, { input: `${password}\n` });
    assert.equal(created.osStatus, 0); assert.equal(created.matchesOwnedKeychain, true); await verifyHost();
    stage = 'source-default-new-process';
    const sourceDefault = await fixture('default', sourceHome);
    assert.equal(sourceDefault.osStatus, 0); assert.equal(sourceDefault.matchesOwnedKeychain, true);
    check('Only the owned source HOME selects the newly created synthetic Keychain.');
    stage = 'production-helper-prepare';
    // Production preparation precedes the shell fence. Its own metadata/select
    // workers apply Seatbelt; macOS rejects nesting a second sandbox_init.
    const prepare = async () => {
      await verifyHelper();
      try { return JSON.parse((await run(helper,
        ['prepare', '--home', targetHome, '--host-home', sourceHome], { env: environment(sourceHome) })).stdout); }
      finally { await verifyHelper(); }
    };
    const prepared = await prepare();
    assert.equal(prepared.schemaVersion, 1); assert.equal(prepared.status, 'ready'); assert.equal(prepared.changed, true); await verifyHost();
    const selected = await fixture('default', targetHome);
    assert.equal(selected.osStatus, 0); assert.equal(selected.matchesOwnedKeychain, true);
    const repeated = await prepare(); assert.equal(repeated.status, 'ready'); assert.equal(repeated.changed, false); await verifyHost();
    check('The production helper selects the owned Keychain for the target HOME and preserves it on a repeated preparation.');
    for (const [account, value, config] of [[firstAccount, firstValue, 'config-a'], [secondAccount, secondValue, 'config-b']]) {
      stage = `synthetic-write-${config}`;
      const written = await fixture('write', targetHome, { args: [account], input: `${password}\n${value}\n`, config });
      assert.equal(written.osStatus, 0); await verifyHost();
      stage = `fresh-process-read-${config}`;
      const reopened = await fixture('read', targetHome, { args: [account], input: `${password}\n${value}\n`, config });
      assert.equal(reopened.osStatus, 0); assert.equal(reopened.matchesSyntheticValue, true);
    }
    check('Two fresh processes reopen and read distinct synthetic account values under a fixed service and separate config directories.');
    stage = 'account-separation';
    const different = await fixture('read', targetHome, { args: [firstAccount], input: `${password}\n${secondValue}\n`, config: 'config-b' });
    assert.equal(different.osStatus, 0); assert.equal(different.matchesSyntheticValue, false);
    stage = 'delete-first-synthetic-item';
    const removed = await fixture('delete-item', targetHome, { args: [firstAccount], input: `${password}\n` });
    assert.equal(removed.osStatus, 0); await verifyHost();
    const absent = await fixture('read', targetHome, { args: [firstAccount], input: `${password}\n${firstValue}\n` });
    assert.equal(absent.osStatus, -25300); assert.equal(absent.found, false);
    const retained = await fixture('read', targetHome, { args: [secondAccount], input: `${password}\n${secondValue}\n`, config: 'config-b' });
    assert.equal(retained.osStatus, 0); assert.equal(retained.matchesSyntheticValue, true);
    stage = 'delete-second-synthetic-item';
    const last = await fixture('delete-item', targetHome, { args: [secondAccount], input: `${password}\n`, config: 'config-b' });
    assert.equal(last.osStatus, 0); await verifyHost();
    const lastAbsent = await fixture('read', targetHome, { args: [secondAccount], input: `${password}\n${secondValue}\n`, config: 'config-b' });
    assert.equal(lastAbsent.osStatus, -25300); assert.equal(lastAbsent.found, false);
    check('Deleting one synthetic account leaves the other intact; both items are then independently confirmed absent.');
    await verifyHelper();
    proof.passed = true;
  } catch {
    failure = safeFailure(stage); proof.failureStage = stage;
    if (lastDiagnostic) proof.failureDiagnostic = lastDiagnostic;
  } finally {
    let cleanupFailure = false;
    for (const child of children) { try { await stop(child); children.delete(child); } catch { cleanupFailure = true; } }
    if (temporary && !cleanupFailure) {
      try {
        if (canCleanVault) {
          stage = 'delete-owned-keychain';
          const cleanup = await fixture('delete-keychain', sourceHome, { duringCleanup: true });
          assert.equal(cleanup.osStatus, 0); assert.equal(cleanup.absent, true);
        }
      } catch { cleanupFailure = true; if (lastDiagnostic) proof.cleanupDiagnostic = lastDiagnostic; }
    }
    if (hostBefore) {
      try { await verifyHost({ duringCleanup: true }); }
      catch { cleanupFailure = true; }
    }
    if (temporary && !cleanupFailure) {
      try {
        const identity = await lstat(temporary);
        assert(identity.isDirectory() && !identity.isSymbolicLink() && identity.dev === rootIdentity.dev && identity.ino === rootIdentity.ino);
        assert.equal(await realpath(temporary), temporary);
        await rm(temporary, { recursive: true, force: false }); proof.cleanupComplete = true;
      } catch { cleanupFailure = true; }
    }
    for (const server of servers) await new Promise(resolve => server.close(resolve));
    if (cleanupFailure) { proof.cleanupComplete = false; proof.cleanupFailure = true; proof.passed = false; failure ??= safeFailure('owned-resource-cleanup'); }
    if (cancellation) { proof.passed = false; proof.cancelled = true; failure ??= safeFailure('cancelled'); }
    if (proof.passed && proof.cleanupComplete) check('The owned Keychain, processes and temporary files are removed; the host default and search list remain unchanged.');
    else proof.passed = false;
    if (outputPath !== null) {
      try { await writeFile(outputPath, JSON.stringify(proof, null, 2) + '\n', { mode: 0o600, flag: 'wx' }); }
      catch { failure ??= safeFailure('write-new-proof'); proof.passed = false; }
    }
    process.removeListener('SIGINT', cancel); process.removeListener('SIGTERM', cancel);
  }
  if (failure) { failure.proof = proof; throw failure; }
  return proof;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2); let helperPath, outputPath = null;
  try {
    for (let index = 0; index < args.length; index += 2) {
      const value = args[index + 1]; assert(value && path.isAbsolute(value));
      if (args[index] === '--helper' && helperPath === undefined) helperPath = value;
      else if (args[index] === '--output' && outputPath === null) outputPath = value;
      else throw safeFailure('arguments');
    }
    assert(helperPath, 'Usage: node scripts/verify-claude-keychain.mjs --helper /absolute/helper [--output /absolute/new-proof.json]');
    console.log(JSON.stringify(await verifyClaudeKeychain({ helperPath, outputPath }), null, 2));
  } catch (error) {
    console.error(JSON.stringify(error.proof ?? { passed: false, error: 'CLAUDE_KEYCHAIN_ACCEPTANCE_FAILED', stage: 'arguments' }, null, 2));
    process.exitCode = 1;
  }
}
