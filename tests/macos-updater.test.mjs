import { before, after, test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { EventEmitter } from 'node:events';
import { mkdtemp, mkdir, writeFile, readFile, readdir, realpath, cp, chmod, rm, symlink, lstat } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { randomBytes } from 'node:crypto';

const execute = promisify(execFile);
const supported = process.platform === 'darwin' && process.arch === 'arm64';
const schema = 'envara.mac-update/v1';
const lsregister = '/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister';
const native = { skip: !supported, timeout: 45000 };
let shared, helper, fixtureExecutable, buildMacUpdater, checkMacUpdaterResources;
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
async function unregisterOwned(app) {
  try { await execute(lsregister, ['-u', app], { timeout: 15000, maxBuffer: 65536 }); }
  catch (error) {
    // kLSApplicationNotFoundErr: most rejection fixtures never reach open(1),
    // so neither they nor their unlaunched backups have a registration to undo.
    if (error.code !== 1 || !/: -10814\b/.test(error.stderr ?? '')) throw error;
  }
}

before(async () => {
  if (!supported) return;
  ({ buildMacUpdater, checkMacUpdaterResources } = await import('../scripts/build-macos-updater.mjs'));
  shared = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-updater-native-tests-')));
  const directory = path.join(shared, 'build');
  await buildMacUpdater({ directory });
  helper = path.join(directory, 'EnvaraUpdater');
  const source = path.join(shared, 'fixture.c');
  fixtureExecutable = path.join(shared, 'FixtureEnvara');
  await writeFile(source, `#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
  if (argc == 3 && strcmp(argv[1], "--owned-wait") == 0) {
    printf("{\\"fixture\\":\\"waiting\\"}\\n"); fflush(stdout);
    for (;;) pause();
  }
  /* /usr/bin/open launches the installed synthetic app without arguments. */
  if (argc != 2) return 0;
  pid_t updater = fork();
  if (updater < 0) return 71;
  if (updater == 0) { execl(argv[1], argv[1], (char *)NULL); _exit(72); }
  printf("{\\"fixture\\":\\"updater-started\\",\\"helperPid\\":%d}\\n", updater);
  fflush(stdout);
  for (;;) pause();
}
`);
  await execute('/usr/bin/xcrun', ['clang', '-arch', 'arm64', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', source, '-o', fixtureExecutable], { timeout: 30000 });
});
after(async () => { if (shared) await rm(shared, { recursive: true, force: true }); });

function plist(version, bundleId = 'io.envara.desktop') {
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>${bundleId}</string>
<key>CFBundleExecutable</key><string>Envara</string>
<key>CFBundleName</key><string>Envara</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleVersion</key><string>${version}</string>
<key>CFBundleShortVersionString</key><string>${version}</string>
<key>LSUIElement</key><true/>
<key>LSMinimumSystemVersion</key><string>12.0</string>
</dict></plist>`;
}
async function signApp(app) { await execute('/usr/bin/codesign', ['--force', '--deep', '--sign', '-', app], { timeout: 15000 }); }
async function makeApp(app, version, bundleId) {
  await mkdir(path.join(app, 'Contents', 'MacOS'), { recursive: true, mode: 0o700 });
  await mkdir(path.join(app, 'Contents', 'Resources'), { mode: 0o700 });
  await cp(fixtureExecutable, path.join(app, 'Contents', 'MacOS', 'Envara')); await chmod(path.join(app, 'Contents', 'MacOS', 'Envara'), 0o700);
  await writeFile(path.join(app, 'Contents', 'Info.plist'), plist(version, bundleId));
  await writeFile(path.join(app, 'Contents', 'Resources', 'fixture.txt'), `signed fixture ${version}`);
  await signApp(app);
}
async function fixture(t) {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-updater-case-')));
  const sessions = [];
  const installed = path.join(directory, 'installed'), stageRoot = path.join(directory, 'stage');
  const currentApp = path.join(installed, 'Envara.app'), stagedApp = path.join(stageRoot, 'Envara.app'), stagedHelper = path.join(stageRoot, 'EnvaraUpdater');
  t.after(async () => {
    for (const session of sessions) await session.stop();
    // /usr/bin/open may register these disposable bundles. Unregister only the
    // exact owned paths before removal; never reset the Launch Services database.
    for (const app of [currentApp, ...await backupPaths({ installed }).catch(() => [])]) {
      if (await lstat(app).catch(() => null)) await unregisterOwned(app);
    }
    await rm(directory, { recursive: true, force: true });
  });
  await mkdir(installed, { mode: 0o700 }); await mkdir(stageRoot, { mode: 0o700 });
  await makeApp(currentApp, '1.2.3'); await makeApp(stagedApp, '1.2.4');
  await cp(helper, stagedHelper); await chmod(stagedHelper, 0o700);
  const userData = path.join(directory, 'user-data'); await mkdir(userData, { mode: 0o700 });
  await writeFile(path.join(userData, 'account-fixture'), 'preserve account fixture');
  const capability = randomBytes(32).toString('hex');
  return { directory, installed, stageRoot, currentApp, stagedApp, stagedHelper, userData, capability, sessions,
    request: { schema, currentApp, stagedApp, stageRoot, expectedVersion: '1.2.4', expectedCurrentVersion: '1.2.3', capability } };
}
async function appVersion(app) {
  const content = await readFile(path.join(app, 'Contents', 'Info.plist'), 'utf8');
  return content.match(/<key>CFBundleShortVersionString<\/key>\s*<string>([^<]+)<\/string>/)?.[1];
}
async function backupPaths(f) {
  return (await readdir(f.installed)).filter(name => name.startsWith('.envara-update-')).map(name => path.join(f.installed, name, 'Envara.app'));
}
function capture(child) {
  const frames = [], updates = new EventEmitter(); let partial = '', stderr = '', closed = false, helperPid = null;
  child.stdin.on('error', () => {});
  child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
  child.stdout.on('data', chunk => {
    partial += chunk;
    for (;;) {
      const end = partial.indexOf('\n'); if (end === -1) break;
      const line = partial.slice(0, end); partial = partial.slice(end + 1);
      if (!line.trim()) continue;
      try { const frame = JSON.parse(line); if (frame.fixture === 'updater-started') helperPid = frame.helperPid; else frames.push(frame); }
      catch { frames.push({ invalidOutput: line.slice(0, 200) }); }
      updates.emit('update');
    }
  });
  child.stderr.on('data', chunk => { stderr = (stderr + chunk).slice(-4000); });
  child.on('error', error => { frames.push({ spawnError: error.message }); updates.emit('update'); });
  child.on('close', () => { closed = true; updates.emit('update'); });
  const waitFor = (predicate, timeout = 15000) => new Promise((resolve, reject) => {
    let timer;
    const cleanup = () => { clearTimeout(timer); updates.off('update', check); };
    function check() {
      const frame = frames.find(predicate);
      if (frame) { cleanup(); resolve(frame); }
      else if (closed) { cleanup(); reject(new Error(`Updater closed without expected frame: ${JSON.stringify(frames)} ${stderr}`)); }
    }
    timer = setTimeout(() => { cleanup(); reject(new Error(`Updater frame timeout: ${JSON.stringify(frames)} ${stderr}`)); }, timeout);
    updates.on('update', check); check();
  });
  return { child, frames, waitFor, get closed() { return closed; },
    send: value => child.stdin.write(`${JSON.stringify(value)}\n`),
    async stop() {
      child.stdin.end();
      // These PIDs belong solely to this test's signed app and forked updater.
      if (child.exitCode == null && child.signalCode == null) child.kill('SIGTERM');
      for (let n = 0; !closed && n < 100; n++) await delay(10);
      if (!closed && Number.isInteger(helperPid)) { try { process.kill(helperPid, 'SIGTERM'); } catch (error) { if (error.code !== 'ESRCH') throw error; } }
      for (let n = 0; !closed && n < 100; n++) await delay(10);
      assert.equal(closed, true, 'owned fixture and updater must finish before deleting their temporary files');
    },
  };
}
async function launch(t, f, changes = {}) {
  const child = spawn(path.join(f.currentApp, 'Contents', 'MacOS', 'Envara'), [f.stagedHelper], { stdio: ['pipe', 'pipe', 'pipe'], env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', TMPDIR: f.directory } });
  const session = capture(child); f.sessions.push(session);
  session.send({ ...f.request, parentPid: child.pid, ...changes });
  return session;
}
async function assertUnchanged(f) {
  assert.equal(await appVersion(f.currentApp), '1.2.3');
  assert.equal(await readFile(path.join(f.userData, 'account-fixture'), 'utf8'), 'preserve account fixture');
  await execute('/usr/bin/codesign', ['--verify', '--deep', '--strict', f.currentApp], { timeout: 15000 });
}
function failed(frame) { assert.equal(frame.schema, schema); assert.equal(frame.type, 'failed'); assert.match(frame.code, /^[A-Z][A-Z0-9_]+$/); }
async function assertReceipt(f, result) {
  const receipt = path.join(f.stageRoot, 'result.json'), text = await readFile(receipt, 'utf8');
  const expected = result.type === 'failed' ? Object.fromEntries(Object.entries(result).filter(([key]) => key !== 'relaunch')) : result;
  assert.deepEqual(JSON.parse(text), expected); assert.equal((await lstat(receipt)).mode & 0o777, 0o600);
  assert.equal(text.includes(f.directory), false, 'receipt must not expose absolute paths');
  assert.equal(text.includes(f.capability), false, 'receipt must not persist the full commit capability');
}

test('builder produces a verifiable arm64 helper and rejects a modified packaged resource', native, async t => {
  const manifest = await checkMacUpdaterResources(path.dirname(helper));
  assert.equal(manifest.schemaVersion, 1); assert.equal(manifest.platform, 'darwin');
  assert.equal(manifest.architecture, 'arm64'); assert.equal(manifest.executable, 'EnvaraUpdater');
  for (const key of ['sha256', 'sourceSha256', 'builderSha256']) assert.match(manifest[key], /^[a-f0-9]{64}$/);
  const f = await fixture(t), copied = path.join(f.directory, 'tampered-build');
  await cp(path.dirname(helper), copied, { recursive: true });
  await writeFile(path.join(copied, 'EnvaraUpdater'), 'corrupted owned fixture');
  await assert.rejects(checkMacUpdaterResources(copied));
});

test('commit waits for the captured parent to exit, atomically installs and retains the signed previous app', native, async t => {
  const f = await fixture(t), session = await launch(t, f);
  const ready = await session.waitFor(frame => frame.type === 'ready');
  assert.equal(ready.schema, schema); assert.match(ready.parentBirth, /^\d+:\d+$/);
  await assertUnchanged(f);
  session.send({ type: 'commit', capability: f.capability });
  await session.waitFor(frame => frame.type === 'authorized');
  await delay(250);
  assert.ok(!session.frames.some(frame => frame.type === 'installed'), 'live parent must prevent replacement');
  await assertUnchanged(f);
  session.child.kill('SIGTERM');
  const installed = await session.waitFor(frame => frame.type === 'installed'); assert.equal(installed.schema, schema);
  await assertReceipt(f, installed);
  assert.equal(await appVersion(f.currentApp), '1.2.4');
  await execute('/usr/bin/codesign', ['--verify', '--deep', '--strict', f.currentApp], { timeout: 15000 });
  const backups = await backupPaths(f); assert.equal(backups.length, 1); assert.equal(await appVersion(backups[0]), '1.2.3');
  await execute('/usr/bin/codesign', ['--verify', '--deep', '--strict', backups[0]], { timeout: 15000 });
  assert.equal(await readFile(path.join(f.userData, 'account-fixture'), 'utf8'), 'preserve account fixture');
});

test('EOF before commit cancels without replacing the app', native, async t => {
  const f = await fixture(t), session = await launch(t, f);
  await session.waitFor(frame => frame.type === 'ready'); session.child.stdin.end();
  const result = await session.waitFor(frame => frame.type === 'failed'); failed(result);
  await assertUnchanged(f);
  assert.deepEqual(await backupPaths(f), [], 'uncommitted preparation must be reclaimed');
  await assert.rejects(lstat(path.join(f.stageRoot, 'result.json')), { code: 'ENOENT' });
  await session.stop();
  const retry = await launch(t, f); await retry.waitFor(frame => frame.type === 'ready'); retry.child.stdin.end();
  failed(await retry.waitFor(frame => frame.type === 'failed')); await assertUnchanged(f);
});

test('an incorrect commit capability cannot authorize replacement', native, async t => {
  const f = await fixture(t), session = await launch(t, f);
  await session.waitFor(frame => frame.type === 'ready'); session.send({ type: 'commit', capability: '0'.repeat(64) });
  failed(await session.waitFor(frame => frame.type === 'failed'));
  await assertUnchanged(f);
  await assert.rejects(lstat(path.join(f.stageRoot, 'result.json')), { code: 'ENOENT' });
});

test('installer-active inspection is read only and follows the owned parent/helper lifetime', native, async t => {
  const f = await fixture(t), session = await launch(t, f);
  await session.waitFor(frame => frame.type === 'ready');
  const inspect = async () => {
    const before = (await readdir(f.stageRoot)).sort(), helperBefore = await lstat(f.stagedHelper);
    const result = await execute(helper, ['--installer-active', f.stageRoot, String(session.child.pid), f.currentApp], {
      timeout: 15000, maxBuffer: 65536, env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', TMPDIR: f.directory },
    });
    assert.deepEqual((await readdir(f.stageRoot)).sort(), before);
    const helperAfter = await lstat(f.stagedHelper);
    assert.equal(helperAfter.ino, helperBefore.ino); assert.equal(helperAfter.mtimeMs, helperBefore.mtimeMs);
    return JSON.parse(result.stdout);
  };
  assert.deepEqual(await inspect(), { schema, type: 'installer-status', active: true });
  session.child.stdin.end(); failed(await session.waitFor(frame => frame.type === 'failed')); await session.stop();
  assert.deepEqual(await inspect(), { schema, type: 'installer-status', active: false });
  await assertUnchanged(f);
});

test('request schema, unknown fields and false parent PID are rejected before ready', native, async t => {
  for (const change of [{ schema: 'untrusted/v1' }, { unexpectedPath: '/unowned' }, { parentPid: 1 }]) {
    await t.test(JSON.stringify(Object.keys(change)), async childTest => {
      const f = await fixture(childTest), session = await launch(childTest, f, change);
      failed(await session.waitFor(frame => frame.type === 'failed'));
      assert.equal(session.frames.some(frame => frame.type === 'ready'), false); await assertUnchanged(f);
    });
  }
});

test('current and target versions are both checked before preparation', native, async t => {
  for (const change of [{ expectedVersion: '9.9.9' }, { expectedCurrentVersion: '0.0.1' }]) {
    await t.test(Object.keys(change)[0], async childTest => {
      const f = await fixture(childTest), session = await launch(childTest, f, change);
      failed(await session.waitFor(frame => frame.type === 'failed')); await assertUnchanged(f);
    });
  }
});

test('minimum macOS system requirement rejects newer or malformed staged bundles before ready', native, async t => {
  const original = '<key>LSMinimumSystemVersion</key><string>12.0</string>';
  const cases = [
    ['newer generic system requirement', '<key>LSMinimumSystemVersion</key><string>9999.0</string>'],
    ['newer arm64 system requirement overrides generic minimum', '<key>LSMinimumSystemVersion</key><string>10.0</string><key>LSMinimumSystemVersionByArchitecture</key><dict><key>arm64</key><string>9999.0</string></dict>'],
    ['malformed system requirement', '<key>LSMinimumSystemVersion</key><string>13.x</string>'],
    ['trailing newline in system requirement', '<key>LSMinimumSystemVersion</key><string>13.0\n</string>'],
    ['invalid architecture system requirement shape', '<key>LSMinimumSystemVersion</key><string>10.0</string><key>LSMinimumSystemVersionByArchitecture</key><string>13.0</string>'],
  ];
  for (const [name, replacement] of cases) await t.test(name, async childTest => {
    const f = await fixture(childTest), infoPlist = path.join(f.stagedApp, 'Contents', 'Info.plist');
    const content = await readFile(infoPlist, 'utf8'); assert.ok(content.includes(original));
    await writeFile(infoPlist, content.replace(original, replacement)); await signApp(f.stagedApp);
    const session = await launch(childTest, f), result = await session.waitFor(frame => frame.type === 'failed');
    failed(result); assert.equal(result.code, 'APP_UPDATE_SYSTEM_UNSUPPORTED');
    assert.equal(session.frames.some(frame => frame.type === 'ready'), false);
    assert.equal(session.frames.some(frame => frame.type === 'installed'), false);
    await assert.rejects(lstat(path.join(f.stageRoot, 'result.json')), { code: 'ENOENT' });
    await assertUnchanged(f);
  });
});

test('a different bundle identity and a damaged staged code signature are refused', native, async t => {
  await t.test('different identity', async childTest => {
    const f = await fixture(childTest);
    await writeFile(path.join(f.stagedApp, 'Contents', 'Info.plist'), plist('1.2.4', 'test.unrelated.application')); await signApp(f.stagedApp);
    const session = await launch(childTest, f); failed(await session.waitFor(frame => frame.type === 'failed')); await assertUnchanged(f);
  });
  await t.test('damaged signature', async childTest => {
    const f = await fixture(childTest); await writeFile(path.join(f.stagedApp, 'Contents', 'Resources', 'fixture.txt'), 'tampered after signing');
    const session = await launch(childTest, f); failed(await session.waitFor(frame => frame.type === 'failed')); await assertUnchanged(f);
  });
  await t.test('wrong architecture', async childTest => {
    const f = await fixture(childTest);
    await execute('/usr/bin/xcrun', ['clang', '-arch', 'x86_64', '-std=c11', '-O2', path.join(shared, 'fixture.c'), '-o', path.join(f.stagedApp, 'Contents', 'MacOS', 'Envara')], { timeout: 30000 });
    await signApp(f.stagedApp);
    const session = await launch(childTest, f); failed(await session.waitFor(frame => frame.type === 'failed')); await assertUnchanged(f);
  });
});

test('symlink stage paths and shared writable staging directories are rejected', native, async t => {
  await t.test('linked staged app', async childTest => {
    const f = await fixture(childTest), outside = path.join(f.directory, 'outside.app');
    await cp(f.stagedApp, outside, { recursive: true }); await rm(f.stagedApp, { recursive: true }); await symlink(outside, f.stagedApp);
    const session = await launch(childTest, f); failed(await session.waitFor(frame => frame.type === 'failed')); await assertUnchanged(f);
    assert.equal(await appVersion(outside), '1.2.4');
  });
  await t.test('linked stage root', async childTest => {
    const f = await fixture(childTest), alias = path.join(f.directory, 'stage-alias'); await symlink(f.stageRoot, alias);
    const session = await launch(childTest, f, { stageRoot: alias, stagedApp: path.join(alias, 'Envara.app') });
    failed(await session.waitFor(frame => frame.type === 'failed')); await assertUnchanged(f);
  });
  await t.test('shared writable staging', async childTest => {
    const f = await fixture(childTest); await chmod(f.stageRoot, 0o777);
    const session = await launch(childTest, f); failed(await session.waitFor(frame => frame.type === 'failed')); await assertUnchanged(f);
  });
});

test('a helper directly launched by Node cannot impersonate the current signed app parent', native, async t => {
  const f = await fixture(t), child = spawn(f.stagedHelper, [], { stdio: ['pipe', 'pipe', 'pipe'], env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', TMPDIR: f.directory } });
  const session = capture(child); f.sessions.push(session); session.send({ ...f.request, parentPid: process.pid });
  failed(await session.waitFor(frame => frame.type === 'failed')); await assertUnchanged(f);
});

test('the helper accepts no command-line override arguments', native, async t => {
  const f = await fixture(t), child = spawn(f.stagedHelper, ['--current-app', f.currentApp], {
    stdio: ['pipe', 'pipe', 'pipe'], env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', TMPDIR: f.directory },
  });
  const session = capture(child); f.sessions.push(session);
  const result = await session.waitFor(frame => frame.type === 'failed'); failed(result); assert.equal(result.code, 'APP_UPDATE_LOCATION');
  await assertUnchanged(f);
});

test('post-swap validation failure rolls back the two captured app identities', { ...native, timeout: 90000 }, async t => {
  const f = await fixture(t);
  const production = await readFile(new URL('../native/macos-updater/main.swift', import.meta.url), 'utf8');
  const point = 'try validateBundle(currentApp, version: version)';
  assert.equal(production.split(point).length - 1, 1, 'fault injection must identify only the post-swap validation');
  // Fault injection exists only in this disposable source, never in production
  // environment flags, request fields or installer command-line arguments.
  const injected = production.replace(point, 'throw Refusal(code: "APP_UPDATE_VALIDATION")');
  const source = path.join(f.directory, 'rollback-fixture.swift'); await writeFile(source, injected);
  await execute('/usr/bin/xcrun', ['swiftc', '-O', '-target', 'arm64-apple-macos13.0', source, '-o', f.stagedHelper], { timeout: 60000, maxBuffer: 1024 * 1024 });
  await execute('/usr/bin/codesign', ['--force', '--sign', '-', f.stagedHelper], { timeout: 15000 }); await chmod(f.stagedHelper, 0o700);
  const session = await launch(t, f); await session.waitFor(frame => frame.type === 'ready');
  session.send({ type: 'commit', capability: f.capability }); await session.waitFor(frame => frame.type === 'authorized');
  session.child.kill('SIGTERM');
  const result = await session.waitFor(frame => frame.type === 'failed');
  failed(result); assert.equal(result.code, 'APP_UPDATE_ROLLED_BACK'); assert.equal(result.replaced, false);
  await assertReceipt(f, result); assert.ok(['requested', 'failed'].includes(result.relaunch));
  assert.equal(session.frames.some(frame => frame.type === 'installed'), false);
  await assertUnchanged(f);
});

test('rollback revalidation uncertainty retains recovery and does not request a relaunch', { ...native, timeout: 90000 }, async t => {
  const f = await fixture(t);
  const production = await readFile(new URL('../native/macos-updater/main.swift', import.meta.url), 'utf8');
  const afterSwap = 'try validateBundle(currentApp, version: version)';
  const afterRollback = 'do { try validateBundle(currentApp, version: previous) }';
  assert.equal(production.split(afterSwap).length - 1, 1);
  assert.equal(production.split(afterRollback).length - 1, 1);
  const injected = production.replace(afterSwap, 'throw Refusal(code: "APP_UPDATE_VALIDATION")')
    .replace(afterRollback, 'do { throw Refusal(code: "APP_UPDATE_VALIDATION") }');
  const source = path.join(f.directory, 'rollback-uncertain-fixture.swift'); await writeFile(source, injected);
  await execute('/usr/bin/xcrun', ['swiftc', '-O', '-target', 'arm64-apple-macos13.0', source, '-o', f.stagedHelper], { timeout: 60000, maxBuffer: 1024 * 1024 });
  await execute('/usr/bin/codesign', ['--force', '--sign', '-', f.stagedHelper], { timeout: 15000 }); await chmod(f.stagedHelper, 0o700);
  const session = await launch(t, f); await session.waitFor(frame => frame.type === 'ready');
  session.send({ type: 'commit', capability: f.capability }); await session.waitFor(frame => frame.type === 'authorized');
  session.child.kill('SIGTERM');
  const result = await session.waitFor(frame => frame.type === 'failed');
  failed(result); assert.equal(result.code, 'APP_UPDATE_ROLLBACK_UNCERTAIN'); assert.equal(result.replaced, false);
  assert.equal(Object.hasOwn(result, 'relaunch'), false, 'uncertain rollback must not authorize restarting either app');
  assert.equal(session.frames.some(frame => frame.type === 'installed'), false);
  await assertReceipt(f, result); await assertUnchanged(f);
  assert.equal((await backupPaths(f)).length, 1, 'retain the owned recovery copy on uncertainty');
});

test('prepared app content is revalidated after ready and parent exit before any swap', native, async t => {
  const f = await fixture(t), session = await launch(t, f);
  await session.waitFor(frame => frame.type === 'ready');
  const prepared = await backupPaths(f); assert.equal(prepared.length, 1);
  await writeFile(path.join(prepared[0], 'Contents', 'Resources', 'fixture.txt'), 'changed after ready');
  session.send({ type: 'commit', capability: f.capability }); await session.waitFor(frame => frame.type === 'authorized');
  session.child.kill('SIGTERM');
  const result = await session.waitFor(frame => frame.type === 'failed');
  failed(result); assert.equal(result.replaced, false);
  await assertReceipt(f, result); assert.ok(['requested', 'failed'].includes(result.relaunch));
  assert.equal(session.frames.some(frame => frame.type === 'installed'), false);
  await assertUnchanged(f);
});

test('reopening the old executable after commit prevents replacement without ending that new instance', native, async t => {
  const f = await fixture(t), session = await launch(t, f);
  await session.waitFor(frame => frame.type === 'ready');
  session.send({ type: 'commit', capability: f.capability }); await session.waitFor(frame => frame.type === 'authorized');
  const reopened = capture(spawn(path.join(f.currentApp, 'Contents', 'MacOS', 'Envara'), ['--owned-wait', 'fixture'], {
    stdio: ['pipe', 'pipe', 'pipe'], env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', TMPDIR: f.directory },
  }));
  f.sessions.push(reopened); await reopened.waitFor(frame => frame.fixture === 'waiting');
  session.child.kill('SIGTERM');
  const result = await session.waitFor(frame => frame.type === 'failed');
  failed(result); assert.equal(result.code, 'APP_UPDATE_APP_RUNNING'); assert.equal(result.replaced, false);
  assert.equal(reopened.child.exitCode, null); assert.equal(reopened.child.signalCode, null);
  assert.doesNotThrow(() => process.kill(reopened.child.pid, 0), 'installer must leave the reopened owned instance running');
  await assertReceipt(f, result); await assertUnchanged(f);
});
