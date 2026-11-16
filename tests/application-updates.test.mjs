import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile, writeFile, readdir, lstat, realpath, rm, symlink } from 'node:fs/promises';
import { createApplicationUpdater, readApplicationInstallation, APPLICATION_UPDATE_ERRORS } from '../electron/application-updates.mjs';

const API = 'https://api.github.com/repos/ink-scholar/Envara/releases/latest';
const BASE = 'https://github.com/ink-scholar/Envara/releases/download/v1.3.0/';
const ZIP = 'Envara-1.3.0-mac-arm64.zip';
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const deferred = () => { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { promise, resolve, reject }; };
const tick = () => new Promise(resolve => setImmediate(resolve));
async function until(predicate) { for (let i = 0; i < 100; i++) { if (predicate()) return; await new Promise(resolve => setTimeout(resolve, 5)); } assert.fail('Fixture condition did not settle'); }

async function fixture(t, options = {}) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-update-test-')));
  const cacheDir = path.join(root, 'updates');
  const privateData = path.join(root, 'user-data');
  await mkdir(privateData); await writeFile(path.join(privateData, 'login.json'), 'existing login fixture');
  const archive = Buffer.from('synthetic owned archive fixture');
  const sums = Buffer.from(`${sha(archive)}  ${ZIP}\n`);
  const asset = (id, name, bytes) => ({ id, name, state: 'uploaded', size: bytes.length,
    digest: `sha256:${sha(bytes)}`, browser_download_url: `${BASE}${name}` });
  const f = { root, cacheDir, privateData, archive, sums, calls: [], prepared: [], installed: [],
    release: { id: 1, draft: false, prerelease: false, tag_name: 'v1.3.0',
      assets: [asset(2, ZIP, archive), asset(3, 'SHA256SUMS.txt', sums)] } };
  f.respond = async url => {
    if (url === API) return new Response(JSON.stringify(f.release));
    if (url === `${BASE}SHA256SUMS.txt`) return new Response(f.sums);
    if (url === `${BASE}${ZIP}`) return new Response(f.archive);
    throw new Error('unexpected private fixture URL');
  };
  f.setSums = value => {
    f.sums = Buffer.from(value);
    Object.assign(f.release.assets[1], { size: f.sums.length, digest: `sha256:${sha(f.sums)}` });
  };
  f.updater = createApplicationUpdater({ currentVersion: '1.2.3', platform: 'darwin', arch: 'arm64', packaged: true, cacheDir,
    fetch: async (url, init) => { f.calls.push({ url, init }); return f.respond(url, init); },
    prepare: async args => {
      f.prepared.push(args);
      assert.equal(await readFile(args.archivePath, 'utf8'), archive.toString());
      assert.equal((await lstat(args.archivePath)).mode & 0o777, 0o600);
      assert.equal((await lstat(args.stagingDir)).mode & 0o777, 0o700);
      return { version: args.version, privatePath: args.stagingDir, secret: 'PRIVATE-HANDLE' };
    },
    install: async prepared => { f.installed.push(prepared); }, ...options });
  t.after(async () => { await f.updater.close(); await rm(root, { recursive: true, force: true }); });
  return f;
}

test('explicit update checks pin exact official assets and verify bytes before private preparation', async t => {
  const f = await fixture(t);
  assert.equal(f.calls.length, 0);
  assert.equal(f.updater.snapshot().status, 'idle');
  assert.equal((await f.updater.check()).status, 'available');
  const state = await f.updater.download();
  assert.equal(state.status, 'ready'); assert.equal(state.canInstall, true);
  assert.deepEqual(state.progress, { percent: 100, received: f.archive.length, total: f.archive.length });
  assert.equal(f.prepared.length, 1);
  assert.equal(f.prepared[0].sha256, sha(f.archive));
  assert.equal(f.calls.length, 3);
  for (const { init } of f.calls) {
    assert.equal(init.redirect, 'manual'); assert.equal(init.credentials, 'omit');
    assert.equal(Object.keys(init.headers).some(key => /cookie|authorization/i.test(key)), false);
  }
  assert.doesNotMatch(JSON.stringify(state), /PRIVATE|https:|archivePath|stagingDir|releaseId|sha256/);
  const copy = f.updater.snapshot(); copy.progress.received = -20;
  assert.equal(f.updater.snapshot().progress.received, f.archive.length);
  const count = f.calls.length;
  assert.equal((await f.updater.check()).status, 'ready');
  assert.equal((await f.updater.download()).status, 'ready');
  assert.equal(f.calls.length, count, 'checking never discards the ready candidate');
  const installed = await f.updater.install();
  assert.equal(installed.status, 'installing'); assert.equal(installed.canInstall, false);
  assert.equal(f.installed[0].secret, 'PRIVATE-HANDLE');
  assert.equal(await readFile(path.join(f.privateData, 'login.json'), 'utf8'), 'existing login fixture');
  await f.updater.close();
  assert.equal((await lstat(f.prepared[0].stagingDir)).isDirectory(), true, 'committed installer owns stage lifetime');
});

test('development and unavailable platform builds never use network', async t => {
  for (const options of [{ packaged: false }, { platform: 'win32' }, { arch: 'x64' }, { currentVersion: '1.2.3\nprivate' }]) {
    const f = await fixture(t, options);
    assert.equal((await f.updater.check()).status, 'unsupported');
    assert.equal((await f.updater.download()).status, 'unsupported');
    assert.equal((await f.updater.install()).canInstall, false);
    assert.equal(f.calls.length, 0);
    assert.doesNotMatch(JSON.stringify(f.updater.snapshot()), /private/);
  }
});

test('version comparison is numeric and never permits a downgrade', async t => {
  for (const [currentVersion, status] of [['1.3.0', 'current'], ['2.0.0', 'current'], ['1.10.0', 'current'], ['1.2.99', 'available']]) {
    const f = await fixture(t, { currentVersion });
    assert.equal((await f.updater.check()).status, status);
    if (status === 'current') assert.equal((await f.updater.download()).error, 'APP_UPDATE_CHECK_REQUIRED');
  }
});

test('hostile release metadata cannot choose another package, URL, channel or unbounded asset', async t => {
  const cases = [
    ['draft', r => { r.draft = true; }], ['prerelease', r => { r.prerelease = true; }],
    ['unstable tag', r => { r.tag_name = 'v1.3.0-rc.1'; }],
    ['ambiguous asset', r => { r.assets.push({ ...r.assets[0] }); }],
    ['wrong origin', r => { r.assets[0].browser_download_url = 'https://private.example/token'; }],
    ['embedded credentials', r => { r.assets[0].browser_download_url = `${BASE.replace('https://', 'https://secret@')}${ZIP}`; }],
    ['other repository', r => { r.assets[0].browser_download_url = r.assets[0].browser_download_url.replace('ink-scholar', 'someone'); }],
    ['missing digest', r => { delete r.assets[0].digest; }],
    ['wrong digest algorithm', r => { r.assets[0].digest = 'sha1:' + 'a'.repeat(40); }],
    ['not uploaded', r => { r.assets[0].state = 'new'; }],
    ['unsafe size', r => { r.assets[0].size = 1.5; }],
    ['large archive', r => { r.assets[0].size = 1024 ** 3 + 1; }, 'APP_UPDATE_TOO_LARGE'],
    ['missing platform asset', r => { r.assets[0].name = 'Envara-1.3.0-mac-x64.zip'; }, 'APP_UPDATE_ASSET_UNAVAILABLE'],
    ['missing sums', r => { r.assets.pop(); }, 'APP_UPDATE_ASSET_UNAVAILABLE'],
  ];
  for (const [name, mutate, expected = 'APP_UPDATE_METADATA_INVALID'] of cases) await t.test(name, async t => {
    const f = await fixture(t); mutate(f.release);
    const result = await f.updater.check();
    assert.equal(result.error, expected); assert.equal(result.canInstall, false);
    assert.equal(f.calls.length, 1); assert.equal(f.prepared.length, 0);
    assert.doesNotMatch(JSON.stringify(result), /secret|token|private\.example|someone/);
  });
});

test('metadata responses are byte bounded and raw failures are sanitized', async t => {
  const f = await fixture(t);
  f.respond = async () => new Response('{}', { headers: { 'content-length': String(2 * 1024 * 1024 + 1) } });
  assert.equal((await f.updater.check()).error, 'APP_UPDATE_TOO_LARGE');
  f.respond = async () => new Response(new Uint8Array(2 * 1024 * 1024 + 1));
  assert.equal((await f.updater.check()).error, 'APP_UPDATE_TOO_LARGE');
  f.respond = async () => new Response('not JSON private/token');
  assert.equal((await f.updater.check()).error, 'APP_UPDATE_METADATA_INVALID');
  f.respond = async () => { throw new Error('private host, token, password'); };
  const result = await f.updater.check();
  assert.equal(result.error, 'APP_UPDATE_NETWORK');
  assert.doesNotMatch(JSON.stringify(result), /private|token|password/);
});

test('redirects allow bounded official HTTPS asset delivery and reject other destinations', async t => {
  for (const location of ['https://evil.example/update', 'http://github.com/update', 'https://github.com:444/update',
    'https://secret@github.com/update', 'https://release-assets.githubusercontent.com.evil.example/update']) {
    const f = await fixture(t);
    f.respond = async () => new Response(null, { status: 302, headers: { location } });
    assert.equal((await f.updater.check()).error, 'APP_UPDATE_METADATA_INVALID');
    assert.equal(f.calls.length, 1);
  }
  const f = await fixture(t); const respond = f.respond;
  f.respond = async url => url === `${BASE}${ZIP}` ? new Response(null, { status: 302,
    headers: { location: 'https://release-assets.githubusercontent.com/github-production-release-asset/owned?sig=private' } })
    : url.startsWith('https://release-assets.') ? new Response(f.archive) : respond(url);
  await f.updater.check(); assert.equal((await f.updater.download()).status, 'ready');
  assert.equal(f.calls.length, 4); assert.doesNotMatch(JSON.stringify(f.updater.snapshot()), /private/);
  await f.updater.cancel();
  const loop = await fixture(t);
  loop.respond = async () => new Response(null, { status: 302, headers: { location: API } });
  assert.equal((await loop.updater.check()).error, 'APP_UPDATE_METADATA_INVALID');
  assert.equal(loop.calls.length, 5);
});

test('API digest, checksum manifest and exact archive bytes must all agree', async t => {
  for (const mode of ['manifest bytes', 'manifest mismatch', 'duplicate manifest', 'missing manifest entry', 'archive bytes', 'truncated archive', 'large archive stream']) await t.test(mode, async t => {
    const f = await fixture(t);
    if (mode === 'manifest bytes') f.sums[0] = f.sums[0] === 97 ? 98 : 97;
    if (mode === 'manifest mismatch') f.setSums(`${'f'.repeat(64)}  ${ZIP}\n`);
    if (mode === 'duplicate manifest') f.setSums(f.sums.toString().repeat(2));
    if (mode === 'missing manifest entry') f.setSums(`${sha(f.archive)}  Other.zip\n`);
    await f.updater.check();
    if (mode === 'archive bytes') f.archive[0] ^= 1;
    if (mode === 'truncated archive') f.archive = f.archive.subarray(0, -1);
    if (mode === 'large archive stream') f.archive = Buffer.concat([f.archive, Buffer.from('x')]);
    const result = await f.updater.download();
    assert.equal(result.error, mode === 'duplicate manifest' ? 'APP_UPDATE_METADATA_INVALID' : 'APP_UPDATE_HASH_MISMATCH');
    assert.equal(result.canInstall, false); assert.equal(f.prepared.length, 0);
    assert.deepEqual(await readdir(f.cacheDir).catch(() => []), []);
    assert.equal(await readFile(path.join(f.privateData, 'login.json'), 'utf8'), 'existing login fixture');
  });
});

test('coalesced checks/downloads make one request sequence and ready candidates survive rechecks', async t => {
  const gate = deferred(); const f = await fixture(t); const respond = f.respond;
  f.respond = async url => { if (url === API) await gate.promise; return respond(url); };
  const first = f.updater.check(), second = f.updater.check(); assert.equal(first, second);
  assert.equal(f.updater.snapshot().status, 'checking'); gate.resolve(); await first;
  const download = f.updater.download(); assert.equal(download, f.updater.download());
  await download; assert.equal(f.calls.length, 3);
  await f.updater.check(); assert.equal(f.calls.length, 3);
});

test('cancel ignores a late check response and a later check can succeed', async t => {
  const gate = deferred(); const f = await fixture(t); const respond = f.respond;
  f.respond = async url => { if (url === API) await gate.promise; return respond(url); };
  const checking = f.updater.check(); await tick();
  assert.equal((await f.updater.cancel()).status, 'idle');
  gate.resolve(); await checking; await tick();
  assert.equal(f.updater.snapshot().status, 'idle'); assert.equal(f.updater.snapshot().latestVersion, null);
  f.respond = respond; assert.equal((await f.updater.check()).status, 'available');
});

test('cancel during streaming aborts and removes only this incomplete download', async t => {
  const f = await fixture(t); const respond = f.respond;
  let streamCancelled = false;
  f.respond = async url => url === `${BASE}${ZIP}` ? new Response(new ReadableStream({
    start(controller) { controller.enqueue(f.archive.subarray(0, 4)); }, cancel() { streamCancelled = true; },
  })) : respond(url);
  await f.updater.check();
  await mkdir(f.cacheDir, { mode: 0o700 }); await writeFile(path.join(f.cacheDir, 'unrelated.txt'), 'preserve');
  const downloading = f.updater.download();
  await until(() => f.updater.snapshot().progress.received === 4);
  const result = await f.updater.cancel(); await downloading;
  assert.equal(result.status, 'available'); assert.equal(result.error, null); assert.equal(streamCancelled, true);
  assert.deepEqual(await readdir(f.cacheDir), ['unrelated.txt']);
  assert.equal(f.prepared.length, 0);
});

test('cancellation waits for preparation to stop writing and suppresses stale ready state', async t => {
  const gate = deferred(), entered = deferred(); let args;
  const f = await fixture(t, { prepare: async value => { args = value; entered.resolve(); await gate.promise;
    await writeFile(path.join(value.stagingDir, 'late-owned-file'), 'fixture'); return { private: true }; } });
  await f.updater.check(); const downloading = f.updater.download(); await entered.promise;
  let cancelled = false; const cancelling = f.updater.cancel().then(value => { cancelled = true; return value; });
  await tick(); assert.equal(cancelled, false); assert.equal(args.signal.aborted, true);
  gate.resolve(); await downloading;
  assert.equal((await cancelling).status, 'available');
  assert.deepEqual(await readdir(f.cacheDir), []); assert.equal(f.updater.snapshot().canInstall, false);
});

test('unsafe cache roots and replaced stage directories are not followed or deleted', async t => {
  const f = await fixture(t);
  await symlink(f.privateData, f.cacheDir);
  await f.updater.check(); assert.equal((await f.updater.download()).error, 'APP_UPDATE_UNSAFE_PATH');
  assert.equal(await readFile(path.join(f.privateData, 'login.json'), 'utf8'), 'existing login fixture');
  const g = await fixture(t);
  await g.updater.check(); await g.updater.download();
  const stage = g.prepared[0].stagingDir;
  await rm(stage, { recursive: true }); await symlink(g.privateData, stage);
  assert.equal((await g.updater.cancel()).error, 'APP_UPDATE_CLEANUP');
  assert.equal((await lstat(stage)).isSymbolicLink(), true);
  assert.equal(await readFile(path.join(g.privateData, 'login.json'), 'utf8'), 'existing login fixture');
});

test('failed preparation never creates an installable candidate and can download again', async t => {
  let fail = true;
  const f = await fixture(t, { prepare: async args => { if (fail) throw new Error('private extraction command output'); return { stage: args.stagingDir }; } });
  await f.updater.check();
  assert.equal((await f.updater.download()).error, 'APP_UPDATE_PREPARE_FAILED');
  assert.deepEqual(await readdir(f.cacheDir), []);
  fail = false; assert.equal((await f.updater.download()).canInstall, true);
});

test('busy or cleanup-refused installs preserve staged bytes for retry without redownload', async t => {
  let count = 0;
  const f = await fixture(t, { install: async () => {
    count++; if (count < 3) throw Object.assign(new Error('private process details'), { code: count === 1 ? 'APP_UPDATE_BUSY' : 'APP_UPDATE_CLEANUP' });
  } });
  await f.updater.check(); await f.updater.download(); const stage = f.prepared[0].stagingDir;
  for (const error of ['APP_UPDATE_BUSY', 'APP_UPDATE_CLEANUP']) {
    const result = await f.updater.install();
    assert.equal(result.status, 'ready'); assert.equal(result.error, error); assert.equal(result.canInstall, true);
    assert.equal((await lstat(stage)).isDirectory(), true);
  }
  assert.equal((await f.updater.install()).canInstall, false); assert.equal(f.calls.length, 3);
});

test('deferred installation acknowledges immediately and holds ownership until its outcome', async t => {
  const completion = deferred(); let installs = 0;
  const f = await fixture(t, { install: () => { installs++; return { accepted: true, completion: completion.promise }; } });
  await f.updater.check(); await f.updater.download();
  const stage = f.prepared[0].stagingDir;
  assert.equal((await f.updater.install()).status, 'installing');
  assert.equal((await f.updater.cancel()).status, 'installing');
  await f.updater.install(); assert.equal(installs, 1);
  assert.equal((await lstat(stage)).isDirectory(), true);
  completion.reject(new Error('private installation failure')); await until(() => f.updater.snapshot().status === 'ready');
  assert.equal(f.updater.snapshot().status, 'ready'); assert.equal(f.updater.snapshot().canInstall, true);
  assert.equal(f.updater.snapshot().error, 'APP_UPDATE_INSTALL_FAILED');
});

test('shutdown cannot delete files or deadlock while an accepted installation is running', async t => {
  const completion = deferred();
  const f = await fixture(t, { install: () => ({ accepted: true, completion: completion.promise }) });
  await f.updater.check(); await f.updater.download(); await f.updater.install();
  const stage = f.prepared[0].stagingDir;
  await f.updater.close(); assert.equal((await lstat(stage)).isDirectory(), true);
  assert.equal((await f.updater.check()).error, 'APP_UPDATE_CLOSED');
  completion.resolve(); await tick(); assert.equal((await lstat(stage)).isDirectory(), true);
});

test('request deadlines expose a fixed timeout and error codes remain a public allowlist', async t => {
  let time = 0;
  const f = await fixture(t, { now: () => { time += 31_000; return time; } });
  assert.equal((await f.updater.check()).error, 'APP_UPDATE_TIMEOUT');
  assert.equal(f.calls.length, 0);
  assert.equal(new Set(APPLICATION_UPDATE_ERRORS).size, APPLICATION_UPDATE_ERRORS.length);
  assert.equal(APPLICATION_UPDATE_ERRORS.every(code => /^APP_UPDATE_[A-Z_]+$/.test(code)), true);
  assert.equal(APPLICATION_UPDATE_ERRORS.includes('APP_UPDATE_CANCELLED'), false);
});

function recoveryUpdater(t, cacheDir) {
  const updater = createApplicationUpdater({ currentVersion: '1.3.0', platform: 'darwin', arch: 'arm64', packaged: true, cacheDir,
    fetch: () => { assert.fail('Recovery must not fetch'); }, prepare: () => { assert.fail('Recovery cannot prepare'); },
    install: () => { assert.fail('Recovery cannot restore installation authority'); } });
  t.after(() => updater.close());
  return updater;
}

test('installation pointer is durable before the dependency can schedule quitting', async t => {
  let f, observed;
  f = await fixture(t, { install: async () => {
    observed = JSON.parse(await readFile(path.join(f.cacheDir, 'last-installation.json'), 'utf8'));
    assert.equal(observed.outcome, 'pending');
    assert.equal((await lstat(path.join(f.cacheDir, 'last-installation.json'))).mode & 0o777, 0o600);
  } });
  await f.updater.check(); await f.updater.download(); await f.updater.install();
  assert.equal(observed.version, '1.3.0'); assert.match(observed.stageName, /^update-[A-Za-z0-9]{6}$/);
  assert.doesNotMatch(JSON.stringify(observed), /privatePath|PRIVATE|https:|\/Users|archivePath/);
});

test('a new process reports installed/failed receipts without reclaiming helper or backup files', async t => {
  for (const [receipt, expected] of [
    [{ type: 'installed', version: '1.3.0', relaunch: 'requested', backupName: '.envara-update-0123456789abcdef' }, { status: 'installed', error: null }],
    [{ type: 'installed', version: '1.3.0', relaunch: 'failed' }, { status: 'installed', error: 'APP_UPDATE_HELPER' }],
    [{ type: 'failed', code: 'APP_UPDATE_ROLLBACK_UNCERTAIN', committed: true, replaced: true }, { status: 'failed', error: 'APP_UPDATE_ROLLBACK_FAILED' }],
    [{ type: 'failed', code: 'raw private token secret', committed: false, replaced: false }, { status: 'pending', error: 'APP_UPDATE_PROTOCOL' }],
  ]) {
    const f = await fixture(t); await f.updater.check(); await f.updater.download(); await f.updater.install();
    const stage = f.prepared[0].stagingDir;
    await writeFile(path.join(stage, 'result.json'), JSON.stringify({ schema: 'envara.mac-update/v1', ...receipt }), { mode: 0o600 });
    await writeFile(path.join(stage, 'keep-helper-fixture'), 'owned helper');
    const next = recoveryUpdater(t, f.cacheDir); await next.ready;
    assert.deepEqual(next.snapshot().lastResult, { ...expected, version: '1.3.0' });
    assert.equal(next.snapshot().canInstall, false);
    assert.equal((await next.install()).error, 'APP_UPDATE_CHECK_REQUIRED');
    await next.close();
    assert.equal(await readFile(path.join(stage, 'keep-helper-fixture'), 'utf8'), 'owned helper');
    assert.doesNotMatch(JSON.stringify(next.snapshot()), /private token|keep-helper|stageName|backupName/);
  }
});

test('missing final receipt stays unconfirmed until an explicit bounded reread observes publication', async t => {
  const f = await fixture(t); await f.updater.check(); await f.updater.download(); await f.updater.install();
  const next = recoveryUpdater(t, f.cacheDir); await next.ready;
  assert.deepEqual(next.snapshot().lastResult, { status: 'pending', version: '1.3.0', error: null });
  const stage = f.prepared[0].stagingDir;
  await writeFile(path.join(stage, 'result.json'), JSON.stringify({ schema: 'envara.mac-update/v1', type: 'installed', version: '1.3.0', relaunch: 'requested' }), { mode: 0o600 });
  const first = next.refreshResult(); assert.equal(first, next.refreshResult());
  assert.equal((await first).lastResult.status, 'installed');
  assert.equal((await lstat(stage)).isDirectory(), true);
});

test('recovery never follows attacker-selected pointer paths or receipt links', async t => {
  const f = await fixture(t); await f.updater.check(); await f.updater.download(); await f.updater.install();
  const pointerPath = path.join(f.cacheDir, 'last-installation.json');
  const pointer = JSON.parse(await readFile(pointerPath, 'utf8'));
  await writeFile(pointerPath, JSON.stringify({ ...pointer, stageName: '../user-data' }));
  const badPointer = recoveryUpdater(t, f.cacheDir); await badPointer.ready;
  assert.equal(badPointer.snapshot().error, 'APP_UPDATE_PROTOCOL'); assert.equal(badPointer.snapshot().lastResult, null);
  await writeFile(pointerPath, JSON.stringify(pointer));
  const stage = f.prepared[0].stagingDir;
  await symlink(path.join(f.privateData, 'login.json'), path.join(stage, 'result.json'));
  const badReceipt = recoveryUpdater(t, f.cacheDir); await badReceipt.ready;
  assert.deepEqual(badReceipt.snapshot().lastResult, { status: 'pending', version: '1.3.0', error: 'APP_UPDATE_PROTOCOL' });
  assert.equal(await readFile(path.join(f.privateData, 'login.json'), 'utf8'), 'existing login fixture');
  assert.equal((await lstat(path.join(stage, 'result.json'))).isSymbolicLink(), true);
});

test('pre-install refusals survive restart without pretending a helper ran', async t => {
  const f = await fixture(t, { install: () => { throw Object.assign(new Error('active user sessions'), { code: 'APP_UPDATE_BUSY' }); } });
  await f.updater.check(); await f.updater.download(); await f.updater.install();
  const next = recoveryUpdater(t, f.cacheDir); await next.ready;
  assert.deepEqual(next.snapshot().lastResult, { status: 'failed', version: '1.3.0', error: 'APP_UPDATE_BUSY' });
  assert.equal(next.snapshot().canInstall, false);
});

test('private startup inspection returns only a verified owned stage and known final receipt', async t => {
  const f = await fixture(t);
  assert.equal(await readApplicationInstallation({ cacheDir: f.cacheDir }), null);
  await f.updater.check(); await f.updater.download(); await f.updater.install();
  const stage = f.prepared[0].stagingDir;
  const pending = await readApplicationInstallation({ cacheDir: f.cacheDir });
  assert.deepEqual(pending, { stageRoot: stage, version: '1.3.0', originatingPid: process.pid, outcome: 'pending', error: null, receipt: null });
  await writeFile(path.join(stage, 'result.json'), JSON.stringify({ schema: 'envara.mac-update/v1',
    type: 'failed', code: 'APP_UPDATE_APP_RUNNING', committed: true, replaced: false, extra: 'private detail' }), { mode: 0o600 });
  const observed = await readApplicationInstallation({ cacheDir: f.cacheDir });
  assert.deepEqual(observed.receipt, { type: 'failed', code: 'APP_UPDATE_APP_RUNNING', committed: true, replaced: false });
  assert.doesNotMatch(JSON.stringify(observed), /private detail/);
  await rm(path.join(stage, 'result.json'));
  await rm(stage, { recursive: true });
  await assert.rejects(readApplicationInstallation({ cacheDir: f.cacheDir }), { code: 'APP_UPDATE_PROTOCOL' });
});

test('invalid installation acknowledgements retain the candidate instead of claiming a handoff', async t => {
  for (const result of [{ accepted: false }, { accepted: true }, { unexpected: true }]) {
    const f = await fixture(t, { install: () => result });
    await f.updater.check(); await f.updater.download();
    const state = await f.updater.install();
    assert.equal(state.status, 'ready'); assert.equal(state.error, 'APP_UPDATE_PROTOCOL'); assert.equal(state.canInstall, true);
  }
});

test('pending pointers without a valid originating process remain fail closed', async t => {
  const f = await fixture(t); await f.updater.check(); await f.updater.download(); await f.updater.install();
  const pointerPath = path.join(f.cacheDir, 'last-installation.json');
  const pointer = JSON.parse(await readFile(pointerPath, 'utf8'));
  for (const originatingPid of [undefined, 0, -1, 1.1, 2147483648, '123']) {
    await writeFile(pointerPath, JSON.stringify({ ...pointer, originatingPid }));
    await assert.rejects(readApplicationInstallation({ cacheDir: f.cacheDir }), { code: 'APP_UPDATE_PROTOCOL' });
  }
  assert.doesNotMatch(JSON.stringify(f.updater.snapshot()), /originatingPid|stageRoot|stageDev|stageIno/);
});
