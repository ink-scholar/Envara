import { macOSOnly as test } from './support/platform-test.mjs';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { EventEmitter } from 'node:events';
import { PassThrough, Writable } from 'node:stream';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, realpath, writeFile, readFile, rm } from 'node:fs/promises';
import { createMacApplicationUpdateAdapter } from '../electron/macos-application-updater.mjs';

const schema = 'envara.mac-update/v1';
async function fixture(t, options = {}) {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-update-adapter-')));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const currentApp = path.join(directory, 'Envara.app'), helperDirectory = path.join(directory, 'resources');
  const stagingDir = path.join(directory, 'stage');
  await mkdir(currentApp, { mode: 0o700 }); await mkdir(helperDirectory, { mode: 0o700 }); await mkdir(stagingDir, { mode: 0o700 });
  await writeFile(path.join(directory, 'account-sentinel'), 'unchanged');
  const helperBytes = Buffer.from('synthetic updater fixture');
  await writeFile(path.join(helperDirectory, 'EnvaraUpdater'), helperBytes, { mode: 0o700 });
  const manifest = { schemaVersion: 1, platform: 'darwin', architecture: 'arm64', executable: 'EnvaraUpdater',
    sha256: createHash('sha256').update(helperBytes).digest('hex') };
  await writeFile(path.join(helperDirectory, 'manifest.json'), JSON.stringify(manifest), { mode: 0o600 });
  const calls = [], frames = [];
  let child;
  const spawnHelper = (executable, args, spawnOptions) => {
    calls.push({ executable, args, spawnOptions });
    child = new EventEmitter(); child.stdout = new PassThrough(); child.unref = () => {};
    child.stdin = new Writable({ write(bytes, encoding, done) {
      const frame = JSON.parse(bytes.toString()); frames.push(frame);
      const response = frame.type === 'commit' ? { schema, type: options.refuseCommit ? 'failed' : 'authorized', code: 'APP_UPDATE_PARENT' }
        : { schema, type: options.refuseReady ? 'failed' : 'ready', code: 'APP_UPDATE_LOCATION' };
      queueMicrotask(() => child.stdout.write(`${JSON.stringify(response)}\n`)); done();
    }, final(done) { done(); queueMicrotask(() => child.emit('close', 0, null)); } });
    child.kill = () => { child.emit('close', null, 'SIGTERM'); return true; };
    return child;
  };
  const run = async (command, args) => {
    if (command.endsWith('plutil')) return { stdout: JSON.stringify({ CFBundleIdentifier: options.wrongId ? 'wrong' : 'io.envara.desktop', CFBundleShortVersionString: '1.2.4', CFBundleExecutable: 'Envara', ...(options.minimum ? { LSMinimumSystemVersion: options.minimum } : {}) }) };
    if (command.endsWith('lipo')) return { stdout: options.wrongArch ? 'x86_64' : 'arm64' };
    if (command.endsWith('sw_vers')) return { stdout: '15.0.1' };
    if (options.badSignature) throw new Error('synthetic invalid signature');
    return { stdout: '' };
  };
  const extract = async ({ destination }) => {
    const bundle = path.join(destination, 'Envara.app');
    await mkdir(path.join(bundle, 'Contents', 'MacOS'), { recursive: true, mode: 0o700 });
    await writeFile(path.join(bundle, 'Contents', 'MacOS', 'Envara'), 'synthetic binary', { mode: 0o700 });
    return bundle;
  };
  const adapter = createMacApplicationUpdateAdapter({ executablePath: path.join(currentApp, 'Contents', 'MacOS', 'Envara'),
    currentVersion: '1.2.3', helperDirectory, run, spawnHelper, extract });
  return { adapter, calls, frames, directory, helperDirectory, stagingDir,
    prepare: () => adapter.prepare({ archivePath: path.join(directory, 'archive.zip'), version: '1.2.4', sha256: 'a'.repeat(64), stagingDir }) };
}

test('installer needs a main-owned prepared handle and private authorization; abort does not replace data', async t => {
  const f = await fixture(t);
  await assert.rejects(f.adapter.arm({ stageRoot: '/arbitrary' }), { code: 'APP_UPDATE_PACKAGE' });
  const prepared = await f.prepare();
  assert.equal(f.calls.length, 0, 'download verification never starts installer');
  const armed = await f.adapter.arm(prepared);
  assert.equal(f.frames.length, 1);
  assert.equal(f.frames[0].schema, schema);
  assert.match(f.frames[0].capability, /^[a-f0-9]{64}$/);
  assert.deepEqual(f.calls[0].args, []);
  assert.equal(f.calls[0].spawnOptions.env.HOME, undefined);
  await armed.abort();
  assert.equal(f.frames.length, 1, 'EOF cancellation never grants commit');
  assert.equal(await readFile(path.join(f.directory, 'account-sentinel'), 'utf8'), 'unchanged');
});

test('commit waits for the helper to acknowledge this exact capability', async t => {
  const f = await fixture(t); const armed = await f.adapter.arm(await f.prepare());
  await armed.commit();
  assert.equal(f.frames[1].type, 'commit');
  assert.equal(f.frames[1].capability, f.frames[0].capability);
  await assert.rejects(armed.commit());
  await armed.abort(); // Once authorized the detached installer owns its exit.
});

for (const [option, code] of [['wrongId', 'APP_UPDATE_PACKAGE'], ['wrongArch', 'APP_UPDATE_PACKAGE'], ['badSignature', 'APP_UPDATE_PACKAGE']]) {
  test(`package validation rejects ${option} without launching installer`, async t => {
    const f = await fixture(t, { [option]: true });
    await assert.rejects(f.prepare(), { code }); assert.equal(f.calls.length, 0);
  });
}

test('tampered bundled helper is rejected before extraction or execution', async t => {
  const f = await fixture(t);
  await writeFile(path.join(f.helperDirectory, 'EnvaraUpdater'), 'tampered');
  await assert.rejects(f.prepare(), { code: 'APP_UPDATE_HELPER' }); assert.equal(f.calls.length, 0);
});

test('a higher or malformed macOS requirement refuses the candidate before arming', async t => {
  for (const minimum of ['16.0', '15.1', '9999.0', '15.x']) {
    const f = await fixture(t, { minimum });
    await assert.rejects(f.prepare(), { code: 'APP_UPDATE_SYSTEM_UNSUPPORTED' });
    assert.equal(f.calls.length, 0);
  }
  const f = await fixture(t, { minimum: '15.0' });
  assert.ok(await f.prepare());
});

test('helper location refusal and authorization refusal propagate fixed codes', async t => {
  const f = await fixture(t, { refuseReady: true });
  await assert.rejects(f.adapter.arm(await f.prepare()), { code: 'APP_UPDATE_LOCATION' });
  const g = await fixture(t, { refuseCommit: true }); const armed = await g.adapter.arm(await g.prepare());
  await assert.rejects(armed.commit(), { code: 'APP_UPDATE_PARENT' }); await armed.abort();
});
