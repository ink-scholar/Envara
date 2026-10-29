import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  LSREGISTER, RELEASE_SLOT_KINDS, openReleaseWorkspace, parseLaunchServicesDump,
  planReleaseCleanup, releaseWorkspacePaths,
} from '../scripts/macos-release-workspace.mjs';
import { inventory } from '../scripts/build-macos-release.mjs';

// Every command is handled below. These tests never invoke a native executable.
const otherApp = '/Applications/Other.app';
const lsRecord = (filename, identifier = 'io.envara.desktop') =>
  `----------------------------------------\npath: ${filename}\nidentifier: ${identifier}\ncodeInfoID: 123\n`;
const dump = paths => 'LaunchServices synthetic fixture\n' + lsRecord(otherApp, 'example.other')
  + [...paths].map(filename => lsRecord(filename)).join('');
const psRow = (command, pid = 44) => `${pid} 1 ${pid} Sun Oct 25 02:55:40 2026 ${command}\n`;
const exists = filename => fs.lstat(filename).then(() => true, error => {
  if (error.code === 'ENOENT') return false;
  throw error;
});

async function fixture(t) {
  const temporary = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'envara-release-workspace-test-')));
  const before = await fs.lstat(temporary);
  t.after(async () => {
    const current = await fs.lstat(temporary);
    assert.equal(current.dev, before.dev); assert.equal(current.ino, before.ino);
    await fs.rm(temporary, { recursive: true, force: false });
  });
  const home = path.join(temporary, 'home'), repository = path.join(temporary, 'repository');
  await fs.mkdir(home, { mode: 0o700 }); await fs.mkdir(repository, { mode: 0o700 });
  assert.equal(await fs.realpath(home), home); assert.equal(await fs.realpath(repository), repository);
  return { temporary, home, repository, open: () => openReleaseWorkspace({ home, repository }) };
}

async function fakeApp(filename) {
  await fs.mkdir(path.join(filename, 'Contents/Resources'), { recursive: true, mode: 0o700 });
  await fs.writeFile(path.join(filename, 'Contents/Info.plist'),
    'Inert fixture bytes, deliberately not a valid application property list.\n', { mode: 0o600 });
  await fs.writeFile(path.join(filename, 'Contents/Resources/app.asar'), 'synthetic sealed application bytes\n', { mode: 0o600 });
  await fs.symlink('Resources', path.join(filename, 'Contents/Current'));
}

async function sealed(workspace, kind = 'candidate') {
  const filename = await workspace.claim(kind);
  await fakeApp(filename); await workspace.seal(kind);
  return filename;
}

async function rebuiltCandidate(t) {
  const f = await fixture(t), workspace = await f.open(), app = await workspace.claim('candidate');
  const parent = path.dirname(app), original = await fs.lstat(parent);
  // Retain the empty old directory outside the workspace so inode reuse cannot
  // turn this replacement test into an unchanged-parent test.
  await fs.rename(parent, path.join(f.temporary, 'original-candidate-parent'));
  await fs.mkdir(parent, { mode: 0o755 }); await fs.chmod(parent, 0o755);
  assert.notEqual((await fs.lstat(parent)).ino, original.ino);
  await fakeApp(app);
  return { ...f, workspace, app, parent, signedManifest: await inventory(app) };
}

const completedBuilder = { code: 0, closeConfirmed: true, cleanupUncertain: false };

async function assertUnsealedRetained(workspace, app) {
  const fake = fakeCommands(), report = await workspace.cleanup({ run: fake.run });
  assert.equal(report.complete, false);
  assert.equal(report.cleanupErrors[0].code, 'UNSEALED_APP_RETAINED');
  assert.equal(fake.calls.length, 0);
  assert(await exists(app)); assert(await exists(path.join(workspace.root, 'lock.json')));
}

function fakeCommands({ registrations = [], ownedApps = [], failure = null, mount = null } = {}) {
  const registered = new Set(registrations), allowedApps = new Set([...registrations, ...ownedApps]), calls = [];
  let mounted = mount !== null, unregisterAttempted = false;
  const result = (code = 0, stdout = '', stderr = '') => ({ code, stdout, stderr });
  const run = async (command, args, options) => {
    calls.push({ command, args: [...args], cwd: options.cwd });
    if (command === LSREGISTER && args.length === 1 && args[0] === '-dump') {
      const listing = failure === 'path-only-remains' && unregisterAttempted
        ? dump([]) + [...registered].map(filename => `---\npath: ${filename}\n`).join('') : dump(registered);
      return result(0, failure === 'dump' ? 'malformed synthetic dump' : listing);
    }
    if (command === LSREGISTER && args.length === 2 && args[0] === '-u') {
      assert(registered.has(args[1]), 'Only an explicitly registered fixture path may be unregistered.');
      assert.notEqual(args[1], otherApp);
      unregisterAttempted = true;
      if (failure === 'unregister') return result(1, '', 'synthetic unregister refusal');
      if (failure === 'unregister-stderr') return result(0, '', 'synthetic unregister diagnostic');
      if (!['registration-remains', 'path-only-remains'].includes(failure)) registered.delete(args[1]);
      return result();
    }
    if (command === '/bin/ps') {
      assert.deepEqual(args, ['-axo', 'pid=,ppid=,pgid=,lstart=,comm=']);
      return result(0, psRow('/usr/bin/true') + (failure === 'live-process'
        ? psRow(path.join([...registered][0], 'Contents/MacOS/Envara'), 45) : ''));
    }
    if (command === '/usr/sbin/lsof') {
      assert.deepEqual(args.slice(0, 4), ['-nP', '-Fpf', '+D', args[3]]);
      assert.equal(args.length, 4); assert(allowedApps.has(args[3]));
      return failure === 'lsof' ? result(2, '', 'synthetic inspection failure') : result(1);
    }
    if (command === '/usr/bin/codesign') {
      assert.deepEqual(args.slice(0, 3), ['--verify', '--deep', '--strict']);
      assert.equal(args.length, 4); assert(allowedApps.has(args[3]));
      return failure === 'signature' ? result(1, '', 'synthetic invalid seal') : result();
    }
    if (command === '/usr/bin/hdiutil' && args[0] === 'info') {
      assert.deepEqual(args, ['info', '-plist']); return result(0, 'synthetic-plist');
    }
    if (command === '/usr/bin/plutil') {
      assert.deepEqual(args, ['-convert', 'json', '-o', '-', '-']);
      assert.equal(options.input, 'synthetic-plist');
      return result(0, JSON.stringify({ images: mounted ? [{ 'image-path': mount.imagePath,
        'system-entities': [{ 'mount-point': mount.mountpoint, 'dev-entry': mount.device }] }] : [] }));
    }
    if (command === '/usr/bin/hdiutil' && args[0] === 'detach') {
      assert(mount && mounted); assert.deepEqual(args, ['detach', mount.device]);
      assert(!registered.has(mount.app), 'Unregister the exact mounted App before detaching.');
      await fs.rm(mount.app, { recursive: true, force: false }); mounted = false; return result();
    }
    assert.fail(`Unexpected fake command: ${command} ${JSON.stringify(args)}`);
  };
  return { run, calls, registered, unregisters: () => calls.filter(call => call.command === LSREGISTER && call.args[0] === '-u') };
}

test('LaunchServices parser handles separated records and legal non-target partial records', () => {
  const filename = '/private/synthetic candidate/Envara.app';
  assert.deepEqual(parseLaunchServicesDump(dump([filename])), [
    { path: otherApp, identifier: 'example.other', codeInfoID: '123' },
    { path: filename, identifier: 'io.envara.desktop', codeInfoID: '123' },
  ]);
  assert.deepEqual(parseLaunchServicesDump('header\n---\npath: /Applications/Other.app (0x123)\nidentifier: example.other (0xaB)\n'),
    [{ path: otherApp, identifier: 'example.other' }]);
  assert.deepEqual(parseLaunchServicesDump('---\npath: /Applications/Other.app\n'),
    [{ path: otherApp, identifier: null }]);
  assert.deepEqual(parseLaunchServicesDump('---\npath: /Applications/Envara.app\n'),
    [{ path: '/Applications/Envara.app', identifier: null }]);
  assert.deepEqual(parseLaunchServicesDump('---\npath: /private/synthetic-helper\ncodeInfoID: 321\n'),
    [{ path: '/private/synthetic-helper', identifier: null, codeInfoID: '321' }]);
  assert.deepEqual(parseLaunchServicesDump(lsRecord(otherApp, 'example.other') + '---\nidentifier: unrelated.helper\n'),
    [{ path: otherApp, identifier: 'example.other', codeInfoID: '123' }]);
  assert.deepEqual(parseLaunchServicesDump(lsRecord(otherApp) + lsRecord(otherApp)),
    Array(2).fill({ path: otherApp, identifier: 'io.envara.desktop', codeInfoID: '123' }));
});

test('LaunchServices parser rejects incomplete target records, malformed paths and duplicate fields', () => {
  for (const text of ['', 'no recognizable record',
    '---\nidentifier: example.other\n', '---\npath: relative.app\nidentifier: example.other\n',
    '---\npath: /Applications/../Other.app\nidentifier: example.other\n',
    '---\npath: /Applications/Other.app\npath: /Applications/Second.app\nidentifier: example.other\n',
    '---\npath: /Applications/Other.app\nidentifier: one\nidentifier: two\n',
    lsRecord(otherApp) + 'codeInfoID: 456\n',
    ...['io.envara.desktop', 'io.envara.desktop.helper', 'io.envara.link-router', 'io.envara.link-router.helper']
      .map(identifier => lsRecord(otherApp, 'example.other') + `---\nidentifier: ${identifier}\n`)])
    assert.throws(() => parseLaunchServicesDump(text), error => typeof error.code === 'string' && error.code.startsWith('LS_DUMP_'), text);
});

test('fixed slots are outside the repository and cleanup order is exact', async t => {
  const f = await fixture(t), paths = releaseWorkspacePaths(f.home);
  assert.equal(paths.root, path.join(f.home, 'Library/Caches/io.envara.release/mac-arm64'));
  assert.equal(paths.candidateApp, path.join(paths.root, 'candidate/mac-arm64/Envara.app'));
  const claims = RELEASE_SLOT_KINDS.map(kind => ({ kind, path: paths[`${kind === 'mounted' ? 'mounted' : kind}App`] }));
  assert.deepEqual(planReleaseCleanup(paths, claims).map(item => item.kind), ['mounted', 'zip', 'payload', 'candidate']);
  assert.throws(() => planReleaseCleanup(paths, [{ kind: 'candidate', path: otherApp }]), { code: 'CLEANUP_SLOT_INVALID' });
  assert.throws(() => planReleaseCleanup(paths, [claims[0], claims[0]]), { code: 'CLEANUP_SLOT_INVALID' });
  for (const value of Object.values(paths)) assert(!value.startsWith(f.repository + path.sep));
});

test('sealed owned copies unregister only their exact paths and preserve evidence', async t => {
  const f = await fixture(t), workspace = await f.open();
  const apps = [];
  for (const kind of ['candidate', 'payload', 'zip']) apps.push(await sealed(workspace, kind));
  const fake = fakeCommands({ registrations: apps });
  const report = await workspace.cleanup({ run: fake.run });
  assert.equal(report.complete, true); assert.deepEqual(report.cleanupErrors, []);
  assert.deepEqual(fake.unregisters().map(call => call.args), [...apps].reverse().map(filename => ['-u', filename]));
  assert.deepEqual(report.results.map(item => [item.unregistered, item.removed, item.detached]), Array(3).fill([true, true, false]));
  for (const filename of apps) assert.equal(await exists(filename), false);
  assert.equal(await exists(path.join(workspace.root, 'lock.json')), false);
  for (const name of ['candidate-manifest.json', 'payload-manifest.json', 'zip-manifest.json', 'journal.jsonl', 'cleanup.json'])
    assert.equal(await exists(path.join(workspace.evidenceDir, name)), true);
  const events = (await fs.readFile(workspace.journalPath, 'utf8')).trim().split('\n').map(JSON.parse);
  assert.equal(events.at(-1).event, 'complete');
  assert.deepEqual(events.map(event => event.sequence), events.map((_, index) => index + 1));
});

test('an existing lock or foreign repository cannot adopt the workspace', async t => {
  const f = await fixture(t), workspace = await f.open();
  await assert.rejects(f.open(), { code: 'WORKSPACE_LOCKED' });
  const foreign = path.join(f.temporary, 'foreign-repository'); await fs.mkdir(foreign, { mode: 0o700 });
  await assert.rejects(openReleaseWorkspace({ home: f.home, repository: foreign }), { code: 'WORKSPACE_OWNER_MISMATCH' });
  assert.equal((await workspace.cleanup({ run: fakeCommands().run })).complete, true);
});

test('reopening an occupied slot preserves its foreign file without creating a lock', async t => {
  const f = await fixture(t), workspace = await f.open();
  assert.equal((await workspace.cleanup({ run: fakeCommands().run })).complete, true);
  const notes = path.join(workspace.payloadDir, 'notes.txt');
  await fs.writeFile(notes, 'foreign payload notes must remain unchanged\n', { mode: 0o600 });
  const contents = await fs.readFile(notes), journal = await fs.readFile(workspace.journalPath);
  const evidence = await fs.readdir(path.dirname(workspace.evidenceDir));
  await assert.rejects(f.open(), { code: 'WORKSPACE_SLOT_NOT_EMPTY' });
  assert.deepEqual(await fs.readFile(notes), contents);
  assert.deepEqual(await fs.readFile(workspace.journalPath), journal);
  assert.deepEqual(await fs.readdir(path.dirname(workspace.evidenceDir)), evidence);
  assert.equal(await exists(path.join(workspace.root, 'lock.json')), false);
});

test('claim rejects an occupied parent before recording intent or modifying its file', async t => {
  const f = await fixture(t), workspace = await f.open();
  const notes = path.join(workspace.payloadDir, 'notes.txt');
  await fs.writeFile(notes, 'foreign contents inserted before claim\n', { mode: 0o600 });
  const contents = await fs.readFile(notes), journal = await fs.readFile(workspace.journalPath);
  await assert.rejects(workspace.claim('payload'), { code: 'CLAIM_PARENT_NOT_EMPTY' });
  assert.deepEqual(await fs.readFile(notes), contents);
  assert.deepEqual(await fs.readFile(workspace.journalPath), journal);
  assert(!(await fs.readFile(workspace.journalPath, 'utf8')).includes('claim-intent'));
  const fake = fakeCommands(); await workspace.cleanup({ run: fake.run });
  assert.equal(fake.calls.length, 0); assert.deepEqual(await fs.readFile(notes), contents);
});

test('seal refuses a foreign sibling while retaining the claimed App and notes', async t => {
  const f = await fixture(t), workspace = await f.open(), app = await workspace.claim('payload');
  await fakeApp(app);
  const notes = path.join(workspace.payloadDir, 'notes.txt'); await fs.writeFile(notes, 'foreign sibling after claim\n', { mode: 0o600 });
  const contents = await fs.readFile(notes), asar = path.join(app, 'Contents/Resources/app.asar');
  const appBytes = await fs.readFile(asar), appIdentity = await fs.lstat(app), journal = await fs.readFile(workspace.journalPath);
  await assert.rejects(workspace.seal('payload'), { code: 'SEAL_PARENT_NOT_EXCLUSIVE' });
  assert.deepEqual(await fs.readFile(notes), contents); assert.deepEqual(await fs.readFile(asar), appBytes);
  const after = await fs.lstat(app); assert.equal(after.dev, appIdentity.dev); assert.equal(after.ino, appIdentity.ino);
  assert.deepEqual(await fs.readFile(workspace.journalPath), journal);
  const fake = fakeCommands({ registrations: [app] }), report = await workspace.cleanup({ run: fake.run });
  assert.equal(report.complete, false); assert.equal(report.cleanupErrors[0].code, 'UNSEALED_APP_RETAINED');
  assert.equal(fake.calls.length, 0); assert(await exists(app)); assert.deepEqual(await fs.readFile(notes), contents);
});

test('completed builder output adopts only the replaced candidate parent before sealing and cleanup', async t => {
  const f = await rebuiltCandidate(t), replacement = await fs.lstat(f.parent);
  const options = { builderResult: completedBuilder, signedManifest: f.signedManifest };
  assert.equal(await f.workspace.adoptCandidateOutput(options), f.app);
  const after = await fs.lstat(f.parent);
  assert.equal(after.ino, replacement.ino); assert.equal(after.dev, replacement.dev);
  assert.equal(after.mode & 0o7777, 0o700);
  assert.deepEqual(await inventory(f.app), f.signedManifest);
  const events = (await fs.readFile(f.workspace.journalPath, 'utf8')).trim().split('\n').map(JSON.parse);
  assert.equal(events.filter(event => event.event === 'builder-output-adopted').length, 1);
  await assert.rejects(f.workspace.adoptCandidateOutput(options), { code: 'BUILDER_ADOPTION_INVALID' });
  await f.workspace.seal('candidate');
  const fake = fakeCommands({ registrations: [f.app] });
  assert.equal((await f.workspace.cleanup({ run: fake.run })).complete, true);
  assert.equal(fake.unregisters().length, 1);
  assert.equal(await exists(f.app), false);
  assert.equal(await exists(path.join(f.workspace.root, 'lock.json')), false);
});

test('failed or uncertain builder completion cannot adopt or chmod the candidate parent', async t => {
  for (const builderResult of [
    { ...completedBuilder, code: 1 }, { ...completedBuilder, closeConfirmed: false },
    { ...completedBuilder, cleanupUncertain: true }, { code: 0 },
  ]) await t.test(JSON.stringify(builderResult), async t => {
    const f = await rebuiltCandidate(t), journal = await fs.readFile(f.workspace.journalPath);
    await assert.rejects(f.workspace.adoptCandidateOutput({ builderResult, signedManifest: f.signedManifest }),
      { code: 'BUILDER_COMPLETION_UNCONFIRMED' });
    assert.equal((await fs.lstat(f.parent)).mode & 0o7777, 0o755);
    assert.deepEqual(await fs.readFile(f.workspace.journalPath), journal);
    assert.deepEqual(await inventory(f.app), f.signedManifest);
    await assertUnsealedRetained(f.workspace, f.app);
  });
});

test('candidate adoption refuses replacement of the controlled output ancestor', async t => {
  const f = await rebuiltCandidate(t), journal = await fs.readFile(f.workspace.journalPath);
  await fs.rename(f.workspace.candidateOutput, path.join(f.temporary, 'original-candidate-output'));
  await fs.mkdir(f.workspace.candidateOutput, { mode: 0o700 });
  await fs.mkdir(f.parent, { mode: 0o755 }); await fs.chmod(f.parent, 0o755); await fakeApp(f.app);
  assert.deepEqual(await inventory(f.app), f.signedManifest);
  await assert.rejects(f.workspace.adoptCandidateOutput({ builderResult: completedBuilder, signedManifest: f.signedManifest }),
    { code: 'BUILDER_OUTPUT_PARENT_CHANGED' });
  assert.equal((await fs.lstat(f.parent)).mode & 0o7777, 0o755);
  assert.deepEqual(await fs.readFile(f.workspace.journalPath), journal);
  await assertUnsealedRetained(f.workspace, f.app);
});

test('candidate adoption refuses bytes that differ from the signed manifest', async t => {
  const f = await rebuiltCandidate(t), journal = await fs.readFile(f.workspace.journalPath);
  const asar = path.join(f.app, 'Contents/Resources/app.asar');
  await fs.writeFile(asar, 'modified after synthetic signing\n');
  await assert.rejects(f.workspace.adoptCandidateOutput({ builderResult: completedBuilder, signedManifest: f.signedManifest }),
    { code: 'BUILDER_SIGNED_MANIFEST_CHANGED' });
  assert.equal((await fs.lstat(f.parent)).mode & 0o7777, 0o755);
  assert.deepEqual(await fs.readFile(f.workspace.journalPath), journal);
  assert.equal(await fs.readFile(asar, 'utf8'), 'modified after synthetic signing\n');
  await assertUnsealedRetained(f.workspace, f.app);
});

test('candidate adoption rejects extra siblings and a symlinked output directory', async t => {
  for (const kind of ['file', 'sibling-symlink', 'parent-symlink']) await t.test(kind, async t => {
    const f = await rebuiltCandidate(t), journal = await fs.readFile(f.workspace.journalPath);
    if (kind === 'file') await fs.writeFile(path.join(f.parent, 'foreign.txt'), 'retain foreign file\n', { mode: 0o600 });
    else if (kind === 'sibling-symlink') await fs.symlink('Envara.app', path.join(f.parent, 'foreign-link'));
    else {
      const retained = path.join(f.temporary, 'retained-candidate-parent');
      await fs.rename(f.parent, retained); await fs.symlink(retained, f.parent);
    }
    await assert.rejects(f.workspace.adoptCandidateOutput({ builderResult: completedBuilder, signedManifest: f.signedManifest }),
      { code: kind === 'parent-symlink' ? 'BUILDER_OUTPUT_PARENT_UNSAFE' : 'BUILDER_OUTPUT_NOT_EXCLUSIVE' });
    assert.deepEqual(await fs.readFile(f.workspace.journalPath), journal);
    if (kind === 'file') assert.equal(await fs.readFile(path.join(f.parent, 'foreign.txt'), 'utf8'), 'retain foreign file\n');
    else assert.equal((await fs.lstat(kind === 'parent-symlink' ? f.parent : path.join(f.parent, 'foreign-link'))).isSymbolicLink(), true);
    await assertUnsealedRetained(f.workspace, f.app);
  });
});

test('ordinary payload sealing still refuses a replaced parent directory', async t => {
  const f = await fixture(t), workspace = await f.open(), app = await workspace.claim('payload');
  const parent = path.dirname(app), journal = await fs.readFile(workspace.journalPath);
  await fs.rename(parent, path.join(f.temporary, 'original-payload-parent'));
  await fs.mkdir(parent, { mode: 0o700 }); await fakeApp(app);
  await assert.rejects(workspace.seal('payload'), { code: 'SEAL_PARENT_CHANGED' });
  assert.deepEqual(await fs.readFile(workspace.journalPath), journal);
  await assertUnsealedRetained(workspace, app);
});

test('unknown root or candidate entries block workspace reuse without deleting evidence', async t => {
  for (const location of ['root', 'candidate']) await t.test(location, async t => {
    const f = await fixture(t), workspace = await f.open();
    assert.equal((await workspace.cleanup({ run: fakeCommands().run })).complete, true);
    const filename = path.join(location === 'root' ? workspace.root : workspace.candidateOutput, 'unexpected.txt');
    await fs.writeFile(filename, `owned by another operation: ${location}\n`, { mode: 0o600 });
    const contents = await fs.readFile(filename), journal = await fs.readFile(workspace.journalPath);
    const evidence = await fs.readdir(path.dirname(workspace.evidenceDir));
    await assert.rejects(f.open(), { code: 'WORKSPACE_UNEXPECTED_ENTRY' });
    assert.deepEqual(await fs.readFile(filename), contents);
    assert.deepEqual(await fs.readFile(workspace.journalPath), journal);
    assert.deepEqual(await fs.readdir(path.dirname(workspace.evidenceDir)), evidence);
    assert.equal(await exists(path.join(workspace.root, 'lock.json')), false);
  });
});

test('replacing a sealed App inode retains the replacement and refuses unregister', async t => {
  const f = await fixture(t), workspace = await f.open(), app = await sealed(workspace);
  const original = path.join(path.dirname(app), 'retained-original'); await fs.rename(app, original); await fakeApp(app);
  const fake = fakeCommands({ registrations: [app] });
  const report = await workspace.cleanup({ run: fake.run });
  assert.equal(report.complete, false); assert.equal(report.cleanupErrors[0].code, 'SEALED_APP_CHANGED');
  assert.equal(fake.calls.length, 0); assert(await exists(app)); assert(await exists(original));
  assert(await exists(path.join(workspace.root, 'lock.json')));
});

test('sealed contents drifting in place remain available as failure evidence', async t => {
  const f = await fixture(t), workspace = await f.open(), app = await sealed(workspace);
  const asar = path.join(app, 'Contents/Resources/app.asar'); await fs.writeFile(asar, 'changed synthetic bytes');
  const fake = fakeCommands({ registrations: [app] });
  const report = await workspace.cleanup({ run: fake.run, operationError: { code: 'SYNTHETIC_BUILD_FAILURE' } });
  assert.equal(report.complete, false); assert.equal(report.cleanupErrors[0].code, 'SEALED_APP_CHANGED');
  assert.deepEqual(report.operationError, { code: 'SYNTHETIC_BUILD_FAILURE' });
  assert.equal(fake.unregisters().length, 0); assert.equal(await fs.readFile(asar, 'utf8'), 'changed synthetic bytes');
});

test('an unsealed claimed App is retained without running inspection commands', async t => {
  const f = await fixture(t), workspace = await f.open(), app = await workspace.claim('candidate'); await fakeApp(app);
  const fake = fakeCommands({ registrations: [app] });
  const report = await workspace.cleanup({ run: fake.run });
  assert.equal(report.complete, false); assert.equal(report.cleanupErrors[0].code, 'UNSEALED_APP_RETAINED');
  assert.equal(fake.calls.length, 0); assert(await exists(app));
});

test('inspection and unregister failures stop removal and retain independent failure records', async t => {
  const cases = [
    ['lsof', 'APP_IN_USE_OR_INSPECTION_FAILED', 0], ['live-process', 'APP_STILL_RUNNING', 0],
    ['signature', 'INSPECTION_COMMAND_FAILED', 0], ['dump', 'LS_DUMP_EMPTY_OR_UNRECOGNIZED', 0],
    ['unregister', 'UNREGISTER_FAILED', 1], ['unregister-stderr', 'UNREGISTER_FAILED', 1], ['registration-remains', 'REGISTRATION_REMAINS', 1],
    ['path-only-remains', 'REGISTRATION_REMAINS', 1],
  ];
  for (const [failure, code, unregisters] of cases) await t.test(failure, async t => {
    const f = await fixture(t), workspace = await f.open(), app = await sealed(workspace);
    const fake = fakeCommands({ registrations: [app], failure });
    const report = await workspace.cleanup({ run: fake.run, operationError: 'synthetic original failure' });
    assert.equal(report.complete, false); assert.equal(report.cleanupErrors[0].code, code);
    assert.equal(report.operationError, 'synthetic original failure'); assert.equal(fake.unregisters().length, unregisters);
    assert(await exists(app)); assert(await exists(path.join(workspace.root, 'lock.json')));
    const events = (await fs.readFile(workspace.journalPath, 'utf8')).trim().split('\n').map(JSON.parse);
    assert.equal(events.at(-1).event, 'cleanup-failed'); assert(!events.some(event => event.event === 'removed'));
  });
});

test('unregistered zip and payload copies clean up without an unregister command', async t => {
  for (const kind of ['zip', 'payload']) await t.test(kind, async t => {
    const f = await fixture(t), workspace = await f.open(), app = await sealed(workspace, kind);
    const fake = fakeCommands({ ownedApps: [app] });
    const report = await workspace.cleanup({ run: fake.run });
    assert.equal(report.complete, true); assert.deepEqual(report.cleanupErrors, []);
    assert.equal(report.results[0].alreadyAbsent, true);
    assert.equal(report.results[0].unregistered, false);
    assert.equal(report.results[0].removed, true);
    assert.equal(fake.unregisters().length, 0);
    assert.equal(await exists(app), false);
    assert.equal(await exists(path.join(workspace.root, 'lock.json')), false);
    const events = (await fs.readFile(workspace.journalPath, 'utf8')).trim().split('\n').map(JSON.parse);
    assert.equal(events.filter(event => event.event === 'unregister-already-absent' && event.path === app).length, 1);
    assert(!events.some(event => ['unregister-intent', 'unregister-result'].includes(event.event)));
    assert(fake.calls.filter(call => call.command === LSREGISTER && call.args[0] === '-dump').length >= 3);
    assert(fake.calls.some(call => call.command === '/usr/bin/codesign'));
    assert(fake.calls.some(call => call.command === '/usr/sbin/lsof'));
  });
});

test('the already-absent branch retains the candidate when protected registrations change', async t => {
  for (const changed of ['installed-app', 'link-router']) await t.test(changed, async t => {
    const f = await fixture(t), workspace = await f.open(), app = await sealed(workspace, 'zip');
    const fake = fakeCommands({ ownedApps: [app] }); let dumps = 0;
    const installed = lsRecord('/Applications/Envara.app');
    const router = lsRecord('/private/synthetic-router/EnvaraLinkRouter.app', 'io.envara.link-router');
    const run = async (cmd, args, options) => {
      const result = await fake.run(cmd, args, options);
      if (cmd === LSREGISTER && args[0] === '-dump') {
        dumps++;
        result.stdout += dumps > 1 && changed === 'installed-app'
          ? installed.replace('codeInfoID: 123', 'codeInfoID: 456') : installed;
        if (!(dumps > 1 && changed === 'link-router')) result.stdout += router;
      }
      return result;
    };
    const report = await workspace.cleanup({ run });
    assert.equal(report.complete, false);
    assert.equal(report.cleanupErrors[0].code, 'PROTECTED_REGISTRATION_CHANGED');
    assert.equal(report.results[0].alreadyAbsent, true);
    assert.equal(report.results[0].removed, false);
    assert.equal(fake.unregisters().length, 0);
    assert(await exists(app)); assert(await exists(path.join(workspace.root, 'lock.json')));
  });
});

test('late registration after an absent snapshot is refused before removing the owned copy', async t => {
  for (const appearance of [2, 3]) await t.test(`registration appears on dump ${appearance}`, async t => {
    const f = await fixture(t), workspace = await f.open(), app = await sealed(workspace, 'payload');
    const fake = fakeCommands({ ownedApps: [app] }); let dumps = 0;
    const run = async (cmd, args, options) => {
      const result = await fake.run(cmd, args, options);
      if (cmd === LSREGISTER && args[0] === '-dump' && ++dumps >= appearance) result.stdout += lsRecord(app);
      return result;
    };
    const report = await workspace.cleanup({ run });
    assert.equal(report.complete, false); assert.equal(report.cleanupErrors[0].code, 'REGISTRATION_REMAINS');
    assert.equal(report.results[0].alreadyAbsent, true); assert.equal(report.results[0].removed, false);
    assert.equal(fake.unregisters().length, 0);
    assert(await exists(app)); assert(await exists(path.join(workspace.root, 'lock.json')));
    const events = (await fs.readFile(workspace.journalPath, 'utf8')).trim().split('\n').map(JSON.parse);
    assert(!events.some(event => ['removed', 'complete'].includes(event.event)));
  });
});

test('changing an installed App or link-router registration prevents target removal', async t => {
  for (const changed of ['installed-app', 'link-router']) await t.test(changed, async t => {
    const f = await fixture(t), workspace = await f.open(), app = await sealed(workspace);
    const fake = fakeCommands({ registrations: [app] });
    const installed = lsRecord('/Applications/Envara.app');
    const router = lsRecord('/private/synthetic-router/EnvaraLinkRouter.app', 'io.envara.link-router');
    const run = async (command, args, options) => {
      const result = await fake.run(command, args, options);
      if (command === LSREGISTER && args[0] === '-dump') {
        const afterUnregister = fake.unregisters().length > 0;
        result.stdout += afterUnregister && changed === 'installed-app'
          ? installed.replace('codeInfoID: 123', 'codeInfoID: 456') : installed;
        if (!(afterUnregister && changed === 'link-router')) result.stdout += router;
      }
      return result;
    };
    const report = await workspace.cleanup({ run });
    assert.equal(report.complete, false); assert.equal(report.cleanupErrors[0].code, 'PROTECTED_REGISTRATION_CHANGED');
    assert.deepEqual(fake.unregisters().map(call => call.args), [['-u', app]]);
    assert(await exists(app)); assert(await exists(path.join(workspace.root, 'lock.json')));
    assert.equal(report.results[0].removed, false);
    const events = (await fs.readFile(workspace.journalPath, 'utf8')).trim().split('\n').map(JSON.parse);
    assert.equal(events.at(-1).event, 'cleanup-failed');
    assert(!events.some(event => ['remove-intent', 'removed', 'complete'].includes(event.event)));
  });
});

test('completed workspace reopens fixed slots while retaining the previous journal', async t => {
  const f = await fixture(t), first = await f.open(), firstApp = await sealed(first);
  assert.equal((await first.cleanup({ run: fakeCommands({ registrations: [firstApp] }).run })).complete, true);
  const originalJournal = await fs.readFile(first.journalPath), originalReport = await fs.readFile(path.join(first.evidenceDir, 'cleanup.json'));
  const next = await f.open(); assert.equal(next.candidateApp, first.candidateApp); assert.notEqual(next.evidenceDir, first.evidenceDir);
  const nextApp = await sealed(next); assert.equal((await next.cleanup({ run: fakeCommands({ registrations: [nextApp] }).run })).complete, true);
  assert.deepEqual(await fs.readFile(first.journalPath), originalJournal);
  assert.deepEqual(await fs.readFile(path.join(first.evidenceDir, 'cleanup.json')), originalReport);
});

test('incomplete state and a truncated completed journal both block reopening', async t => {
  await t.test('incomplete state even after a synthetic stale-lock removal', async t => {
    const f = await fixture(t), workspace = await f.open(), app = await workspace.claim('candidate'); await fakeApp(app);
    assert.equal((await workspace.cleanup({ run: fakeCommands().run })).complete, false);
    await fs.unlink(path.join(workspace.root, 'lock.json'));
    await assert.rejects(f.open(), { code: 'WORKSPACE_RECOVERY_REQUIRED' }); assert(await exists(app));
  });
  await t.test('truncated journal with complete state', async t => {
    const f = await fixture(t), workspace = await f.open();
    assert.equal((await workspace.cleanup({ run: fakeCommands().run })).complete, true);
    const journal = await fs.readFile(workspace.journalPath, 'utf8'); await fs.writeFile(workspace.journalPath, journal.trimEnd());
    await assert.rejects(f.open(), { code: 'WORKSPACE_JOURNAL_INVALID' });
  });
});

test('mounted App is unregistered while inspectable and detached before completion', async t => {
  const f = await fixture(t), workspace = await f.open(), app = await workspace.claim('mounted'); await fakeApp(app);
  const imagePath = path.join(workspace.evidenceDir, 'synthetic.dmg'); await fs.writeFile(imagePath, 'synthetic immutable image', { mode: 0o600 });
  const mount = { app, imagePath, device: '/dev/disk81s1', mountpoint: workspace.mountDir };
  await workspace.seal('mounted', { imagePath, device: mount.device });
  const fake = fakeCommands({ registrations: [app], mount }); const report = await workspace.cleanup({ run: fake.run });
  assert.equal(report.complete, true); assert.deepEqual(report.cleanupErrors, []);
  assert.equal(report.results[0].unregistered, true); assert.equal(report.results[0].detached, true); assert.equal(report.results[0].removed, false);
  const unregister = fake.calls.findIndex(call => call.command === LSREGISTER && call.args[0] === '-u');
  const detach = fake.calls.findIndex(call => call.command === '/usr/bin/hdiutil' && call.args[0] === 'detach');
  assert(unregister >= 0 && detach > unregister); assert.equal(await exists(app), false); assert(await exists(imagePath));
  const events = (await fs.readFile(workspace.journalPath, 'utf8')).trim().split('\n').map(JSON.parse).map(entry => entry.event);
  assert(events.indexOf('unregister-result') < events.indexOf('detach-intent'));
  assert(events.indexOf('detached') < events.indexOf('complete'));
});
