import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, writeFileSync, copyFileSync, chmodSync, lchmodSync, rmSync, realpathSync, readFileSync,
  lstatSync, readdirSync, readlinkSync, symlinkSync, linkSync, unlinkSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Builds and runs only a caller-owned fixture. The fake .app contains compiled
// fixture bytes for inspection/copying; its executable is never invoked.
const directory = path.dirname(fileURLToPath(import.meta.url));
const uuid = number => `00000000-0000-4000-8000-${String(number).padStart(12, '0')}`;
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
function image(root) {
  const result = [];
  function visit(target) {
    const stat = lstatSync(target);
    result.push({ path: path.relative(root, target), mode: stat.mode & 0o7777, uid: stat.uid, gid: stat.gid,
      inode: stat.ino, mtime: stat.mtimeMs, ctime: stat.ctimeMs, hash: stat.isFile() ? hash(readFileSync(target)) : null });
    if (stat.isDirectory()) for (const name of readdirSync(target).sort()) visit(path.join(target, name));
  }
  visit(root); return result;
}
function removable(root) {
  const stat = lstatSync(root);
  if (stat.isDirectory()) { chmodSync(root, 0o700); for (const name of readdirSync(root)) removable(path.join(root, name)); }
  else if (stat.isFile()) chmodSync(root, 0o600);
}
test('standalone application registrar: copy, invalidation, durable intent and permanent retirement', () => {
  assert.equal(process.platform, 'darwin'); assert.notEqual(process.getuid(), 0);
  const temporary = realpathSync(mkdtempSync(path.join(tmpdir(), 'envara-app-registry-fixture-')));
  chmodSync(temporary, 0o700);
  try {
    const executable = path.join(temporary, 'app-registry-fixture');
    const compile = spawnSync('xcrun', ['clang', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
      '-Wno-deprecated-declarations', '-target', `${process.arch === 'arm64' ? 'arm64' : 'x86_64'}-apple-macos13.0`,
      path.join(directory, 'app-registry.c'), path.join(directory, 'app-registry-fixture.c'),
      path.join(directory, 'gui-launch.m'), path.join(directory, 'launcher.c'),
      '-framework', 'Foundation', '-framework', 'AppKit', '-framework', 'Security', '-lbsm', '-o', executable],
    { encoding: 'utf8', timeout: 60_000 });
    assert.equal(compile.status, 0, compile.stderr);
    let count = 0;
    function scenario() {
      const parent = path.join(temporary, `case-${++count}`); mkdirSync(parent, { mode: 0o700 });
      const root = path.join(parent, 'registry'), bundle = path.join(parent, 'Original Fixture.app');
      mkdirSync(path.join(bundle, 'Contents', 'MacOS'), { recursive: true, mode: 0o755 });
      mkdirSync(path.join(bundle, 'Contents', 'Resources'), { recursive: true, mode: 0o755 });
      copyFileSync(executable, path.join(bundle, 'Contents', 'MacOS', 'Fixture')); chmodSync(path.join(bundle, 'Contents', 'MacOS', 'Fixture'), 0o755);
      writeFileSync(path.join(bundle, 'Contents', 'Resources', 'marker'), 'original', { mode: 0o644 });
      writeFileSync(path.join(bundle, 'Contents', 'Info.plist'), `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleIdentifier</key><string>io.envara.registry-fixture</string><key>CFBundleExecutable</key><string>Fixture</string></dict></plist>`, { mode: 0o644 });
      return { parent, root, bundle, id: uuid(100 + count), version: uuid(1000 + count), marker: path.join(bundle, 'Contents', 'Resources', 'marker') };
    }
    function run(args, expected = true, errors, timeoutMs = 15_000) {
      const result = spawnSync(executable, args, { encoding: 'utf8', timeout: timeoutMs });
      if (result.status !== (expected ? 0 : 1)) {
        const attrs = spawnSync('/usr/bin/xattr', ['-lr', path.dirname(args[1])], { encoding: 'utf8', timeout: 5000 });
        const modes = spawnSync('/bin/ls', ['-lde', args[1], path.dirname(args[1])], { encoding: 'utf8', timeout: 5000 });
        result.stderr += `\nFixture metadata:\n${modes.stdout}${attrs.stdout}`;
      }
      assert.equal(result.status, expected ? 0 : 1, `${args[0]}: ${result.stderr}\n${result.stdout}`);
      const report = JSON.parse(result.stdout.trim()); assert.equal(report.ok, expected);
      assert.equal(report.ready, false); assert.equal(report.protected, false); assert.equal(report.activatesSystem, false);
      assert.equal(report.fixtureOnly, true);
      if (errors) assert.ok(errors.includes(report.error), `${report.error} not in ${errors}`);
      return report;
    }
    const register = (s, version = s.version, previous = '-', fault = 'none', expected = true, errors) =>
      run(['register', s.root, s.id, version, s.bundle, previous, fault], expected, errors);
    const resolve = (s, version = s.version, expected = true, errors) => run(['resolve', s.root, s.id, version], expected, errors);
    const positive = scenario();
    run(['open-read', positive.root], false, ['ENOENT']); assert.equal(existsSync(positive.root), false);
    run(['open-create', positive.root]);
    const original = image(positive.bundle), copied = register(positive);
    assert.equal(copied.registrationReady, false); assert.equal(copied.registrationProtected, false); assert.equal(copied.registrationFixtureOnly, true);
    assert.equal(copied.originalContentSHA256, copied.snapshotContentSHA256);
    assert.equal(copied.originalExecutableSHA256, copied.snapshotExecutableSHA256);
    assert.equal(copied.originalCDHash, ''); assert.equal(copied.snapshotCDHash, '');
    assert.notEqual(copied.snapshotBundle, positive.bundle); assert.ok(copied.snapshotBundle.startsWith(path.join(positive.root, 'objects') + '/'));
    assert.deepEqual(image(positive.bundle), original);
    const snapshot = image(copied.snapshotBundle);
    for (const entry of snapshot) {
      assert.equal(entry.uid, process.getuid());
      assert.equal(entry.mode, entry.hash === null ? 0o555 : entry.path.endsWith('/Fixture') ? 0o555 : 0o444, entry.path);
    }
    const beforeRead = image(positive.root); resolve(positive); run(['open-read', positive.root]);
    assert.deepEqual(image(positive.root), beforeRead, 'resolve/open-read must not write');
    register(positive, positive.version, '-', 'none', false);
    writeFileSync(positive.marker, 'updated-v2');
    resolve(positive, positive.version, false, ['ESTALE']);
    const v2 = uuid(2000); register(positive, v2, positive.version); resolve(positive, v2);
    resolve(positive, positive.version, false); assert.ok(existsSync(copied.snapshotBundle), 'superseded snapshot must remain');
    run(['retire', positive.root, positive.id]); resolve(positive, v2, false);
    register(positive, uuid(2001), v2, 'none', false); assert.ok(existsSync(copied.snapshotBundle));

    for (const fault of ['after-intent', 'after-copy-file', 'after-object']) {
      const s = scenario(); run(['open-create', s.root]); register(s, s.version, '-', fault, false, ['EIO']);
      const before = image(s.root); resolve(s, s.version, false, ['EINPROGRESS', 'EAGAIN']);
      assert.deepEqual(image(s.root), before); register(s, s.version, '-', 'none', false);
    }
    const failedUpdate = scenario(); run(['open-create', failedUpdate.root]); register(failedUpdate);
    const retained = resolve(failedUpdate).snapshotBundle;
    register(failedUpdate, uuid(3000), failedUpdate.version, 'after-intent', false, ['EIO']);
    resolve(failedUpdate, failedUpdate.version, false, ['EINPROGRESS', 'EAGAIN']);
    assert.ok(existsSync(retained), 'failed update must block fallback and preserve original object');
    const lostAck = scenario(); run(['open-create', lostAck.root]);
    register(lostAck, lostAck.version, '-', 'after-commit', false, ['EIO']);
    const committed = resolve(lostAck);
    assert.equal(committed.originalContentSHA256, committed.snapshotContentSHA256);
    register(lostAck, lostAck.version, '-', 'none', false);
    const mutation = scenario(); run(['open-create', mutation.root]);
    register(mutation, mutation.version, '-', 'mutate-after-copy-file', false, ['ESTALE']);
    assert.equal(readFileSync(mutation.marker, 'utf8'), 'original-changed-during-copy');
    resolve(mutation, mutation.version, false, ['EINPROGRESS', 'EAGAIN']);

    const capacity = scenario(); run(['open-create', capacity.root]);
    let previous = '-';
    for (let version = 1; version <= 8; version++) {
      writeFileSync(capacity.marker, `version-${version}`);
      const id = uuid(4000 + version); register(capacity, id, previous); previous = id;
    }
    const full = image(capacity.root);
    register(capacity, uuid(4009), previous, 'none', false, ['ENOSPC']);
    assert.deepEqual(image(capacity.root), full, 'capacity refusal must not create an ambiguous ninth intent');
    resolve(capacity, previous);

    const internal = scenario(); run(['open-create', internal.root]);
    const internalLink = path.join(internal.bundle, 'Contents', 'Resources', 'internal');
    symlinkSync('marker', internalLink);
    const internalRecord = register(internal);
    assert.equal(readlinkSync(path.join(internalRecord.snapshotBundle, 'Contents', 'Resources', 'internal')), 'marker');
    assert.equal(internalRecord.originalContentSHA256, internalRecord.snapshotContentSHA256);
    resolve(internal);

    // The actual root helper uses umask 077. Framework links must retain the
    // original traverse bits and content manifest without chmod following a target.
    const restrictive = scenario(); run(['open-create', restrictive.root]);
    const framework = path.join(restrictive.bundle, 'Contents', 'Frameworks', 'Fixture.framework');
    mkdirSync(path.join(framework, 'Versions', 'A'), { recursive: true, mode: 0o755 });
    const frameworkTarget = path.join(framework, 'Versions', 'A', 'resource');
    writeFileSync(frameworkTarget, 'signed-framework-resource', { mode: 0o644 });
    const frameworkLinks = [path.join(framework, 'Versions', 'Current'), path.join(framework, 'resource')];
    symlinkSync('A', frameworkLinks[0]); symlinkSync('Versions/Current/resource', frameworkLinks[1]);
    for (const link of frameworkLinks) lchmodSync(link, 0o755);
    const sourceBefore = image(restrictive.bundle);
    const restrictiveRecord = register(restrictive, restrictive.version, '-', 'umask-077');
    assert.equal(restrictiveRecord.originalContentSHA256, restrictiveRecord.snapshotContentSHA256);
    for (const link of frameworkLinks) {
      const snapshotLink = path.join(restrictiveRecord.snapshotBundle, path.relative(restrictive.bundle, link));
      assert.equal(lstatSync(snapshotLink).mode & 0o777, 0o755);
      assert.equal(readlinkSync(snapshotLink), readlinkSync(link));
    }
    const copiedTarget = path.join(restrictiveRecord.snapshotBundle, path.relative(restrictive.bundle, frameworkTarget));
    assert.equal(lstatSync(copiedTarget).mode & 0o777, 0o444, 'link chmod must not modify its target');
    assert.equal(readFileSync(path.join(restrictiveRecord.snapshotBundle, 'Contents', 'Frameworks', 'Fixture.framework', 'resource'), 'utf8'), 'signed-framework-resource');
    assert.deepEqual(image(restrictive.bundle), sourceBefore, 'registration must preserve original metadata and bytes');
    resolve(restrictive);
    for (const invalid of ['external-link', 'dangling-link', 'cyclic-link', 'absolute-internal-link', 'hardlink', 'setid', 'execute-bits']) {
      const s = scenario(); run(['open-create', s.root]);
      const extra = path.join(s.bundle, 'Contents', 'Resources', 'invalid');
      if (invalid === 'external-link') symlinkSync('/etc/hosts', extra);
      if (invalid === 'dangling-link') symlinkSync('missing', extra);
      if (invalid === 'cyclic-link') symlinkSync('invalid', extra);
      if (invalid === 'absolute-internal-link') symlinkSync(s.marker, extra);
      if (invalid === 'hardlink') linkSync(s.marker, extra);
      if (invalid === 'setid') chmodSync(s.marker, 0o4644);
      if (invalid === 'execute-bits') chmodSync(s.marker, 0o744);
      register(s, s.version, '-', 'none', false);
      if (invalid.endsWith('-link') || invalid === 'hardlink') unlinkSync(extra);
    }
    const xattrs = scenario(); run(['open-create', xattrs.root]);
    const xattr = spawnSync('/usr/bin/xattr', ['-w', 'user.envara.fixture', 'fixture', xattrs.marker], { encoding: 'utf8', timeout: 5000 });
    assert.equal(xattr.status, 0, xattr.stderr); register(xattrs, xattrs.version, '-', 'none', false);
    const acl = scenario(); run(['open-create', acl.root]);
    const addACL = spawnSync('/bin/chmod', ['+a', 'everyone deny write', acl.marker], { encoding: 'utf8', timeout: 5000 });
    assert.equal(addACL.status, 0, addACL.stderr);
    const aclList = spawnSync('/bin/ls', ['-le', acl.marker], { encoding: 'utf8', timeout: 5000 });
    assert.equal(aclList.status, 0, aclList.stderr); assert.match(aclList.stdout, /everyone deny write/);
    register(acl, acl.version, '-', 'none', false);
    const removeACL = spawnSync('/bin/chmod', ['-N', acl.marker], { encoding: 'utf8', timeout: 5000 });
    assert.equal(removeACL.status, 0, removeACL.stderr);
    const orphan = scenario(); run(['open-create', orphan.root]);
    const orphanRecord = register(orphan);
    mkdirSync(path.join(path.dirname(path.dirname(orphanRecord.snapshotBundle)), uuid(6000)), { mode: 0o755 });
    const orphanInventory = image(orphan.root);
    resolve(orphan, orphan.version, false);
    register(orphan, uuid(6001), orphan.version, 'none', false);
    assert.deepEqual(image(orphan.root), orphanInventory, 'unknown version must refuse before a new durable intent');
    const unexpected = scenario(); run(['open-create', unexpected.root]);
    const unexpectedRecord = register(unexpected);
    writeFileSync(path.join(path.dirname(unexpectedRecord.snapshotBundle), 'unexpected'), 'unregistered', { mode: 0o644 });
    const unexpectedInventory = image(unexpected.root);
    resolve(unexpected, unexpected.version, false);
    assert.deepEqual(image(unexpected.root), unexpectedInventory, 'extra object file must be a read-only refusal');
    const fifo = scenario(); run(['open-create', fifo.root]); register(fifo);
    const descriptor = path.join(fifo.root, 'registrations', fifo.id, 'descriptor');
    unlinkSync(descriptor);
    const fifoRecord = spawnSync('/usr/bin/mkfifo', ['-m', '600', descriptor], { encoding: 'utf8', timeout: 5000 });
    assert.equal(fifoRecord.status, 0, fifoRecord.stderr); assert.equal(lstatSync(descriptor).isFIFO(), true);
    const fifoInventory = image(fifo.root);
    // No writer exists; return an ordinary refusal rather than waiting for data.
    run(['resolve', fifo.root, fifo.id, fifo.version], false, undefined, 1000);
    assert.deepEqual(image(fifo.root), fifoInventory, 'FIFO descriptor refusal must remain read-only');
    const badParent = scenario(); chmodSync(badParent.parent, 0o755);
    run(['open-create', badParent.root], false, ['EACCES']); assert.equal(existsSync(badParent.root), false);

    /* Storage lifecycle. Each attach used to register a new copy and nothing
     * was removed, so the 32-registration inventory filled up. One registration
     * per application is now reused while exact and removed when unused. */
    const current = (s, expected = true, errors) => run(['current', s.root, s.id], expected, errors);
    const life = scenario(); run(['open-create', life.root]);
    current(life, false, ['ENOENT']);
    register(life);
    let state = current(life); assert.equal(state.versionId, life.version); assert.equal(state.reusable, true);
    writeFileSync(life.marker, 'updated-original');
    state = current(life); assert.equal(state.versionId, life.version, 'a stale version is still the one to supersede');
    assert.equal(state.reusable, false, 'a changed original is never reused');
    const lifeV2 = uuid(4000); register(life, lifeV2, life.version);
    state = current(life); assert.equal(state.versionId, lifeV2); assert.equal(state.reusable, true);
    const objects = path.join(life.root, 'objects', life.id), records = path.join(life.root, 'registrations', life.id);
    assert.ok(existsSync(objects) && existsSync(records));
    run(['delete', life.root, life.id]);
    assert.equal(existsSync(objects), false); assert.equal(existsSync(records), false);
    current(life, false, ['ENOENT']);
    run(['delete', life.root, life.id], false, ['ENOENT']);
    register(life, uuid(4001)); assert.equal(current(life).reusable, true, 'the same registration id is usable again after a delete');

    const retired = scenario(); run(['open-create', retired.root]); register(retired);
    run(['retire', retired.root, retired.id]); current(retired, false, ['EIDRM']);
    run(['delete', retired.root, retired.id]); current(retired, false, ['ENOENT']);

    // A copy that is running must keep its files.
    const busy = scenario(); run(['open-create', busy.root]); register(busy);
    /* macOS refuses to run a copied system binary, so a small sleeper is
     * compiled here and placed inside the registered copy's directory. */
    const sleeper = path.join(busy.root, 'objects', busy.id, busy.version, 'sleeper');
    const built = spawnSync('xcrun', ['clang', '-x', 'c', '-', '-o', sleeper], { input: '#include <unistd.h>\nint main(void){sleep(30);return 0;}\n', encoding: 'utf8', timeout: 60_000 });
    assert.equal(built.status, 0, built.stderr);
    const holder = spawnSync('/bin/sh', ['-c', `"${sleeper}" 30 >/dev/null 2>&1 & echo $!`], { encoding: 'utf8' });
    const holderPid = Number(holder.stdout.trim()); assert.ok(holderPid > 1);
    try {
      for (let i = 0; i < 50 && spawnSync('/bin/ps', ['-p', String(holderPid)]).status !== 0; i++) spawnSync('/bin/sleep', ['0.05']);
      run(['delete', busy.root, busy.id], false, ['EBUSY']);
      assert.ok(existsSync(path.join(busy.root, 'objects', busy.id)), 'a refused delete removes nothing');
      current(busy);
    } finally { try { process.kill(holderPid, 'SIGKILL'); } catch {} }
    for (let i = 0; i < 50 && spawnSync('/bin/ps', ['-p', String(holderPid)]).status === 0; i++) spawnSync('/bin/sleep', ['0.05']);
    run(['delete', busy.root, busy.id]); assert.equal(existsSync(path.join(busy.root, 'objects', busy.id)), false);

    // Environment data removal never follows a symlink, including ones the
    // console user can place in their own data.
    const data = scenario(), dataRoot = path.join(data.parent, 'data'), environment = uuid(5000), registration = uuid(5001);
    run(['open-create', data.root]);
    const leaf = path.join(dataRoot, environment, registration, 'UserData');
    mkdirSync(path.join(leaf, 'Cache', 'deep'), { recursive: true, mode: 0o700 });
    writeFileSync(path.join(leaf, 'Cookies'), 'session'); writeFileSync(path.join(leaf, 'Cache', 'deep', 'blob'), 'cached');
    mkdirSync(path.join(leaf, 'Locked'), { mode: 0o700 }); writeFileSync(path.join(leaf, 'Locked', 'inside'), 'x'); chmodSync(path.join(leaf, 'Locked'), 0o555);
    const outside = path.join(data.parent, 'outside'); mkdirSync(outside, { mode: 0o700 }); writeFileSync(path.join(outside, 'keep'), 'must survive');
    symlinkSync(outside, path.join(leaf, 'link-to-directory')); symlinkSync(path.join(outside, 'keep'), path.join(leaf, 'link-to-file'));
    const other = uuid(5002); mkdirSync(path.join(dataRoot, other), { mode: 0o755 }); writeFileSync(path.join(dataRoot, other, 'kept'), 'other environment');
    run(['data-delete', dataRoot, data.root, 'not-a-uuid'], false, ['EACCES']);
    run(['data-delete', dataRoot, data.root, environment]);
    assert.equal(existsSync(path.join(dataRoot, environment)), false);
    assert.equal(readFileSync(path.join(outside, 'keep'), 'utf8'), 'must survive', 'a symlink is removed, never followed');
    assert.ok(existsSync(path.join(dataRoot, other, 'kept')), 'only the named environment is removed');
    run(['data-delete', dataRoot, data.root, environment], false, ['ENOENT']);
    chmodSync(dataRoot, 0o775); run(['data-delete', dataRoot, data.root, other], false, ['EACCES']); chmodSync(dataRoot, 0o755);
    assert.ok(existsSync(path.join(dataRoot, other, 'kept')), 'a group-writable data root is refused, not used');
  } finally {
    removable(temporary); rmSync(temporary, { recursive: true, force: true });
  }
});
