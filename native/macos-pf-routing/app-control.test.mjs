import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, copyFileSync, chmodSync, rmSync, realpathSync,
  lstatSync, readdirSync, existsSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Only temporary, caller-owned fixtures. Authority is synthetic and trusted
// solely inside the fixture; no app executable, stage, or resume is invoked.
const directory = path.dirname(fileURLToPath(import.meta.url));
const uuid = value => `00000000-0000-4000-8000-${String(value).padStart(12, '0')}`;
function image(root) {
  if (!existsSync(root)) return null;
  const result = [];
  function visit(target) {
    const s = lstatSync(target);
    result.push({ path: path.relative(root, target), mode: s.mode & 0o7777, inode: s.ino, uid: s.uid, gid: s.gid,
      mtime: s.mtimeMs, ctime: s.ctimeMs, bytes: s.isFile() ? createHash('sha256').update(readFileSync(target)).digest('hex') : null });
    if (s.isDirectory()) for (const name of readdirSync(target).sort()) visit(path.join(target, name));
  }
  visit(root); return result;
}
function removable(root) {
  const s = lstatSync(root);
  if (s.isDirectory()) { chmodSync(root, 0o700); for (const name of readdirSync(root)) removable(path.join(root, name)); }
  else if (s.isFile()) chmodSync(root, 0o600);
}
test('standalone app control and private tickets refuse missing authority, stale state and replay', () => {
  assert.equal(process.platform, 'darwin'); assert.notEqual(process.getuid(), 0);
  const temporary = realpathSync(mkdtempSync(path.join(tmpdir(), 'envara-app-control-fixture-'))); chmodSync(temporary, 0o700);
  try {
    const fixture = path.join(temporary, 'app-control-fixture'), standalone = path.join(temporary, 'app-control-main');
    const common = ['app-control.c', 'app-ticket.c', 'app-registry.c', 'gui-launch.m', 'launcher.c'].map(name => path.join(directory, name));
    for (const [main, output] of [['app-control-fixture.c', fixture], ['app-control-main.c', standalone]]) {
      const compiled = spawnSync('xcrun', ['clang', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-deprecated-declarations',
        '-target', `${process.arch === 'arm64' ? 'arm64' : 'x86_64'}-apple-macos13.0`, ...common, path.join(directory, main),
        '-framework', 'Foundation', '-framework', 'AppKit', '-framework', 'Security', '-lbsm', '-o', output], { encoding: 'utf8', timeout: 60_000 });
      assert.equal(compiled.status, 0, compiled.stderr);
    }
    let count = 0;
    function setup() {
      const parent = path.join(temporary, `case-${++count}`); mkdirSync(parent, { mode: 0o700 });
      const bundle = path.join(parent, 'Fixture.app'), workspace = path.join(parent, 'workspace');
      mkdirSync(workspace, { mode: 0o700 }); mkdirSync(path.join(bundle, 'Contents', 'MacOS'), { recursive: true, mode: 0o755 });
      mkdirSync(path.join(bundle, 'Contents', 'Resources'), { mode: 0o755 });
      copyFileSync(fixture, path.join(bundle, 'Contents', 'MacOS', 'Fixture')); chmodSync(path.join(bundle, 'Contents', 'MacOS', 'Fixture'), 0o755);
      writeFileSync(path.join(bundle, 'Contents', 'Info.plist'), '<plist version="1.0"><dict><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleIdentifier</key><string>io.envara.app-control-fixture</string><key>CFBundleExecutable</key><string>Fixture</string></dict></plist>', { mode: 0o644 });
      const marker = path.join(bundle, 'Contents', 'Resources', 'marker'); writeFileSync(marker, 'original', { mode: 0o644 });
      return { parent, bundle, workspace, marker, registry: path.join(parent, 'registry'), tickets: path.join(parent, 'tickets'),
        registration: uuid(100 + count), version: uuid(1000 + count), ticket: uuid(2000 + count), environment: uuid(3000 + count),
        run: uuid(4000 + count), lease: uuid(5000 + count) };
    }
    function run(executable, args, expected = true, timeout = 15_000) {
      const child = spawnSync(executable, args, { encoding: 'utf8', timeout });
      assert.equal(child.status, expected ? 0 : 1, `${args[0]} ${args[1]}: ${child.stderr}\n${child.stdout}`);
      const out = JSON.parse(child.stdout.trim()); assert.equal(out.ok, expected);
      for (const flag of ['ready', 'protected', 'activatesSystem']) assert.equal(out[flag], false, flag);
      return out;
    }
    const control = (s, args, mode = 'none', expected = true, lease = s.lease) =>
      run(fixture, ['control', s.registry, s.tickets, s.workspace, lease, mode, ...args, s.registration], expected);
    const api = (s, action, mode = 'good', expected = true, options = {}) =>
      run(fixture, ['api', action, s.registry, s.tickets, options.workspace ?? s.workspace, options.lease ?? s.lease, mode,
        options.ticket ?? s.ticket, ...(action === 'prepare' ? [options.registration ?? s.registration, options.version ?? s.version,
          s.environment, options.run ?? s.run] : []), s.registration], expected, options.timeout ?? 15_000);
    const register = (s, version = s.version, previous = '-') => control(s, ['app-register', s.registration, version, s.bundle, previous]);
    function issued() { const s = setup(); register(s); api(s, 'store-create'); api(s, 'prepare'); return s; }

    /* Expired tickets move to an archive that still refuses their identities.
     * Every attach used to leave a ticket and two bindings in the bounded live
     * store, which refused all further attaches once 64 had accumulated. */
    {
      const shortLived = path.join(temporary, 'app-control-fixture-short');
      const built = spawnSync('xcrun', ['clang', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-deprecated-declarations',
        '-DENVARA_APP_TICKET_LIFETIME_NS=UINT64_C(1500000000)', '-target', `${process.arch === 'arm64' ? 'arm64' : 'x86_64'}-apple-macos13.0`,
        ...common, path.join(directory, 'app-control-fixture.c'), '-framework', 'Foundation', '-framework', 'AppKit', '-framework', 'Security',
        '-lbsm', '-o', shortLived], { encoding: 'utf8', timeout: 60_000 });
      assert.equal(built.status, 0, built.stderr);
      const quick = (s, action, mode = 'good', expected = true, options = {}) =>
        run(shortLived, ['api', action, s.registry, s.tickets, s.workspace, options.lease ?? s.lease, mode,
          options.ticket ?? s.ticket, ...(action === 'prepare' ? [s.registration, s.version, s.environment, options.run ?? s.run] : []), s.registration], expected);
      const s = setup(); register(s); quick(s, 'store-create'); quick(s, 'prepare');
      const archive = `${s.tickets}-archive`, names = [s.ticket, `lease.${s.lease}`, `run.${s.run}`];
      spawnSync('/bin/sleep', ['1.6']);
      const next = { ticket: uuid(8000), run: uuid(8001), lease: uuid(8002) };
      quick(s, 'prepare', 'good', true, next);
      for (const name of names) {
        assert.equal(existsSync(path.join(s.tickets, name)), false, `${name} left the live store`);
        assert.equal(existsSync(path.join(archive, name)), true, `${name} is archived, not deleted`);
      }
      assert.equal(existsSync(path.join(s.tickets, next.ticket)), true, 'the live ticket stays live');
      const before = image(s.tickets), beforeArchive = image(archive);
      quick(s, 'prepare', 'good', false, { ticket: s.ticket, run: uuid(8100), lease: uuid(8101) });
      quick(s, 'prepare', 'good', false, { ticket: uuid(8102), run: s.run, lease: uuid(8103) });
      quick(s, 'prepare', 'good', false, { ticket: uuid(8104), run: uuid(8105), lease: s.lease });
      assert.deepEqual(image(s.tickets), before, 'an archived identity is refused without writing');
      assert.deepEqual(image(archive), beforeArchive);
    }
    const basic = setup(); const original = image(basic.bundle);
    const registered = register(basic); assert.equal(registered.applicationIdentityVerified, true);
    assert.equal(registered.ticketIssued, false); assert.deepEqual(image(basic.bundle), original);
    const beforePlan = image(basic.parent);
    const plan = control(basic, ['app-plan', basic.registration, basic.version, basic.environment, basic.run]);
    assert.equal(plan.applicationIdentityVerified, true); assert.equal(plan.environmentLeaseVerified, false);
    assert.equal(plan.ticketIssued, false); assert.equal(plan.reason, 'LIVE_NATIVE_LAUNCH_AUTHORITY_REQUIRED');
    assert.equal(existsSync(basic.tickets), false); assert.deepEqual(image(basic.parent), beforePlan);
    for (const mode of ['none', 'no-adopt']) {
      const refused = control(basic, ['app-ticket-prepare', basic.ticket, basic.registration, basic.version, basic.environment, basic.run], mode, false);
      assert.equal(refused.reason, 'LIVE_NATIVE_LAUNCH_AUTHORITY_REQUIRED'); assert.equal(existsSync(basic.tickets), false);
      assert.deepEqual(image(basic.parent), beforePlan);
    }
    const defaultMain = setup(), untouched = image(defaultMain.parent);
    const refusedMain = run(standalone, ['app-register', defaultMain.registration, defaultMain.version, defaultMain.bundle, '-'], false);
    assert.equal(refusedMain.reason, 'FIXED_ROOT_NATIVE_ENTRY_REQUIRED'); assert.deepEqual(image(defaultMain.parent), untouched);
    assert.equal(existsSync(defaultMain.registry), false); assert.equal(existsSync(defaultMain.tickets), false);

    api(basic, 'store-create'); const emptyStore = image(basic.tickets);
    const unauthorizedApp = setup();
    control(basic, ['app-register', unauthorizedApp.registration, unauthorizedApp.version, unauthorizedApp.bundle, '-']);
    const deniedApp = api(basic, 'prepare', 'good', false, { registration: unauthorizedApp.registration,
      version: unauthorizedApp.version, ticket: uuid(6900), run: uuid(6901) });
    assert.equal(deniedApp.inspectCalls, 1); assert.equal(deniedApp.verifyCalls, 0);
    assert.deepEqual(image(basic.tickets), emptyStore, 'a different sealed registration must not borrow the environment authority');
    for (const mode of ['none', 'no-adopt', 'deny']) {
      const denied = api(basic, 'prepare', mode, false); assert.equal(denied.adoptCalls, 0);
      assert.deepEqual(image(basic.tickets), emptyStore, 'missing custody/denied native gates must not write tickets');
    }
    const prepared = api(basic, 'prepare'); assert.equal(prepared.requestUID, process.getuid()); assert.equal(prepared.requestGID, process.getgid());
    assert.equal(prepared.recordReady, false); assert.equal(prepared.recordProtected, false); assert.equal(prepared.recordFixtureOnly, true);
    assert.equal(BigInt(prepared.expiresNS) - BigInt(prepared.issuedNS), 60_000_000_000n);
    const beforeInspect = image(basic.tickets); api(basic, 'inspect', 'none');
    assert.deepEqual(image(basic.tickets), beforeInspect, 'ticket inspection must be read-only');
    api(basic, 'prepare', 'good', false);
    api(basic, 'prepare', 'good', false, { ticket: uuid(7000), run: uuid(7001) });
    api(basic, 'prepare', 'good', false, { ticket: uuid(7002), lease: uuid(7003) });
    assert.deepEqual(image(basic.tickets), beforeInspect, 'ticket, native lease and run replay must not write');
    for (const [mode, options] of [['good', { lease: uuid(7100) }], ['changed-hash', {}], ['deny', {}], ['good', { workspace: basic.parent }]]) {
      const rejected = api(basic, 'claim', mode, false, options); assert.equal(rejected.adoptCalls, 0);
      assert.deepEqual(image(basic.tickets), beforeInspect, 'stale authority must refuse before durable claim');
    }
    const claimed = api(basic, 'claim'); assert.equal(claimed.adoptCalls, 0);
    assert.equal(existsSync(path.join(basic.tickets, basic.ticket, 'claimed')), true);
    const consumed = image(basic.tickets); api(basic, 'claim', 'good', false); api(basic, 'inspect', 'none', false);
    assert.deepEqual(image(basic.tickets), consumed);

    const stage = issued(); const stageRefused = api(stage, 'stage-consumed', 'good', false);
    assert.equal(stageRefused.claimedBeforeStage, true); assert.equal(stageRefused.phase, 0); assert.equal(stageRefused.adoptCalls, 0);
    const source = issued(); writeFileSync(source.marker, 'source-updated');
    api(source, 'claim', 'good', false); assert.equal(existsSync(path.join(source.tickets, source.ticket, 'claimed')), false);
    const nextVersion = uuid(7200); register(source, nextVersion, source.version);
    api(source, 'claim', 'good', false); assert.equal(existsSync(path.join(source.tickets, source.ticket, 'claimed')), false);

    const pending = setup(); register(pending); api(pending, 'store-create');
    api(pending, 'prepare', 'flip-lease', false);
    assert.equal(existsSync(path.join(pending.tickets, pending.ticket, 'reserved')), true);
    assert.equal(existsSync(path.join(pending.tickets, pending.ticket, 'ticket')), false);
    const pendingImage = image(pending.tickets); api(pending, 'inspect', 'none', false);
    api(pending, 'prepare', 'good', false, { ticket: uuid(7300), run: uuid(7301) });
    assert.deepEqual(image(pending.tickets), pendingImage, 'partial preparation must preserve immutable native lease burn');

    const fifo = issued(); const record = path.join(fifo.tickets, fifo.ticket, 'ticket'); unlinkSync(record);
    const createdFIFO = spawnSync('/usr/bin/mkfifo', ['-m', '600', record], { encoding: 'utf8', timeout: 5000 });
    assert.equal(createdFIFO.status, 0, createdFIFO.stderr); assert.equal(lstatSync(record).isFIFO(), true);
    const fifoImage = image(fifo.tickets); api(fifo, 'inspect', 'none', false, { timeout: 1000 });
    assert.deepEqual(image(fifo.tickets), fifoImage);
    const unknownClaim = issued(); writeFileSync(path.join(unknownClaim.tickets, unknownClaim.ticket, 'claimed'), 'unknown-claim', { mode: 0o600 });
    const unknownImage = image(unknownClaim.tickets); api(unknownClaim, 'inspect', 'none', false); api(unknownClaim, 'claim', 'good', false);
    assert.deepEqual(image(unknownClaim.tickets), unknownImage, 'unknown claim must never reopen a capability');

    const capacity = setup(); register(capacity); api(capacity, 'store-create');
    for (let i = 0; i < 64; i++) mkdirSync(path.join(capacity.tickets, uuid(8000 + i)), { mode: 0o700 });
    const full = image(capacity.tickets); const capped = api(capacity, 'prepare', 'good', false);
    assert.equal(capped.errorName, 'ENOSPC'); assert.equal(capped.inspectCalls, 0); assert.deepEqual(image(capacity.tickets), full);
  } finally { removable(temporary); rmSync(temporary, { recursive: true, force: true }); }
});
