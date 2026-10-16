import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, copyFileSync, chmodSync, rmSync,
  realpathSync, lstatSync, readdirSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// This standalone fixture uses synthetic native authority and owned inert
// descriptors. Resume cases execute only the copied own fixture Mach-O.
// It never authorizes root, activates PF, or executes an installed app.
const directory = path.dirname(fileURLToPath(import.meta.url));
const ticket = '01234567-89ab-4cde-8fab-0123456789ab';
function image(root) {
  if (!existsSync(root)) return null;
  const result = [];
  function visit(target) {
    const info = lstatSync(target);
    result.push({ path: path.relative(root, target), mode: info.mode & 0o7777, inode: info.ino,
      device: info.dev, uid: info.uid, gid: info.gid, links: info.nlink,
      mtime: info.mtimeMs, ctime: info.ctimeMs,
      bytes: info.isFile() ? createHash('sha256').update(readFileSync(target)).digest('hex') : null });
    if (info.isDirectory()) for (const name of readdirSync(target).sort()) visit(path.join(target, name));
  }
  visit(root); return result;
}
function removable(root) {
  const info = lstatSync(root);
  assert.equal(info.uid, process.getuid(), 'cleanup stays inside caller-owned fixtures');
  if (info.isDirectory()) {
    chmodSync(root, 0o700);
    for (const name of readdirSync(root)) removable(path.join(root, name));
  } else if (info.isFile()) chmodSync(root, 0o600);
}
test('standalone supervisor verifies inert guardian custody, manager cancellation and refusal paths',
  { skip: process.platform !== 'darwin' }, () => {
    assert.notEqual(process.getuid(), 0, 'this fixture refuses root');
    assert.equal(process.getuid(), process.geteuid(), 'this fixture refuses changed effective identity');
    const temporary = realpathSync(mkdtempSync(path.join(tmpdir(), 'envara-app-supervisor-fixture-')));
    chmodSync(temporary, 0o700); const owned = lstatSync(temporary);
    try {
      const fixture = path.join(temporary, 'app-supervisor-fixture');
      const standalone = path.join(temporary, 'app-supervisor-main');
      const common = ['app-command.c', 'app-supervisor.c', 'app-control.c', 'app-ticket.c', 'app-registry.c',
        'gui-launch.m', 'launcher.c', 'launch-guardian.c'].map(name => path.join(directory, name));
      const inputs = [...common, ...['app-supervisor-fixture.c', 'app-supervisor-main.c', 'app-supervisor.h',
        'launch-guardian.h', 'gui-launch.h', 'notion-launch.m', 'notion-launch.h'].map(name => path.join(directory, name))];
      const hashes = () => inputs.map(name => [name, createHash('sha256').update(readFileSync(name)).digest('hex')]);
      const boundSources = hashes();
      const postcheck = path.join(temporary, 'notion-postcheck-fixture.m');
      writeFileSync(postcheck, `
#include ${JSON.stringify(path.join(directory, 'notion-launch.m'))}
#include <sys/wait.h>
int envara_fixture_notion_postcheck(const struct envara_app_registration *app,
    const struct envara_gui_request *request, struct envara_gui_lifecycle *child) {
    /* Demonstrate why a provider's real early reap cannot be adopted by a
     * supervisor using independent live PID/birth reads. Only an own child. */
    struct envara_gui_lifecycle old; envara_gui_lifecycle_init(&old);
    char *arguments[] = {"/usr/bin/true", NULL}, *environment[] = {"PATH=/usr/bin:/bin", NULL};
    if (envara_spawn_suspended(getuid(), getgid(), request->cwd, arguments[0], arguments, environment, 1, &old.child)) return -1;
    old.phase = ENVARA_GUI_SUSPENDED;
    struct envara_identity original = old.child.identity, gone;
    if (envara_gui_cancel(&old) || !old.leader_reaped || old.child.identity.pid != original.pid ||
        envara_identity_read(original.pid, &gone) == 0) { errno = EIO; return -1; }
    int status; errno = 0;
    if (waitpid(original.pid, &status, WNOHANG) != -1 || errno != ECHILD) { errno = EIO; return -1; }
    int fd = open(request->cwd, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    struct envara_gui_request refused = *request;
    refused.realm_gid = 0; /* Actual child's supplementary vector cannot be sole gid0. */
    struct envara_notion_plan plan = {0};
    strcpy(plan.user_data, request->cwd);
    struct notion_data_holds holds;
    for (unsigned i = 0; i < 6; i++) holds.fds[i] = -1;
    /* This fixture deliberately refuses at the sole-group predicate before
     * inspecting data paths. Keep one real owned descriptor to verify that
     * the new multi-directory postcheck closes its holds without reaping. */
    holds.fds[0] = fd;
    original = child->child.identity;
    int result = finish_stopped_stage(app, &refused, &plan, &holds, child);
    int error = errno; struct proc_bsdinfo actual;
    errno = 0;
    if (fcntl(fd, F_GETFD) != -1 || errno != EBADF) { errno = EIO; return -1; }
    if (result != -1 || error != ESTALE || child->phase != ENVARA_GUI_SUSPENDED || child->leader_reaped ||
        memcmp(&original, &child->child.identity, sizeof(original)) || child->child.error_fd < 3 ||
        fcntl(child->child.error_fd, F_GETFD) < 0 || !envara_same_process(&original) ||
        proc_pidinfo(original.pid, PROC_PIDTBSDINFO, 0, &actual, sizeof(actual)) != sizeof(actual) ||
        actual.pbi_status != SSTOP || actual.pbi_ppid != (uint32_t)getpid()) { errno = EIO; return -1; }
    errno = ESTALE; return -1;
}
`, { mode: 0o600 });
      for (const [main, output] of [['app-supervisor-fixture.c', fixture], ['app-supervisor-main.c', standalone]]) {
        const compiled = spawnSync('xcrun', ['clang', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
          '-Wno-deprecated-declarations', '-target', `${process.arch === 'arm64' ? 'arm64' : 'x86_64'}-apple-macos13.0`,
          ...(main === 'app-supervisor-fixture.c' ? ['-DENVARA_NOTION_POSTCHECK_FIXTURE', postcheck] : []),
          ...common, path.join(directory, main), '-framework', 'Foundation', '-framework', 'AppKit',
          '-framework', 'Security', '-lbsm', '-o', output],
        { encoding: 'utf8', timeout: 60_000, cwd: temporary });
        assert.equal(compiled.error, undefined, compiled.error?.message);
        assert.equal(compiled.signal, null, compiled.stderr);
        assert.equal(compiled.status, 0, compiled.stderr);
      }
      function setup(mode) {
        const parent = path.join(temporary, mode); mkdirSync(parent, { mode: 0o700 });
        const bundle = path.join(parent, 'Fixture.app'), workspace = path.join(parent, 'workspace');
        mkdirSync(workspace, { mode: 0o700 });
        mkdirSync(path.join(bundle, 'Contents', 'MacOS'), { recursive: true, mode: 0o755 });
        mkdirSync(path.join(bundle, 'Contents', 'Resources'), { mode: 0o755 });
        const executable = path.join(bundle, 'Contents', 'MacOS', 'Fixture');
        copyFileSync(fixture, executable); chmodSync(executable, 0o755);
        writeFileSync(path.join(bundle, 'Contents', 'Info.plist'),
          '<plist version="1.0"><dict><key>CFBundlePackageType</key><string>APPL</string>' +
          '<key>CFBundleIdentifier</key><string>io.envara.app-supervisor-fixture</string>' +
          '<key>CFBundleExecutable</key><string>Fixture</string></dict></plist>', { mode: 0o644 });
        const marker = path.join(bundle, 'Contents', 'Resources', 'marker');
        writeFileSync(marker, 'original', { mode: 0o644 });
        return { parent, bundle, workspace, marker };
      }
      function run(executable, args, cwd, status) {
        const child = spawnSync(executable, args, { encoding: 'utf8', timeout: 30_000, cwd });
        assert.equal(child.error, undefined, child.error?.message);
        assert.equal(child.signal, null, `${args[0]}: ${child.stderr}`);
        assert.equal(child.status, status, `${args[0]}: ${child.stderr}\n${child.stdout}`);
        const lines = child.stdout.trim().split('\n');
        assert.equal(lines.length, 1, 'guardian events stay private to the inert fixture');
        return JSON.parse(lines[0]);
      }
      const modes = [
        { mode: 'lifecycle', claimed: true, stopped: true, released: true },
        { mode: 'manager-signal', claimed: true, stopped: true, released: true },
        { mode: 'source-changed', claimed: false, stopped: false, released: false },
        { mode: 'missing-guardian', claimed: false, stopped: false, released: false },
        { mode: 'missing-authority', claimed: false, stopped: false, released: false },
        { mode: 'callback-lifecycle', claimed: true, stopped: true, released: true },
        { mode: 'callback-refused', claimed: true, stopped: false, released: false },
        { mode: 'callback-partial', claimed: true, stopped: false, released: true },
        { mode: 'callback-foreign', claimed: true, stopped: false, released: false },
        ...['resume-good', 'resume-missing', 'resume-stale', 'resume-replay', 'resume-unverified']
          .map(mode => ({ mode, claimed: true, stopped: true, released: true })),
      ];
      for (const { mode, claimed, stopped, released } of modes) {
        const state = setup(mode), before = image(state.bundle);
        const report = run(fixture, [mode, state.parent, state.bundle, state.workspace], state.parent, 0);
        assert.equal(report.ok, true); assert.equal(report.mode, mode); assert.equal(report.fixtureOnly, true);
        for (const flag of ['ready', 'protected', 'activatesSystem']) assert.equal(report[flag], false, `${mode}: ${flag}`);
        assert.equal(report.childGone, true, `${mode}: the exact owned cold child must be reaped`);
        assert.equal(report.claimed, claimed, `${mode}: durable ticket claim`);
        assert.equal(report.replayRefused, claimed, `${mode}: the consumed ticket cannot replay`);
        assert.equal(existsSync(path.join(state.parent, 'tickets', '00000000-0000-4000-8000-000000000103', 'claimed')),
          claimed, `${mode}: persisted ticket consumption`);
        assert.equal(report.stoppedACK, stopped, `${mode}: validated stopped-child acknowledgement`);
        assert.equal(report.releasedACK, released, `${mode}: validated release acknowledgement`);
        if (stopped || released) assert.ok(report.profileACKs >= Number(stopped) + Number(released),
          `${mode}: each frame binds execution proof and the fixture profile without claiming FRONT/Seatbelt admission`);
        else assert.equal(report.profileACKs, 0);
        if (mode.startsWith('callback-')) {
          assert.equal(report.stageCalls, 1, `${mode}: fixed native stage called once`);
          for (const field of ['stageAfterClaim', 'stageAfterGuard', 'stageAfterFreshVerify']) assert.equal(report[field], true, `${mode}: ${field}`);
          if (mode === 'callback-refused' || mode === 'callback-foreign') assert.equal(report.childPID, 0);
          else assert.ok(report.childPID > 1, `${mode}: a real direct child was recorded`);
        } else assert.equal(report.stageCalls, 0, `${mode}: default generic stage remains unchanged`);
        if (mode.startsWith('resume-')) {
          const resumed = mode === 'resume-good' || mode === 'resume-replay';
          assert.equal(report.resumeSent, resumed || mode === 'resume-unverified');
          assert.equal(report.resumed, resumed); assert.equal(report.resumedACK, resumed);
          assert.equal(report.stoppingACK, true); assert.equal(report.cancelSent, true);
          assert.equal(report.verifyResumeCalls, mode === 'resume-missing' ? 0 : 1,
            'B replay and missing authority never invoke the resume callback again');
          if (resumed || mode === 'resume-unverified') assert.ok(report.verifyExecutedCalls > 0);
          else assert.equal(report.verifyExecutedCalls, 0);
        } else {
          assert.equal(report.resumeSent, false); assert.equal(report.resumed, false);
          assert.equal(report.verifyResumeCalls, 0); assert.equal(report.verifyExecutedCalls, 0);
        }
        const after = image(state.bundle);
        if (mode === 'source-changed' || mode === 'resume-stale') {
          assert.notEqual(readFileSync(state.marker, 'utf8'), 'original');
          assert.ok(readFileSync(state.marker, 'utf8').startsWith('original'), 'fixture appends its owned source marker');
          const markerPath = path.join('Contents', 'Resources', 'marker');
          const currentMarker = after.find(row => row.path === markerPath);
          assert.ok(currentMarker);
          assert.deepEqual(after, before.map(row => row.path === markerPath ? currentMarker : row),
            'source-change fixture modifies only its owned marker');
        } else assert.deepEqual(after, before, `${mode}: the original app bundle stays unchanged`);
      }
      const defaultMain = setup('standalone-refusal'), unchanged = image(defaultMain.parent);
      const refused = run(standalone, ['gui-launch-lease', ticket], defaultMain.parent, 1);
      assert.equal(refused.schema, 'envara.pf-app-keeper/v1'); assert.equal(refused.event, 'refused');
      assert.equal(refused.reason, 'LIVE_FIXED_NATIVE_SUPERVISOR_AUTHORITY_REQUIRED');
      assert.equal(refused.error, 13, 'the nonroot standalone entry refuses before opening stores');
      assert.equal(refused.ready, false); assert.equal(refused.protected, false);
      assert.equal(existsSync(path.join(defaultMain.parent, 'registry')), false);
      assert.equal(existsSync(path.join(defaultMain.parent, 'tickets')), false);
      assert.deepEqual(image(defaultMain.parent), unchanged, 'default authority refusal writes no owned state');
      assert.deepEqual(hashes(), boundSources, 'all compiled sources and resume ABI headers remain bound to this run');
    } finally {
      const current = lstatSync(temporary);
      assert.ok(current.isDirectory() && !current.isSymbolicLink());
      assert.equal(current.uid, process.getuid()); assert.equal(current.dev, owned.dev); assert.equal(current.ino, owned.ino);
      removable(temporary); rmSync(temporary, { recursive: true, force: true });
    }
  });
