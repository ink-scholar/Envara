import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash } from 'node:crypto';

const exec = promisify(execFile), root = path.resolve(import.meta.dirname, '..');
const native = path.join(root, 'native/macos-pf-routing');
const fixedOldSHA = 'fbb72973188f51cc44fa5b5a961b6e6ce51912c11d8e0d5350cfb19e19fad053';
const helper = `static void quarantine_refusal_delay(void) {
    struct timespec delay = {0, 50000000};
    while (nanosleep(&delay, &delay) < 0 && errno == EINTR) {}
}
`;
function frozenOldSource(current) {
  return current.replace(helper, '').replace('if (result < 0 || (item.revents & (POLLHUP | POLLERR | POLLNVAL))) { quarantine_refusal_delay(); }',
    'if (result < 0 || (item.revents & (POLLHUP | POLLERR | POLLNVAL))) { struct timespec delay = {0, 50000000}; nanosleep(&delay, NULL); }')
    .replace('if (amount <= 0) { quarantine_refusal_delay(); continue; }', 'if (amount <= 0) continue;')
    .replace('        quarantine_refusal_delay();\n    }\n}\nstatic int adopt', '    }\n}\nstatic int adopt');
}

test('actual quarantine EOF/error paths stay alive with custody and bounded CPU; fixed 14b87 path reproduces the spin',
  { skip: process.platform !== 'darwin' }, async () => {
    assert.notEqual(process.getuid(), 0); assert.equal(process.getuid(), process.geteuid());
    const directory = await mkdtemp(path.join(tmpdir(), 'envara-quarantine-refusal-fixture-'));
    try {
      const current = await readFile(path.join(native, 'app-supervisor.c'), 'utf8');
      const old = frozenOldSource(current);
      assert.equal(createHash('sha256').update(old).digest('hex'), fixedOldSHA,
        'baseline is the actual immutable 14b87 supervisor, not a mirrored implementation');
      const baseline = path.join(directory, 'frozen-14b87-app-supervisor.c'); await writeFile(baseline, old, { mode: 0o600 });
      const common = ['app-control.c', 'app-ticket.c', 'app-registry.c', 'gui-launch.m', 'launcher.c', 'launch-guardian.c'];
      const inputs = ['app-supervisor.c', 'app-supervisor.h', 'app-supervisor-quarantine-fixture.c', ...common];
      const hashes = async () => Promise.all(inputs.map(async name => [name,
        createHash('sha256').update(await readFile(path.join(native, name))).digest('hex')]));
      const before = await hashes();
      for (const [name, source] of [['old', baseline], ['fixed', path.join(native, 'app-supervisor.c')]]) {
        const binary = path.join(directory, name);
        await exec('/usr/bin/clang', ['-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-deprecated-declarations',
          '-I', native, `-DENVARA_QUARANTINE_SOURCE=${JSON.stringify(source)}`,
          path.join(native, 'app-supervisor-quarantine-fixture.c'), ...common.map(n => path.join(native, n)),
          '-framework', 'Foundation', '-framework', 'AppKit', '-framework', 'Security', '-lbsm', '-o', binary],
        { timeout: 30000, maxBuffer: 1024 * 1024 });
        const reports = [];
        for (const mode of name === 'old' ? [1] : [1, 2, 3, 4, 5]) {
          const reply = await exec(binary, [String(mode)], { timeout: 5000 });
          const report = JSON.parse(reply.stdout); reports.push(report);
          assert.equal(report.ready, false); assert.equal(report.protected, false);
          if (mode === 4) {
            assert.equal(report.heldUntilAuthorizedR, true); assert.equal(report.actualChildReaped, true);
          } else {
            assert.equal(report.heldBeforeOwnFixtureCancellation, true); assert.equal(report.released, false);
            assert.ok(report.elapsedSeconds >= 0.6);
            if (name === 'old') {
              assert.equal(report.actualEOFEvents, 17, 'actual Darwin pipe emits POLLIN | POLLHUP');
              assert.ok(report.reads > 1000, JSON.stringify(report));
              assert.ok(report.cpuSeconds > 0.15, JSON.stringify(report));
            } else {
              assert.ok(report.reads > 0 && report.reads <= 20, JSON.stringify(report));
              assert.ok(report.polls <= 20, JSON.stringify(report));
              assert.ok(report.cpuSeconds < 0.12, JSON.stringify(report));
            }
          }
        }
        console.log(`${name} quarantine observations: ${JSON.stringify(reports)}`);
      }
      assert.deepEqual(await hashes(), before, 'all actual compiled inputs remain unchanged');
    } finally { await rm(directory, { recursive: true, force: true }); }
  });
