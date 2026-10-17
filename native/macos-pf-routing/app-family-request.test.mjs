import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Real fork/exec, loopback HTTP, waitpid, and public production observations.
// No syscall fault injection, PF activation, GUI, or installed application.
test('application family observes 128 real short-lived command and HTTP request generations',
  { skip: process.platform !== 'darwin', timeout: 65_000 }, t => {
    assert.notEqual(process.getuid(), 0, 'the fixture refuses root');
    assert.equal(process.getuid(), process.geteuid());
    assert.equal(process.getgid(), process.getegid());
    const directory = path.dirname(fileURLToPath(import.meta.url));
    const temporary = realpathSync(mkdtempSync(path.join(tmpdir(), 'envara-family-request-fixture-')));
    chmodSync(temporary, 0o700);
    try {
      // Compile one byte-for-byte source snapshot. Shared-checkout edits after
      // this read must not make a stress failure's source version ambiguous.
      for (const name of ['app-family.c', 'app-family-request-fixture.c', 'launcher.c', 'app-family.h', 'native.h']) {
        const source = readFileSync(path.join(directory, name));
        writeFileSync(path.join(temporary, name), source);
        if (name === 'app-family.c') {
          t.diagnostic(`productionSourceSha256=${createHash('sha256').update(source).digest('hex')}, ` +
            `snapshotAt=${new Date().toISOString()}`);
        }
      }
      const executable = path.join(temporary, 'app-family-request-fixture');
      const compile = spawnSync('xcrun', ['clang', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
        '-target', `${process.arch === 'arm64' ? 'arm64' : 'x86_64'}-apple-macos13.0`,
        ...['app-family.c', 'app-family-request-fixture.c', 'launcher.c'].map(name => path.join(temporary, name)),
        '-o', executable], { encoding: 'utf8', timeout: 15_000, cwd: temporary });
      assert.equal(compile.error, undefined, compile.error?.message);
      assert.equal(compile.signal, null, compile.stderr);
      assert.equal(compile.status, 0, compile.stderr);
      const result = spawnSync(executable, [], { encoding: 'utf8', timeout: 45_000, cwd: temporary });
      assert.equal(result.error, undefined, result.error?.message);
      assert.equal(result.signal, null, result.stderr);
      assert.equal(result.status, 0, `${result.stderr}\n${result.stdout}`);
      const report = JSON.parse(result.stdout.trim());
      assert.equal(report.ok, true);
      assert.equal(report.fixtureOnly, true);
      assert.equal(report.ready, false);
      assert.equal(report.protected, false);
      assert.equal(report.activatesSystem, false);
      assert.equal(report.usesProductionObserver, true);
      assert.equal(report.faultInjection, false);
      assert.equal(report.loopbackRequests, 64);
      assert.equal(report.httpResponses, 63);
      assert.equal(report.curlReaped, 63);
      assert.equal(report.quickCommandsReaped, 64);
      assert.equal(report.registeredChildren, 128);
      assert.ok(report.observationCalls >= 382);
      assert.equal(report.sameIdentitySiblingUnaffected, true);
      assert.equal(report.ownedCleanupComplete, true);
      assert.equal(report.familyStopped, true);
      assert.equal(report.leaderSignalSent, true);
      assert.equal(report.activeRequestStopped, true);
      assert.equal(report.failureRetainedCustody, false);
      assert.equal(report.failedRound, 0);
      assert.equal(report.failedPhase, 'none');
      assert.equal(report.failureReason, 'none');
      assert.equal(report.failureOsError, 0);
      assert.equal(report.failureMachError, 0);
      t.diagnostic(`loopback requests=${report.loopbackRequests}, completed requests=${report.curlReaped}, ` +
        `quick commands=${report.quickCommandsReaped}, registered generations=${report.registeredChildren}, ` +
        `production observations=${report.observationCalls}, active request stopped=${report.activeRequestStopped}, ` +
        `owned cleanup=${report.ownedCleanupComplete}, independent sibling unaffected=${report.sameIdentitySiblingUnaffected}`);
    } finally {
      rmSync(temporary, { recursive: true, force: true });
    }
  });
