import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Actual own forked process trees; this does not authorize or activate routing,
// launch installed applications, or establish signed application acceptance.
test('application family stops only observed owned generations, including detached descendants',
  { skip: process.platform !== 'darwin' }, () => {
    assert.notEqual(process.getuid(), 0, 'the fixture refuses root');
    assert.equal(process.getuid(), process.geteuid());
    assert.equal(process.getgid(), process.getegid());
    const directory = path.dirname(fileURLToPath(import.meta.url));
    const temporary = realpathSync(mkdtempSync(path.join(tmpdir(), 'envara-app-family-fixture-')));
    chmodSync(temporary, 0o700);
    try {
      const executable = path.join(temporary, 'app-family-fixture');
      const compile = spawnSync('xcrun', ['clang', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
        '-target', `${process.arch === 'arm64' ? 'arm64' : 'x86_64'}-apple-macos13.0`,
        ...['app-family.c', 'app-family-fixture.c', 'launcher.c'].map(name => path.join(directory, name)),
        '-o', executable], { encoding: 'utf8', timeout: 60_000, cwd: temporary });
      assert.equal(compile.error, undefined, compile.error?.message);
      assert.equal(compile.signal, null, compile.stderr);
      assert.equal(compile.status, 0, compile.stderr);
      for (const scenario of ['tree', 'detached', 'natural', 'repeat', 'refusal']) {
        const result = spawnSync(executable, [scenario], { encoding: 'utf8', timeout: 15_000, cwd: temporary });
        assert.equal(result.error, undefined, `${scenario}: ${result.error?.message}`);
        assert.equal(result.signal, null, `${scenario}: ${result.stderr}`);
        assert.equal(result.status, 0, `${scenario}: ${result.stderr}\n${result.stdout}`);
        assert.deepEqual(JSON.parse(result.stdout.trim()), {
          ok: true, fixtureOnly: true, ready: false, protected: false, activatesSystem: false,
          sameIdentitySiblingUnaffected: true, ownedCleanupComplete: true,
          refusedUnownedOrStaleIdentity: scenario === 'refusal',
          detachedMemberStopped: scenario === 'detached',
          naturalLeaderExitRetainedMembers: scenario === 'natural',
          repeatedStopSafe: scenario === 'repeat', familyStopped: scenario !== 'refusal',
          failureRetainedCustody: false, wrongGenerationSignalRefused: false,
          stableZombieVerified: false, stableZombieReaped: false, zombieTokenAndSignalUntouched: false, trueChurnRetained: false,
          typedRetrySucceeded: false, firstFailurePreserved: false, knownReapTransitions: 0,
        });
      }
    } finally { rmSync(temporary, { recursive: true, force: true }); }
  });

test('application family retains uncertain custody after token or generation-bound signal refusal',
  { skip: process.platform !== 'darwin' }, () => {
    assert.notEqual(process.getuid(), 0, 'the fixture refuses root');
    const directory = path.dirname(fileURLToPath(import.meta.url));
    const temporary = realpathSync(mkdtempSync(path.join(tmpdir(), 'envara-app-family-failure-fixture-')));
    chmodSync(temporary, 0o700);
    try {
      const executable = path.join(temporary, 'app-family-failure-fixture');
      const compile = spawnSync('xcrun', ['clang', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
        '-DENVARA_APP_FAMILY_FAILURE_FIXTURE',
        '-target', `${process.arch === 'arm64' ? 'arm64' : 'x86_64'}-apple-macos13.0`,
        ...['app-family-fixture.c', 'launcher.c'].map(name => path.join(directory, name)),
        '-lbsm', '-o', executable], { encoding: 'utf8', timeout: 60_000, cwd: temporary });
      assert.equal(compile.error, undefined, compile.error?.message);
      assert.equal(compile.signal, null, compile.stderr);
      assert.equal(compile.status, 0, compile.stderr);
      for (const scenario of ['retire-sequential', 'retire-adjacent', 'retire-parent', 'retire-leader', 'retire-zombie',
        'retire-reuse-confirmed', 'retire-freeze-replacement', 'retire-capacity', 'retire-reuse-unconfirmed',
        'retire-revision-admit', 'retire-revision-remove', 'retire-unknown', 'retire-zero-errno',
        'retire-eagain', 'retire-short', 'retire-birth', 'retire-credentials']) {
        const result = spawnSync(executable, [scenario], { encoding: 'utf8', timeout: 20_000, cwd: temporary });
        assert.equal(result.error, undefined, `${scenario}: ${result.error?.message}`);
        assert.equal(result.signal, null, `${scenario}: ${result.stderr}`);
        assert.equal(result.status, 0, `${scenario}: ${result.stderr}\n${result.stdout}`);
        const report = JSON.parse(result.stdout.trim());
        const positive = ['retire-sequential', 'retire-adjacent', 'retire-parent', 'retire-leader', 'retire-zombie',
          'retire-reuse-confirmed', 'retire-freeze-replacement'].includes(scenario);
        assert.equal(report.ok, true); assert.equal(report.familyStopped, positive);
        assert.equal(report.failureRetainedCustody, !positive); assert.equal(report.firstFailurePreserved, !positive);
        assert.equal(report.knownReapTransitions, scenario === 'retire-sequential' ? 320 : 0);
        assert.equal(report.ownedCleanupComplete, true); assert.equal(report.sameIdentitySiblingUnaffected, true);
        assert.equal(report.activatesSystem, false); assert.equal(report.ready, false); assert.equal(report.protected, false);
      }
      for (const scenario of ['api-unavailable-create', 'api-unavailable-stop', 'token-denied-create',
        'token-denied-stop', 'signal-denied-stop', 'wrong-generation-stop']) {
        const result = spawnSync(executable, [scenario], { encoding: 'utf8', timeout: 15_000, cwd: temporary });
        assert.equal(result.error, undefined, `${scenario}: ${result.error?.message}`);
        assert.equal(result.signal, null, `${scenario}: ${result.stderr}`);
        assert.equal(result.status, 0, `${scenario}: ${result.stderr}\n${result.stdout}`);
        assert.deepEqual(JSON.parse(result.stdout.trim()), {
          ok: true, fixtureOnly: true, ready: false, protected: false, activatesSystem: false,
          sameIdentitySiblingUnaffected: true, ownedCleanupComplete: true,
          refusedUnownedOrStaleIdentity: false, detachedMemberStopped: false,
          naturalLeaderExitRetainedMembers: false, repeatedStopSafe: false, familyStopped: false,
          failureRetainedCustody: true, wrongGenerationSignalRefused: scenario === 'wrong-generation-stop',
          stableZombieVerified: false, stableZombieReaped: false, zombieTokenAndSignalUntouched: false, trueChurnRetained: false,
          typedRetrySucceeded: false, firstFailurePreserved: scenario.endsWith('-stop'), knownReapTransitions: 0,
        });
      }
      for (const scenario of ['stable-zombie-create', 'stable-zombie-observe', 'stable-zombie-stop',
        'zombie-parent-mismatch', 'zombie-credential-mismatch', 'zombie-inspection-denied', 'true-inventory-churn']) {
        const result = spawnSync(executable, [scenario], { encoding: 'utf8', timeout: 15_000, cwd: temporary });
        assert.equal(result.error, undefined, `${scenario}: ${result.error?.message}`);
        assert.equal(result.signal, null, `${scenario}: ${result.stderr}`);
        assert.equal(result.status, 0, `${scenario}: ${result.stderr}\n${result.stdout}`);
        const positive = scenario.startsWith('stable-zombie-');
        const zombie = scenario !== 'true-inventory-churn';
        const retry = !zombie;
        assert.deepEqual(JSON.parse(result.stdout.trim()), {
          ok: true, fixtureOnly: true, ready: false, protected: false, activatesSystem: false,
          sameIdentitySiblingUnaffected: true, ownedCleanupComplete: true,
          refusedUnownedOrStaleIdentity: false, detachedMemberStopped: false,
          naturalLeaderExitRetainedMembers: false, repeatedStopSafe: false,
          familyStopped: scenario === 'stable-zombie-stop' || retry, failureRetainedCustody: !positive && !retry,
          wrongGenerationSignalRefused: false, stableZombieVerified: zombie,
          stableZombieReaped: scenario === 'stable-zombie-observe', zombieTokenAndSignalUntouched: zombie,
          trueChurnRetained: !zombie,
          typedRetrySucceeded: retry, firstFailurePreserved: retry, knownReapTransitions: 0,
        });
      }
      for (const scenario of ['candidate-live-absent', 'candidate-zombie-absent', 'candidate-name-absent',
        'candidate-second-list-gap', 'candidate-first-absent', 'candidate-first-unknown', 'candidate-first-short',
        'candidate-second-birth', 'candidate-second-credentials', 'candidate-second-parent', 'candidate-post-parent',
        'candidate-pid-mismatch', 'candidate-short-token', 'candidate-parent-absent', 'candidate-parent-changed',
        'candidate-zombie-parent', 'candidate-churn']) {
        const result = spawnSync(executable, [scenario], { encoding: 'utf8', timeout: 15_000, cwd: temporary });
        assert.equal(result.error, undefined, `${scenario}: ${result.error?.message}`);
        assert.equal(result.signal, null, `${scenario}: ${result.stderr}`);
        assert.equal(result.status, 0, `${scenario}: ${result.stderr}\n${result.stdout}`);
        const positive = ['candidate-live-absent', 'candidate-zombie-absent', 'candidate-name-absent'].includes(scenario);
        const report = JSON.parse(result.stdout.trim());
        assert.equal(report.ok, true); assert.equal(report.familyStopped, positive);
        assert.equal(report.failureRetainedCustody, !positive); assert.equal(report.ownedCleanupComplete, true);
        assert.equal(report.sameIdentitySiblingUnaffected, true);
        assert.equal(report.activatesSystem, false); assert.equal(report.ready, false); assert.equal(report.protected, false);
      }
      // The child is registered while live, exits normally, and is really
      // reaped before or between native BSD reads. Stress repeats 64 fresh children;
      // boundary injections must retain permanent custody and first failure.
      for (const scenario of ['known-reap-absent', 'known-reap-stress', 'known-reap-first-absent',
        'known-reap-first-unknown', 'known-reap-first-short', 'known-reap-first-birth',
        'known-reap-first-credentials', 'known-reap-first-parent', 'known-reap-second-unknown',
        'known-reap-second-short', 'known-reap-second-birth', 'known-reap-second-credentials',
        'known-reap-second-parent', 'known-reap-second-live', 'known-reap-parent-absent',
        'known-reap-parent-zombie', 'known-reap-parent-birth', 'known-reap-parent-credentials',
        'known-reap-parent-unknown', 'known-reap-parent-short', 'known-reap-parent-token',
        'known-reap-parent-after-birth', 'known-reap-parent-after-credentials', 'known-reap-prior-uncertain',
        'known-reap-first-stress', 'known-reap-absence-second-unknown', 'known-reap-absence-second-zero-errno',
        'known-reap-absence-second-eagain', 'known-reap-absence-second-short', 'known-reap-absence-second-live',
        'known-reap-absence-second-birth', 'known-reap-absence-second-credentials', 'known-reap-absence-parent-absent',
        'known-reap-absence-parent-zombie', 'known-reap-absence-parent-birth', 'known-reap-absence-parent-credentials',
        'known-reap-absence-parent-unknown', 'known-reap-absence-parent-short', 'known-reap-absence-parent-token',
        'known-reap-absence-parent-after-birth', 'known-reap-absence-parent-after-credentials',
        'known-reap-absence-parent-binding', 'known-reap-absence-vector-reuse', 'known-reap-absence-round-reuse',
        'known-reap-absence-final-reuse', 'known-reap-absence-churn', 'known-reap-first-live', 'known-reap-first-live-stress']) {
        const result = spawnSync(executable, [scenario], { encoding: 'utf8', timeout: 15_000, cwd: temporary });
        assert.equal(result.error, undefined, `${scenario}: ${result.error?.message}`);
        assert.equal(result.signal, null, `${scenario}: ${result.stderr}`);
        assert.equal(result.status, 0, `${scenario}: ${result.stderr}\n${result.stdout}`);
        const positive = ['known-reap-absent', 'known-reap-stress', 'known-reap-first-absent', 'known-reap-first-stress',
          'known-reap-first-live', 'known-reap-first-live-stress'].includes(scenario);
        const churn = scenario === 'known-reap-absence-churn';
        const report = JSON.parse(result.stdout.trim());
        assert.equal(report.ok, true); assert.equal(report.familyStopped, positive || churn);
        assert.equal(report.failureRetainedCustody, !positive && !churn); assert.equal(report.ownedCleanupComplete, true);
        assert.equal(report.firstFailurePreserved, !positive);
        assert.equal(report.knownReapTransitions, ['known-reap-stress', 'known-reap-first-stress', 'known-reap-first-live-stress'].includes(scenario) ? 64 : positive ? 1 : 0);
        assert.equal(report.typedRetrySucceeded, churn);
        assert.equal(report.sameIdentitySiblingUnaffected, true);
        assert.equal(report.activatesSystem, false); assert.equal(report.ready, false); assert.equal(report.protected, false);
      }
      for (const scenario of ['leaf-end-absent', 'leaf-end-zombie', 'leaf-end-first-unknown', 'leaf-end-first-short',
        'leaf-end-first-birth', 'leaf-end-first-credentials', 'leaf-end-second-unknown', 'leaf-end-second-zero-errno',
        'leaf-end-second-eagain', 'leaf-end-second-short', 'leaf-end-second-live', 'leaf-end-second-zombie',
        'leaf-end-zombie-second-birth', 'leaf-end-zombie-second-credentials', 'leaf-end-round-unknown',
        'leaf-end-round-live', 'leaf-end-round-birth', 'leaf-end-round-credentials', 'leaf-end-final-live', 'leaf-end-final-birth']) {
        const result = spawnSync(executable, [scenario], { encoding: 'utf8', timeout: 15_000, cwd: temporary });
        assert.equal(result.error, undefined, result.error?.message);
        assert.equal(result.signal, null, result.stderr);
        assert.equal(result.status, 0, `${scenario}: ${result.stderr}\n${result.stdout}`);
        const report = JSON.parse(result.stdout.trim()), positive = ['leaf-end-absent', 'leaf-end-zombie'].includes(scenario);
        assert.equal(report.ok, true); assert.equal(report.familyStopped, positive);
        assert.equal(report.failureRetainedCustody, !positive); assert.equal(report.firstFailurePreserved, !positive);
        assert.equal(report.sameIdentitySiblingUnaffected, true); assert.equal(report.ownedCleanupComplete, true);
        assert.equal(report.ready, false); assert.equal(report.protected, false); assert.equal(report.activatesSystem, false);
      }
      for (const scenario of ['absence-parent-stable', 'absence-parent-birth', 'absence-parent-credentials']) {
        const result = spawnSync(executable, [scenario], { encoding: 'utf8', timeout: 15_000, cwd: temporary });
        assert.equal(result.error, undefined, result.error?.message);
        assert.equal(result.signal, null, result.stderr);
        assert.equal(result.status, 0, `${scenario}: ${result.stderr}\n${result.stdout}`);
        const report = JSON.parse(result.stdout.trim()), positive = scenario === 'absence-parent-stable';
        assert.equal(report.ok, true); assert.equal(report.familyStopped, positive);
        assert.equal(report.failureRetainedCustody, !positive); assert.equal(report.firstFailurePreserved, !positive);
        assert.equal(report.sameIdentitySiblingUnaffected, true); assert.equal(report.ownedCleanupComplete, true);
        assert.equal(report.ready, false); assert.equal(report.protected, false); assert.equal(report.activatesSystem, false);
      }
      for (const scenario of ['known-zombie-reparent', 'known-name-zombie-reparent', 'known-info-zombie-reparent']) {
        const result = spawnSync(executable, [scenario], { encoding: 'utf8', timeout: 15_000, cwd: temporary });
        assert.equal(result.error, undefined, `${scenario}: ${result.error?.message}`);
        assert.equal(result.signal, null, `${scenario}: ${result.stderr}`);
        assert.equal(result.status, 0, `${scenario}: ${result.stderr}\n${result.stdout}`);
        const report = JSON.parse(result.stdout.trim());
        assert.equal(report.ok, true); assert.equal(report.familyStopped, true);
        assert.equal(report.failureRetainedCustody, false); assert.equal(report.ownedCleanupComplete, true);
        assert.equal(report.sameIdentitySiblingUnaffected, true);
        assert.equal(report.activatesSystem, false); assert.equal(report.ready, false); assert.equal(report.protected, false);
      }
      // The first token hook makes the fixture's real intermediate parent
      // exit. Only a registered descendant with one stable replacement
      // bracket and the exact saved token may survive that PPID transition.
      for (const scenario of ['reparent-stable', 'reparent-unregistered', 'reparent-leader', 'reparent-stored-token',
        'reparent-first-token-failed', 'reparent-first-token-short', 'reparent-second-token',
        'reparent-second-token-failed', 'reparent-second-token-short', 'reparent-second-birth',
        'reparent-second-credentials', 'reparent-after-birth', 'reparent-after-credentials',
        'reparent-second-ppid', 'reparent-second-unknown', 'reparent-after-unknown', 'reparent-link-ppid',
        'reparent-second-name-failed', 'reparent-second-info-invalid']) {
        const result = spawnSync(executable, [scenario], { encoding: 'utf8', timeout: 15_000, cwd: temporary });
        assert.equal(result.error, undefined, `${scenario}: ${result.error?.message}`);
        assert.equal(result.signal, null, `${scenario}: ${result.stderr}`);
        assert.equal(result.status, 0, `${scenario}: ${result.stderr}\n${result.stdout}`);
        const stable = scenario === 'reparent-stable';
        assert.deepEqual(JSON.parse(result.stdout.trim()), {
          ok: true, fixtureOnly: true, ready: false, protected: false, activatesSystem: false,
          sameIdentitySiblingUnaffected: true, ownedCleanupComplete: true,
          refusedUnownedOrStaleIdentity: false, detachedMemberStopped: false,
          naturalLeaderExitRetainedMembers: false, repeatedStopSafe: false,
          familyStopped: stable, failureRetainedCustody: !stable, wrongGenerationSignalRefused: false,
          stableZombieVerified: false, stableZombieReaped: false, zombieTokenAndSignalUntouched: false, trueChurnRetained: false,
          typedRetrySucceeded: false, firstFailurePreserved: !stable, knownReapTransitions: 0,
        });
      }
      // The task-name hook ends an already-recorded fixture member after the
      // first live BSD read. Terminal positives use real exit/reap; negatives
      // alter only the post-failure evidence and must retain permanent custody.
      for (const scenario of ['name-exit-zombie', 'name-exit-absent', 'name-exit-birth',
        'name-exit-credentials', 'name-exit-unknown', 'name-exit-second-birth',
        'name-exit-second-credentials', 'name-exit-second-unknown', 'name-exit-second-live', 'name-exit-live']) {
        const result = spawnSync(executable, [scenario], { encoding: 'utf8', timeout: 15_000, cwd: temporary });
        assert.equal(result.error, undefined, `${scenario}: ${result.error?.message}`);
        assert.equal(result.signal, null, `${scenario}: ${result.stderr}`);
        assert.equal(result.status, 0, `${scenario}: ${result.stderr}\n${result.stdout}`);
        const reconciled = scenario === 'name-exit-zombie' || scenario === 'name-exit-absent';
        assert.deepEqual(JSON.parse(result.stdout.trim()), {
          ok: true, fixtureOnly: true, ready: false, protected: false, activatesSystem: false,
          sameIdentitySiblingUnaffected: true, ownedCleanupComplete: true,
          refusedUnownedOrStaleIdentity: false, detachedMemberStopped: false,
          naturalLeaderExitRetainedMembers: false, repeatedStopSafe: false,
          familyStopped: reconciled, failureRetainedCustody: !reconciled, wrongGenerationSignalRefused: false,
          stableZombieVerified: false, stableZombieReaped: false, zombieTokenAndSignalUntouched: false, trueChurnRetained: false,
          typedRetrySucceeded: false, firstFailurePreserved: !reconciled, knownReapTransitions: 0,
        });
      }
      // Real owned exits reproduce the measured task-gone/BSD-live boundary.
      // Deterministic stage faults verify that only a fresh complete bracket
      // can reconcile it, without nesting a third Mach/reparent attempt.
      for (const scenario of ['refresh-recheck-name-exit', 'refresh-recheck-info-exit',
        'refresh-recheck-name-success', 'refresh-recheck-info-success', 'refresh-recheck-name-persistent',
        'refresh-recheck-info-persistent', 'refresh-recheck-name-other', 'refresh-recheck-info-other',
        'refresh-recheck-pid-invalid', 'refresh-recheck-pid-failure', 'refresh-recheck-short',
        'refresh-recheck-invalid-short', 'refresh-recheck-first-parent', 'refresh-recheck-second-birth',
        'refresh-recheck-second-credentials', 'refresh-recheck-second-parent', 'refresh-recheck-second-unknown',
        'refresh-recheck-after-birth', 'refresh-recheck-after-credentials', 'refresh-recheck-after-parent',
        'refresh-recheck-second-short', 'refresh-recheck-name-then-info', 'refresh-recheck-info-then-name',
        'refresh-recheck-interrupted', 'refresh-recheck-zombie-parent', 'refresh-recheck-pid-success',
        'refresh-recheck-pid-exit', 'refresh-recheck-pid-then-name', 'refresh-recheck-pid-then-info',
        'refresh-recheck-pid-candidate', 'refresh-recheck-pid-mismatch', 'refresh-recheck-pid-second-birth',
        'refresh-recheck-pid-second-credentials', 'refresh-recheck-pid-second-parent', 'refresh-recheck-pid-second-unknown',
        'refresh-recheck-pid-first-parent', 'refresh-recheck-pid-interrupted']) {
        const result = spawnSync(executable, [scenario], { encoding: 'utf8', timeout: 15_000, cwd: temporary });
        assert.equal(result.error, undefined, `${scenario}: ${result.error?.message}`);
        assert.equal(result.signal, null, `${scenario}: ${result.stderr}`);
        assert.equal(result.status, 0, `${scenario}: ${result.stderr}\n${result.stdout}`);
        const reconciled = ['refresh-recheck-name-exit', 'refresh-recheck-info-exit',
          'refresh-recheck-name-success', 'refresh-recheck-info-success',
          'refresh-recheck-pid-success', 'refresh-recheck-pid-exit'].includes(scenario);
        assert.deepEqual(JSON.parse(result.stdout.trim()), {
          ok: true, fixtureOnly: true, ready: false, protected: false, activatesSystem: false,
          sameIdentitySiblingUnaffected: true, ownedCleanupComplete: true,
          refusedUnownedOrStaleIdentity: false, detachedMemberStopped: false,
          naturalLeaderExitRetainedMembers: false, repeatedStopSafe: false,
          familyStopped: reconciled, failureRetainedCustody: !reconciled, wrongGenerationSignalRefused: false,
          stableZombieVerified: false, stableZombieReaped: false, zombieTokenAndSignalUntouched: false, trueChurnRetained: false,
          typedRetrySucceeded: false, firstFailurePreserved: !reconciled, knownReapTransitions: 0,
        });
      }
      for (const scenario of ['stop-timeout-retry', 'metadata-eagain-permanent', 'metadata-timeout-permanent',
        'signal-eagain-permanent', 'signal-timeout-permanent', 'gap-eagain-permanent', 'esrch-mismatched-zombie']) {
        const result = spawnSync(executable, [scenario], { encoding: 'utf8', timeout: 15_000, cwd: temporary });
        assert.equal(result.error, undefined, `${scenario}: ${result.error?.message}`);
        assert.equal(result.signal, null, `${scenario}: ${result.stderr}`);
        assert.equal(result.status, 0, `${scenario}: ${result.stderr}\n${result.stdout}`);
        const retry = scenario === 'stop-timeout-retry', gap = scenario === 'gap-eagain-permanent';
        assert.deepEqual(JSON.parse(result.stdout.trim()), {
          ok: true, fixtureOnly: true, ready: false, protected: false, activatesSystem: false,
          sameIdentitySiblingUnaffected: true, ownedCleanupComplete: true,
          refusedUnownedOrStaleIdentity: false, detachedMemberStopped: false,
          naturalLeaderExitRetainedMembers: false, repeatedStopSafe: false,
          familyStopped: retry, failureRetainedCustody: !retry, wrongGenerationSignalRefused: false,
          stableZombieVerified: gap, stableZombieReaped: false, zombieTokenAndSignalUntouched: gap, trueChurnRetained: false,
          typedRetrySucceeded: retry, firstFailurePreserved: true, knownReapTransitions: 0,
        });
      }
    } finally { rmSync(temporary, { recursive: true, force: true }); }
  });
