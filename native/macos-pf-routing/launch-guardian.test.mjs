import assert from 'node:assert/strict';
import { test } from 'node:test';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

test('guardian custody uses supported kernel-control peer API and preserves strict metadata checks', () => {
  assert.equal(process.platform, 'darwin'); assert.notEqual(process.getuid(), 0);
  const directory = path.dirname(fileURLToPath(import.meta.url));
  const temporary = realpathSync(mkdtempSync(path.join(tmpdir(), 'envara-guardian-custody-fixture-')));
  try {
    const executable = path.join(temporary, 'guardian-custody-fixture');
    const compile = spawnSync('xcrun', ['clang', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
      '-target', `${process.arch === 'arm64' ? 'arm64' : 'x86_64'}-apple-macos13.0`,
      path.join(directory, 'launch-guardian-custody-fixture.c'), path.join(directory, 'launcher.c'),
      '-o', executable], { encoding: 'utf8', timeout: 60_000 });
    assert.equal(compile.status, 0, compile.stderr);
    const result = spawnSync(executable, [], { encoding: 'utf8', timeout: 5_000 });
    assert.equal(result.status, 0, `${result.stderr}\n${result.stdout}`);
    assert.deepEqual(JSON.parse(result.stdout.trim()), {
      ok: true, fixtureOnly: true, ready: false, protected: false, activatesSystem: false,
      createsUTun: false, actualKernelControlGetsocknameUnsupported: true,
      productionUsesPeerOnly: true, fixtureUsesUnixGetsockname: true, rejectedMetadataCases: 12,
    });
  } finally { rmSync(temporary, { recursive: true, force: true }); }
});

test('guardian permits a typed family retry only on explicit Stop after fresh network revocation', () => {
  assert.equal(process.platform, 'darwin'); assert.notEqual(process.getuid(), 0);
  const directory = path.dirname(fileURLToPath(import.meta.url));
  const temporary = realpathSync(mkdtempSync(path.join(tmpdir(), 'envara-guardian-typed-retry-fixture-')));
  try {
    const executable = path.join(temporary, 'guardian-typed-retry-fixture');
    const compile = spawnSync('xcrun', ['clang', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
      '-DENVARA_GUARDIAN_TYPED_RETRY_FIXTURE',
      '-target', `${process.arch === 'arm64' ? 'arm64' : 'x86_64'}-apple-macos13.0`,
      path.join(directory, 'launch-guardian-fixture.c'), path.join(directory, 'launcher.c'),
      '-o', executable], { encoding: 'utf8', timeout: 60_000 });
    assert.equal(compile.status, 0, compile.stderr);
    const result = spawnSync(executable, ['typed-churn-retry'], { encoding: 'utf8', timeout: 15_000 });
    assert.equal(result.status, 0, `${result.stderr}\n${result.stdout}`);
    const report = JSON.parse(result.stdout.trim());
    assert.equal(report.ok, true); assert.equal(report.typedRetryVerified, true);
    assert.equal(report.networkBeforeFamilyVerified, true); assert.equal(report.networkRetryVerified, false);
    assert.equal(report.reason, 1); assert.equal(report.ready, false); assert.equal(report.protected, false);
    assert.equal(report.activatesSystem, false); assert.equal(report.wholeGuardCrashVerified, false);
  } finally { rmSync(temporary, { recursive: true, force: true }); }
});

test('native launch guardian: real death watches, direct-child ownership and retained descriptor custody', () => {
  assert.equal(process.platform, 'darwin'); assert.notEqual(process.getuid(), 0);
  const directory = path.dirname(fileURLToPath(import.meta.url));
  const temporary = realpathSync(mkdtempSync(path.join(tmpdir(), 'envara-launch-guardian-fixture-')));
  try {
    const executable = path.join(temporary, 'launch-guardian-fixture');
    const compile = spawnSync('xcrun', ['clang', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
      '-target', `${process.arch === 'arm64' ? 'arm64' : 'x86_64'}-apple-macos13.0`,
      path.join(directory, 'launch-guardian.c'), path.join(directory, 'launch-guardian-fixture.c'),
      path.join(directory, 'launcher.c'), '-o', executable], { encoding: 'utf8', timeout: 60_000 });
    assert.equal(compile.status, 0, compile.stderr);
    const refused = ['birth-mismatch', 'duplicate-peer', 'foreign-child', 'missing-authority',
      'missing-network-authority', 'production-unprivileged', 'alias-pipe', 'invalid-custody'];
    const reasons = { stop: [1], eof: [1], malformed: [2], signal: [6],
      'dependency-death': [3, 4], 'dependency-exec': [4], 'parent-death': [1, 3, 4],
      expiry: [5], descendant: [1], 'deny-loss': [1], 'network-retry': [1], 'network-auto-retry': [2],
      'network-recovery-retry': [1],
      'heartbeat-lost': [12], 'heartbeat-kept': [1] };
    for (const scenario of ['resume-slow-final-deny', 'resume-expired-final-deny']) {
      const result = spawnSync(executable, [scenario], { encoding: 'utf8', timeout: 15_000 });
      assert.equal(result.status, 0, `${scenario}: ${result.stderr}\n${result.stdout}`);
      const report = JSON.parse(result.stdout.trim());
      assert.equal(report.ok, true); assert.equal(report.custodyHeldUntilVerifiedRelease, true);
      assert.equal(report.resumedAfterSlowFinalDeny, scenario === 'resume-slow-final-deny');
      assert.equal(report.expiredFinalDenyRefusedBeforeSignal, scenario === 'resume-expired-final-deny');
      assert.equal(report.ready, false); assert.equal(report.protected, false);
      assert.equal(report.activatesSystem, false); assert.equal(report.fixtureOnly, true);
    }
    for (const scenario of ['descriptors', ...refused, 'stop', 'eof', 'malformed', 'signal',
      'dependency-death', 'dependency-exec', 'parent-death', 'expiry', 'descendant', 'deny-loss',
      'network-retry', 'network-auto-retry', 'network-recovery-retry', 'heartbeat-lost', 'heartbeat-kept']) {
      const result = spawnSync(executable, [scenario], { encoding: 'utf8', timeout: 15_000 });
      assert.equal(result.status, 0, `${scenario}: ${result.stderr}\n${result.stdout}`);
      const report = JSON.parse(result.stdout.trim());
      assert.equal(report.ok, true, scenario); assert.equal(report.ready, false);
      assert.equal(report.protected, false); assert.equal(report.activatesSystem, false);
      assert.equal(report.fixtureOnly, true);
      if (scenario !== 'descriptors') {
        assert.equal(report.refused, refused.includes(scenario), scenario);
        assert.equal(report.wholeGuardCrashVerified, false);
        assert.equal(report.networkBeforeFamilyVerified, !refused.includes(scenario), scenario);
        assert.equal(report.networkRetryVerified,
          ['deny-loss', 'network-retry', 'network-auto-retry', 'network-recovery-retry'].includes(scenario), scenario);
        assert.ok(report.reason > 0, scenario);
        if (reasons[scenario]) assert.ok(reasons[scenario].includes(report.reason), `${scenario}: reason ${report.reason}`);
      }
    }
  } finally { rmSync(temporary, { recursive: true, force: true }); }
});
