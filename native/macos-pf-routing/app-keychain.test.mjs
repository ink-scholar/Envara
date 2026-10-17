import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, mkdtempSync, readFileSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// No Security framework is linked. All Security calls and root authority are
// compile-time substitutes. Disposable files, anonymous pipes and our own
// children are real; one explicit case also reads public kernel metadata for
// self and the fixed system process. This cannot establish launch authority.
test('keychain selection and opaque custody fail closed with synthetic Security replies',
  { skip: process.platform !== 'darwin', timeout: 90_000 }, async t => {
    assert.notEqual(process.getuid(), 0, 'fixture must remain unprivileged');
    assert.equal(process.getuid(), process.geteuid());
    const root = path.dirname(fileURLToPath(import.meta.url));
    const temporary = realpathSync(mkdtempSync(path.join(tmpdir(), 'envara-keychain-fixture-')));
    chmodSync(temporary, 0o700);
    const names = ['app-keychain.m', 'app-keychain.h', 'app-keychain-fixture.m', 'gui-launch.h'];
    const sourceHashes = () => names.map(name => createHash('sha256').update(readFileSync(path.join(root, name))).digest('hex'));
    const before = sourceHashes();
    try {
      const executable = path.join(temporary, 'fixture');
      const compile = spawnSync('xcrun', ['clang', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
        '-Wno-deprecated-declarations', '-target', `${process.arch === 'arm64' ? 'arm64' : 'x86_64'}-apple-macos13.0`,
        path.join(root, 'app-keychain-fixture.m'), '-framework', 'CoreFoundation', '-o', executable],
      { encoding: 'utf8', timeout: 60_000, cwd: temporary });
      assert.equal(compile.error, undefined, compile.error?.message);
      assert.equal(compile.signal, null, compile.stderr);
      assert.equal(compile.status, 0, compile.stderr);
      const symbols = spawnSync('xcrun', ['nm', '-u', executable], { encoding: 'utf8', timeout: 10_000 });
      assert.equal(symbols.status, 0, symbols.stderr);
      assert.doesNotMatch(symbols.stdout, /\b_Sec[A-Z][A-Za-z0-9_]*\b/, 'fixture must not resolve real Security APIs');
      assert.doesNotMatch(symbols.stdout, /\b_(?:fchflags|chflags|sysctlbyname|fchown|chown|lchown|setuid|seteuid|setgid|setegid|setgroups|sandbox_init|sandbox_free_error)\b/,
        'flags, securelevel, ownership, credentials and sandbox changes must use fixture stubs');
      const scenarios = ['pipe-identity', 'metadata', 'paths', 'frame-ok', 'frame-trailing', 'frame-nonce', 'frame-schema',
        'frame-result', 'frame-unterminated', 'reap-scope-unknown', 'launcher-clear', 'birth-missing', 'echild', 'binding',
        'owner-unknown', 'active-refusal', 'inactive-scope', 'stopped-birth-missing', 'cleanup-policy-unknown',
        'launch-sigchld-ignore', 'launch-no-child-wait', 'create', 'reuse', 'implicit-reuse', 'invalid-existing', 'host-changed',
        'stage-publish-inode', 'stage-existing-destination', 'stage-hardlink-race', 'stage-replaced-inode', 'stage-extra-entry',
        'stage-source-hardlink', 'stage-pending-retention', 'stage-stopped-retention', 'stage-mode-readback',
        'stage-owner-readback', 'stage-unknown-identity', 'stage-publish-fsync',
        'home-securelevel-positive', 'home-securelevel-error', 'home-securelevel-short',
        'home-seal-owner-failure', 'home-seal-owner-readback', 'home-seal-mode-failure', 'home-seal-mode-readback',
        'home-seal-flags-failure', 'home-seal-flags-readback', 'home-clear-failure', 'home-clear-readback',
        'home-reclaim-owner-failure', 'home-reclaim-owner-readback', 'home-reclaim-mode-failure', 'home-reclaim-mode-readback',
        'home-seal-swap', 'home-seal-acl', 'home-reclaim-swap', 'home-reclaim-acl', 'home-unexpected-flags',
        'command-ok', 'command-entry', 'command-identity', 'command-home', 'command-holds', 'command-sandbox',
        'command-metadata', 'command-set-default', 'exit-entry', 'exit-identity', 'exit-home', 'exit-holds',
        'exit-sandbox', 'exit-metadata', 'exit-set-default', 'exit-timeout', 'exit-unrecognized',
        'exit-echild', 'exit-unreaped', 'exit-scope-unknown', 'command-parent-identity',
        'parent-ok', 'parent-null', 'parent-pid-minimum', 'parent-pid-negative', 'parent-expected-uid',
        'parent-expected-ruid', 'parent-expected-saved-uid', 'parent-expected-birth-zero', 'parent-expected-usec-invalid',
        'parent-before-change', 'parent-sysctl-error', 'parent-empty-length', 'parent-short-length', 'parent-long-length',
        'parent-wrong-pid', 'parent-actual-uid', 'parent-actual-ruid', 'parent-actual-saved-uid',
        'parent-birth-seconds', 'parent-birth-microseconds', 'parent-birth-zero', 'parent-birth-negative',
        'parent-usec-negative', 'parent-usec-invalid', 'parent-after-change', 'kernel-snapshot-readonly'];
      for (const scenario of scenarios) await t.test(scenario, () => {
        const home = realpathSync(mkdtempSync(path.join(temporary, `${scenario}-`)));
        chmodSync(home, 0o700);
        const result = spawnSync(executable, [scenario, home], { encoding: 'utf8', timeout: 10_000, cwd: home });
        assert.equal(result.error, undefined, result.error?.message);
        assert.equal(result.signal, null, result.stderr);
        assert.equal(result.status, 0, `${result.stderr}\n${result.stdout}`);
        const report = JSON.parse(result.stdout);
        assert.equal(report.ok, true);
        assert.equal(report.fixtureOnly, true);
        assert.equal(report.rootAuthorityVerified, false);
        assert.equal(report.realKeychainAPICalls, 0);
        assert.equal(report.ready, false);
        assert.equal(report.protected, false);
        assert.equal(report.activatesSystem, false);
        assert.equal(report.ownedChildrenReaped, true);
        assert.equal(report.forbiddenWaits, 0);
        assert.ok(report.checks >= 15);
        assert.equal(report.syntheticSelectorAttempts,
          ['create', 'host-changed', 'stage-pending-retention', 'stage-stopped-retention', 'stage-publish-fsync', 'command-set-default'].includes(scenario) ? 1 : 0);
        if (scenario === 'pipe-identity') assert.equal(report.syntheticWorkers, 0);
        if (scenario.startsWith('home-')) assert.equal(report.syntheticWorkers, 0);
        if (['reuse', 'implicit-reuse', 'invalid-existing'].includes(scenario)) assert.equal(report.syntheticWorkers, 1);
        if (['create', 'host-changed'].includes(scenario)) assert.equal(report.syntheticWorkers, 5);
        if (['stage-pending-retention', 'stage-stopped-retention'].includes(scenario)) assert.equal(report.syntheticWorkers, 3);
        if (['stage-mode-readback', 'stage-owner-readback', 'stage-unknown-identity'].includes(scenario)) assert.equal(report.syntheticWorkers, 2);
        if (scenario === 'stage-publish-fsync') assert.equal(report.syntheticWorkers, 4);
        if (scenario.startsWith('command-')) assert.equal(report.syntheticWorkers, scenario === 'command-set-default' ? 3 : 1);
        if (scenario.startsWith('exit-')) assert.equal(report.syntheticWorkers, 1);
        if (scenario.startsWith('parent-')) assert.equal(report.syntheticWorkers, 0);
        assert.equal(report.readOnlyKernelSnapshots, scenario === 'kernel-snapshot-readonly' ? 2 : 0);
        if (scenario === 'kernel-snapshot-readonly') {
          assert.equal(report.syntheticWorkers, 0);
          assert.equal(typeof report.rootSnapshotReadable, 'boolean');
          assert.equal(typeof report.restrictedRootBsdDenied, 'boolean');
          t.diagnostic(`Ordinary-UID kernel reads: self birth matched; root snapshot readable=${report.rootSnapshotReadable}; restricted BSD denied=${report.restrictedRootBsdDenied}`);
        }
      });
      assert.deepEqual(sourceHashes(), before, 'compile and fixtures must use one frozen source set');
    } finally { rmSync(temporary, { recursive: true, force: true }); }
  });
