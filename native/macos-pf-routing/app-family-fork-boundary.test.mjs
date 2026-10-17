import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

// This exercises the actual guardian release chain with a real owned orphan.
// Its scope callback checks that orphan; it is not a root realm-GID census.
test('guardian retains custody when a fork after two empty snapshots survives recorded-family Stop',
  { skip: process.platform !== 'darwin', timeout: 45_000 }, t => {
    assert.notEqual(process.getuid(), 0, 'the fixture refuses root');
    assert.equal(process.getuid(), process.geteuid());
    assert.equal(process.getgid(), process.getegid());
    const directory = path.dirname(fileURLToPath(import.meta.url));
    const temporary = realpathSync(mkdtempSync(path.join(tmpdir(), 'envara-family-fork-boundary-')));
    chmodSync(temporary, 0o700);
    try {
      for (const name of ['app-family.c', 'app-family.h', 'launch-guardian.c', 'launch-guardian.h',
        'launcher.c', 'native.h', 'app-family-fork-boundary-fixture.c']) {
        const source = readFileSync(path.join(directory, name));
        writeFileSync(path.join(temporary, name), source);
        if (['app-family.c', 'launch-guardian.c'].includes(name))
          t.diagnostic(`${name} sha256=${createHash('sha256').update(source).digest('hex')}`);
      }
      t.diagnostic(`snapshotAt=${new Date().toISOString()}`);
      const executable = path.join(temporary, 'fixture');
      const compile = spawnSync('xcrun', ['clang', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
        '-target', `${process.arch === 'arm64' ? 'arm64' : 'x86_64'}-apple-macos13.0`,
        path.join(temporary, 'app-family-fork-boundary-fixture.c'), path.join(temporary, 'launcher.c'),
        '-o', executable], { encoding: 'utf8', cwd: temporary, timeout: 15_000 });
      assert.equal(compile.error, undefined, compile.error?.message);
      assert.equal(compile.signal, null, compile.stderr);
      assert.equal(compile.status, 0, compile.stderr);
      const result = spawnSync(executable, [], { encoding: 'utf8', cwd: temporary, timeout: 25_000 });
      assert.equal(result.error, undefined, result.error?.message);
      assert.equal(result.signal, null, result.stderr);
      assert.equal(result.status, 0, `${result.stderr}\n${result.stdout}`);
      assert.deepEqual(JSON.parse(result.stdout.trim()), {
        ok: true, fixtureOnly: true, ready: false, protected: false, activatesSystem: false,
        usesProductionGuardian: true, usesProductionFamily: true, schedulingHook: true,
        nativeInventorySnapshots: true, inertNetworkAuthority: true, rootRealmGidCensus: false,
        unregisteredDescendantSurvivedFamilyStop: true, scopeRefusalsWhileDescendantLive: 2,
        custodyHeldWhileDescendantLive: true, releasedWhileDescendantLive: false,
        releasedAfterOwnedDescendantExit: true, custodyEofAfterRelease: true,
        sameIdentitySiblingUnaffected: true, ownedCleanupComplete: true, forcedGuardianCleanup: false,
      });
      t.diagnostic(result.stdout.trim());
    } finally {
      rmSync(temporary, { recursive: true, force: true });
    }
  });
