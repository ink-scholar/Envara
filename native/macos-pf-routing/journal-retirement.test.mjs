import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, realpathSync, chmodSync, rmSync, readFileSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

test('held own journal retirement resumes actual unlink/fsync faults and refuses foreign absence',
  { skip: process.platform !== 'darwin' }, () => {
    assert.notEqual(process.getuid(), 0);
    assert.equal(process.getuid(), process.geteuid());
    const root = path.dirname(fileURLToPath(import.meta.url));
    const names = ['journal-retirement.h', 'journal-retirement.c', 'journal-retirement-fixture.c'];
    const hashes = () => names.map(name => createHash('sha256').update(readFileSync(path.join(root, name))).digest('hex'));
    const before = hashes();
    const temporary = realpathSync(mkdtempSync('/private/tmp/envara-journal-retirement-'));
    chmodSync(temporary, 0o700);
    const executable = path.join(temporary, 'fixture');
    try {
      const compile = spawnSync('xcrun', ['clang', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
        '-DENVARA_JOURNAL_RETIREMENT_INERT=1', '-target',
        `${process.arch === 'arm64' ? 'arm64' : 'x86_64'}-apple-macos13.0`,
        path.join(root, 'journal-retirement.c'), path.join(root, 'journal-retirement-fixture.c'), '-o', executable],
      { encoding: 'utf8', timeout: 30_000 });
      assert.equal(compile.status, 0, compile.stderr);
      const result = spawnSync(executable, [temporary], { encoding: 'utf8', timeout: 30_000 });
      assert.equal(result.status, 0, result.stderr + result.stdout);
      const proof = JSON.parse(result.stdout);
      assert.equal(proof.actualFilesystemCases, 43);
      assert.equal(proof.injectedFaultCases, 28);
      assert.equal(proof.foreignRefusals, 12);
      assert.ok(proof.freshGuardCalls > 200);
      for (const key of ['ok', 'ownedZeroBytePrefix', 'partialUnlinkRetry', 'directoryAndIntentFsyncRetry',
        'missingBeforeIntentRefused', 'replacementsAndUnknownEntriesRefused', 'newInvocationCannotAdopt'])
        assert.equal(proof[key], true, key);
      for (const key of ['root', 'pf', 'ready', 'protected']) assert.equal(proof[key], false, key);
      assert.deepEqual(readdirSync(temporary), ['fixture'], 'all exact owned fixture leaves are retired');
      assert.deepEqual(hashes(), before, 'source files remain unchanged by compilation and fixtures');
    } finally { rmSync(temporary, { recursive: true, force: true }); }
  });
