import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, realpathSync, chmodSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

test('native factory uses bounded manifest JSON, the real hook parser and zero-success Notion checks',
  { skip: process.platform !== 'darwin' }, async t => {
    assert.notEqual(process.getuid(), 0); assert.equal(process.getuid(), process.geteuid());
    const root = path.dirname(fileURLToPath(import.meta.url));
    const temporary = realpathSync(mkdtempSync('/private/tmp/envara-factory-preparation-')); chmodSync(temporary, 0o700);
    const linked = ['launcher.c', 'tunnel.c', 'transport.c', 'gui-launch.m', 'app-registry.c', 'app-ticket.c',
      'app-supervisor.c', 'launch-guardian.c', 'notion-launch.m', 'app-scope-proof.c', 'pf-run-ledger.c',
      'pf-production-filter.c', 'app-transport.c', 'app-native-factory-fixture.m', 'app-native-factory-parser-fixture.c'];
    const sources = [...linked, 'app-native-factory.m', 'pf-hook.c'];
    const hashes = () => sources.map(name => createHash('sha256').update(readFileSync(path.join(root, name))).digest('hex'));
    const before = hashes();
    try {
      const executable = path.join(temporary, 'fixture');
      const compile = spawnSync('xcrun', ['clang', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-deprecated-declarations',
        '-target', `${process.arch === 'arm64' ? 'arm64' : 'x86_64'}-apple-macos13.0`, ...linked.map(name => path.join(root, name)),
        '-framework', 'Foundation', '-framework', 'AppKit', '-framework', 'Security', '-lbsm', '-o', executable],
      { encoding: 'utf8', timeout: 60_000 });
      assert.equal(compile.status, 0, compile.stderr);
      await t.test('actual staged ticket verifier audits fresh scope without repeatedly traversing the bound app', () => {
        const result = spawnSync(executable, ['staged-ticket'], { encoding: 'utf8', timeout: 5_000 });
        assert.equal(result.status, 0, result.stderr + result.stdout);
        assert.deepEqual(JSON.parse(result.stdout), {
          ok: true, stagedChecks: 1000, stagedBundleAudits: 0, prestageBundleAuditRetained: true,
          freshPFLeaseIdentityRefusals: true, bindingMismatchesRefusedBeforeAudit: true,
          ready: false, protected: false, root: false, pf: false,
        });
      });
      await t.test('first failure stays immutable and unknown PF outcomes cannot enable cleanup writes', () => {
        const result=spawnSync(executable,['diagnostic-recovery'],{encoding:'utf8',timeout:5_000});
        assert.equal(result.status,0,result.stderr+result.stdout);const proof=JSON.parse(result.stdout);
        for(const key of ['ok','firstFailureSurvivesCleanup','preflightErrnoPreserved','knownOutcomeOnly','unknownAndRollbackAckRemainRefused','cleanupCannotRestoreProvider'])assert.equal(proof[key],true,key);
        for(const key of ['root','pf','ready','protected'])assert.equal(proof[key],false,key);
      });
      await t.test('exact c37 65-input manifest passes only the manifest decoder; private records retain all bounds', () => {
        const manifest = fileURLToPath(new URL('../../tests/fixtures/macos-pf-app-factory-c37-manifest.json', import.meta.url));
        const bytes = readFileSync(manifest);
        assert.equal(createHash('sha256').update(bytes).digest('hex'), 'c37c49f9ca94b285d7b362ee4a42a01203d3632874d803e90ff38e48dd66c5e0');
        const result = spawnSync(executable, ['manifest', manifest], { encoding: 'utf8', timeout: 10_000 });
        assert.equal(result.status, 0, result.stderr + result.stdout);
        const proof = JSON.parse(result.stdout);
        assert.equal(proof.actualC37SourceCount, 65);
        for (const key of ['ok', 'oldBoundRefused', 'manifestAccepted', 'manifest128Accepted129Refused',
          'leaseAndRegistry64Retained', 'duplicatesRefused', 'arraysNodesBytesDepthRetained']) assert.equal(proof[key], true, key);
        for (const key of ['root', 'pf', 'ready', 'protected']) assert.equal(proof[key], false, key);
      });
      await t.test('Foundation serialization reaches the production lease parser without loosening its refusal', () => {
        const result = spawnSync(executable, ['json'], { encoding: 'utf8', timeout: 10_000 });
        assert.equal(result.status, 0, result.stderr + result.stdout);
        const proof = JSON.parse(result.stdout); assert.equal(proof.legacyEscapesRefused, true);
        assert.equal(proof.fixedSerializationAccepted, true); assert.equal(proof.foreignAndMalformedRefused, true);
        assert.equal(proof.ready, false); assert.equal(proof.protected, false);
      });
      await t.test('actual signed local Notion passes zero-success checks; invalid requests still refuse',
        { skip: !existsSync('/Applications/Notion.app') }, () => {
          const result = spawnSync(executable, ['application', temporary], { encoding: 'utf8', timeout: 15_000 });
          assert.equal(result.status, 0, result.stderr + result.stdout);
          const proof = JSON.parse(result.stdout); assert.equal(proof.actualNotionZeroSuccessAccepted, true);
          assert.equal(proof.invalidRequestAndUnsupportedAppRefused, true); assert.equal(proof.readOnly, true);
          assert.equal(proof.ready, false); assert.equal(proof.protected, false);
        });
      assert.deepEqual(hashes(), before, 'compile and inspection must leave the source set unchanged');
    } finally { rmSync(temporary, { recursive: true, force: true }); }
  });
