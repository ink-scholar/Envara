import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { mkdtemp, rm } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const exec = promisify(execFile);
const native = path.resolve(import.meta.dirname, '../native/macos-pf-routing');
test('preparation handoff retains buffered retries and retires relay before positive Stop',
  { skip: process.platform !== 'darwin' }, async () => {
    assert.notEqual(process.getuid(), 0); assert.equal(process.getuid(), process.geteuid());
    const directory = await mkdtemp(path.join(tmpdir(), 'envara-preparation-transport-'));
    try {
      const binary = path.join(directory, 'fixture');
      const sources = ['app-preparation-transport-fixture.c', 'launcher.c', 'tunnel.c', 'transport.c', 'gui-launch.m',
        'app-registry.c', 'app-ticket.c', 'app-supervisor.c', 'launch-guardian.c', 'notion-launch.m', 'app-keychain.m',
        'app-native-factory.m', 'app-scope-proof.c', 'pf-hook.c', 'pf-run-ledger.c', 'pf-production-filter.c'];
      await exec('/usr/bin/clang', ['-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-deprecated-declarations',
        ...sources.map(name => path.join(native, name)), '-framework', 'Foundation', '-framework', 'AppKit',
        '-framework', 'Security', '-lbsm', '-o', binary], { timeout: 60000, maxBuffer: 1024 * 1024 });
      for (const mode of ['buffered-retry', 'scope-retry', 'relay-echild', 'relay-other-pid', 'relay-wait-error']) {
        const result = await exec(binary, [mode], { timeout: 10000 });
        const frames = result.stdout.trim().split('\n').map(line => JSON.parse(line));
        const summary = frames.at(-1); assert.equal(summary.ok, true);
        if (mode.startsWith('relay-')) {
          assert.equal(summary.waitUnknownHeld, true);
          assert.deepEqual(frames.slice(0, -1).map(frame => [frame.command, frame.cleanupAttempt]), [['S', 1], ['S', 2]]);
          assert.equal(frames.some(frame => frame.event === 'transport-cleanup-stopping'), false);
          continue;
        }
        for (const flag of ['bufferedRetryDelivered', 'relayExactlyReaped', 'immediateRDelivered']) assert.equal(summary[flag], true);
        const negative = frames.filter(frame => frame.schema === 'envara.pf-app-preparation/v1');
        assert.deepEqual(negative.map(frame => [frame.command, frame.cleanupAttempt]), mode === 'scope-retry' ? [['S', 1], ['S', 2]] : [['S', 1]]);
        const positive = frames.filter(frame => frame.event === 'transport-cleanup-stopping'); assert.equal(positive.length, 1);
        assert.equal(positive[0].childAbsent, true); assert.equal(positive[0].childReaped, false);
        assert.equal(frames.some(frame => frame.event === 'released' || frame.event === 'transport-released'), false);
        assert.equal(summary.ready, false); assert.equal(summary.protected, false);
      }
    } finally { await rm(directory, { recursive: true, force: true }); }
  });
