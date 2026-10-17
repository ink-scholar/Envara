import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { mkdtemp, rm } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const exec = promisify(execFile);
const native = path.resolve(import.meta.dirname, '../native/macos-pf-routing');

test('preparation frontend Stop keeps bounded custody and exact terminal evidence across retries',
  { skip: process.platform !== 'darwin' }, async t => {
    assert.notEqual(process.getuid(), 0); assert.equal(process.getuid(), process.geteuid());
    const directory = await mkdtemp(path.join(tmpdir(), 'envara-preparation-frontstop-'));
    try {
      const binary = path.join(directory, 'fixture');
      const sources = ['app-preparation-frontstop-fixture.c', 'launcher.c', 'tunnel.c', 'transport.c', 'gui-launch.m',
        'app-registry.c', 'app-ticket.c', 'app-supervisor.c', 'launch-guardian.c', 'notion-launch.m', 'app-keychain.m',
        'app-native-factory.m', 'app-scope-proof.c', 'pf-hook.c', 'pf-run-ledger.c', 'pf-production-filter.c'];
      await exec('/usr/bin/clang', ['-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-deprecated-declarations',
        ...sources.map(name => path.join(native, name)), '-framework', 'Foundation', '-framework', 'AppKit',
        '-framework', 'Security', '-lbsm', '-o', binary], { timeout: 60000, maxBuffer: 1024 * 1024 });
      const unknownModes = new Set(['echild', 'wait-error', 'nonterminal', 'unexpected-pid',
        'exit-before-identity-echild', 'exit-before-identity-error', 'exit-before-identity-nonterminal']);
      const terminalModes = new Set(['exact-exit', 'exact-signal']);
      const modes = ['delayed-terminal', ...unknownModes, 'clock-start', 'clock-after-kill', ...terminalModes,
        'wrong-owner', 'wait-interrupted', 'kill-retry', 'changed-identity',
        'exit-before-identity', 'exit-before-identity-not-waitable', 'exit-during-kill'];
      for (const mode of modes) {
        await t.test(mode, async () => {
          const result = await exec(binary, [mode], { timeout: 5000, maxBuffer: 1024 * 1024 });
          const summary = JSON.parse(result.stdout.trim());
          assert.equal(summary.ok, true); assert.equal(summary.mode, mode);
          assert.equal(summary.ownedChildCleaned, true); assert.equal(summary.syntheticDeadline, true);
          assert.equal(summary.injectedFault, !terminalModes.has(mode));
          assert.equal(summary.helperReaped, !unknownModes.has(mode));
          assert.equal(summary.helperTerminalWaits, unknownModes.has(mode) ? 0 : 1);
          assert.equal(summary.waitUnknown, unknownModes.has(mode));
          const naturalRace = mode.startsWith('exit-before-identity') || mode === 'exit-during-kill';
          assert.equal(summary.successfulSignals, unknownModes.has(mode) || terminalModes.has(mode) || naturalRace ? 0 : 1);
          assert.equal(summary.signalCalls, mode === 'kill-retry' ? 2 : mode === 'exit-during-kill' ? 1 : summary.successfulSignals);
          assert.equal(summary.ready, false); assert.equal(summary.protected, false);
        });
      }
    } finally { await rm(directory, { recursive: true, force: true }); }
  });
