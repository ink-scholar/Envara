import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { mkdtemp, rm } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const exec = promisify(execFile);
const native = path.resolve(import.meta.dirname, '../native/macos-pf-routing');
test('fixed preparation quarantine answers both pipes and preserves its separate custody',
  { skip: process.platform !== 'darwin' }, async () => {
    assert.notEqual(process.getuid(), 0); assert.equal(process.getuid(), process.geteuid());
    const directory = await mkdtemp(path.join(tmpdir(), 'envara-preparation-supervisor-'));
    try {
      const binary = path.join(directory, 'fixture');
      await exec('/usr/bin/clang', ['-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-deprecated-declarations',
        ...['app-preparation-supervisor-fixture.c', 'app-control.c', 'app-ticket.c', 'app-registry.c',
          'gui-launch.m', 'launcher.c', 'launch-guardian.c'].map(name => path.join(native, name)),
        '-framework', 'Foundation', '-framework', 'AppKit', '-framework', 'Security', '-lbsm', '-o', binary],
      { timeout: 30000, maxBuffer: 1024 * 1024 });
      for (const mode of ['reaped-retry', 'launcher-clear', 'unknown', 'binding-invalid', 'snapshot-changed', 'revoke-refused', 'immediate-stop']) {
        const run = await exec(binary, [mode], { timeout: 10000 });
        const frames = run.stdout.trim().split('\n').map(line => JSON.parse(line));
        const summary = frames.at(-1); assert.equal(summary.ok, true); assert.equal(summary.mode, mode);
        assert.equal(frames.filter(frame => frame.event === 'transport-refused').length, 1);
        assert.equal(frames[0].reason, 'NATIVE_APP_KEYCHAIN_PREPARATION_REFUSED'); assert.equal(frames[0].error, 1);
        const pending = frames.filter(frame => frame.schema === 'envara.pf-app-preparation/v1');
        assert.deepEqual(pending.slice(0, mode === 'immediate-stop' ? 2 : 3).map(frame => [frame.command, frame.cleanupAttempt]),
          mode === 'immediate-stop' ? [['automatic', 0], ['S', 1]] : [['automatic', 0], ['R', 0], ['S', 1]]);
        for (const frame of pending) {
          assert.deepEqual(Object.keys(frame).sort(), ['schema', 'event', 'ticketId', 'registrationId', 'versionId',
            'environmentId', 'runId', 'keeperPID', 'keeperBirth', 'preparationId', 'generation', 'command', 'cleanupAttempt',
            'childState', 'launchAuthorityBurned', 'custodyHeld', 'denyVerified', 'frontClosedVerified', 'ready', 'protected'].sort());
          assert.equal(frame.preparationId, pending[0].preparationId); assert.equal(frame.generation, 1);
          assert.equal(frame.launchAuthorityBurned, true); assert.equal(frame.custodyHeld, true);
          assert.equal(frame.ready, false); assert.equal(frame.protected, false);
        }
        if (summary.held) {
          assert.deepEqual(pending.slice(3).map(frame => [frame.command, frame.cleanupAttempt]), [['S', 2], ['R', 2]]);
          assert.equal(frames.some(frame => frame.fixtureReturned), false);
        } else assert.equal(frames.at(-2).fixtureReturned, true);
        if (mode === 'revoke-refused') assert.equal(pending[0].frontClosedVerified, false);
      }
    } finally { await rm(directory, { recursive: true, force: true }); }
  });
