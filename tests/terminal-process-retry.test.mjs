import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execute = promisify(execFile);

test('an uncertain real cleanup shares its attempt and permits a fresh metadata-only retry', { skip: process.platform === 'win32' }, async () => {
  // The injected metadata failure stays inside this disposable Node process.
  // The real captured shell and child are the only signal targets.
  const fixture = `
    import assert from 'node:assert/strict';
    import cp from 'node:child_process';
    import { once } from 'node:events';
    import { syncBuiltinESMExports } from 'node:module';
    import { promisify } from 'node:util';
    const originalExec = cp.execFile, execute = promisify(originalExec);
    let failOnce = false, metadataCalls = 0;
    function controlledExec(...args) { return originalExec(...args); }
    controlledExec[promisify.custom] = async (...args) => {
      if (args[0] === '/bin/ps') {
        metadataCalls++;
        if (failOnce) { failOnce = false; throw Object.assign(new Error('synthetic metadata failure'), { code: 'EIO' }); }
      }
      return execute(...args);
    };
    cp.execFile = controlledExec; syncBuiltinESMExports();
    const { captureTerminalProcess, closeTerminalProcess } = await import(${JSON.stringify(new URL('../electron/terminal-process.mjs', import.meta.url).href)});
    const shell = cp.spawn('/bin/sh', ['-c', 'sleep 8 & printf "%s\\n" "$!"; wait'], { stdio: ['pipe', 'pipe', 'ignore'] });
    let childIdentity, childPty;
    try {
      const [out] = await once(shell.stdout, 'data');
      const childPid = Number(out.toString().trim());
      const identity = await captureTerminalProcess(shell.pid);
      childIdentity = await captureTerminalProcess(childPid);
      childPty = { pid: childPid, kill: signal => process.kill(childPid, signal) };
      const pty = { pid: shell.pid, kill: signal => shell.kill(signal) };
      failOnce = true;
      const [first, concurrent] = await Promise.all([
        closeTerminalProcess({ pty, identity }), closeTerminalProcess({ pty, identity }),
      ]);
      assert.equal(first, concurrent, 'concurrent callers must share one result');
      assert.equal(first.ok, false);
      assert.equal(first.metadataAvailable, false);
      const beforeRetry = metadataCalls;
      const second = await closeTerminalProcess({ pty, identity });
      assert.notEqual(second, first, 'a failure cannot poison every future retry');
      assert.equal(second.ok, true);
      assert.equal(second.metadataAvailable, true);
      assert.equal(second.rootExited, true);
      assert.deepEqual(second.remainingPids, []);
      assert(metadataCalls > beforeRetry);
      assert.equal(first.ok, false, 'the original failure evidence remains intact');
      const beforeCached = metadataCalls;
      assert.equal(await closeTerminalProcess({ pty, identity }), second);
      assert.equal(metadataCalls, beforeCached, 'confirmed success remains idempotent');
      console.log(JSON.stringify({ uncertainFirst: true, concurrentShared: true, retryConfirmed: true, ownedRemaining: 0, confirmedSuccessCached: true }));
    } finally {
      cp.execFile = originalExec; syncBuiltinESMExports();
      if (childIdentity) await closeTerminalProcess({ pty: childPty, identity: childIdentity }).catch(() => {});
      if (shell.exitCode === null && shell.signalCode === null) shell.kill('SIGKILL');
    }
  `;
  const { stdout } = await execute(process.execPath, ['--input-type=module', '-e', fixture], { timeout: 15000, maxBuffer: 65536 });
  assert.deepEqual(JSON.parse(stdout.trim()), { uncertainFirst: true, concurrentShared: true, retryConfirmed: true, ownedRemaining: 0, confirmedSuccessCached: true });
});
