import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';

test('a changed fallback timezone cannot change a captured process identity or close an unrelated process', { skip: process.platform === 'win32' }, async t => {
  // Isolate the metadata subprocess wrapper from other tests. Only the fallback
  // TZ changes: an explicit TZ supplied by production must take precedence.
  const moduleURL = new URL('../electron/terminal-process.mjs', import.meta.url).href;
  const program = `
    import assert from 'node:assert/strict';
    import childProcess from 'node:child_process';
    import { once } from 'node:events';
    import { syncBuiltinESMExports } from 'node:module';
    import { promisify } from 'node:util';
    const nativeExecFile = childProcess.execFile;
    let fallbackZone = 'UTC';
    const metadataZones = [];
    const execute = (file, args, options, callback) => {
      if (file === '/bin/ps') {
        metadataZones.push(options.env?.TZ ?? null);
        options = { ...options, env: { TZ: fallbackZone, ...options.env } };
      }
      return nativeExecFile(file, args, options, callback);
    };
    execute[promisify.custom] = (file, args, options) => new Promise((resolve, reject) =>
      execute(file, args, options, (error, stdout, stderr) => error ? reject(error) : resolve({ stdout, stderr })));
    childProcess.execFile = execute;
    syncBuiltinESMExports();
    const { captureTerminalProcess, closeTerminalProcess } = await import(${JSON.stringify(moduleURL)});
    const owned = childProcess.spawn('/bin/sleep', ['15'], { stdio: 'ignore' });
    const unrelated = childProcess.spawn('/bin/sleep', ['15'], { stdio: 'ignore' });
    const alive = pid => { try { process.kill(pid, 0); return true; } catch { return false; } };
    let ptyKillCalls = 0;
    try {
      const identity = await captureTerminalProcess(owned.pid);
      fallbackZone = 'America/New_York';
      const result = await closeTerminalProcess({ identity, pty: {
        pid: owned.pid, kill(signal) { ptyKillCalls++; owned.kill(signal); },
      } });
      assert.equal(result.ok, true, 'The same live process must not be mistaken for a reused PID after a timezone change');
      assert.equal(result.rootExited, true);
      assert.deepEqual(result.remainingPids, []);
      assert.deepEqual(result.skippedPids, []);
      assert.ok(ptyKillCalls > 0);
      if (owned.exitCode === null && owned.signalCode === null) await once(owned, 'exit');
      assert.equal(alive(owned.pid), false);
      assert.equal(alive(unrelated.pid), true, 'The unrelated sibling must not be signalled');
      assert.ok(metadataZones.length > 1 && metadataZones.every(zone => zone === 'UTC'));
      process.stdout.write(JSON.stringify({ closed: result.ok, unrelatedAlive: true, fixedMetadataTimezone: true }) + '\\n');
    } finally {
      childProcess.execFile = nativeExecFile;
      syncBuiltinESMExports();
      for (const child of [owned, unrelated]) {
        if (child.exitCode !== null || child.signalCode !== null) continue;
        const exited = once(child, 'exit');
        child.kill('SIGKILL');
        await exited;
      }
    }
  `;
  const worker = spawn(process.execPath, ['--input-type=module', '--eval', program], {
    env: { PATH: '/usr/bin:/bin', LC_ALL: 'C' }, stdio: ['ignore', 'pipe', 'pipe'],
  });
  t.after(() => { if (worker.exitCode === null && worker.signalCode === null) worker.kill('SIGTERM'); });
  let output = '', errors = '';
  worker.stdout.on('data', bytes => { output += bytes; });
  worker.stderr.on('data', bytes => { errors += bytes; });
  const [code, signal] = await once(worker, 'close');
  assert.equal(signal, null, errors);
  assert.equal(code, 0, errors);
  assert.deepEqual(JSON.parse(output), { closed: true, unrelatedAlive: true, fixedMetadataTimezone: true });
});
