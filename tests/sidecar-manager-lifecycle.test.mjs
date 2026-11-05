import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { SidecarManager } from '../electron/sidecar-manager.mjs';
import { spawn } from 'node:child_process';
import { once } from 'node:events';

async function fixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'envara-sidecar-command-'));
  const manager = new SidecarManager({ dataDir: root, resourcesDir: root, commandGraceMs: 25 });
  t.after(async () => {
    for (const child of manager.commands) {
      if (child.exitCode !== null || child.signalCode !== null) continue;
      const closed = once(child, 'close'); child.kill('SIGKILL'); await closed;
    }
    await rm(root, { recursive: true, force: true });
  });
  await mkdir(manager.baseDir, { recursive: true });
  manager.binary = path.join(root, 'owned-command');
  await writeFile(manager.binary, `#!${process.execPath}\nconst fs = require('node:fs');\nconst root = process.argv[process.argv.indexOf('--base-dir') + 1];\nprocess.on('SIGTERM', () => { fs.writeFileSync(root + '/term', 'received'); process.stderr.write('term\\n'); });\nprocess.stderr.write('ready\\n');\nsetInterval(() => {}, 1000);\n`, { mode: 0o700 });
  return manager;
}

function acknowledgement(child, marker) {
  return new Promise((resolve, reject) => {
    let received = '';
    const cleanup = () => { child.stderr.off('data', data); child.off('close', closed); };
    const data = bytes => { received += bytes; if (received.includes(`${marker}\n`)) { cleanup(); resolve(); } };
    const closed = () => { cleanup(); reject(new Error(`Owned child closed before ${marker} acknowledgement.`)); };
    child.stderr.on('data', data); child.once('close', closed);
  });
}

test('sidecar command deadline escalates an owned child that ignores SIGTERM', { skip: process.platform === 'win32', timeout: 10000 }, async t => {
  const manager = await fixture(t);
  // Native startup and signal dispatch are scheduled by the OS. Advance only
  // the parent's deadline/grace clocks after the real child acknowledges each
  // state, rather than assuming Node starts and handles signals within 1 s.
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const operation = manager.command([], 1000);
  const result = assert.rejects(operation, { code: 'BACKEND_COMMAND_TIMEOUT' });
  const [child] = manager.commands;
  await acknowledgement(child, 'ready');
  t.mock.timers.tick(999);
  assert.equal(child.killed, false, 'The command must remain live before its deadline.');
  const terminated = acknowledgement(child, 'term');
  t.mock.timers.tick(1);
  await terminated;
  const closed = once(child, 'close');
  t.mock.timers.tick(manager.commandGraceMs);
  await closed; await result;
  assert.equal(child.signalCode, 'SIGKILL');
  assert.equal(await readFile(path.join(manager.baseDir, 'term'), 'utf8'), 'received');
  assert.equal(manager.commands.size, 0, 'The real owned child close must be observed.');
  await manager.shutdown();
});

test('cancelInstall also bounds a child that ignores the graceful signal', { skip: process.platform === 'win32', timeout: 10000 }, async t => {
  const manager = await fixture(t);
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const operation = manager.command([], 20000);
  const result = assert.rejects(operation, { code: 'BACKEND_COMMAND_CANCELLED' });
  const [child] = manager.commands;
  await acknowledgement(child, 'ready');
  const terminated = acknowledgement(child, 'term');
  manager.cancelInstall();
  await terminated;
  const closed = once(child, 'close');
  t.mock.timers.tick(manager.commandGraceMs);
  await closed; await result;
  assert.equal(child.signalCode, 'SIGKILL');
  assert.equal(await readFile(path.join(manager.baseDir, 'term'), 'utf8'), 'received');
  assert.equal(manager.commands.size, 0);
  assert.equal(manager.commandStops.size, 0);
  await manager.shutdown();
});

test('stop recognizes an already signal-exited backend without waiting for a lost exit event', { skip: process.platform === 'win32', timeout: 2000 }, async t => {
  const manager = await fixture(t);
  const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' });
  t.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); });
  await once(child, 'spawn');
  const exited = once(child, 'exit');
  child.kill('SIGTERM');
  await exited;
  assert.equal(child.signalCode, 'SIGTERM');
  manager.process = child;
  manager.client.request = async () => ({});
  await manager.stop();
  assert.equal(manager.process, null);
});
