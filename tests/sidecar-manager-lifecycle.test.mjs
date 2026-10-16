import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';
import { SidecarManager } from '../electron/sidecar-manager.mjs';
import { spawn } from 'node:child_process';
import { once } from 'node:events';

async function fixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'envara-sidecar-command-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const manager = new SidecarManager({ dataDir: root, resourcesDir: root, commandGraceMs: 25 });
  await mkdir(manager.baseDir, { recursive: true });
  manager.binary = path.join(root, 'owned-command');
  await writeFile(manager.binary, `#!${process.execPath}\nconst fs = require('node:fs');\nconst root = process.argv[process.argv.indexOf('--base-dir') + 1];\nprocess.on('SIGTERM', () => fs.writeFileSync(root + '/term', 'received'));\nfs.writeFileSync(root + '/ready', 'ready');\nsetInterval(() => {}, 1000);\n`, { mode: 0o700 });
  return manager;
}

test('sidecar command deadline escalates an owned child that ignores SIGTERM', { skip: process.platform === 'win32' }, async t => {
  const manager = await fixture(t), started = Date.now();
  await assert.rejects(manager.command([], 1000), { code: 'BACKEND_COMMAND_TIMEOUT' });
  assert.equal(await readFile(path.join(manager.baseDir, 'term'), 'utf8'), 'received');
  assert.equal(manager.commands.size, 0, 'The real owned child close must be observed.');
  assert(Date.now() - started < 4000);
  await manager.shutdown();
});

test('cancelInstall also bounds a child that ignores the graceful signal', { skip: process.platform === 'win32' }, async t => {
  const manager = await fixture(t);
  const operation = manager.command([], 20000);
  const result = assert.rejects(operation, { code: 'BACKEND_COMMAND_CANCELLED' });
  let ready = false;
  for (let index = 0; index < 100 && !ready; index++) {
    ready = await readFile(path.join(manager.baseDir, 'ready'), 'utf8').then(() => true, () => false);
    if (!ready) await delay(20);
  }
  assert(ready, 'Owned fixture must be ready before cancellation.');
  manager.cancelInstall();
  await result;
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
