import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { SidecarManager } from '../electron/sidecar-manager.mjs';

test('sidecar startup traces preparation, status, process spawn and first API readiness in order', { skip: process.platform === 'win32', timeout: 15000 }, async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'envara-sidecar-startup-trace-'));
  const events = [];
  const manager = new SidecarManager({
    dataDir: root, resourcesDir: root,
    startupStep: async (name, operation) => {
      events.push(`${name}:begin`);
      const result = await operation();
      events.push(`${name}:end`);
      return result;
    },
  });
  t.after(async () => {
    await manager.shutdown();
    await rm(root, { recursive: true, force: true });
  });
  await mkdir(path.join(manager.driver, 'package/lib'), { recursive: true });
  for (const resource of ['package/cli.js', 'package/lib/coreBundle.js', 'node']) {
    await writeFile(path.join(manager.driver, resource), 'owned unused fixture');
  }
  await writeFile(manager.binary, `#!${process.execPath}
const http = require('node:http');
if (process.argv.includes('status')) {
  process.stdout.write(JSON.stringify({ browsers: [] }));
} else if (process.argv.includes('serve')) {
  const port = Number(process.argv[process.argv.indexOf('--port') + 1]);
  const server = http.createServer((request, response) => {
    response.setHeader('Content-Type', 'application/json');
    response.end(JSON.stringify({ data: [] }));
    if (request.url === '/api/shutdown') server.close(() => process.exit(0));
  });
  server.listen(port, '127.0.0.1');
} else {
  process.exitCode = 2;
}
`, { mode: 0o700 });

  assert.equal(await manager.initialize(), manager);
  assert.deepEqual(events, [
    'sidecar-files:begin', 'sidecar-files:end',
    'sidecar-probe:begin', 'sidecar-probe:end',
    'sidecar-start:begin',
    'sidecar-process-spawn:begin', 'sidecar-process-spawn:end',
    'sidecar-api-ready:begin', 'sidecar-api-ready:end',
    'sidecar-start:end',
  ]);
  assert(manager.process?.pid, 'The API-ready stage must observe the owned fixture process.');
  assert.equal((await manager.client.request('GET', '/api/runtimes')).data.length, 0);
  await manager.shutdown();
  assert.equal(manager.process, null);
  assert.equal(manager.commands.size, 0);

  const direct = new SidecarManager({ dataDir: root, resourcesDir: root });
  assert.equal(await direct.startupStep('fixed-test-stage', () => 'operation-result'), 'operation-result');
  const failure = new Error('owned fixture failure');
  await assert.rejects(direct.startupStep('fixed-test-stage', async () => { throw failure; }), error => error === failure);
});
