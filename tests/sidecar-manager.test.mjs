import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import { EventEmitter } from 'node:events';
import { mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { SidecarManager, sidecarConfig, mergeEngineStates, macSystemProxyEnvironment } from '../electron/sidecar-manager.mjs';

test('desktop sidecar explicitly selects the prepared bundled driver without installing on startup', () => {
  const manager = new SidecarManager({ dataDir: path.resolve('unused-data'), resourcesDir: path.resolve('unused-resources') });
  const environment = manager.env();
  assert.equal(environment.ENVARA_DESKTOP_BUNDLED_DRIVER, '1');
  assert.equal(environment.PLAYWRIGHT_DRIVER_PATH, manager.driver);
  assert.equal(environment.PLAYWRIGHT_CLI_PATH, path.join(manager.driver, 'package/cli.js'));
  assert.equal(environment.PLAYWRIGHT_NODEJS_PATH, path.join(manager.driver, process.platform === 'win32' ? 'node.exe' : 'node'));
  assert.equal(environment.PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD, '1');
});

test('empty workspace stays loopback-only and disables browser auto downloads', () => {
  const cfg = sidecarConfig('/private/envara', 19234, {}, 'darwin');
  assert.equal(cfg.host, '127.0.0.1');
  assert.equal(cfg.allow_empty_runtime, true);
  assert.equal(Object.values(cfg.runtimes).some(runtime => runtime.enabled), false);
  assert.ok(Object.values(cfg.runtimes).every(runtime => runtime.skip_auto_update));
  assert.equal(Object.hasOwn(cfg, 'enforce_http_proxy_bridge'), false, 'The guard belongs in serve argv, not config JSON.');
});

test('desktop serve enables the runtime bridge guard without changing commands, config or child environment', async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'envara-sidecar-runtime-flag-'));
  const manager = new SidecarManager({ dataDir: root, resourcesDir: root });
  await mkdir(manager.baseDir, { recursive: true });
  manager.token = 'synthetic-local-token';
  const environment = Object.freeze({ PATH: '/owned-fixture', BROWSEFORGE_TOKEN: manager.token });
  manager.env = () => environment;
  const calls = [];
  const spawnMock = mock.method(childProcess, 'spawn', (binary, args, options) => {
    const child = Object.assign(new EventEmitter(), { stdout: new PassThrough(), stderr: new PassThrough(), exitCode: null, signalCode: null });
    calls.push({ binary, args, options, child });
    if (args.includes('browsers')) queueMicrotask(() => {
      child.stdout.write(JSON.stringify({ browsers: [] }));
      child.exitCode = 0;
      child.emit('close', 0);
    });
    return child;
  });
  syncBuiltinESMExports();
  const serverMock = mock.method(net, 'createServer', () => {
    const server = new EventEmitter();
    server.listen = (...args) => { queueMicrotask(args.at(-1)); return server; };
    server.address = () => ({ port: 19427 });
    server.close = callback => { queueMicrotask(callback); return server; };
    return server;
  });
  manager.client.request = async (_method, route) => {
    if (route === '/api/shutdown' && manager.process) {
      manager.process.exitCode = 0;
      manager.process.emit('exit', 0);
    }
    return { data: [] };
  };
  t.after(async () => {
    try { await manager.shutdown(); }
    finally {
      spawnMock.mock.restore();
      syncBuiltinESMExports();
      serverMock.mock.restore();
      await rm(root, { recursive: true, force: true });
    }
  });

  await manager.start();
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0].args, ['--base-dir', manager.baseDir, '--config', manager.configFile,
    'serve', '--host', '127.0.0.1', '--port', '19427', '--no-open', '--enforce-http-proxy-bridge']);
  assert.equal(calls[0].options.env, environment);
  const saved = JSON.parse(await readFile(manager.configFile, 'utf8'));
  assert.equal(Object.hasOwn(saved, 'enforce_http_proxy_bridge'), false);
  assert.equal(Object.hasOwn(saved, 'EnforceHTTPProxyBridge'), false);

  await manager.command(['browsers', 'status', '--json']);
  assert.equal(calls.length, 2);
  assert.deepEqual(calls[1].args, ['--base-dir', manager.baseDir, '--config', manager.configFile, 'browsers', 'status', '--json']);
  assert.equal(calls[1].options.env, environment);
  await manager.stop();
  assert.equal(manager.process, null);
});
test('only actually ready providers receive executable paths', () => {
  const states = mergeEngineStates({ browsers: [
    { name: 'cloakbrowser', ready: true, platform_supported: true, installed: '145', path: '/verified/Chromium' },
    { name: 'camoufox', ready: false, platform_supported: true, expected: '135', path: '/incomplete/firefox' },
  ] });
  assert.equal(states.camoufox.version, null);
  assert.equal(states.camoufox.binaryPath, null);
  const cfg = sidecarConfig('/private/envara', 19234, states);
  assert.equal(cfg.runtimes.cloakbrowser.binary_path, '/verified/Chromium');
  assert.equal(cfg.runtimes.camoufox.enabled, false);
});
test('macOS downloads inherit the active system proxy without changing preferences', () => {
  assert.deepEqual(macSystemProxyEnvironment('SOCKSEnable : 1\nSOCKSProxy : 127.0.0.1\nSOCKSPort : 7897\n'), { HTTP_PROXY: 'socks5://127.0.0.1:7897', HTTPS_PROXY: 'socks5://127.0.0.1:7897' });
  assert.deepEqual(macSystemProxyEnvironment('SOCKSEnable : 0\nSOCKSProxy : 127.0.0.1\nSOCKSPort : 7897\n'), {});
  assert.deepEqual(macSystemProxyEnvironment('HTTPEnable : 1\nHTTPProxy : invalid/host\nHTTPPort : 8080\n'), {});
});
