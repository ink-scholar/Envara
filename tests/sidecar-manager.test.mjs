import test from 'node:test';
import assert from 'node:assert/strict';
import { sidecarConfig, mergeEngineStates, macSystemProxyEnvironment } from '../electron/sidecar-manager.mjs';

test('empty workspace stays loopback-only and disables browser auto downloads', () => {
  const cfg = sidecarConfig('/private/envara', 19234, {}, 'darwin');
  assert.equal(cfg.host, '127.0.0.1');
  assert.equal(cfg.allow_empty_runtime, true);
  assert.equal(Object.values(cfg.runtimes).some(runtime => runtime.enabled), false);
  assert.ok(Object.values(cfg.runtimes).every(runtime => runtime.skip_auto_update));
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
