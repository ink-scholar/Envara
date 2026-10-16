import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { copyDependencyLicenses, nativeRebuildEnvironment, verifyNativeBuildPaths } from '../scripts/prepare-native.mjs';

test('license preparation includes runtime dependency graph and safely replaces read-only previous output', async t => {
  const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'envara-license-test-'));
  t.after(() => fs.rm(temporary, { recursive: true, force: true }));
  const directory = path.join(temporary, 'licenses');
  const first = await copyDependencyLicenses(directory);
  const firstManifest = await fs.readFile(path.join(directory, 'manifest.json'), 'utf8');
  assert(first.some(item => item.name === 'node-addon-api'));
  assert(first.some(item => item.name === 'proxy-agent-negotiate' && item.notices.some(name => name.includes('supplementary'))));
  assert(first.some(item => item.name === 'node-pty' && item.notices.some(name => name.includes('Microsoft-Terminal'))));
  assert(first.some(item => item.name === '@xterm/xterm' && item.renderer));
  assert(!first.some(item => item.name === '@electron/rebuild' || item.name === 'kerberos'));
  for (const item of first) {
    for (const notice of item.notices) assert((await fs.readFile(path.join(directory, notice), 'utf8')).length > 100);
  }
  for (const filename of await fs.readdir(directory)) await fs.chmod(path.join(directory, filename), 0o444);
  await copyDependencyLicenses(directory);
  assert.equal(await fs.readFile(path.join(directory, 'manifest.json'), 'utf8'), firstManifest);
});

test('macOS rebuild maps source and header paths only in the owned child environment', async () => {
  const inherited = { CFLAGS: '-O2', CXXFLAGS: '-std=c++20', LDFLAGS: '-Wl,-dead_strip', UNRELATED: 'retained' };
  const result = await nativeRebuildEnvironment({ env: inherited, platform: 'darwin', checkoutRoot: "/temporary/source with space's", homeDirectory: '/temporary/home' });
  assert.deepEqual(inherited, { CFLAGS: '-O2', CXXFLAGS: '-std=c++20', LDFLAGS: '-Wl,-dead_strip', UNRELATED: 'retained' });
  assert.equal(result.UNRELATED, 'retained');
  for (const key of ['CFLAGS', 'CXXFLAGS']) {
    assert(result[key].startsWith(inherited[key] + ' '));
    assert(result[key].includes('-ffile-prefix-map=/temporary/home=/envara/build-home'));
    assert(result[key].includes("source with space'\"'\"'s=/envara/src"));
    assert(result[key].includes('-fdebug-prefix-map='));
    assert(result[key].includes('-fdebug-compilation-dir=/envara/src/node_modules/node-pty'));
    assert(result[key].endsWith("'-g0'"));
  }
  assert.equal(result.LDFLAGS, '-Wl,-dead_strip -Wl,-S');
});

test('non-macOS native preparation preserves compiler and linker flags', async () => {
  const env = { CFLAGS: '-g', CXXFLAGS: '/guard:cf', LDFLAGS: '-other' };
  for (const platform of ['win32', 'linux']) {
    const result = await nativeRebuildEnvironment({ env, platform });
    assert.deepEqual(result, env);
    assert.notEqual(result, env);
  }
});

test('both macOS PTY products must be free of checkout and build-user paths before reuse', async t => {
  const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'envara-native-path-test-'));
  t.after(() => fs.rm(temporary, { recursive: true, force: true }));
  const release = path.join(temporary, 'build/Release'); await fs.mkdir(release, { recursive: true });
  const options = { platform: 'darwin', checkoutRoot: '/temporary/private-checkout', homeDirectory: '/temporary/private-home' };
  for (const name of ['pty.node', 'spawn-helper']) await fs.writeFile(path.join(release, name), 'owned fixture binary');
  await verifyNativeBuildPaths(temporary, options);
  for (const name of ['pty.node', 'spawn-helper']) {
    for (const prefix of [options.checkoutRoot, options.homeDirectory, '/Users/example-builder/old-checkout', '/home/example-builder/old-checkout', '/private/var/folders/example-build', '/var/folders/example-build']) {
      await fs.writeFile(path.join(release, name), `owned fixture\0${prefix}/object.o\0`);
      await assert.rejects(verifyNativeBuildPaths(temporary, options), error => {
        assert(!error.message.includes(prefix)); return /local source or build path/.test(error.message);
      });
    }
    await fs.writeFile(path.join(release, name), 'owned fixture binary');
  }
  await fs.rm(path.join(release, 'pty.node'));
  await assert.rejects(verifyNativeBuildPaths(temporary, options), { code: 'ENOENT' });
  await verifyNativeBuildPaths(temporary, { ...options, platform: 'win32' });
});
