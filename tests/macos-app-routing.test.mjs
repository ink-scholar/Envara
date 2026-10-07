import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import fs from 'node:fs/promises';
import os from 'node:os';
import { randomUUID } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { signingOptions, outputDirectory, cleanSigningArtifacts } from '../native/macos-app-routing/build-support.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const output = path.join(root, 'build/app-routing/macos');
const helper = path.join(output, 'EnvaraAppRouting.app/Contents/MacOS/EnvaraAppRoutingHelper');
const manifest = path.join(output, 'manifest.json');
const compiledUnsigned = process.platform === 'darwin' && existsSync(helper) && existsSync(manifest) && JSON.parse(readFileSync(manifest, 'utf8')).signed === false;

test('macOS signing requires explicit compatible credentials and isolates local development output', () => {
  assert.equal(signingOptions([], {}).mode, 'unsigned');
  const credentials = { ENVARA_MAC_SIGN_IDENTITY: 'Apple Development: Unit Test', ENVARA_MAC_HOST_PROFILE: '/fixture/host', ENVARA_MAC_EXTENSION_PROFILE: '/fixture/provider' };
  assert.equal(signingOptions(['--development-sign'], credentials).mode, 'development');
  assert.equal(signingOptions([], { ...credentials, ENVARA_MAC_SIGN_MODE: 'development' }).mode, 'development');
  assert.throws(() => signingOptions(['--sign'], credentials));
  assert.throws(() => signingOptions(['--development-sign'], {}));
  assert.throws(() => signingOptions(['--development-sign', '--sign'], credentials));
  assert.throws(() => signingOptions(['--sign'], { ...credentials, ENVARA_MAC_SIGN_MODE: 'development' }));
  assert.throws(() => signingOptions([], { ENVARA_MAC_SIGN_MODE: 'personal-team' }));
  assert.notEqual(outputDirectory(root, 'development'), outputDirectory(root, 'unsigned'));
  assert.equal(outputDirectory(root, 'developer-id'), outputDirectory(root, 'unsigned'));
  assert.ok(!outputDirectory(root, 'development').startsWith(path.join(root, 'build/app-routing') + path.sep));
});

test('unsigned rebuild removes host and provider profiles, signatures and prior acceptance', async () => {
  const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'envara-signature-cleanup-'));
  try {
    const host = path.join(temporary, 'Host.app'), provider = path.join(host, 'Contents/Library/SystemExtensions/Provider.systemextension');
    const artifacts = ['Contents/embedded.provisionprofile', 'Contents/_CodeSignature/CodeResources', '_CodeSignature/CodeResources',
      'Contents/CodeResources', 'Contents/Resources/routing-acceptance.plist'];
    for (const bundle of [host, provider]) {
      for (const relative of artifacts) {
        const filename = path.join(bundle, relative);
        await fs.mkdir(path.dirname(filename), { recursive: true }); await fs.writeFile(filename, 'unit fixture');
      }
      await fs.mkdir(path.join(bundle, 'Contents/MacOS'), { recursive: true });
      await fs.writeFile(path.join(bundle, 'Contents/MacOS/keep'), 'owned executable fixture');
    }
    await cleanSigningArtifacts(host, provider);
    for (const bundle of [host, provider]) {
      for (const relative of artifacts) assert.equal(existsSync(path.join(bundle, relative)), false);
      assert.equal(existsSync(path.join(bundle, 'Contents/MacOS/keep')), true);
    }
    await cleanSigningArtifacts(host, provider);
  } finally { await fs.rm(temporary, { recursive: true, force: true }); }
});

test('compiled unsigned macOS helper refuses protected app launch and keeps private payload out of diagnostics', { skip: !compiledUnsigned }, () => {
  const username = randomUUID(), password = randomUUID();
  const call = (method, params = {}) => {
    const output = execFileSync(helper, ['--rpc'], {
      input: JSON.stringify({ protocol: 'envara.application-routing', version: 1, id: 'native-gate-test', method, params }),
      encoding: 'utf8', timeout: 5000, env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin' },
    });
    assert.ok(!output.includes(username)); assert.ok(!output.includes(password));
    const response = JSON.parse(output);
    assert.equal(response.protocol, 'envara.application-routing'); assert.equal(response.version, 1); assert.equal(response.id, 'native-gate-test');
    return response;
  };
  const state = call('status').result;
  assert.equal(state.ready, false); assert.equal(state.authorized, false); assert.equal(state.verification.passed, false);
  for (const method of ['prepareRoute', 'launch']) {
    const response = call(method, { route: { username, password }, routeId: randomUUID() });
    assert.equal(response.error?.code, 'notReady'); assert.equal(response.result, undefined);
  }
});
