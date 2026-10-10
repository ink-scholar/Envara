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
import { copyProviderVerbatim, fingerprintProvider, productionIdentity, providerRecord, providerRelativePath,
  readProviderReuse, validateReceiptProvider } from '../native/macos-app-routing/provider-reuse.mjs';

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
  assert.equal(signingOptions(['--acceptance'], {}).acceptance, true);
  for (const mode of ['unsigned', 'development', 'developer-id']) {
    assert.notEqual(outputDirectory(root, mode, true), outputDirectory(root, mode));
    assert.equal(outputDirectory(root, mode, true), path.join(root, 'build/acceptance-app-routing/macos'));
  }
  assert.throws(() => signingOptions(['--reuse-provider'], {}));
  assert.throws(() => signingOptions(['--reuse-provider', '--sign'], {}));
  assert.throws(() => signingOptions(['--reuse-provider', '/one', '--reuse-provider', '/two'], {}));
  assert.throws(() => signingOptions([], { ENVARA_MAC_ACCEPTANCE_RECEIPT: '/fixture/receipt' }));
  assert.throws(() => signingOptions(['--acceptance'], { ENVARA_MAC_ACCEPTANCE_RECEIPT: '/fixture/receipt' }));
  assert.throws(() => signingOptions(['--development-sign'], { ...credentials, ENVARA_MAC_ACCEPTANCE_RECEIPT: '/fixture/receipt' }));
  assert.equal(signingOptions(['--development-sign', '--reuse-provider', '/fixture/manifest.json'], {
    ...credentials, ENVARA_MAC_ACCEPTANCE_RECEIPT: '/fixture/receipt',
  }).reuseProvider, '/fixture/manifest.json');
});

async function withProviderFixture(operation) {
  const temporary = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'envara-provider-reuse-')));
  try {
    const bundle = path.join(temporary, providerRelativePath), executable = path.join(bundle, 'Contents/MacOS/EnvaraAppProxy');
    await fs.mkdir(path.dirname(executable), { recursive: true, mode: 0o755 });
    await fs.writeFile(executable, 'ordinary non-native unit fixture bytes', { mode: 0o755 });
    await fs.mkdir(path.join(bundle, 'Contents/Resources'), { mode: 0o755 });
    await fs.writeFile(path.join(bundle, 'Contents/Info.plist'), 'unsigned unit fixture metadata', { mode: 0o644 });
    await fs.writeFile(path.join(bundle, 'Contents/Resources/keep'), 'unit resource', { mode: 0o600 });
    const fingerprint = await fingerprintProvider(bundle);
    const manifest = { version: 1, platform: 'darwin', architecture: process.arch,
      helper: 'EnvaraAppRouting.app/Contents/MacOS/EnvaraAppRoutingHelper', signed: false, signingMode: 'unsigned',
      acceptanceOnly: false, profileVerification: { verified: false }, ...productionIdentity, provider: providerRecord(fingerprint) };
    const manifestPath = path.join(temporary, 'manifest.json');
    await fs.writeFile(manifestPath, JSON.stringify(manifest));
    await operation({ temporary, bundle, executable, fingerprint, manifest, manifestPath });
  } finally { await fs.rm(temporary, { recursive: true, force: true }); }
}

test('provider reuse verifies complete manifest bytes and copies ordinary unsigned bundle unchanged', async () => {
  await withProviderFixture(async ({ temporary, bundle, fingerprint, manifestPath }) => {
    const read = await readProviderReuse(manifestPath, { mode: 'unsigned' });
    assert.equal(read.fingerprint.bundleSHA256, fingerprint.bundleSHA256);
    const copy = await copyProviderVerbatim(bundle, path.join(temporary, 'Copied.systemextension'), fingerprint);
    assert.deepEqual(copy, fingerprint);
    await assert.rejects(copyProviderVerbatim(bundle, path.join(temporary, 'Copied.systemextension'), fingerprint));
    await assert.rejects(copyProviderVerbatim(bundle, bundle, fingerprint));
  });
});

test('provider fingerprint binds resources, file permissions and directories independently of executable bytes', async () => {
  await withProviderFixture(async ({ bundle, fingerprint, manifestPath }) => {
    const resource = path.join(bundle, 'Contents/Resources/keep');
    await fs.chmod(resource, 0o644);
    const modeChange = await fingerprintProvider(bundle);
    assert.equal(modeChange.binarySHA256, fingerprint.binarySHA256);
    assert.notEqual(modeChange.bundleSHA256, fingerprint.bundleSHA256);
    await assert.rejects(readProviderReuse(manifestPath, { mode: 'unsigned' }));
    await fs.chmod(resource, 0o600);
    await fs.mkdir(path.join(bundle, 'Contents/Resources/empty'), { mode: 0o700 });
    assert.notEqual((await fingerprintProvider(bundle)).bundleSHA256, fingerprint.bundleSHA256);
    await fs.rm(path.join(bundle, 'Contents/Resources/empty'), { recursive: true });
    await fs.writeFile(resource, 'changed resource', { mode: 0o600 });
    await assert.rejects(readProviderReuse(manifestPath, { mode: 'unsigned' }));
  });
});

test('provider complete-bundle digest matches independent Swift golden vectors including UTF8 filename order', async () => {
  await withProviderFixture(async ({ bundle, executable }) => {
    for (const relative of ['', 'Contents', 'Contents/MacOS', 'Contents/Resources']) await fs.chmod(path.join(bundle, relative), 0o755);
    await fs.writeFile(executable, 'fixture-provider-v1\n');
    await fs.writeFile(path.join(bundle, 'Contents/Info.plist'), 'fixture-info');
    await fs.rm(path.join(bundle, 'Contents/Resources/keep'));
    await fs.writeFile(path.join(bundle, 'Contents/Resources/.hidden'), '', { mode: 0o644 });
    assert.equal((await fingerprintProvider(bundle)).bundleSHA256, '4580df75091102e035d5a0692750bf5caca7d673ca2b3f59627bc6825f3b7fe1');
    await fs.writeFile(path.join(bundle, 'Contents/Resources/\uE000.txt'), 'A', { mode: 0o644 });
    await fs.writeFile(path.join(bundle, 'Contents/Resources/😀.txt'), 'B', { mode: 0o644 });
    assert.equal((await fingerprintProvider(bundle)).bundleSHA256, '417011116ffce2ce61e8329f3086c2430a92f0599851fb74fb15aa0cfc2827b0');
  });
});

test('provider reuse refuses alternate identity, architecture, namespace and unsupported fingerprint claims', async () => {
  await withProviderFixture(async ({ manifest, manifestPath }) => {
    for (const change of [
      { acceptanceOnly: true }, { architecture: 'wrong-architecture' }, { providerIdentifier: 'io.envara.other' },
      { runtimeNamespace: 'owned-fixture-acceptance' }, { signingMode: 'development', signed: true },
      { provider: { ...manifest.provider, bundle: '../Escape.systemextension' } },
      { provider: { ...manifest.provider, binarySHA256: '0'.repeat(64) } },
      { provider: { ...manifest.provider, bundleSHA256: '0'.repeat(64) } },
      { provider: { ...manifest.provider, fingerprintVersion: 2 } },
    ]) {
      await fs.writeFile(manifestPath, JSON.stringify({ ...manifest, ...change }));
      await assert.rejects(readProviderReuse(manifestPath, { mode: 'unsigned' }));
    }
  });
});

test('provider reuse rejects symbolic links, hard links and ambiguous filenames', async () => {
  await withProviderFixture(async ({ temporary, bundle, executable, manifestPath }) => {
    const alias = path.join(temporary, 'alias-manifest.json');
    await fs.symlink(manifestPath, alias);
    await assert.rejects(readProviderReuse(alias, { mode: 'unsigned' }));
    const aliasBundle = path.join(temporary, 'Alias.systemextension');
    await fs.symlink(bundle, aliasBundle);
    await assert.rejects(fingerprintProvider(aliasBundle));
    const resourceAlias = path.join(bundle, 'Contents/Resources/alias');
    await fs.symlink(executable, resourceAlias);
    await assert.rejects(fingerprintProvider(bundle));
    await fs.rm(resourceAlias);
    await fs.link(executable, resourceAlias);
    await assert.rejects(fingerprintProvider(bundle));
    await fs.rm(resourceAlias);
    const control = path.join(bundle, 'Contents/Resources/line\nbreak');
    await fs.writeFile(control, 'unit fixture');
    await assert.rejects(fingerprintProvider(bundle));
  });
});

test('native receipt finalization requires complete matching provider fingerprints and every native gate', async () => {
  await withProviderFixture(async ({ fingerprint }) => {
    // Pure input-validation data, never an Apple proof or a generated native receipt.
    const receipt = { providerSHA256: fingerprint.binarySHA256, providerBundleSHA256: fingerprint.bundleSHA256,
      providerVersion: '1', version: 'unit-validator-only', osMajor: 27, passed: true,
      checks: { tcp: true, udp: true, dns: true, childProcesses: true, failClosed: true },
      testedApplications: ['io.envara.routing.fixture.one'] };
    assert.doesNotThrow(() => validateReceiptProvider(receipt, fingerprint));
    assert.throws(() => validateReceiptProvider(receipt, fingerprint, { osMajor: 26 }));
    assert.doesNotThrow(() => validateReceiptProvider(receipt, fingerprint, { osMajor: 27 }));
    for (const invalid of [undefined, { ...receipt, providerBundleSHA256: undefined },
      { ...receipt, providerSHA256: '0'.repeat(64) }, { ...receipt, providerBundleSHA256: '0'.repeat(64) },
      { ...receipt, checks: { ...receipt.checks, dns: false } }, { ...receipt, passed: false },
      { ...receipt, testedApplications: ['*'] }, { ...receipt, testedApplications: [] }]) {
      assert.throws(() => validateReceiptProvider(invalid, fingerprint));
    }
  });
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
