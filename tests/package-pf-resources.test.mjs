import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, readFile, rm, chmod } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { inspectPFRoutingResources } from '../scripts/verify-package-resources.mjs';
import { PF_INSTALLATION_SCHEMA, PF_MANIFEST_FILES } from '../native/macos-pf-routing/controller.mjs';
import { driverArtifacts, NODE_VERSION } from '../scripts/prepare-playwright-driver.mjs';
import { PROXY_CORE_VERSION, PROXY_CORE_COMMIT, proxyCoreArtifacts } from '../scripts/prepare-proxy-core.mjs';
import { PF_RUNTIME_MODULE_FILES, PF_BUILD_DEPENDENCY_INPUTS } from '../scripts/build-macos-pf-routing.mjs';

// These are inert byte fixtures, never executed or presented as verified builds.
const macHeader = () => {
  const bytes = Buffer.alloc(64); bytes.writeUInt32LE(0xfeedfacf); bytes.writeUInt32LE(0x0100000c, 4); return bytes;
};
const fixtureNames = ['Entry.swift', 'FixtureRuntime.swift', 'FixtureProbe.swift', 'FixtureProtocol.swift', 'ProcessIdentity.swift'];
const upgradeInputs = ['installer-upgrade-f8.h', 'known-installations/f8.manifest.json',
  'installer-upgrade-e940.h', 'known-installations/e940.manifest.json',
  'installer-upgrade-518.h', 'known-installations/518.manifest.json',
  'installer-upgrade-2a7.h', 'known-installations/2a7.manifest.json',
  'installer-upgrade-832.h', 'known-installations/832.manifest.json',
  'installer-upgrade-ff9.h', 'known-installations/ff9.manifest.json',
  'installer-upgrade-6f8.h', 'known-installations/6f8.manifest.json',
  'installer-upgrade-199.h', 'known-installations/199.manifest.json',
  'installer-upgrade-46a.h', 'known-installations/46a.manifest.json',
  'installer-upgrade-c37.h', 'known-installations/c37.manifest.json',
  'installer-upgrade-f99.h', 'known-installations/f99.manifest.json',
  'installer-upgrade-05d6.h', 'known-installations/05d6.manifest.json',
  'installer-upgrade-14b87.h', 'known-installations/14b87.manifest.json',
  'installer-upgrade-dbcf.h', 'known-installations/dbcf.manifest.json',
  'installer-upgrade-43b.h', 'known-installations/43b.manifest.json',
  'installer-upgrade-acfc.h', 'known-installations/acfc.manifest.json',
  'installer-upgrade-c34.h', 'known-installations/c34.manifest.json',
  'installer-upgrade-4b9f85.h', 'known-installations/4b9f85.manifest.json',
  'installer-upgrade-43392e.h', 'known-installations/43392e.manifest.json', 'installer-upgrade-03245359.h', 'known-installations/03245359.manifest.json',
  'installer-upgrade-2059a0.h', 'known-installations/2059a0.manifest.json',
  'installer-upgrade-127e83.h', 'known-installations/127e83.manifest.json',
  'installer-upgrade-010117.h', 'known-installations/010117.manifest.json', 'installer-upgrade-9b51cf.h', 'known-installations/9b51cf.manifest.json', 'installer-upgrade-91b62a.h', 'known-installations/91b62a.manifest.json', 'installer-upgrade-7c91a1.h', 'known-installations/7c91a1.manifest.json', 'installer-upgrade-af79b1.h', 'known-installations/af79b1.manifest.json', 'installer-upgrade-dceba9.h', 'known-installations/dceba9.manifest.json', 'installer-upgrade-fa70a2.h', 'known-installations/fa70a2.manifest.json', 'installer-upgrade-32811e.h', 'known-installations/32811e.manifest.json', 'installer-upgrade-22a6f3.h', 'known-installations/22a6f3.manifest.json',
  'installer-upgrade-f0b99f.h', 'known-installations/f0b99f.manifest.json',
  'installer-upgrade-f39101.h', 'known-installations/f39101.manifest.json',
  'installer-upgrade-a8bd00.h', 'known-installations/a8bd00.manifest.json',
  'installer-upgrade-da6e7c.h', 'known-installations/da6e7c.manifest.json'];
const linkedAppFilterInputs = [
  'pf-filter-command.c', 'pf-filter-command.h',
  'pf-filter-transaction.c', 'pf-filter-transaction.h',
  'app-command.c', 'app-command.h',
  'app-control.c', 'app-control.h',
  'app-ticket.c', 'app-ticket.h',
  'app-registry.c', 'app-registry.h',
  'app-supervisor.c', 'app-supervisor.h',
  'gui-launch.m', 'gui-launch.h',
  'launch-guardian.c', 'launch-guardian.h',
  'pf-production-filter.c', 'pf-production-filter.h',
  'app-native-factory.m', 'app-native-factory.h',
  'journal-retirement.c', 'journal-retirement.h',
  'app-scope-proof.c', 'app-scope-proof.h',
  'app-transport.c', 'app-transport.h', 'transport-session.h',
  'notion-launch.m', 'notion-launch.h'
];
async function fixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'envara-pf-resource-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const resourceRoot = path.join(root, 'payload'); await mkdir(resourceRoot);
  const binaries = new Set(['node', 'mihomo', 'envara-pf-native', 'fixtures/EnvaraRoutingAcceptanceFixture']);
  const files = {};
  for (const [name, executable] of Object.entries(PF_MANIFEST_FILES)) {
    const filename = path.join(resourceRoot, name); await mkdir(path.dirname(filename), { recursive: true });
    const bytes = binaries.has(name) ? macHeader() : Buffer.from(`inert resource fixture: ${name}\n`);
    await writeFile(filename, bytes, { mode: executable ? 0o755 : 0o644 });
    files[name] = createHash('sha256').update(bytes).digest('hex');
  }
  for (const name of PF_RUNTIME_MODULE_FILES) {
    const filename = path.join(root, 'native/macos-pf-routing', name);
    await mkdir(path.dirname(filename), { recursive: true });
    await writeFile(filename, await readFile(path.join(resourceRoot, name)));
  }
  await writeFile(path.join(resourceRoot, 'EnvaraPFInstall'), macHeader(), { mode: 0o755 });
  const nativeSourceFiles = {};
  const nativeInputs = [
    ...['Makefile', 'native.h', 'main.c', 'launcher.c', 'tunnel.c', 'transport.c', 'authorize-install.c',
      ...upgradeInputs, 'pf-hook.c', 'pf-hook.h', 'pf-hook-abi.h', 'pf-run-ledger.c', 'pf-run-ledger.h', ...linkedAppFilterInputs].map(name => `native/macos-pf-routing/${name}`),
    'scripts/build-macos-pf-routing.mjs', ...fixtureNames.map(name => `native/macos-pf-routing/fixture/${name}`),
  ];
  for (const name of nativeInputs) {
    const filename = path.join(root, name), bytes = Buffer.from(`inert source fixture: ${name}\n`);
    await mkdir(path.dirname(filename), { recursive: true }); await writeFile(filename, bytes);
    nativeSourceFiles[name] = createHash('sha256').update(bytes).digest('hex');
  }
  const node = driverArtifacts('darwin', 'arm64'), core = proxyCoreArtifacts('darwin', 'arm64');
  const manifest = { schema: PF_INSTALLATION_SCHEMA, component: 'envara-pf-routing', version: '1', backend: 'pf-utun',
    platform: 'darwin', arch: 'arm64', ready: false, nativeAcceptance: false, files, nativeSourceFiles,
    node: { version: NODE_VERSION, archiveSha256: node.nodeArchiveSha256, source: node.nodeUrl },
    mihomo: { version: PROXY_CORE_VERSION, commit: PROXY_CORE_COMMIT, sourceArchiveSha256: core.sourceSha256 } };
  const save = () => writeFile(path.join(resourceRoot, 'manifest.json'), `${JSON.stringify(manifest)}\n`);
  await save();
  return { sourceRoot: root, resourceRoot, manifest, save, inspect: () => inspectPFRoutingResources({ resourceRoot, arch: 'arm64', sourceRoot: root }) };
}
const skip = process.platform === 'win32';

test('PF build pins the complete eight-module runtime including the Notion front and pure verifier', () => {
  assert.equal(Object.keys(PF_MANIFEST_FILES).length, 18);
  assert.equal(PF_MANIFEST_FILES['stateless-verifier.mjs'], false);
  assert.deepEqual(PF_RUNTIME_MODULE_FILES, Object.keys(PF_MANIFEST_FILES).filter(name => name.endsWith('.mjs')));
  assert.equal(Object.isFrozen(PF_RUNTIME_MODULE_FILES), true);
  assert.deepEqual(PF_BUILD_DEPENDENCY_INPUTS, ['scripts/prepare-playwright-driver.mjs', 'scripts/prepare-proxy-core.mjs']);
  assert.equal(Object.isFrozen(PF_BUILD_DEPENDENCY_INPUTS), true);
});

test('PF resources cannot advertise readiness or native acceptance', { skip }, async t => {
  const value = await fixture(t);
  value.manifest.ready = true; await value.save();
  await assert.rejects(value.inspect(), /cannot advertise production readiness/);
  value.manifest.ready = false; value.manifest.nativeAcceptance = true; await value.save();
  await assert.rejects(value.inspect(), /not native routing acceptance/);
});

test('PF resources require all manifest files', { skip }, async t => {
  const value = await fixture(t);
  await rm(path.join(value.resourceRoot, 'node-LICENSE'));
  await assert.rejects(value.inspect(), /resource inventory differs/);
});

test('PF resources refuse an omitted verifier manifest entry or runtime file', { skip }, async t => {
  const value = await fixture(t), digest = value.manifest.files['stateless-verifier.mjs'];
  delete value.manifest.files['stateless-verifier.mjs']; await value.save();
  await assert.rejects(value.inspect(), /PF manifest file contract differs/);
  value.manifest.files['stateless-verifier.mjs'] = digest; await value.save();
  await rm(path.join(value.resourceRoot, 'stateless-verifier.mjs'));
  await assert.rejects(value.inspect(), /PF resource inventory differs/);
});

test('PF verifier runtime bytes and non-executable mode are fixed', { skip }, async t => {
  const value = await fixture(t), filename = path.join(value.resourceRoot, 'stateless-verifier.mjs'), original = await readFile(filename);
  await writeFile(filename, 'changed inert verifier fixture');
  await assert.rejects(value.inspect(), /stateless-verifier.mjs differs from PF manifest/);
  await writeFile(filename, original); await chmod(filename, 0o755);
  await assert.rejects(value.inspect(), /stateless-verifier.mjs executable permission differs/);
});

test('PF verifier cannot be replaced by forging a matching payload manifest', { skip }, async t => {
  const value = await fixture(t), bytes = Buffer.from('changed inert verifier and manifest fixture');
  await writeFile(path.join(value.resourceRoot, 'stateless-verifier.mjs'), bytes);
  value.manifest.files['stateless-verifier.mjs'] = createHash('sha256').update(bytes).digest('hex'); await value.save();
  await assert.rejects(value.inspect(), /stateless-verifier.mjs differs from production source/);
});

test('PF verifier production source must exist and match pinned runtime bytes', { skip }, async t => {
  const value = await fixture(t), filename = path.join(value.sourceRoot, 'native/macos-pf-routing/stateless-verifier.mjs');
  await writeFile(filename, 'changed inert production verifier');
  await assert.rejects(value.inspect(), /stateless-verifier.mjs differs from production source/);
  await rm(filename);
  await assert.rejects(value.inspect(), error => error.code === 'ENOENT' && error.path === filename);
});

test('PF resources reject unexpected payloads', { skip }, async t => {
  const value = await fixture(t);
  await writeFile(path.join(value.resourceRoot, 'unexpected.mjs'), 'unexpected fixture');
  await assert.rejects(value.inspect(), /resource inventory differs/);
});

test('PF resources detect tampering even when the inventory is complete', { skip }, async t => {
  const value = await fixture(t);
  await writeFile(path.join(value.resourceRoot, 'controller.mjs'), 'changed owned fixture');
  await assert.rejects(value.inspect(), /controller.mjs differs from PF manifest/);
});

test('PF resources reject a non-executable pinned runtime', { skip }, async t => {
  const value = await fixture(t);
  await chmod(path.join(value.resourceRoot, 'node'), 0o644);
  await assert.rejects(value.inspect(), /node executable permission differs/);
});

test('PF installer binary target is checked outside the self-referential manifest', { skip }, async t => {
  const value = await fixture(t);
  const bytes = await readFile(path.join(value.resourceRoot, 'EnvaraPFInstall'));
  bytes.writeUInt32LE(0x01000007, 4);
  await writeFile(path.join(value.resourceRoot, 'EnvaraPFInstall'), bytes);
  await assert.rejects(value.inspect(), /EnvaraPFInstall binary target differs/);
});

test('PF native compilation inputs must have a complete build-time source map', { skip }, async t => {
  const value = await fixture(t), sourceFiles = value.manifest.nativeSourceFiles;
  delete value.manifest.nativeSourceFiles; await value.save();
  await assert.rejects(value.inspect(), /must record native source SHA-256/);
  value.manifest.nativeSourceFiles = { ...sourceFiles };
  delete value.manifest.nativeSourceFiles['native/macos-pf-routing/authorize-install.c']; await value.save();
  await assert.rejects(value.inspect(), /native source inventory differs/);
  value.manifest.nativeSourceFiles = { ...sourceFiles, 'native/macos-pf-routing/obsolete.c': '0'.repeat(64) }; await value.save();
  await assert.rejects(value.inspect(), /native source inventory differs/);
});

test('PF source updates invalidate an otherwise complete native payload', { skip }, async t => {
  const value = await fixture(t);
  await writeFile(path.join(value.sourceRoot, 'native/macos-pf-routing/main.c'), 'changed native source fixture');
  await assert.rejects(value.inspect(), /main.c differs from build-time native source/);
});

test('PF fixed upgrade and linked FILTER/app inputs must be complete and byte-identical to the source build', { skip }, async t => {
  const value = await fixture(t), original = { ...value.manifest.nativeSourceFiles };
  for (const name of [...upgradeInputs, 'pf-hook.c', 'pf-hook.h', 'pf-hook-abi.h', 'pf-run-ledger.c', 'pf-run-ledger.h', ...linkedAppFilterInputs]) {
    value.manifest.nativeSourceFiles = { ...original };
    delete value.manifest.nativeSourceFiles[`native/macos-pf-routing/${name}`]; await value.save();
    await assert.rejects(value.inspect(), /native source inventory differs/);
  }
  value.manifest.nativeSourceFiles = original; await value.save();
  for (const name of [...upgradeInputs, ...linkedAppFilterInputs]) {
    const filename = path.join(value.sourceRoot, 'native/macos-pf-routing', name), bytes = await readFile(filename);
    await writeFile(filename, 'changed pinned native input');
    await assert.rejects(value.inspect(), error => {
      assert.equal(error.message.split('\n')[0], `native/macos-pf-routing/${name} differs from build-time native source`); return true;
    });
    await writeFile(filename, bytes);
  }
});

test('PF e940 upgrade inputs must exist in the source checkout', { skip }, async t => {
  const value = await fixture(t);
  for (const name of ['installer-upgrade-e940.h', 'known-installations/e940.manifest.json']) {
    const filename = path.join(value.sourceRoot, 'native/macos-pf-routing', name), bytes = await readFile(filename);
    await rm(filename);
    await assert.rejects(value.inspect(), error => {
      assert.equal(error.code, 'ENOENT'); assert.equal(error.path, filename); return true;
    });
    await writeFile(filename, bytes);
  }
});

test('PF reviewed upgrade inputs must exist in the source checkout', { skip }, async t => {
  const value = await fixture(t);
  for (const name of upgradeInputs.slice(4)) {
    const filename = path.join(value.sourceRoot, 'native/macos-pf-routing', name), bytes = await readFile(filename);
    await rm(filename);
    await assert.rejects(value.inspect(), error => {
      assert.equal(error.code, 'ENOENT'); assert.equal(error.path, filename); return true;
    });
    await writeFile(filename, bytes);
  }
});

test('PF acceptance fixture inputs must match the current dedicated source inventory', { skip }, async t => {
  const value = await fixture(t);
  await writeFile(path.join(value.sourceRoot, 'native/macos-pf-routing/fixture/Additional.swift'), 'additional inert source fixture');
  await assert.rejects(value.inspect(), /native source inventory differs/);
});

test('a self-authored complete manifest cannot replace the pinned source build', { skip }, async t => {
  const value = await fixture(t);
  assert.equal(Object.keys(value.manifest.nativeSourceFiles).length, 119);
  await assert.rejects(value.inspect(), { code: 'ENOENT' });
});
