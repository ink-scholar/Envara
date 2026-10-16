import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { LocalApplicationCatalog, localApplicationRoots } from '../electron/local-application-catalog.mjs';
import { inspectLocalApplication } from '../electron/application-service.mjs';

async function fixture(t) {
  const temporary = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-catalog-')));
  t.after(() => rm(temporary, { recursive: true, force: true }));
  const system = path.join(temporary, 'Applications'), user = path.join(temporary, 'UserApplications');
  await mkdir(system); await mkdir(user);
  return { temporary, system, user, catalog: options => new LocalApplicationCatalog({ platform: 'darwin', roots: [system, user], ...options }) };
}
async function bundle(root, filename, { identity = 'io.envara.fixture', name = filename.replace(/\.app$/, ''), executable = 'fixture', metadata } = {}) {
  const directory = path.join(root, filename); await mkdir(path.join(directory, 'Contents/MacOS'), { recursive: true });
  await writeFile(path.join(directory, 'Contents/Info.plist'), metadata ?? `<plist><dict><key>CFBundleIdentifier</key><string>${identity}</string><key>CFBundleDisplayName</key><string>${name}</string><key>CFBundleExecutable</key><string>${executable}</string></dict></plist>`);
  const command = path.join(directory, 'Contents/MacOS', executable);
  await writeFile(command, '#!/bin/sh\nexit 99\n'); await chmod(command, 0o700);
  return directory;
}

test('Mac discovery includes shallow application folders, deduplicates identities and returns only safe metadata', async t => {
  const f = await fixture(t), alpha = await bundle(f.system, 'Alpha.app', { identity: 'io.envara.alpha', name: 'Alpha Workspace' });
  await bundle(f.user, 'Duplicate.app', { identity: 'io.envara.alpha' });
  await bundle(path.join(f.system, 'Utilities'), 'Beta.app', { identity: 'io.envara.beta', name: '境舱工具' });
  await bundle(path.join(alpha, 'Contents'), 'Internal.app', { identity: 'io.envara.internal' });
  const output = await f.catalog().list();
  assert.equal(output.available, true); assert.equal(output.scanComplete, true); assert.equal(output.truncated, false);
  assert.equal(output.applications.length, 2); assert.equal(output.applications[0].path, alpha);
  assert.deepEqual(Object.keys(output.applications[0]).sort(), ['compatibility', 'executablePath', 'identity', 'name', 'path']);
  assert.deepEqual(output.applications[0].compatibility, { supported: false, adapter: 'unsupported', reasonCode: 'APPLICATION_ADAPTER_UNSUPPORTED', dataScope: 'unavailable', verification: 'pending' });
  assert.equal(output.applications.some(item => item.identity === 'bundle:io.envara.internal'), false);
  assert.equal(await readFile(path.join(alpha, 'Contents/MacOS/fixture'), 'utf8'), '#!/bin/sh\nexit 99\n');
});

test('incomplete bundles, external metadata/executables and symlink directory escapes are omitted', async t => {
  const f = await fixture(t), outside = await bundle(path.join(f.temporary, 'outside'), 'External.app', { identity: 'io.envara.external' });
  await bundle(f.system, 'Good.app', { identity: 'io.envara.good' });
  await symlink(outside, path.join(f.system, 'Alias.app'));
  await symlink(path.dirname(outside), path.join(f.system, 'EscapedFolder'));
  const escaped = await bundle(f.system, 'Escaped.app');
  await rm(path.join(escaped, 'Contents/MacOS/fixture'));
  await symlink(process.execPath, path.join(escaped, 'Contents/MacOS/fixture'));
  const metadata = await bundle(f.system, 'Metadata.app');
  await rm(path.join(metadata, 'Contents/Info.plist'));
  await symlink(path.join(outside, 'Contents/Info.plist'), path.join(metadata, 'Contents/Info.plist'));
  const missing = await bundle(f.system, 'Missing.app'); await rm(path.join(missing, 'Contents/MacOS/fixture'));
  await bundle(f.system, 'Invalid.app', { metadata: '<plist><dict><key>CFBundleExecutable</key><string>../outside</string></dict></plist>' });
  await bundle(f.system, 'Oversize.app', { metadata: 'x'.repeat(1024 * 1024 + 1) });
  const result = await f.catalog().list();
  assert.deepEqual(result.applications.map(item => item.name), ['Good']);
  assert.equal(result.scanComplete, true);
});

test('search, response limits and defensive copies do not rescan or alter the cached inventory', async t => {
  const f = await fixture(t); await bundle(f.system, 'Alpha.app', { identity: 'io.envara.alpha' });
  await bundle(f.system, 'Beta.app', { identity: 'io.envara.beta' });
  let inspections = 0;
  const catalog = f.catalog({ inspectApplication: async (...args) => { inspections++; return inspectLocalApplication(...args); } });
  const [first, second] = await Promise.all([catalog.list({ limit: 1 }), catalog.list({ query: 'ＡＬＰＨＡ' })]);
  assert.equal(inspections, 2); assert.equal(first.truncated, true); assert.equal(second.truncated, false);
  assert.equal(second.applications[0].name, 'Alpha'); second.applications[0].name = 'Changed';
  second.applications[0].compatibility.supported = true;
  assert.equal((await catalog.list({ query: 'alpha.app' })).applications[0].name, 'Alpha');
  assert.equal((await catalog.list({ query: 'alpha.app' })).applications[0].compatibility.supported, false);
  assert.deepEqual((await catalog.list({ query: 'not installed' })).applications, []);
});

test('catalog attaches metadata eligibility without codesign or changing application identity', async t => {
  const f = await fixture(t), target = await bundle(f.system, 'Candidate.app', { identity: 'io.envara.candidate' });
  const calls = [];
  const catalog = f.catalog({ inspectCompatibility: async (descriptor, options) => {
    calls.push({ descriptor, options });
    return { supported: true, adapter: 'chromium-front', reasonCode: null, dataScope: 'environment', verification: 'pending', privateDiagnostic: 'not exposed' };
  } });
  const output = await catalog.list();
  assert.equal(calls.length, 1); assert.equal(calls[0].descriptor.path, target);
  assert.deepEqual(calls[0].options, { platform: 'darwin', verifySignature: false });
  assert.equal(output.applications[0].identity, 'bundle:io.envara.candidate');
  assert.deepEqual(output.applications[0].compatibility, { supported: true, adapter: 'chromium-front', reasonCode: null, dataScope: 'environment', verification: 'pending' });
});

test('budget exhaustion is explicit and nesting is bounded without entering bundles', async t => {
  const f = await fixture(t); await bundle(f.system, 'First.app', { identity: 'io.envara.first' });
  await bundle(f.system, 'Second.app', { identity: 'io.envara.second' });
  await bundle(path.join(f.system, 'one/two/three'), 'TooDeep.app', { identity: 'io.envara.deep' });
  const bounded = await f.catalog({ maxCandidates: 1 }).list();
  assert.equal(bounded.applications.length, 1); assert.equal(bounded.scanComplete, false); assert.equal(bounded.truncated, true);
  const directories = await f.catalog({ maxDirectories: 1 }).list();
  assert.equal(directories.applications.length, 2); assert.equal(directories.scanComplete, false);
  assert.equal((await f.catalog().list()).applications.some(item => item.identity === 'bundle:io.envara.deep'), false);
});

test('missing roots are normal, unsafe root aliases and inaccessible scan results stay incomplete', async t => {
  const f = await fixture(t); await bundle(f.system, 'Good.app');
  const missing = new LocalApplicationCatalog({ platform: 'darwin', roots: [path.join(f.temporary, 'missing')] });
  assert.deepEqual(await missing.list(), { applications: [], platform: 'darwin', available: true, scanComplete: true, truncated: false });
  const alias = path.join(f.temporary, 'alias'); await symlink(f.system, alias);
  const unsafe = new LocalApplicationCatalog({ platform: 'darwin', roots: [alias] });
  assert.equal((await unsafe.list()).scanComplete, false); assert.equal((await unsafe.list()).applications.length, 0);
});

test('Windows source discovery inspects bounded exe installation roots without accepting shortcuts or symlinks', async t => {
  const f = await fixture(t), install = path.join(f.system, 'Vendor/Product'); await mkdir(install, { recursive: true });
  const exe = path.join(install, 'Workspace.exe'); await writeFile(exe, 'owned inert fixture; never run');
  await writeFile(path.join(install, 'shortcut.lnk'), 'not followed'); await writeFile(path.join(install, 'config.json'), '{}');
  await symlink(exe, path.join(f.system, 'Alias.exe'));
  const result = await new LocalApplicationCatalog({ platform: 'win32', roots: [f.system] }).list({ query: 'workspace' });
  assert.equal(result.applications.length, 1); assert.equal(result.applications[0].path, exe);
  assert.match(result.applications[0].identity, /^path:[a-f0-9]{64}$/); assert.equal(result.scanComplete, true);
});

test('unsupported platforms and invalid renderer queries cannot expand filesystem scope', async t => {
  assert.deepEqual(await new LocalApplicationCatalog({ platform: 'unsupported', roots: [] }).list(),
    { applications: [], platform: 'unsupported', available: false, scanComplete: true, truncated: false });
  const f = await fixture(t), catalog = f.catalog();
  for (const value of [{ root: f.temporary }, { query: 'bad\nquery' }, { query: 'x'.repeat(257) }, { query: 1 }, { limit: true }, { limit: 0 }, { limit: 501 }, [], null]) {
    await assert.rejects(catalog.list(value), { code: 'APPLICATION_CATALOG_INVALID_QUERY' });
  }
  assert.deepEqual(localApplicationRoots({ platform: 'darwin', home: '/Users/fixture' }), ['/Applications', '/Users/fixture/Applications']);
  assert.deepEqual(localApplicationRoots({ platform: 'linux' }), []);
});

test('browser preview returns an unavailable inventory rather than inventing installed apps', async t => {
  const previousWindow = globalThis.window, previousStorage = globalThis.localStorage;
  globalThis.window = {}; globalThis.localStorage = { getItem: () => null, setItem: () => {} };
  t.after(() => {
    if (previousWindow === undefined) delete globalThis.window; else globalThis.window = previousWindow;
    if (previousStorage === undefined) delete globalThis.localStorage; else globalThis.localStorage = previousStorage;
  });
  const { api } = await import('../src/client.js?application-catalog-fixture');
  assert.equal(api.isDesktop, false);
  assert.deepEqual(await api.call('listLocalApplications', { query: 'Notion' }),
    { applications: [], platform: 'preview', available: false, scanComplete: true, truncated: false });
});
