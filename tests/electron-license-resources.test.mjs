import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile, writeFile, rm, symlink } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { ELECTRON_LICENSE_RESOURCES, inspectElectronLicenseResources } from '../scripts/electron-license-resources.mjs';

async function fixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'envara-electron-license-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const sourceRoot = path.join(root, 'source'), resourceRoot = path.join(root, 'resources');
  const config = { devDependencies: { electron: '44.6.0' },
    build: { extraResources: ELECTRON_LICENSE_RESOURCES.map(entry => ({ ...entry })) } };
  const put = async (filename, bytes) => { await mkdir(path.dirname(filename), { recursive: true }); await writeFile(filename, bytes); };
  const save = () => put(path.join(sourceRoot, 'package.json'), JSON.stringify(config));
  await save();
  await put(path.join(sourceRoot, 'node_modules/electron/package.json'), JSON.stringify({ name: 'electron', version: '44.6.0' }));
  await put(path.join(sourceRoot, 'node_modules/electron/dist/version'), '44.6.0\n');
  for (const entry of ELECTRON_LICENSE_RESOURCES) {
    // Deliberately inert fixture text; no Electron executable or real bundle.
    const bytes = Buffer.from(`Inert complete notice fixture: ${entry.to}\n`);
    await put(path.join(sourceRoot, entry.from), bytes); await put(path.join(resourceRoot, entry.to), bytes);
  }
  return { root, sourceRoot, resourceRoot, config, save, inspect: () => inspectElectronLicenseResources({ sourceRoot, resourceRoot }) };
}

test('Electron license verification compares both complete ordinary files and reports the installed version', async t => {
  const value = await fixture(t), report = await value.inspect();
  assert.equal(report.verified, true); assert.equal(report.electronVersion, '44.6.0');
  assert.equal(report.completeBytesCompared, true); assert.equal(report.regularFilesChecked, true);
  assert.equal(report.files.length, 2);
  for (const entry of report.files) {
    const bytes = await readFile(path.join(value.sourceRoot, entry.from));
    assert.equal(entry.size, bytes.length);
    assert.equal(entry.sha256, createHash('sha256').update(bytes).digest('hex'));
  }
});

test('Electron licenses remain required when a common mapping is omitted or moved into a platform section', async t => {
  for (const entry of ELECTRON_LICENSE_RESOURCES) {
    const value = await fixture(t);
    value.config.build.extraResources = value.config.build.extraResources.filter(item => item.to !== entry.to);
    value.config.build.mac = { extraResources: [{ ...entry }] };
    await value.save();
    await assert.rejects(value.inspect(), /Electron license mapping must occur exactly once/);
  }
});

test('Electron license mappings reject replacement sources, duplicates and content filters', async t => {
  for (const mutation of [
    config => { config.build.extraResources[0].from = 'other/LICENSE'; },
    config => { config.build.extraResources.push({ ...config.build.extraResources[0] }); },
    config => { config.build.extraResources[0].filter = ['!**/*']; },
  ]) {
    const value = await fixture(t); mutation(value.config); await value.save();
    await assert.rejects(value.inspect(), /Electron license (?:source mapping differs|mapping must)/);
  }
});

test('Electron license verification refuses each missing source or packaged notice', async t => {
  for (const entry of ELECTRON_LICENSE_RESOURCES) for (const side of ['source', 'packaged']) {
    const value = await fixture(t);
    const filename = side === 'source' ? path.join(value.sourceRoot, entry.from) : path.join(value.resourceRoot, entry.to);
    await rm(filename);
    await assert.rejects(value.inspect(), error => error.code === 'ENOENT' && error.path === filename);
  }
});

test('Electron license verification refuses same-length changes and truncated bytes on either side', async t => {
  for (const entry of ELECTRON_LICENSE_RESOURCES) for (const side of ['source', 'packaged']) for (const truncate of [false, true]) {
    const value = await fixture(t);
    const filename = side === 'source' ? path.join(value.sourceRoot, entry.from) : path.join(value.resourceRoot, entry.to);
    const original = await readFile(filename), changed = Buffer.from(original);
    changed[0] ^= 1;
    await writeFile(filename, truncate ? original.subarray(0, original.length - 1) : changed);
    await assert.rejects(value.inspect(), /Electron license bytes differ/);
  }
});

test('Electron license verification rejects matching symlink substitutions on either side', { skip: process.platform === 'win32' }, async t => {
  for (const entry of ELECTRON_LICENSE_RESOURCES) for (const side of ['source', 'packaged']) {
    const value = await fixture(t);
    const filename = side === 'source' ? path.join(value.sourceRoot, entry.from) : path.join(value.resourceRoot, entry.to);
    const replacement = path.join(value.root, 'owned-link-target');
    await writeFile(replacement, await readFile(filename)); await rm(filename); await symlink(replacement, filename);
    await assert.rejects(value.inspect(), /regular non-symlink file/);
  }
});

test('Electron license verification rejects non-files and empty matching notices', async t => {
  const directory = await fixture(t), entry = ELECTRON_LICENSE_RESOURCES[0];
  const target = path.join(directory.resourceRoot, entry.to); await rm(target); await mkdir(target);
  await assert.rejects(directory.inspect(), /regular non-symlink file/);
  const empty = await fixture(t);
  await writeFile(path.join(empty.sourceRoot, entry.from), ''); await writeFile(path.join(empty.resourceRoot, entry.to), '');
  await assert.rejects(empty.inspect(), /complete and nonempty/);
});

test('Electron license verification binds installed package and distribution versions to the exact dependency', async t => {
  const unpinned = await fixture(t); unpinned.config.devDependencies.electron = '^44.6.0'; await unpinned.save();
  await assert.rejects(unpinned.inspect(), /must use an exact version/);
  const packageMismatch = await fixture(t);
  await writeFile(path.join(packageMismatch.sourceRoot, 'node_modules/electron/package.json'), JSON.stringify({ name: 'electron', version: '44.5.0' }));
  await assert.rejects(packageMismatch.inspect(), /Installed Electron version differs/);
  const distributionMismatch = await fixture(t);
  await writeFile(path.join(distributionMismatch.sourceRoot, 'node_modules/electron/dist/version'), '44.5.0');
  await assert.rejects(distributionMismatch.inspect(), /Electron distribution version differs/);
});
