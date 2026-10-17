import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open } from 'node:fs/promises';
import path from 'node:path';

export const ELECTRON_LICENSE_RESOURCES = Object.freeze(['LICENSE', 'LICENSES.chromium.html'].map(name =>
  Object.freeze({ from: `node_modules/electron/dist/${name}`, to: `licenses/electron/${name}` })));

export function assertElectronLicenseMappings(build) {
  assert.ok(Array.isArray(build?.extraResources), 'Electron licenses require common extraResources mappings');
  for (const expected of ELECTRON_LICENSE_RESOURCES) {
    const entries = build.extraResources.filter(entry => entry?.to === expected.to);
    assert.equal(entries.length, 1, `Electron license mapping must occur exactly once: ${expected.to}`);
    assert.equal(entries[0].from, expected.from, `Electron license source mapping differs: ${expected.to}`);
    assert.equal(entries[0].filter, undefined, `Electron license mapping must preserve the complete file: ${expected.to}`);
  }
}

async function regularBytes(filename) {
  const entry = await lstat(filename);
  assert.ok(entry.isFile() && !entry.isSymbolicLink(), `Electron license input must be a regular non-symlink file: ${filename}`);
  const handle = await open(filename, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const before = await handle.stat();
    assert.ok(before.isFile() && before.dev === entry.dev && before.ino === entry.ino,
      `Electron license input changed before reading: ${filename}`);
    const bytes = await handle.readFile(), after = await handle.stat();
    assert.ok(['dev', 'ino', 'size', 'mtimeMs', 'ctimeMs'].every(key => before[key] === after[key]),
      `Electron license input changed while reading: ${filename}`);
    assert.ok(bytes.length > 0 && bytes.length === before.size, `Electron license input must be complete and nonempty: ${filename}`);
    return bytes;
  } finally { await handle.close(); }
}

/** Copy fidelity against the installed Electron distribution, without executing
 * Electron or claiming independent upstream/runtime provenance verification. */
export async function inspectElectronLicenseResources({ sourceRoot, resourceRoot } = {}) {
  assert.ok(path.isAbsolute(sourceRoot ?? '') && path.isAbsolute(resourceRoot ?? ''), 'Electron license roots must be absolute');
  const sourcePackage = JSON.parse(await regularBytes(path.join(sourceRoot, 'package.json')));
  assertElectronLicenseMappings(sourcePackage.build);
  const expectedVersion = sourcePackage.devDependencies?.electron;
  assert.match(expectedVersion ?? '', /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/, 'Electron dependency must use an exact version');
  const installed = JSON.parse(await regularBytes(path.join(sourceRoot, 'node_modules/electron/package.json')));
  assert.equal(installed.name, 'electron', 'Installed Electron package identity differs');
  assert.equal(installed.version, expectedVersion, 'Installed Electron version differs from the pinned dependency');
  const distributionVersion = (await regularBytes(path.join(sourceRoot, 'node_modules/electron/dist/version'))).toString('utf8').trim();
  assert.equal(distributionVersion, expectedVersion, 'Electron distribution version differs from the pinned dependency');
  const files = [];
  for (const entry of ELECTRON_LICENSE_RESOURCES) {
    const source = await regularBytes(path.join(sourceRoot, entry.from));
    const packaged = await regularBytes(path.join(resourceRoot, entry.to));
    assert.ok(source.equals(packaged), `Electron license bytes differ: ${entry.to}`);
    files.push({ ...entry, size: source.length, sha256: createHash('sha256').update(source).digest('hex') });
  }
  return { verified: true, electronVersion: expectedVersion, regularFilesChecked: true, completeBytesCompared: true, files };
}
