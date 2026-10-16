import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { mkdir, mkdtemp, readFile, realpath, rename, rm, symlink, unlink, writeFile } from 'node:fs/promises';
import { inspectApplicationCompatibility } from '../electron/application-compatibility.mjs';

const SUPPORTED = { supported: true, adapter: 'chromium-front', reasonCode: null, dataScope: 'environment', verification: 'pending' };
const UNSUPPORTED = { supported: false, adapter: 'unsupported', reasonCode: 'APPLICATION_ADAPTER_UNSUPPORTED', dataScope: 'unavailable', verification: 'pending' };
const xml = value => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;');
const plist = fields => `<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict>${Object.entries(fields).map(([key, value]) => `<key>${xml(key)}</key><string>${xml(value)}</string>`).join('')}</dict></plist>\n`;

function macho(fileType = 2, extra = Buffer.alloc(0)) {
  const header = Buffer.alloc(32);
  header.writeUInt32LE(0xfeedfacf, 0); // MH_MAGIC_64, little endian.
  header.writeUInt32LE(0x0100000c, 4); // CPU_TYPE_ARM64.
  header.writeUInt32LE(fileType, 12); // MH_EXECUTE (2) or MH_DYLIB (6).
  return Buffer.concat([header, extra]);
}

function fatMachO(fileType, { wide = false, little = false } = {}) {
  const slice = macho(fileType), offset = wide ? 64 : 32;
  const binary = Buffer.alloc(offset + slice.length);
  binary.writeUInt32BE(wide ? (little ? 0xbfbafeca : 0xcafebabf) : (little ? 0xbebafeca : 0xcafebabe), 0);
  const write32 = (value, position) => binary[little ? 'writeUInt32LE' : 'writeUInt32BE'](value, position);
  write32(1, 4); write32(0x0100000c, 8);
  if (wide) {
    binary[little ? 'writeBigUInt64LE' : 'writeBigUInt64BE'](BigInt(offset), 16);
    binary[little ? 'writeBigUInt64LE' : 'writeBigUInt64BE'](BigInt(slice.length), 24);
  } else {
    write32(offset, 16); write32(slice.length, 20);
  }
  slice.copy(binary, offset);
  return binary;
}

async function fixture(t, { kind = 'electron', symlinkFramework = false } = {}) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-app-compatibility-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  const bundle = path.join(root, 'Synthetic Product.app');
  const identifier = kind === 'electron' ? 'com.example.SyntheticElectron' : 'com.example.SyntheticChromium';
  const executableName = 'Synthetic Product';
  const mainDirectory = path.join(bundle, 'Contents', 'MacOS');
  const frameworksDirectory = path.join(bundle, 'Contents', 'Frameworks');
  await mkdir(mainDirectory, { recursive: true, mode: 0o700 });
  await mkdir(frameworksDirectory, { mode: 0o700 });
  const mainExecutable = path.join(mainDirectory, executableName);
  await writeFile(mainExecutable, macho(2), { mode: 0o700 });
  const mainInfo = path.join(bundle, 'Contents', 'Info.plist');
  const mainMetadata = { CFBundlePackageType: 'APPL', CFBundleIdentifier: identifier, CFBundleExecutable: executableName,
    CFBundleVersion: '1.0.0', NSPrincipalClass: kind === 'electron' ? 'AtomApplication' : 'BrowserCrApplication' };
  await writeFile(mainInfo, plist(mainMetadata), { mode: 0o600 });
  const frameworkName = kind === 'electron' ? 'Electron Framework' : 'Synthetic Chromium Framework';
  const framework = path.join(frameworksDirectory, `${frameworkName}.framework`);
  const frameworkMetadata = { CFBundlePackageType: 'FMWK', CFBundleIdentifier: kind === 'electron' ? 'com.github.Electron.framework' : `${identifier}.framework`,
    CFBundleExecutable: frameworkName, CFBundleVersion: '35.2.1' };
  let frameworkInfo, frameworkExecutable;
  if (symlinkFramework) {
    const version = path.join(framework, 'Versions', 'A');
    await mkdir(path.join(version, 'Resources'), { recursive: true, mode: 0o700 });
    frameworkInfo = path.join(version, 'Resources', 'Info.plist');
    frameworkExecutable = path.join(version, frameworkName);
    await symlink('A', path.join(framework, 'Versions', 'Current'));
    await symlink('Versions/Current/Resources', path.join(framework, 'Resources'));
    await symlink(`Versions/Current/${frameworkName}`, path.join(framework, frameworkName));
  } else {
    await mkdir(path.join(framework, 'Resources'), { recursive: true, mode: 0o700 });
    frameworkInfo = path.join(framework, 'Resources', 'Info.plist');
    frameworkExecutable = path.join(framework, frameworkName);
  }
  await writeFile(frameworkInfo, plist(frameworkMetadata), { mode: 0o600 });
  await writeFile(frameworkExecutable, macho(6), { mode: 0o700 });
  const descriptor = { path: bundle, executablePath: mainExecutable, identity: `bundle:${identifier}` };
  return { root, bundle, identifier, executableName, mainExecutable, mainInfo, mainMetadata, frameworksDirectory,
    framework, frameworkInfo, frameworkExecutable, frameworkMetadata, frameworkName, descriptor };
}

const metadataOnly = target => inspectApplicationCompatibility(target, { platform: 'darwin', verifySignature: false });
const updateMain = (f, fields) => writeFile(f.mainInfo, plist({ ...f.mainMetadata, ...fields }), { mode: 0o600 });
const updateFramework = (f, fields) => writeFile(f.frameworkInfo, plist({ ...f.frameworkMetadata, ...fields }), { mode: 0o600 });

async function addChromiumFramework(f, name, fields = {}) {
  const directory = path.join(f.frameworksDirectory, `${name}.framework`);
  await mkdir(path.join(directory, 'Resources'), { recursive: true, mode: 0o700 });
  await writeFile(path.join(directory, 'Resources', 'Info.plist'), plist({ ...f.frameworkMetadata, CFBundleExecutable: name, ...fields }));
  await writeFile(path.join(directory, name), macho(6), { mode: 0o700 });
}

async function vscodeFixture(t, { insiders = false } = {}) {
  const f = await fixture(t);
  const identifier = insiders ? 'com.microsoft.VSCodeInsiders' : 'com.microsoft.VSCode';
  await updateMain(f, { CFBundleIdentifier: identifier });
  const product = { darwinBundleIdentifier: identifier, applicationName: insiders ? 'code-insiders' : 'code', quality: insiders ? 'insider' : 'stable' };
  const productDirectory = path.join(f.bundle, 'Contents', 'Resources', 'app');
  await mkdir(productDirectory, { recursive: true, mode: 0o700 });
  const productFile = path.join(productDirectory, 'product.json');
  await writeFile(productFile, JSON.stringify(product), { mode: 0o600 });
  return { ...f, identifier, product, productFile, descriptor: { ...f.descriptor, identity: `bundle:${identifier}` } };
}

test('matching Electron and Chromium metadata produce only pending adapter support', async t => {
  for (const kind of ['electron', 'chromium']) {
    await t.test(kind, async subtest => {
      const f = await fixture(subtest, { kind });
      let calls = 0;
      const result = await inspectApplicationCompatibility(f.bundle, { platform: 'darwin', signatureVerifier: async bundle => {
        calls += 1; assert.equal(bundle, f.bundle); return true;
      } });
      assert.deepEqual(result, SUPPORTED);
      assert.equal(calls, 1);
      assert.deepEqual(await metadataOnly(f.descriptor), SUPPORTED);
    });
  }
});

test('normal contained framework Resources and executable symlinks are supported', async t => {
  for (const kind of ['electron', 'chromium']) {
    await t.test(kind, async subtest => {
      const f = await fixture(subtest, { kind, symlinkFramework: true });
      assert.deepEqual(await metadataOnly(f.bundle), SUPPORTED);
    });
  }
});

test('bounded native fat headers support both widths and byte orders', async t => {
  for (const options of [{ wide: false, little: false }, { wide: false, little: true }, { wide: true, little: false }, { wide: true, little: true }]) {
    await t.test(`${options.wide ? 64 : 32} bit ${options.little ? 'little' : 'big'} endian`, async subtest => {
      const f = await fixture(subtest);
      await writeFile(f.mainExecutable, fatMachO(2, options));
      await writeFile(f.frameworkExecutable, fatMachO(6, options));
      assert.deepEqual(await metadataOnly(f.bundle), SUPPORTED);
    });
  }
});

test('fat native headers with invalid counts or escaping slice bounds are refused', async t => {
  const cases = [
    ['empty architecture table', () => { const binary = fatMachO(2); binary.writeUInt32BE(0, 4); return binary; }],
    ['oversized architecture count', () => { const binary = fatMachO(2); binary.writeUInt32BE(33, 4); return binary; }],
    ['truncated architecture table', () => fatMachO(2).subarray(0, 8)],
    ['slice overlaps header', () => { const binary = fatMachO(2); binary.writeUInt32BE(8, 16); return binary; }],
    ['slice extends past file', () => { const binary = fatMachO(2); binary.writeUInt32BE(0xffffffff, 20); return binary; }],
    ['unsafe wide offset', () => { const binary = fatMachO(2, { wide: true }); binary.writeBigUInt64BE(BigInt(Number.MAX_SAFE_INTEGER) + 1n, 16); return binary; }],
    ['wrong member file type', () => fatMachO(6)],
  ];
  for (const [name, content] of cases) {
    await t.test(name, async subtest => {
      const f = await fixture(subtest);
      await writeFile(f.mainExecutable, content());
      assert.deepEqual(await metadataOnly(f.bundle), UNSUPPORTED);
    });
  }
});

test('metadata-only inspection never calls the supplied signature verifier', async t => {
  const f = await fixture(t);
  let calls = 0;
  assert.deepEqual(await inspectApplicationCompatibility(f.bundle, { platform: 'darwin', verifySignature: false, signatureVerifier: async () => {
    calls += 1; throw new Error('signature verification must be disabled');
  } }), SUPPORTED);
  assert.equal(calls, 0);
});

test('failed or unavailable signature verification refuses otherwise matching metadata', async t => {
  const f = await fixture(t);
  assert.deepEqual(await inspectApplicationCompatibility(f.bundle, { platform: 'darwin', signatureVerifier: async () => false }), UNSUPPORTED);
  assert.deepEqual(await inspectApplicationCompatibility(f.bundle, { platform: 'darwin', signatureVerifier: async () => { throw new Error('synthetic signature refusal'); } }), UNSUPPORTED);
});

test('invalid input and paths are rejected without attempting signature verification', async t => {
  const f = await fixture(t);
  const ordinaryFile = path.join(f.root, 'plain.txt');
  await writeFile(ordinaryFile, 'synthetic file');
  const invalid = [null, undefined, 42, {}, { path: 1 }, '', 'relative.app', '../outside.app', '/bad\0path.app', ordinaryFile, path.join(f.root, 'Missing.app')];
  let calls = 0;
  for (const target of invalid) {
    await assert.rejects(inspectApplicationCompatibility(target, { platform: 'darwin', signatureVerifier: async () => { calls += 1; return true; } }),
      { code: 'APPLICATION_INVALID_PATH' });
  }
  assert.equal(calls, 0);
});

test('a valid app descriptor must match the canonical executable and bundle identifier', async t => {
  const f = await fixture(t);
  assert.deepEqual(await metadataOnly(f.descriptor), SUPPORTED);
  assert.deepEqual(await metadataOnly({ ...f.descriptor, identity: 'bundle:com.example.OtherApp' }), UNSUPPORTED);
  assert.deepEqual(await metadataOnly({ ...f.descriptor, identity: 'path:synthetic' }), UNSUPPORTED);
  const otherExecutable = path.join(f.bundle, 'Contents', 'MacOS', 'Other');
  await writeFile(otherExecutable, macho(2), { mode: 0o700 });
  assert.deepEqual(await metadataOnly({ ...f.descriptor, executablePath: otherExecutable }), UNSUPPORTED);
});

test('root metadata and the main native executable are required', async t => {
  const cases = [
    ['not an APPL bundle', f => updateMain(f, { CFBundlePackageType: 'BNDL' })],
    ['data value instead of APPL string', f => writeFile(f.mainInfo, plist(f.mainMetadata).replace('<string>APPL</string>', '<data>APPL</data>'))],
    ['invalid identifier', f => updateMain(f, { CFBundleIdentifier: 'invalid identifier' })],
    ['identifier with unsupported underscore', f => updateMain(f, { CFBundleIdentifier: 'com.example.Has_Underscore' })],
    ['unsafe executable basename', f => updateMain(f, { CFBundleExecutable: '../Synthetic Product' })],
    ['unknown principal class', f => updateMain(f, { NSPrincipalClass: 'NSApplication' })],
    ['missing principal class', async f => { const { NSPrincipalClass, ...rest } = f.mainMetadata; await writeFile(f.mainInfo, plist(rest)); }],
    ['missing main metadata', f => unlink(f.mainInfo)],
    ['malformed main metadata', f => writeFile(f.mainInfo, '<plist><dict>invalid')],
    ['oversized main metadata', f => writeFile(f.mainInfo, 'x'.repeat(1024 * 1024 + 1))],
    ['missing main executable', f => unlink(f.mainExecutable)],
    ['script instead of native executable', f => writeFile(f.mainExecutable, '#!/bin/sh\nexit 0\n')],
    ['dylib instead of main executable', f => writeFile(f.mainExecutable, macho(6))],
    ['truncated native header', f => writeFile(f.mainExecutable, macho(2).subarray(0, 12))],
  ];
  for (const [name, change] of cases) {
    await t.test(name, async subtest => {
      const f = await fixture(subtest);
      await change(f);
      assert.deepEqual(await metadataOnly(f.bundle), UNSUPPORTED);
    });
  }
});

test('Electron framework metadata cannot be forged or replaced with a script', async t => {
  const cases = [
    ['wrong package type', f => updateFramework(f, { CFBundlePackageType: 'APPL' })],
    ['data value instead of FMWK string', f => writeFile(f.frameworkInfo, plist(f.frameworkMetadata).replace('<string>FMWK</string>', '<data>FMWK</data>'))],
    ['wrong identifier', f => updateFramework(f, { CFBundleIdentifier: 'com.example.Forged.framework' })],
    ['wrong executable', f => updateFramework(f, { CFBundleExecutable: 'Other Framework' })],
    ['non-numeric version', f => updateFramework(f, { CFBundleVersion: '35.2-beta' })],
    ['missing version', async f => { const { CFBundleVersion, ...rest } = f.frameworkMetadata; await writeFile(f.frameworkInfo, plist(rest)); }],
    ['missing framework', f => rm(f.framework, { recursive: true })],
    ['malformed framework metadata', f => writeFile(f.frameworkInfo, 'not a plist')],
    ['oversized framework metadata', f => writeFile(f.frameworkInfo, 'x'.repeat(1024 * 1024 + 1))],
    ['script framework binary', f => writeFile(f.frameworkExecutable, '#!/bin/sh\nexit 0\n')],
    ['executable instead of framework dylib', f => writeFile(f.frameworkExecutable, macho(2))],
    ['truncated framework header', f => writeFile(f.frameworkExecutable, macho(6).subarray(0, 12))],
    ['unknown framework directory', f => rename(f.framework, path.join(f.frameworksDirectory, 'Unknown.framework'))],
  ];
  for (const [name, change] of cases) {
    await t.test(name, async subtest => {
      const f = await fixture(subtest);
      await change(f);
      assert.deepEqual(await metadataOnly(f.bundle), UNSUPPORTED);
    });
  }
});

test('Chromium requires exactly one eligible framework with its own basename executable', async t => {
  const cases = [
    ['identifier not derived from the app', f => updateFramework(f, { CFBundleIdentifier: 'com.example.Other.framework' })],
    ['framework executable not the directory basename', f => updateFramework(f, { CFBundleExecutable: 'Other Framework' })],
    ['invalid framework version', f => updateFramework(f, { CFBundleVersion: 'unknown' })],
    ['extra eligible framework candidate', f => addChromiumFramework(f, 'Extra')],
    ['missing framework candidate', f => rm(f.framework, { recursive: true })],
  ];
  for (const [name, change] of cases) {
    await t.test(name, async subtest => {
      const f = await fixture(subtest, { kind: 'chromium' });
      await change(f);
      assert.deepEqual(await metadataOnly(f.bundle), UNSUPPORTED);
    });
  }
});

test('Chromium ignores empty or unrelated frameworks while retaining its one eligible candidate', async t => {
  const f = await fixture(t, { kind: 'chromium' });
  await mkdir(path.join(f.frameworksDirectory, 'Empty.framework'));
  await addChromiumFramework(f, 'Unrelated', { CFBundleIdentifier: 'com.example.Unrelated.framework' });
  assert.deepEqual(await metadataOnly(f.bundle), SUPPORTED);
});

test('Chromium counts only frameworks whose metadata and native binary qualify', async t => {
  const f = await fixture(t, { kind: 'chromium' });
  await addChromiumFramework(f, 'Extra');
  await writeFile(path.join(f.frameworksDirectory, 'Extra.framework', 'Extra'), '#!/bin/sh\nexit 0\n');
  // Native engine_metadata calls engine_entry before counting candidates. A
  // metadata match with a script cannot introduce a second engine candidate.
  assert.deepEqual(await metadataOnly(f.bundle), SUPPORTED);
  await rm(f.framework, { recursive: true });
  assert.deepEqual(await metadataOnly(f.bundle), UNSUPPORTED, 'the ignored script must never supply the required engine');
});

test('the framework directory budget includes unrelated entries for both adapters', async t => {
  for (const kind of ['electron', 'chromium']) {
    await t.test(kind, async subtest => {
      const f = await fixture(subtest, { kind });
      await Promise.all(Array.from({ length: 63 }, (_, index) => writeFile(path.join(f.frameworksDirectory, `unrelated-${index}.txt`), 'synthetic resource')));
      assert.deepEqual(await metadataOnly(f.bundle), SUPPORTED, 'one framework plus 63 unrelated entries is within the budget');
      await writeFile(path.join(f.frameworksDirectory, 'over-budget.txt'), 'synthetic resource');
      assert.deepEqual(await metadataOnly(f.bundle), UNSUPPORTED);
    });
  }
});

test('VS Code stable and Insiders require their matching product tuple', async t => {
  for (const insiders of [false, true]) {
    await t.test(insiders ? 'Insiders' : 'stable', async subtest => {
      const f = await vscodeFixture(subtest, { insiders });
      assert.deepEqual(await metadataOnly(f.descriptor), SUPPORTED);
    });
  }
});

test('VS Code product metadata must be valid, bounded and contained in the app', async t => {
  const cases = [
    ['missing product file', f => unlink(f.productFile)],
    ['mismatched bundle identifier', f => writeFile(f.productFile, JSON.stringify({ ...f.product, darwinBundleIdentifier: 'com.example.Other' }))],
    ['mismatched application name', f => writeFile(f.productFile, JSON.stringify({ ...f.product, applicationName: 'other' }))],
    ['mismatched quality', f => writeFile(f.productFile, JSON.stringify({ ...f.product, quality: 'insider' }))],
    ['missing required tuple member', f => writeFile(f.productFile, JSON.stringify({ darwinBundleIdentifier: f.identifier, quality: 'stable' }))],
    ['wrong tuple value type', f => writeFile(f.productFile, JSON.stringify({ ...f.product, applicationName: 123 }))],
    ['malformed JSON', f => writeFile(f.productFile, '{invalid synthetic JSON')],
    ['JSON array', f => writeFile(f.productFile, '[]')],
    ['oversized valid JSON', f => writeFile(f.productFile, JSON.stringify({ ...f.product, padding: 'x'.repeat(1024 * 1024) }))],
    ['external product link', async f => {
      const external = path.join(f.root, 'outside-product.json');
      await writeFile(external, JSON.stringify(f.product)); await unlink(f.productFile); await symlink(external, f.productFile);
    }],
  ];
  for (const [name, change] of cases) {
    await t.test(name, async subtest => {
      const f = await vscodeFixture(subtest);
      await change(f);
      assert.deepEqual(await metadataOnly(f.bundle), UNSUPPORTED);
    });
  }
});

test('VS Code product JSON participates in positive signature-cache invalidation', async t => {
  const f = await vscodeFixture(t);
  let calls = 0;
  const options = { platform: 'darwin', signatureVerifier: async () => { calls += 1; return true; } };
  assert.deepEqual(await inspectApplicationCompatibility(f.bundle, options), SUPPORTED);
  assert.deepEqual(await inspectApplicationCompatibility(f.bundle, options), SUPPORTED);
  assert.equal(calls, 1);
  await writeFile(f.productFile, JSON.stringify({ ...f.product, syntheticRevision: 1 }));
  assert.deepEqual(await inspectApplicationCompatibility(f.bundle, options), SUPPORTED);
  assert.equal(calls, 2);
  await writeFile(f.productFile, JSON.stringify({ ...f.product, syntheticRevision: 2 }));
  assert.deepEqual(await inspectApplicationCompatibility(f.bundle, options), SUPPORTED);
  assert.equal(calls, 3);
});

test('metadata, executable, Resources and framework escapes remain unsupported', async t => {
  const cases = [
    ['root metadata', async f => {
      const external = path.join(f.root, 'outside-info.plist');
      await writeFile(external, plist(f.mainMetadata)); await unlink(f.mainInfo); await symlink(external, f.mainInfo);
    }],
    ['main executable', async f => {
      const external = path.join(f.root, 'outside-main');
      await writeFile(external, macho(2), { mode: 0o700 }); await unlink(f.mainExecutable); await symlink(external, f.mainExecutable);
    }],
    ['framework executable', async f => {
      const external = path.join(f.root, 'outside-dylib');
      await writeFile(external, macho(6), { mode: 0o700 }); await unlink(f.frameworkExecutable); await symlink(external, f.frameworkExecutable);
    }],
    ['framework Resources', async f => {
      const external = path.join(f.root, 'outside-resources');
      await mkdir(external); await writeFile(path.join(external, 'Info.plist'), plist(f.frameworkMetadata));
      await rm(path.join(f.framework, 'Resources'), { recursive: true }); await symlink(external, path.join(f.framework, 'Resources'));
    }],
    ['entire framework', async f => {
      const external = path.join(f.root, 'outside.framework');
      await rename(f.framework, external); await symlink(external, f.framework);
    }],
  ];
  for (const [name, change] of cases) {
    await t.test(name, async subtest => {
      const f = await fixture(subtest);
      await change(f);
      assert.deepEqual(await metadataOnly(f.bundle), UNSUPPORTED);
    });
  }
});

test('positive signature cache is invalidated by metadata, executable content and inode changes', async t => {
  const f = await fixture(t);
  let calls = 0;
  const options = { platform: 'darwin', signatureVerifier: async () => { calls += 1; return true; } };
  const inspect = async expectedCalls => {
    assert.deepEqual(await inspectApplicationCompatibility(f.bundle, options), SUPPORTED);
    assert.equal(calls, expectedCalls);
  };
  await inspect(1); await inspect(1);
  await updateMain(f, { CFBundleVersion: '1.0.1' });
  await inspect(2);
  await updateFramework(f, { CFBundleVersion: '35.2.2' });
  await inspect(3);
  await writeFile(f.mainExecutable, macho(2, Buffer.from([1, 2, 3])));
  await inspect(4);
  await writeFile(f.frameworkExecutable, macho(6, Buffer.from([4, 5, 6])));
  await inspect(5);
  const replacement = path.join(f.bundle, 'Contents', 'MacOS', 'replacement');
  await writeFile(replacement, await readFile(f.mainExecutable), { mode: 0o700 });
  await rename(replacement, f.mainExecutable);
  await inspect(6);
  await inspect(6);
});

test('different signature verifiers do not share a positive verification result', async t => {
  const f = await fixture(t);
  let acceptedCalls = 0, refusedCalls = 0;
  const accepted = async () => { acceptedCalls += 1; return true; };
  const refused = async () => { refusedCalls += 1; return false; };
  assert.deepEqual(await inspectApplicationCompatibility(f.bundle, { platform: 'darwin', signatureVerifier: accepted }), SUPPORTED);
  assert.deepEqual(await inspectApplicationCompatibility(f.bundle, { platform: 'darwin', signatureVerifier: accepted }), SUPPORTED);
  assert.equal(acceptedCalls, 1);
  assert.deepEqual(await inspectApplicationCompatibility(f.bundle, { platform: 'darwin', signatureVerifier: refused }), UNSUPPORTED);
  assert.equal(refusedCalls, 1);
  assert.deepEqual(await inspectApplicationCompatibility(f.bundle, { platform: 'darwin', signatureVerifier: accepted }), SUPPORTED);
  assert.equal(acceptedCalls, 1);
});
