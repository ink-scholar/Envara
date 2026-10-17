import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile, writeFile, readdir, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { gzipSync, gunzipSync } from 'node:zlib';
import { c as createTar } from 'tar';
import { extractProxyCoreBinary, extractProxyCoreCA, prepareProxyCore, proxyCoreArtifacts, verifyProxyCoreHash,
  PROXY_CORE_VERSION, PROXY_CORE_COMMIT, SOURCE_ARCHIVE_METADATA_POLICY } from '../scripts/prepare-proxy-core.mjs';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
async function fixture(t) {
  const rootDir = await mkdtemp(path.join(os.tmpdir(), 'envara-proxy-prepare-test-'));
  t.after(() => rm(rootDir, { recursive: true, force: true }));
  await mkdir(path.join(rootDir, 'third_party', 'proxy-core'), { recursive: true });
  await writeFile(path.join(rootDir, 'third_party', 'proxy-core', 'LICENSE'), 'GPL test license');
  await writeFile(path.join(rootDir, 'third_party', 'proxy-core', 'SOURCE.md'), 'Source test notice');
  const binary = Buffer.from('A fixture executable');
  const archive = gzipSync(binary);
  const source = Buffer.from('A fixture upstream source');
  const sourceDir = path.join(rootDir, 'fixture-source');
  await mkdir(sourceDir);
  await writeFile(path.join(sourceDir, 'LICENSE'), 'A fixture vendored source');
  const sourceFile = path.join(rootDir, 'fixture-source.tar.gz');
  await createTar({ cwd: rootDir, file: sourceFile, portable: true, noMtime: true,
    gzip: { portable: true } }, ['fixture-source']);
  const completeSource = await readFile(sourceFile);
  const artifact = { ...proxyCoreArtifacts(), archiveSha256: hash(archive), sourceSha256: hash(source) };
  let downloads = 0;
  let validations = 0;
  let sourceBuilds = 0;
  const options = {
    rootDir, artifact,
    downloadImpl: async url => { downloads++; return url === artifact.url ? archive : source; },
    validateImpl: async file => { validations++; assert.deepEqual(await readFile(file), binary); return 'fixture native version'; },
    prepareSourceImpl: async ({ sourceBytes, destination }) => {
      sourceBuilds++; assert.deepEqual(sourceBytes, source); await writeFile(destination, completeSource);
      return { filename: 'mihomo-corresponding-source.tar.gz', sha256: hash(completeSource), offlineDependencies: true, releaseCA: true };
    },
  };
  return { rootDir, artifact, binary, archive, source, completeSource, options,
    counts: () => ({ downloads, validations, sourceBuilds }) };
}

test('proxy preparation pins official stable assets and source rather than moving release names', () => {
  assert.equal(PROXY_CORE_VERSION, 'v1.19.32');
  assert.match(PROXY_CORE_COMMIT, /^[a-f0-9]{40}$/);
  for (const [platform, arch, name] of [['darwin', 'arm64', 'mihomo'], ['linux', 'x64', 'mihomo'], ['win32', 'x64', 'mihomo.exe']]) {
    const artifact = proxyCoreArtifacts(platform, arch);
    assert.equal(artifact.binaryName, name);
    assert.match(artifact.archiveSha256, /^[a-f0-9]{64}$/);
    assert.match(artifact.sourceSha256, /^[a-f0-9]{64}$/);
    assert.ok(artifact.url.includes(`/download/${PROXY_CORE_VERSION}/`));
    assert.ok(artifact.sourceUrl.endsWith(PROXY_CORE_COMMIT));
    assert.ok(!artifact.url.includes('latest') && !artifact.url.includes('Alpha'));
  }
  assert.throws(() => proxyCoreArtifacts('darwin', 'riscv64'), /No pinned/);
});

test('executable extraction verifies archive integrity before decompression', () => {
  const binary = Buffer.from('native binary');
  const archive = gzipSync(binary);
  const artifact = { archiveName: 'core.gz', archiveSha256: hash(archive) };
  assert.deepEqual(extractProxyCoreBinary(archive, artifact), binary);
  assert.throws(() => extractProxyCoreBinary(Buffer.from('corrupted'), artifact), /SHA-256 verification/);
  assert.throws(() => verifyProxyCoreHash(archive, 'not a hash'), /Invalid pinned/);
  assert.throws(() => extractProxyCoreBinary(archive, { ...artifact, archiveName: 'core.tar' }), /Unsupported/);
});

test('corresponding source carries the CA input used by the release build', () => {
  const pem = `-----BEGIN CERTIFICATE-----\n${'A'.repeat(110000)}\n-----END CERTIFICATE-----\n`;
  const ca = extractProxyCoreCA(Buffer.from(`Binaryprefix${pem}Binarysuffix`));
  assert.equal(ca.toString(), pem);
  assert.throws(() => extractProxyCoreCA(Buffer.from('no certificates')), /could not be identified/);
  assert.throws(() => extractProxyCoreCA(Buffer.from(`${pem}Split${pem}`)), /could not be identified/);
});

test('native preparation rejects a cross platform target before any download', async t => {
  const f = await fixture(t);
  const target = process.platform === 'linux' ? 'darwin' : 'linux';
  await assert.rejects(prepareProxyCore({ ...f.options, platform: target }), /native runner/);
  assert.equal(f.counts().downloads, 0);
});

test('prepared bundle includes executable, full source, license and immutable provenance', async t => {
  const f = await fixture(t);
  const prepared = await prepareProxyCore(f.options);
  const files = await readdir(prepared.outputDir);
  assert.deepEqual(files.sort(), [f.artifact.binaryName, 'LICENSE', 'SOURCE.md', 'mihomo-corresponding-source.tar.gz', 'provenance.json'].sort());
  assert.deepEqual(await readFile(prepared.binaryPath), f.binary);
  assert.deepEqual(await readFile(path.join(prepared.outputDir, 'mihomo-corresponding-source.tar.gz')), f.completeSource);
  assert.equal(prepared.provenance.core, 'mihomo');
  assert.equal(prepared.provenance.commit, PROXY_CORE_COMMIT);
  assert.equal(prepared.provenance.sha256.archive, hash(f.archive));
  assert.equal(prepared.provenance.sha256.binary, hash(f.binary));
  assert.equal(prepared.provenance.sha256.correspondingSource, hash(f.completeSource));
  assert.equal(prepared.provenance.source.offlineDependencies, true);
  assert.equal(prepared.provenance.source.archiveMetadata.policy, SOURCE_ARCHIVE_METADATA_POLICY);
  assert.equal(prepared.provenance.source.archiveMetadata.verified, true);
  assert.equal(prepared.reused, false);
  assert.deepEqual(f.counts(), { downloads: 2, validations: 1, sourceBuilds: 1 });
});

function withSyntheticOwner(archive) {
  const bytes = gunzipSync(archive);
  bytes.fill(0, 265, 297);
  bytes.write('synthetic-builder', 265, 'ascii');
  bytes.fill(0x20, 148, 156);
  let checksum = 0;
  for (const byte of bytes.subarray(0, 512)) checksum += byte;
  bytes.write(`${checksum.toString(8).padStart(6, '0')}\0 `, 148, 'ascii');
  return gzipSync(bytes);
}

test('legacy provenance and owner-bearing source caches are rebuilt even with matching hashes', async t => {
  const f = await fixture(t);
  const first = await prepareProxyCore(f.options);
  const provenanceFile = path.join(first.outputDir, 'provenance.json');
  const oldProvenance = JSON.parse(await readFile(provenanceFile, 'utf8'));
  delete oldProvenance.source.archiveMetadata;
  await writeFile(provenanceFile, JSON.stringify(oldProvenance));
  const migrated = await prepareProxyCore(f.options);
  assert.equal(migrated.reused, false);
  const dirty = withSyntheticOwner(f.completeSource);
  const forged = JSON.parse(await readFile(provenanceFile, 'utf8'));
  forged.sha256.correspondingSource = hash(dirty);
  forged.source.sha256 = hash(dirty);
  await writeFile(path.join(first.outputDir, 'mihomo-corresponding-source.tar.gz'), dirty);
  await writeFile(provenanceFile, JSON.stringify(forged));
  const repaired = await prepareProxyCore(f.options);
  assert.equal(repaired.reused, false);
  assert.deepEqual(await readFile(path.join(first.outputDir, 'mihomo-corresponding-source.tar.gz')), f.completeSource);
  assert.equal(f.counts().sourceBuilds, 3);
});

test('new source with correct digest but host metadata cannot replace the previous clean bundle', async t => {
  const f = await fixture(t);
  const first = await prepareProxyCore(f.options);
  const before = await readFile(path.join(first.outputDir, 'provenance.json'));
  const dirty = withSyntheticOwner(f.completeSource);
  await assert.rejects(prepareProxyCore({ ...f.options, force: true, prepareSourceImpl: async ({ destination }) => {
    await writeFile(destination, dirty);
    return { sha256: hash(dirty), offlineDependencies: true, releaseCA: true,
      archiveMetadata: { policy: SOURCE_ARCHIVE_METADATA_POLICY, verified: true } };
  } }), { code: 'SOURCE_ARCHIVE_METADATA_REFUSED' });
  assert.deepEqual(await readFile(path.join(first.outputDir, 'provenance.json')), before);
  assert.deepEqual(await readFile(path.join(first.outputDir, 'mihomo-corresponding-source.tar.gz')), f.completeSource);
});

test('reuse checks both executable and source hashes and runs native version validation', async t => {
  const f = await fixture(t);
  await prepareProxyCore(f.options);
  const again = await prepareProxyCore(f.options);
  assert.equal(again.reused, true);
  assert.deepEqual(f.counts(), { downloads: 2, validations: 2, sourceBuilds: 1 });
  await writeFile(path.join(again.outputDir, 'mihomo-corresponding-source.tar.gz'), 'corrupt source');
  const repaired = await prepareProxyCore(f.options);
  assert.equal(repaired.reused, false);
  assert.deepEqual(await readFile(path.join(repaired.outputDir, 'mihomo-corresponding-source.tar.gz')), f.completeSource);
  assert.deepEqual(f.counts(), { downloads: 2, validations: 3, sourceBuilds: 2 });
});

test('a corrupted archive cache is evicted instead of silently reused', async t => {
  const f = await fixture(t);
  const cacheDir = path.join(f.rootDir, '.cache', 'proxy-core');
  await mkdir(cacheDir, { recursive: true });
  await writeFile(path.join(cacheDir, f.artifact.archiveSha256), 'corrupted cache');
  const result = await prepareProxyCore(f.options);
  assert.deepEqual(await readFile(result.binaryPath), f.binary);
  assert.deepEqual(await readFile(path.join(cacheDir, f.artifact.archiveSha256)), f.archive);
  assert.equal(f.counts().downloads, 2);
});

test('failed integrity or corresponding source preparation preserves the prior usable bundle', async t => {
  const f = await fixture(t);
  const old = await prepareProxyCore(f.options);
  const before = await readFile(path.join(old.outputDir, 'provenance.json'));
  await assert.rejects(prepareProxyCore({ ...f.options, force: true,
    prepareSourceImpl: async () => { throw new Error('source build failed'); } }), /source build failed/);
  assert.deepEqual(await readFile(path.join(old.outputDir, 'provenance.json')), before);
  assert.deepEqual(await readFile(old.binaryPath), f.binary);
  assert.deepEqual((await readdir(path.dirname(old.outputDir))).filter(name => name.includes('.stage-') || name.includes('.previous-')), []);
  await assert.rejects(prepareProxyCore({ ...f.options, force: true, artifact: { ...f.artifact, archiveSha256: 'a'.repeat(64) } }), /SHA-256 verification/);
  assert.deepEqual(await readFile(path.join(old.outputDir, 'provenance.json')), before);
});

test('incomplete source and an incorrect native version cannot replace the prior bundle', async t => {
  const f = await fixture(t);
  const old = await prepareProxyCore(f.options);
  await assert.rejects(prepareProxyCore({ ...f.options, force: true, prepareSourceImpl: async ({ destination }) => {
    await writeFile(destination, f.completeSource); return { sha256: hash(f.completeSource), offlineDependencies: false };
  } }), /incomplete/);
  await assert.rejects(prepareProxyCore({ ...f.options, force: true,
    validateImpl: async () => { throw new Error('incorrect architecture'); } }), /incorrect architecture/);
  assert.deepEqual(await readFile(old.binaryPath), f.binary);
});
