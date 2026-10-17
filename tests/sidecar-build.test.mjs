import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmod, mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { deflateRawSync, gzipSync } from 'node:zlib';
import { copyModuleLicenses, nativeGoTarget } from '../scripts/build-sidecar.mjs';
import { driverArtifacts, patchDriverBundle, safeArchivePath, selectedZipFiles, tarGzFiles, treeSha256, verifyIntegrity } from '../scripts/prepare-playwright-driver.mjs';

function tar(entries) {
  const chunks = [];
  for (const [name, content] of entries) {
    const data = Buffer.from(content);
    const header = Buffer.alloc(512);
    header.write(name, 0, 100, 'utf8');
    header.write('0000644\0', 100);
    header.write(`${data.length.toString(8).padStart(11, '0')}\0`, 124);
    header[156] = 48;
    header.write('ustar\0', 257);
    chunks.push(header, data, Buffer.alloc((512 - data.length % 512) % 512));
  }
  return gzipSync(Buffer.concat([...chunks, Buffer.alloc(1024)]));
}

function zip(name, content, method = 8) {
  const filename = Buffer.from(name);
  const data = Buffer.from(content);
  const compressed = method === 8 ? deflateRawSync(data) : data;
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50);
  local.writeUInt16LE(method, 8);
  local.writeUInt32LE(compressed.length, 18);
  local.writeUInt32LE(data.length, 22);
  local.writeUInt16LE(filename.length, 26);
  const central = Buffer.alloc(46);
  central.writeUInt32LE(0x02014b50);
  central.writeUInt16LE(method, 10);
  central.writeUInt32LE(compressed.length, 20);
  central.writeUInt32LE(data.length, 24);
  central.writeUInt16LE(filename.length, 28);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50);
  end.writeUInt16LE(1, 8);
  end.writeUInt16LE(1, 10);
  end.writeUInt32LE(central.length + filename.length, 12);
  end.writeUInt32LE(local.length + filename.length + compressed.length, 16);
  return Buffer.concat([local, filename, compressed, central, filename, end]);
}

test('native build targets and driver Node artifacts agree across packaging runners', () => {
  for (const [platform, arch, goos, goarch, artifact] of [
    ['darwin', 'arm64', 'darwin', 'arm64', 'darwin-arm64.tar.gz'],
    ['darwin', 'x64', 'darwin', 'amd64', 'darwin-x64.tar.gz'],
    ['linux', 'x64', 'linux', 'amd64', 'linux-x64.tar.gz'],
    ['linux', 'arm64', 'linux', 'arm64', 'linux-arm64.tar.gz'],
    ['win32', 'x64', 'windows', 'amd64', 'win-x64.zip'],
  ]) {
    assert.deepEqual(nativeGoTarget(platform, arch), { goos, goarch, executable: platform === 'win32' ? 'BrowseForge-sidecar.exe' : 'BrowseForge-sidecar' });
    assert.ok(driverArtifacts(platform, arch).nodeUrl.endsWith(artifact));
    assert.match(driverArtifacts(platform, arch).nodeArchiveSha256, /^[a-f0-9]{64}$/);
  }
  assert.throws(() => nativeGoTarget('linux', 'ia32'), /Unsupported/);
  assert.throws(() => driverArtifacts('linux', 'ia32'), /No pinned/);
});

test('pinned integrity rejects modified artifacts before extraction', () => {
  const bytes = Buffer.from('verified build input');
  const npmIntegrity = `sha512-${createHash('sha512').update(bytes).digest('base64')}`;
  const nodeIntegrity = createHash('sha256').update(bytes).digest('hex');
  verifyIntegrity(bytes, npmIntegrity);
  verifyIntegrity(bytes, nodeIntegrity);
  assert.throws(() => verifyIntegrity(Buffer.from('modified input'), npmIntegrity), /integrity/);
  assert.throws(() => verifyIntegrity(Buffer.from('modified input'), nodeIntegrity), /integrity/);
});

test('tar reader preserves native binary bytes and rejects traversal or truncated archive entries', () => {
  const archive = tar([['package/package.json', '{"version":"1.60.0"}'], ['node-v24.18.0-darwin-arm64/bin/node', Buffer.from([0, 255, 1, 2])]]);
  const files = tarGzFiles(archive);
  assert.equal(files.get('package/package.json').toString(), '{"version":"1.60.0"}');
  assert.deepEqual(files.get('node-v24.18.0-darwin-arm64/bin/node'), Buffer.from([0, 255, 1, 2]));
  assert.throws(() => tarGzFiles(tar([['../outside', 'invalid']])), /Unsafe/);
  const broken = Buffer.alloc(512);
  broken.write('package/file', 0);
  broken.write('00000002000\0', 124);
  assert.throws(() => tarGzFiles(gzipSync(broken)), /Truncated/);
});

test('Windows ZIP reader selects only needed binary entries and validates compression and paths', () => {
  const name = 'node-v24.18.0-win-x64/node.exe';
  const binary = Buffer.from([77, 90, 0, 255, 1]);
  for (const method of [0, 8]) assert.deepEqual(selectedZipFiles(zip(name, binary, method), new Set([name])).get(name), binary);
  assert.equal(selectedZipFiles(zip(name, binary), new Set(['unrelated'])).size, 0);
  assert.throws(() => selectedZipFiles(zip('../outside', binary), new Set(['../outside'])), /Unsafe/);
  assert.throws(() => selectedZipFiles(Buffer.from('not zip'), new Set([name])), /Unsupported/);
  for (const name of ['../x', '/absolute', 'C:/absolute', 'foo\\bar']) assert.throws(() => safeArchivePath(name), /Unsafe/);
});

test('the Go compatibility patch is idempotent for read-only packaged resources', () => {
  const original = 'pageError.location.url; pageError.location.lineNumber; pageError.location.columnNumber';
  const patched = patchDriverBundle(original);
  assert.match(patched, /pageError\.location\?\.url \|\| ""/);
  assert.match(patched, /pageError\.location\?\.lineNumber \|\| 0/);
  assert.match(patched, /pageError\.location\?\.columnNumber \|\| 0/);
  assert.equal(patchDriverBundle(patched), patched);
  assert.throws(() => patchDriverBundle('unexpected release'), /pattern is missing/);
});

test('source tree provenance ignores timestamps and changes with file path or content', async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'envara-build-provenance-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await mkdir(path.join(directory, 'sub'));
  await writeFile(path.join(directory, 'sub', 'file.go'), 'source');
  const first = await treeSha256(directory);
  await writeFile(path.join(directory, 'sub', 'file.go'), 'source');
  assert.equal(await treeSha256(directory), first);
  await writeFile(path.join(directory, 'sub', 'file.go'), 'different');
  assert.notEqual(await treeSha256(directory), first);
});

test('repeated builds can replace license outputs copied from an immutable Go module cache', async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'envara-build-licenses-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const cache = path.join(directory, 'cache');
  const source = path.join(cache, 'github.com', 'go-chi', 'chi', 'v5@v5.1.0');
  const output = path.join(directory, 'licenses');
  await mkdir(source, { recursive: true });
  await writeFile(path.join(source, 'LICENSE'), 'upstream license', { mode: 0o444 });
  assert.deepEqual(await copyModuleLicenses(cache, output), ['go-chi-LICENSE']);
  if (process.platform !== 'win32') await chmod(path.join(output, 'go-chi-LICENSE'), 0o444);
  assert.deepEqual(await copyModuleLicenses(cache, output), ['go-chi-LICENSE']);
  assert.equal(await readFile(path.join(output, 'go-chi-LICENSE'), 'utf8'), 'upstream license');
});
