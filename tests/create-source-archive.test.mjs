import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { gunzipSync } from 'node:zlib';
import { chmod, lchmod, link, lstat, mkdir, mkdtemp, readFile, readdir, rm, symlink, utimes, writeFile } from 'node:fs/promises';
import { list } from 'tar';
import { createSourceArchive } from '../scripts/create-source-archive.mjs';
import { inspectSourceArchive } from '../scripts/source-archive.mjs';

async function fixture(t) {
  const temporary = await mkdtemp(path.join(tmpdir(), 'envara-source-archive-'));
  t.after(() => rm(temporary, { recursive: true, force: true }));
  const sourceDir = path.join(temporary, '@upstream-source');
  await mkdir(sourceDir, { mode: 0o755 });
  await chmod(sourceDir, 0o755);
  const destination = path.join(temporary, 'source.tar.gz');
  async function file(relative, bytes, mode = 0o644) {
    const filename = path.join(sourceDir, relative);
    await mkdir(path.dirname(filename), { recursive: true, mode: 0o755 });
    await writeFile(filename, bytes, { mode });
    await chmod(filename, mode);
    return filename;
  }
  return { temporary, sourceDir, destination, file };
}

async function entries(file) {
  const result = new Map();
  await list({ file, onReadEntry(entry) {
    const data = [];
    const record = { mode: entry.mode & 0o7777, type: entry.type, linkpath: entry.linkpath };
    result.set(entry.path, record);
    entry.on('data', bytes => data.push(bytes));
    entry.on('end', () => { record.bytes = Buffer.concat(data); });
  } });
  return result;
}

function headers(archive) {
  const tar = gunzipSync(archive), result = [];
  for (let offset = 0; offset + 512 <= tar.length; ) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every(byte => byte === 0)) break;
    const size = parseInt(header.subarray(124, 136).toString().replace(/\0/g, '').trim(), 8) || 0;
    result.push({ header, type: header.subarray(156, 157).toString(), body: tar.subarray(offset + 512, offset + 512 + size) });
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  return result;
}

test('portable source archive preserves bytes, executable mode, license, hardlinks and long PAX paths', async t => {
  const f = await fixture(t);
  await f.file('LICENSE', 'Upstream copyright and license\n');
  await f.file('run.sh', '#!/bin/sh\nexit 0\n', 0o755);
  await f.file('@ordinary-file', 'This is source, not an imported tar.\n');
  const long = `${'long-name-'.repeat(22)}.txt`;
  const bytes = Buffer.from([0, 255, 2, 13, 10, 0, 42]);
  await f.file(long, bytes);
  await link(path.join(f.sourceDir, 'LICENSE'), path.join(f.sourceDir, 'LICENSE-copy'));
  const result = await createSourceArchive(f);
  assert.equal(result.entryCount, 6);
  assert.equal(result.excludedMetadataCount, 0);
  const output = await entries(f.destination);
  const prefix = path.basename(f.sourceDir) + '/';
  assert.deepEqual(output.get(prefix + long).bytes, bytes);
  assert.equal(output.get(prefix + 'LICENSE').bytes.toString(), 'Upstream copyright and license\n');
  assert.equal(output.get(prefix + 'LICENSE').mode, 0o644);
  assert.equal(output.get(prefix + 'run.sh').mode, 0o755);
  assert.equal(output.get(prefix + '@ordinary-file').bytes.toString(), 'This is source, not an imported tar.\n');
  assert.equal(output.get(prefix + 'LICENSE-copy').type, 'Link');
  assert.equal(output.get(prefix + 'LICENSE-copy').linkpath, prefix + 'LICENSE');
  assert.ok(headers(await readFile(f.destination)).some(entry => entry.type === 'x' && entry.body.includes(Buffer.from(long))));
  assert.equal((await inspectSourceArchive(f.destination)).verified, true);
});

test('magic-confirmed AppleDouble sidecars are excluded without deleting source files', async t => {
  const f = await fixture(t);
  const appleDouble = Buffer.from([0, 5, 22, 7, 0, 2, 0, 0, 0]);
  await f.file('._metadata', appleDouble);
  await f.file('LICENSE', 'License preserved.\n');
  const report = await createSourceArchive(f);
  assert.equal(report.excludedMetadataCount, 1);
  const output = await entries(f.destination), prefix = path.basename(f.sourceDir) + '/';
  assert.equal(output.has(prefix + '._metadata'), false);
  assert.equal(output.get(prefix + 'LICENSE').bytes.toString(), 'License preserved.\n');
  assert.deepEqual(await readFile(path.join(f.sourceDir, '._metadata')), appleDouble, 'source metadata is not deleted');
  assert.equal((await inspectSourceArchive(f.destination)).verified, true);
});

test('ambiguous macOS metadata names are refused without discarding genuine source', async t => {
  for (const [name, bytes] of [
    ['._real-source', Buffer.from('module.exports = true;\n')],
    ['._short', Buffer.from([0, 5, 22])],
    ['._not-AppleDouble', Buffer.from([0, 5, 22, 7, 0, 3, 0, 0])],
    ['__MACOSX/source.txt', Buffer.from('genuine source')],
  ]) {
    const f = await fixture(t), filename = await f.file(name, bytes);
    await assert.rejects(createSourceArchive(f), { code: 'ARCHIVE_MACOS_METADATA_NAME' });
    assert.deepEqual(await readFile(filename), bytes);
    assert.equal((await readdir(f.temporary)).includes('source.tar.gz'), false);
  }
});

test('safe relative symlinks retain their targets and long linkpath PAX when their mode is representable', async t => {
  const f = await fixture(t), target = `${'target-'.repeat(20)}.txt`;
  await f.file(target, 'linked source\n');
  const filename = path.join(f.sourceDir, 'source-link');
  await symlink(target, filename);
  if (process.platform === 'darwin') await lchmod(filename, 0o755);
  const mode = (await lstat(filename)).mode & 0o7777;
  if (mode !== ((mode | 0o600) & ~0o22)) {
    await assert.rejects(createSourceArchive(f), /cannot be preserved by portable tar/);
    assert.equal((await lstat(filename)).mode & 0o7777, mode);
    return;
  }
  await createSourceArchive(f);
  const output = await entries(f.destination), item = output.get(path.basename(f.sourceDir) + '/source-link');
  assert.equal(item.type, 'SymbolicLink');
  assert.equal(item.linkpath, target);
  assert.equal(item.mode, mode);
  assert.ok(headers(await readFile(f.destination)).some(entry => entry.type === 'x' && entry.body.includes(Buffer.from('linkpath=' + target))));
  assert.equal((await inspectSourceArchive(f.destination)).verified, true);
});

test('absolute, escaping and indirectly escaping symlinks are refused without following them', async t => {
  for (const kind of ['absolute', 'escape', 'indirect']) {
    const f = await fixture(t);
    const outside = path.join(f.temporary, 'outside');
    await mkdir(outside);
    await writeFile(path.join(outside, 'secret'), 'must not be archived');
    const target = kind === 'absolute' ? path.join(outside, 'secret') : kind === 'escape' ? '../outside/secret' : 'bridge/secret';
    if (kind === 'indirect') await symlink('../outside', path.join(f.sourceDir, 'bridge'));
    await symlink(target, path.join(f.sourceDir, 'source-link'));
    if (process.platform === 'darwin') {
      await lchmod(path.join(f.sourceDir, 'source-link'), 0o755);
      if (kind === 'indirect') await lchmod(path.join(f.sourceDir, 'bridge'), 0o755);
    }
    await assert.rejects(createSourceArchive(f), /symlink|cannot be preserved/);
    assert.equal((await readdir(f.temporary)).includes('source.tar.gz'), false);
    assert.equal(await readFile(path.join(outside, 'secret'), 'utf8'), 'must not be archived');
  }
});

test('read-only and group-writable modes are rejected rather than silently rewritten', async t => {
  for (const mode of [0o444, 0o664]) {
    const f = await fixture(t);
    const filename = await f.file('source.txt', 'mode must remain unchanged', mode);
    await assert.rejects(createSourceArchive(f), /cannot be preserved by portable tar/);
    assert.equal((await lstat(filename)).mode & 0o7777, mode);
    assert.equal(await readFile(filename, 'utf8'), 'mode must remain unchanged');
    assert.equal((await readdir(f.temporary)).includes('source.tar.gz'), false);
  }
});

test('archive is reproducible across timestamps and contains no owner, host time or device metadata', async t => {
  const f = await fixture(t);
  const filename = await f.file(`${'source-'.repeat(20)}.mjs`, 'export default 1;\n');
  await createSourceArchive(f);
  const first = await readFile(f.destination);
  await utimes(filename, new Date('2001-01-01T00:00:00Z'), new Date('2031-01-01T00:00:00Z'));
  await utimes(f.sourceDir, new Date('2002-01-01T00:00:00Z'), new Date('2032-01-01T00:00:00Z'));
  const secondPath = path.join(f.temporary, 'again.tar.gz');
  await createSourceArchive({ ...f, destination: secondPath });
  assert.deepEqual(await readFile(secondPath), first);
  assert.equal(first[9], 255, 'portable gzip has no host OS identifier');
  assert.equal(first.readUInt32LE(4), 0, 'gzip does not embed source mtime');
  for (const { header, type, body } of headers(first)) {
    for (const [start, end] of [[108, 124], [136, 148], [265, 329], [329, 345]]) {
      assert.ok(header.subarray(start, end).every(byte => byte === 0 || byte === 48 || byte === 32), 'owner/time/device header fields must be empty or zero');
    }
    if (type === 'x') {
      for (const record of body.toString().trimEnd().split('\n')) assert.match(record, /^\d+ (path|linkpath|size)=/);
    }
  }
});

test('existing destinations and destinations inside the input are preserved', async t => {
  const f = await fixture(t);
  await f.file('LICENSE', 'source');
  await writeFile(f.destination, 'existing archive');
  await assert.rejects(createSourceArchive(f), { code: 'EEXIST' });
  assert.equal(await readFile(f.destination, 'utf8'), 'existing archive');
  assert.equal((await readdir(f.temporary)).some(name => name.includes('.stage-')), false);
  await assert.rejects(createSourceArchive({ ...f, destination: path.join(f.sourceDir, 'archive.tar.gz') }), /outside the source tree/);
});
