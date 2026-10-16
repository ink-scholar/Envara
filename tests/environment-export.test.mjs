import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { mkdir, mkdtemp, readFile, readdir, realpath, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { EXPORT_SCHEMA, isEnvironmentExport, readEnvironmentExport, writeEnvironmentExport } from '../electron/environment-export.mjs';

async function fixture(t) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-export-test-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  const browser = path.join(root, 'browser-data');
  await mkdir(path.join(browser, 'Default', 'Cache'), { recursive: true });
  await mkdir(path.join(browser, 'Default', 'Empty'), { recursive: true });
  await writeFile(path.join(browser, 'Default', 'Cookies'), Buffer.from([0, 1, 2, 255]));
  await writeFile(path.join(browser, 'Default', 'Cache', 'big'), 'cache');
  await writeFile(path.join(browser, 'run.sh'), '#!/bin/sh\n', { mode: 0o755 });
  await symlink('/etc/hosts', path.join(browser, 'outside'));
  const manifest = { schema: EXPORT_SCHEMA, version: 1, profile: { schema: 'envara.profiles', version: 2, profiles: [{ name: 'A' }] } };
  const sources = [{ section: 'browser', root: browser, exclude: (_relative, name) => name === 'Cache' },
    { section: 'terminal', root: path.join(root, 'missing') }];
  return { root, manifest, sources };
}

test('an export round-trips data, skips links and excluded names, and starts with its header', async t => {
  const f = await fixture(t), file = path.join(f.root, 'out.envara');
  const written = await writeEnvironmentExport({ file, password: 'correct horse', manifest: f.manifest, sources: f.sources });
  assert.equal(written.bytes, 4 + 10);
  assert.equal(await isEnvironmentExport(file), true);
  assert.equal((await stat(file)).mode & 0o777, 0o600);
  assert.equal((await readFile(file)).includes(Buffer.from('Cookies')), false, 'names are encrypted');
  const staging = path.join(f.root, 'staging');
  const manifest = await readEnvironmentExport({ file, password: 'correct horse', staging });
  assert.deepEqual(manifest, f.manifest);
  assert.deepEqual(await readFile(path.join(staging, 'browser', 'Default', 'Cookies')), Buffer.from([0, 1, 2, 255]));
  assert.deepEqual((await readdir(path.join(staging, 'browser', 'Default'))).sort(), ['Cookies', 'Empty']);
  assert.deepEqual((await readdir(path.join(staging, 'browser'))).sort(), ['Default', 'run.sh']);
  assert.equal((await stat(path.join(staging, 'browser', 'run.sh'))).mode & 0o777, 0o700);
  assert.equal((await stat(path.join(staging, 'browser', 'Default', 'Cookies'))).mode & 0o777, 0o600);
});

test('a wrong password or one altered byte stages nothing', async t => {
  const f = await fixture(t), file = path.join(f.root, 'out.envara');
  await writeEnvironmentExport({ file, password: 'correct horse', manifest: f.manifest, sources: f.sources });
  const staging = path.join(f.root, 'staging');
  await assert.rejects(readEnvironmentExport({ file, password: 'wrong horse', staging }), { code: 'EXPORT_PASSWORD_WRONG' });
  await assert.rejects(stat(staging), { code: 'ENOENT' });
  const bytes = await readFile(file); bytes[bytes.length - 20] ^= 1; await writeFile(file, bytes);
  await assert.rejects(readEnvironmentExport({ file, password: 'correct horse', staging }), { code: 'EXPORT_PASSWORD_WRONG' });
  await assert.rejects(stat(staging), { code: 'ENOENT' });
  await assert.rejects(writeEnvironmentExport({ file: path.join(f.root, 'short.envara'), password: 'short', manifest: f.manifest }), { code: 'EXPORT_PASSWORD_INVALID' });
  await writeFile(path.join(f.root, 'plain.json'), '{}');
  assert.equal(await isEnvironmentExport(path.join(f.root, 'plain.json')), false);
});

test('a valid large profile manifest remains readable and an oversized one never replaces a saved export', async t => {
  const f = await fixture(t), file = path.join(f.root, 'large.envara');
  const manifest = { ...f.manifest, profile: { ...f.manifest.profile, profiles: [{ name: 'A', fingerprint: { setting: 'x'.repeat(128 * 1024) } }] } };
  await writeEnvironmentExport({ file, password: 'correct horse', manifest });
  assert.deepEqual(await readEnvironmentExport({ file, password: 'correct horse', staging: path.join(f.root, 'large-staging') }), manifest);
  const previous = await readFile(file);
  await assert.rejects(writeEnvironmentExport({ file, password: 'correct horse', manifest: { ...manifest, extra: 'x'.repeat(1024 * 1024) } }), { code: 'EXPORT_TOO_LARGE' });
  assert.deepEqual(await readFile(file), previous);
  assert.equal((await readdir(f.root)).some(name => name.endsWith('.partial')), false);
});

test('short filesystem writes restore every authenticated byte instead of silently truncating it', async t => {
  const f = await fixture(t), file = path.join(f.root, 'short-write.envara'), staging = path.join(f.root, 'short-staging');
  await writeEnvironmentExport({ file, password: 'correct horse', manifest: f.manifest, sources: f.sources });
  const originalOpen = fs.promises.open;
  let shortWrites = 0;
  fs.promises.open = async (filename, ...args) => {
    const handle = await originalOpen(filename, ...args);
    if (!filename.startsWith(staging + path.sep)) return handle;
    return { close: () => handle.close(), write: buffer => {
      shortWrites++; return handle.write(buffer.subarray(0, Math.max(1, Math.floor(buffer.length / 2))));
    } };
  };
  syncBuiltinESMExports();
  try {
    await readEnvironmentExport({ file, password: 'correct horse', staging });
    assert.deepEqual(await readFile(path.join(staging, 'browser/Default/Cookies')), Buffer.from([0, 1, 2, 255]));
    assert.equal(await readFile(path.join(staging, 'browser/run.sh'), 'utf8'), '#!/bin/sh\n');
    assert(shortWrites > 2);
  } finally { fs.promises.open = originalOpen; syncBuiltinESMExports(); }
});

test('a staging write failure closes its plaintext handle before removing failed import data', async t => {
  const f = await fixture(t), file = path.join(f.root, 'failed-write.envara'), staging = path.join(f.root, 'failed-staging');
  await writeEnvironmentExport({ file, password: 'correct horse', manifest: f.manifest, sources: f.sources });
  const originalOpen = fs.promises.open, opened = [];
  let closed = 0;
  fs.promises.open = async (filename, ...args) => {
    const handle = await originalOpen(filename, ...args);
    if (!filename.startsWith(staging + path.sep)) return handle;
    opened.push(handle);
    return { close: () => { closed++; return handle.close(); }, write: async () => { throw Object.assign(new Error('synthetic disk failure'), { code: 'EIO' }); } };
  };
  syncBuiltinESMExports();
  try {
    await assert.rejects(readEnvironmentExport({ file, password: 'correct horse', staging }), { code: 'EXPORT_IO_FAILED' });
    assert.equal(closed, opened.length);
    assert.equal(opened.length, 1);
    await assert.rejects(stat(staging), { code: 'ENOENT' });
  } finally {
    fs.promises.open = originalOpen; syncBuiltinESMExports();
    for (const handle of opened) await handle.close().catch(() => {});
  }
});

test('unsupported source path names are refused before replacing an existing archive', async t => {
  const f = await fixture(t), file = path.join(f.root, 'path.envara');
  await writeFile(file, 'existing export');
  await writeFile(path.join(f.sources[0].root, 'unsupported\\name'), 'fixture');
  await assert.rejects(writeEnvironmentExport({ file, password: 'correct horse', manifest: f.manifest, sources: f.sources }), { code: 'EXPORT_SOURCE_INVALID' });
  assert.equal(await readFile(file, 'utf8'), 'existing export');
});
