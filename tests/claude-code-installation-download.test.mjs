import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import fsPromises from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { chmod, copyFile, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import { ensureClaudeInstallation, resolveClaudeInstallation } from '../electron/claude-code-installation.mjs';

async function fixture(t) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-native-download-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  const home = path.join(root, 'home'); await mkdir(home, { mode: 0o700 });
  const binary = await readFile('/usr/bin/true'), checksum = createHash('sha256').update(binary).digest('hex');
  const proxyUrl = 'http://fixture:private-password@127.0.0.1:43731';
  const calls = [];
  const downloadNative = async options => {
    calls.push(options);
    await writeFile(options.destination, binary, { flag: 'wx', mode: 0o600 });
    return { version: '2.1.300', checksum, size: binary.length };
  };
  return { root, home, binary, calls, downloadNative, downloadContext: { proxyUrl },
    versions: path.join(home, '.local/share/claude/versions'), entry: path.join(home, '.local/bin/claude') };
}

test('a machine without Claude installs once from the selected route into the environment', async t => {
  const f = await fixture(t), progress = [];
  const request = { ...f, findHostExecutable: async () => { throw Object.assign(new Error('missing'), { code: 'CLAUDE_CODE_NOT_INSTALLED' }); }, onProgress: value => progress.push(value) };
  const results = await Promise.all(Array.from({ length: 5 }, () => ensureClaudeInstallation(request)));
  assert.equal(f.calls.length, 1); assert.equal(f.calls[0].proxyUrl, f.downloadContext.proxyUrl);
  assert.equal(await resolveClaudeInstallation(results[0]), path.join(f.versions, '2.1.300'));
  assert.deepEqual(await readdir(f.versions), ['2.1.300']);
  const info = await lstat(path.join(f.versions, '2.1.300'));
  assert.equal(info.mode & 0o777, 0o700); assert.equal(info.nlink, 1);
  assert.ok(progress.some(value => value.phase === 'installing'));
  assert.ok(!JSON.stringify(progress).includes('private-password'));
  await ensureClaudeInstallation({ home: f.home, findHostExecutable: async () => { throw new Error('host should not be read'); }, downloadNative: () => { throw new Error('download should not run'); } });
});

test('a script-only host falls back to official download rather than copying a launcher', async t => {
  const f = await fixture(t), script = path.join(f.root, '2.1.296');
  await writeFile(script, '#!/bin/sh\nexit 1\n', { mode: 0o700 });
  const installation = await ensureClaudeInstallation({ ...f, findHostExecutable: async () => script });
  assert.equal(f.calls.length, 1); assert.equal(await resolveClaudeInstallation(installation), path.join(f.versions, '2.1.300'));
});

test('a suitable native host is copied without any download', async t => {
  const f = await fixture(t), host = path.join(f.root, '2.1.296');
  await copyFile('/usr/bin/true', host); await chmod(host, 0o700);
  const installation = await ensureClaudeInstallation({ ...f, findHostExecutable: async () => host });
  assert.equal(f.calls.length, 0);
  assert.notEqual((await lstat(await resolveClaudeInstallation(installation))).ino, (await lstat(host)).ino);
});

test('failed or cancelled downloads leave no temporary file or native entry and can retry', async t => {
  for (const code of ['CLAUDE_CODE_DOWNLOAD_FAILED', 'CLAUDE_CODE_DOWNLOAD_CANCELLED']) {
    const f = await fixture(t);
    await assert.rejects(ensureClaudeInstallation({ ...f, downloadNative: async options => {
      await writeFile(options.destination, 'partial', { flag: 'wx', mode: 0o600 });
      throw Object.assign(new Error(code), { code });
    } }), { code });
    assert.deepEqual(await readdir(f.versions), []); await assert.rejects(lstat(f.entry), { code: 'ENOENT' });
    await ensureClaudeInstallation(f);
    assert.equal(await resolveClaudeInstallation({ home: f.home }), path.join(f.versions, '2.1.300'));
  }
});

test('download failure remains primary when staging cleanup fails and can be retried privately', async t => {
  const f = await fixture(t), originalRemove = fsPromises.rm;
  const primary = Object.assign(new Error('fixture download cancelled'), { code: 'CLAUDE_CODE_DOWNLOAD_CANCELLED' });
  let refuseCleanup = true, observed;
  t.mock.method(fsPromises, 'rm', async (filename, ...args) => {
    if (path.dirname(filename) === f.versions && path.basename(filename).startsWith('.envara-bootstrap-') && refuseCleanup)
      throw Object.assign(new Error('fixture private cleanup path'), { code: 'EACCES' });
    return originalRemove(filename, ...args);
  });
  syncBuiltinESMExports();
  try {
    await assert.rejects(ensureClaudeInstallation({ ...f, downloadNative: async options => {
      await writeFile(options.destination, 'partial', { flag: 'wx', mode: 0o600 });
      throw primary;
    } }), error => {
      observed = error;
      assert.equal(error, primary);
      assert.equal(error.code, 'CLAUDE_CODE_DOWNLOAD_CANCELLED');
      assert.equal(error.message, 'fixture download cancelled');
      assert.equal(error.cleanupError, 'Claude 安装临时文件清理未完成，请重试关闭会话。');
      assert.equal(typeof error.claudeCleanup, 'function');
      assert.equal(Object.getOwnPropertyDescriptor(error, 'claudeCleanup').enumerable, false);
      assert.equal(JSON.stringify(error).includes('fixture private cleanup path'), false);
      return true;
    });
    assert.equal((await readdir(f.versions)).length, 1);
    await assert.rejects(observed.claudeCleanup(), { code: 'EACCES' });
    refuseCleanup = false;
    await observed.claudeCleanup(); await observed.claudeCleanup();
    assert.deepEqual(await readdir(f.versions), []);
    await assert.rejects(lstat(f.entry), { code: 'ENOENT' });
    await ensureClaudeInstallation(f);
  } finally { t.mock.restoreAll(); syncBuiltinESMExports(); }
});

test('a final cleanup failure cannot turn an otherwise completed installation into success', async t => {
  const f = await fixture(t), originalRemove = fsPromises.rm;
  let stagingRemovals = 0, refuseCleanup = true, observed;
  t.mock.method(fsPromises, 'rm', async (filename, ...args) => {
    if (path.dirname(filename) === f.versions && path.basename(filename).startsWith('.envara-bootstrap-')) {
      stagingRemovals += 1;
      if (stagingRemovals >= 2 && refuseCleanup) throw Object.assign(new Error('fixture private final cleanup path'), { code: 'EACCES' });
    }
    return originalRemove(filename, ...args);
  });
  syncBuiltinESMExports();
  try {
    await assert.rejects(ensureClaudeInstallation(f), error => {
      observed = error;
      assert.equal(error.code, 'CLAUDE_CODE_INSTALLATION_CLEANUP_FAILED');
      assert.equal(error.message, 'Claude 安装临时文件清理未完成，请重试关闭会话。');
      assert.equal(error.cleanupError, error.message);
      assert.equal(Object.getOwnPropertyDescriptor(error, 'claudeCleanup').enumerable, false);
      assert.equal(JSON.stringify(error).includes('fixture private final cleanup path'), false);
      return true;
    });
    assert.equal(await resolveClaudeInstallation({ home: f.home }), path.join(f.versions, '2.1.300'));
    await assert.rejects(observed.claudeCleanup(), { code: 'EACCES' });
    refuseCleanup = false;
    await observed.claudeCleanup();
    await ensureClaudeInstallation(f);
  } finally { t.mock.restoreAll(); syncBuiltinESMExports(); }
});

test('cancellation after verification but before publication does not commit a native entry', async t => {
  const f = await fixture(t), controller = new AbortController();
  await assert.rejects(ensureClaudeInstallation({ ...f, downloadContext: { ...f.downloadContext, signal: controller.signal }, onProgress: () => controller.abort() }), { code: 'CLAUDE_CODE_DOWNLOAD_CANCELLED' });
  assert.deepEqual(await readdir(f.versions), []); await assert.rejects(lstat(f.entry), { code: 'ENOENT' });
});

test('a different pre-existing version file is preserved but never adopted after validating another binary', async t => {
  const f = await fixture(t);
  await mkdir(f.versions, { recursive: true, mode: 0o700 });
  const file = path.join(f.versions, '2.1.300'), changed = Buffer.concat([f.binary, Buffer.from('different fixture')]);
  await writeFile(file, changed, { mode: 0o700 });
  await assert.rejects(ensureClaudeInstallation(f), { code: 'CLAUDE_CODE_INSTALLATION_INVALID' });
  assert.deepEqual(await readFile(file), changed); await assert.rejects(lstat(f.entry), { code: 'ENOENT' });
  assert.deepEqual(await readdir(f.versions), ['2.1.300']);
});
