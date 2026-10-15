import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { chmod, link, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, symlink, utimes, writeFile } from 'node:fs/promises';
import { claudeInstallationStatus, ensureClaudeInstallation, resolveClaudeInstallation } from '../electron/claude-code-installation.mjs';

const HOST_VERSION = '2.1.296';
const DOWNLOAD_VERSION = '2.1.301';
const DOWNLOAD_CONTEXT = { proxyUrl: 'http://fixture:synthetic-route@127.0.0.1:49123' };
const SYNTHETIC_AUTH = 'SYNTHETIC_AUTH_MARKER_MUST_NOT_BE_READ_OR_CHANGED';
const nativePlatform = ['darwin', 'linux'].includes(process.platform);

async function fixture(t) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-claude-install-source-')));
  await chmod(root, 0o700);
  t.after(() => rm(root, { recursive: true, force: true }));
  const home = path.join(root, 'environment-home');
  const hostDirectory = path.join(root, 'synthetic-host-versions');
  await mkdir(home, { mode: 0o700 });
  await mkdir(hostDirectory, { mode: 0o700 });
  // Copy known native bytes into fixtures; no fixture or actual CLI is run.
  const nativeBytes = await readFile('/usr/bin/true');
  const hostExecutable = path.join(hostDirectory, HOST_VERSION);
  await writeFile(hostExecutable, nativeBytes, { mode: 0o700 });
  return { root, home, hostExecutable, nativeBytes,
    entryPath: path.join(home, '.local', 'bin', 'claude'),
    versionsDirectory: path.join(home, '.local', 'share', 'claude', 'versions') };
}

function downloader(f, calls) {
  return async options => {
    calls.push(options);
    assert.equal(options.proxyUrl, DOWNLOAD_CONTEXT.proxyUrl);
    await writeFile(options.destination, f.nativeBytes, { mode: 0o600, flag: 'wx' });
    return { version: DOWNLOAD_VERSION, checksum: createHash('sha256').update(f.nativeBytes).digest('hex') };
  };
}

async function tree(root) {
  const entries = [];
  async function visit(filename, relative) {
    const info = await lstat(filename);
    entries.push({ relative, directory: info.isDirectory(), symlink: info.isSymbolicLink(),
      dev: info.dev, ino: info.ino, nlink: info.nlink, mode: info.mode, size: info.size, mtimeMs: info.mtimeMs });
    if (info.isDirectory()) for (const name of (await readdir(filename)).sort()) await visit(path.join(filename, name), path.join(relative, name));
  }
  await visit(root, '.');
  return entries;
}

function hasCode(code) {
  return error => {
    assert.equal(error.code, code);
    assert.equal(error.message.includes(SYNTHETIC_AUTH), false);
    return true;
  };
}

async function installationDirectories(f) {
  for (const relative of ['.local', '.local/bin', '.local/share', '.local/share/claude', '.local/share/claude/versions']) {
    await mkdir(path.join(f.home, relative), { mode: 0o700 });
  }
}

test('installation status for an empty environment creates no directories', { skip: !nativePlatform }, async t => {
  const f = await fixture(t);
  const before = await tree(f.home);
  assert.deepEqual(await claudeInstallationStatus({ home: f.home }), { installed: false });
  assert.deepEqual(await tree(f.home), before);
});

test('each valid source reuses the existing environment install before finding or downloading anything', { skip: !nativePlatform }, async t => {
  const f = await fixture(t);
  const installation = await ensureClaudeInstallation({ home: f.home, source: 'local', findHostExecutable: async () => f.hostExecutable });
  const executable = await resolveClaudeInstallation(installation);
  const before = await tree(f.home);
  let hostCalls = 0, downloadCalls = 0;
  for (const source of ['auto', 'download', 'local']) {
    const reused = await ensureClaudeInstallation({ home: f.home, source, downloadContext: DOWNLOAD_CONTEXT,
      findHostExecutable: async () => { hostCalls += 1; throw new Error('existing installs must not inspect the host'); },
      downloadNative: async () => { downloadCalls += 1; throw new Error('existing installs must not download'); } });
    assert.equal(await resolveClaudeInstallation(reused), executable);
  }
  assert.equal(hostCalls, 0);
  assert.equal(downloadCalls, 0);
  assert.equal((await claudeInstallationStatus({ home: f.home })).installed, true);
  assert.deepEqual(await tree(f.home), before);
});

test('download explicitly ignores an available host installation', { skip: !nativePlatform }, async t => {
  const f = await fixture(t);
  const downloads = [];
  let hostCalls = 0;
  const installation = await ensureClaudeInstallation({ home: f.home, source: 'download', downloadContext: DOWNLOAD_CONTEXT,
    findHostExecutable: async () => { hostCalls += 1; return f.hostExecutable; }, downloadNative: downloader(f, downloads) });
  assert.equal(hostCalls, 0);
  assert.equal(downloads.length, 1);
  const executable = await resolveClaudeInstallation(installation);
  assert.equal(path.basename(executable), DOWNLOAD_VERSION);
  assert.equal((await lstat(executable)).nlink, 1);
  assert.deepEqual(await readFile(executable), f.nativeBytes);
});

test('download requires an environment route and does not substitute a host copy', { skip: !nativePlatform }, async t => {
  const f = await fixture(t);
  let hostCalls = 0, downloadCalls = 0;
  await assert.rejects(ensureClaudeInstallation({ home: f.home, source: 'download',
    findHostExecutable: async () => { hostCalls += 1; return f.hostExecutable; },
    downloadNative: async () => { downloadCalls += 1; throw new Error('downloading without a route is forbidden'); } }),
  hasCode('CLAUDE_CODE_DOWNLOAD_ROUTE_REQUIRED'));
  assert.equal(hostCalls, 0);
  assert.equal(downloadCalls, 0);
  assert.deepEqual(await claudeInstallationStatus({ home: f.home }), { installed: false });
});

test('local copies the host native version into an independent environment inode without downloading', { skip: !nativePlatform }, async t => {
  const f = await fixture(t);
  let hostCalls = 0, downloadCalls = 0;
  const installation = await ensureClaudeInstallation({ home: f.home, source: 'local', downloadContext: DOWNLOAD_CONTEXT,
    findHostExecutable: async () => { hostCalls += 1; return f.hostExecutable; },
    downloadNative: async () => { downloadCalls += 1; throw new Error('local source must not download'); } });
  assert.equal(hostCalls, 1);
  assert.equal(downloadCalls, 0);
  const executable = await resolveClaudeInstallation(installation);
  assert.equal(path.basename(executable), HOST_VERSION);
  const host = await lstat(f.hostExecutable), copied = await lstat(executable);
  assert.equal(copied.nlink, 1);
  assert.equal(copied.dev === host.dev && copied.ino === host.ino, false);
  assert.deepEqual(await readFile(executable), f.nativeBytes);
  await writeFile(f.hostExecutable, 'changed synthetic host file');
  assert.deepEqual(await readFile(executable), f.nativeBytes, 'host changes cannot alter the environment copy');
});

test('local installation failure never falls back to download', { skip: !nativePlatform }, async t => {
  for (const kind of ['missing finder', 'not installed', 'non-native launcher']) {
    await t.test(kind, async subtest => {
      const f = await fixture(subtest);
      const launcherDirectory = path.join(f.root, 'synthetic-non-native-versions');
      await mkdir(launcherDirectory, { mode: 0o700 });
      const launcher = path.join(launcherDirectory, '2.1.999');
      await writeFile(launcher, '#!/bin/sh\nexit 0\n', { mode: 0o700 });
      let downloadCalls = 0;
      const findHostExecutable = kind === 'missing finder' ? undefined : kind === 'not installed'
        ? async () => { throw Object.assign(new Error('no synthetic host installation'), { code: 'CLAUDE_CODE_NOT_INSTALLED' }); }
        : async () => launcher;
      await assert.rejects(ensureClaudeInstallation({ home: f.home, source: 'local', findHostExecutable,
        downloadContext: DOWNLOAD_CONTEXT, downloadNative: async () => { downloadCalls += 1; throw new Error('local failure must not download'); } }),
      hasCode('CLAUDE_CODE_LOCAL_INSTALL_UNAVAILABLE'));
      assert.equal(downloadCalls, 0);
      assert.deepEqual(await claudeInstallationStatus({ home: f.home }), { installed: false });
    });
  }
});

test('omitted source and explicit auto retain local-first compatibility', { skip: !nativePlatform }, async t => {
  for (const source of [undefined, 'auto']) {
    await t.test(source ?? 'omitted', async subtest => {
      const f = await fixture(subtest);
      let downloadCalls = 0;
      const options = { home: f.home, findHostExecutable: async () => f.hostExecutable, downloadContext: DOWNLOAD_CONTEXT,
        downloadNative: async () => { downloadCalls += 1; throw new Error('available local source must be reused'); } };
      if (source !== undefined) options.source = source;
      const installation = await ensureClaudeInstallation(options);
      assert.equal(path.basename(await resolveClaudeInstallation(installation)), HOST_VERSION);
      assert.equal(downloadCalls, 0);
    });
  }
});

test('auto downloads through the supplied context when no local native version is available', { skip: !nativePlatform }, async t => {
  const f = await fixture(t);
  const downloads = [];
  let hostCalls = 0;
  const installation = await ensureClaudeInstallation({ home: f.home, source: 'auto', downloadContext: DOWNLOAD_CONTEXT,
    findHostExecutable: async () => { hostCalls += 1; throw Object.assign(new Error('not installed'), { code: 'CLAUDE_CODE_NOT_INSTALLED' }); },
    downloadNative: downloader(f, downloads) });
  assert.equal(hostCalls, 1);
  assert.equal(downloads.length, 1);
  assert.equal(path.basename(await resolveClaudeInstallation(installation)), DOWNLOAD_VERSION);
});

test('unknown source values fail before filesystem or installer side effects', { skip: !nativePlatform }, async t => {
  const f = await fixture(t);
  const before = await tree(f.home);
  let hostCalls = 0, downloadCalls = 0;
  for (const source of ['unknown', '', null, 42]) {
    await assert.rejects(ensureClaudeInstallation({ home: f.home, source, downloadContext: DOWNLOAD_CONTEXT,
      findHostExecutable: async () => { hostCalls += 1; return f.hostExecutable; },
      downloadNative: async () => { downloadCalls += 1; throw new Error('invalid source must not download'); } }),
    hasCode('CLAUDE_CODE_INSTALL_SOURCE_INVALID'));
  }
  assert.equal(hostCalls, 0);
  assert.equal(downloadCalls, 0);
  assert.deepEqual(await tree(f.home), before);
});

test('invalid existing entries and escaping links are status errors and never trigger replacement', { skip: !nativePlatform }, async t => {
  for (const kind of ['regular entry', 'escaping link', 'broken link']) {
    await t.test(kind, async subtest => {
      const f = await fixture(subtest);
      await installationDirectories(f);
      if (kind === 'regular entry') await writeFile(f.entryPath, '#!/bin/sh\nexit 0\n', { mode: 0o700 });
      else await symlink(kind === 'escaping link' ? f.hostExecutable : path.join(f.versionsDirectory, '0.0.0'), f.entryPath);
      const before = await tree(f.home);
      assert.deepEqual(await claudeInstallationStatus({ home: f.home }), { installed: false, errorCode: 'CLAUDE_CODE_INSTALLATION_INVALID' });
      let hostCalls = 0, downloadCalls = 0;
      for (const source of ['auto', 'download', 'local']) {
        await assert.rejects(ensureClaudeInstallation({ home: f.home, source, downloadContext: DOWNLOAD_CONTEXT,
          findHostExecutable: async () => { hostCalls += 1; return f.hostExecutable; },
          downloadNative: async () => { downloadCalls += 1; throw new Error('invalid existing install must not download'); } }),
        hasCode('CLAUDE_CODE_INSTALLATION_INVALID'));
      }
      assert.equal(hostCalls, 0);
      assert.equal(downloadCalls, 0);
      assert.deepEqual(await tree(f.home), before);
    });
  }
});

test('read-only status does not perform interrupted-publication recovery', { skip: !nativePlatform }, async t => {
  const f = await fixture(t);
  const installation = await ensureClaudeInstallation({ home: f.home, source: 'local', findHostExecutable: async () => f.hostExecutable });
  const executable = await resolveClaudeInstallation(installation);
  const staging = path.join(f.versionsDirectory, '.envara-bootstrap-aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee');
  await link(executable, staging);
  const before = await tree(f.home);
  assert.deepEqual(await claudeInstallationStatus({ home: f.home }), { installed: false, errorCode: 'CLAUDE_CODE_INSTALLATION_INVALID' });
  assert.deepEqual(await tree(f.home), before);
  assert.equal((await lstat(staging)).nlink, 2);
});

test('installation sources and status leave synthetic existing authentication files untouched', { skip: !nativePlatform }, async t => {
  for (const source of ['local', 'download']) {
    await t.test(source, async subtest => {
      const f = await fixture(subtest);
      const authDirectory = path.join(f.home, '.claude');
      await mkdir(authDirectory, { mode: 0o700 });
      const markers = [path.join(authDirectory, '.credentials.json'), path.join(f.home, '.claude.json')];
      for (const marker of markers) {
        await writeFile(marker, SYNTHETIC_AUTH, { mode: 0o600 });
        const oldTime = new Date('2001-01-01T00:00:00Z');
        await utimes(marker, oldTime, oldTime);
        await chmod(marker, 0o000);
      }
      const before = await Promise.all(markers.map(marker => lstat(marker)));
      assert.deepEqual(await claudeInstallationStatus({ home: f.home }), { installed: false });
      const downloads = [];
      await ensureClaudeInstallation({ home: f.home, source, findHostExecutable: async () => f.hostExecutable,
        downloadContext: DOWNLOAD_CONTEXT, downloadNative: downloader(f, downloads) });
      assert.equal((await claudeInstallationStatus({ home: f.home })).installed, true);
      assert.equal(downloads.length, source === 'download' ? 1 : 0);
      for (let index = 0; index < markers.length; index += 1) {
        const after = await lstat(markers[index]);
        for (const field of ['dev', 'ino', 'mode', 'size', 'mtimeMs', 'atimeMs']) assert.equal(after[field], before[index][field], `authentication ${field} changed`);
        await chmod(markers[index], 0o600);
        assert.equal(await readFile(markers[index], 'utf8'), SYNTHETIC_AUTH);
      }
    });
  }
});
