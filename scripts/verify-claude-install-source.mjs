/** Installation-source acceptance using an already verified native Claude binary.
 * All homes and configuration markers belong to this fixture. No host discovery,
 * native CLI execution, browser operation or network request is performed here.
 */
import assert from 'node:assert/strict';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { lstat, mkdir, readFile, readdir, readlink, realpath, rm, symlink, writeFile } from 'node:fs/promises';

const DOWNLOAD_CONTEXT = Object.freeze({ proxyUrl: 'http://source-selection:fixture-only@127.0.0.1:49123' });
const CONFIGURATION_MARKER = JSON.stringify({ synthetic: 'ENVARA_SOURCE_SELECTION_CONFIGURATION_MUST_REMAIN_UNCHANGED' }) + '\n';

async function digest(filename) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(filename)) hash.update(chunk);
  return hash.digest('hex');
}

// atime is deliberately excluded: reads may update it. Everything that could
// indicate a write, replacement, permission change or link repair is retained.
async function tree(root) {
  const entries = [];
  async function visit(filename, relative) {
    let info;
    try { info = await lstat(filename); }
    catch (error) { if (error.code === 'ENOENT') { entries.push({ relative, missing: true }); return; } throw error; }
    const entry = { relative, directory: info.isDirectory(), symlink: info.isSymbolicLink(),
      dev: info.dev, ino: info.ino, nlink: info.nlink, mode: info.mode, size: info.size,
      mtimeMs: info.mtimeMs, ctimeMs: info.ctimeMs };
    if (info.isSymbolicLink()) entry.target = await readlink(filename);
    entries.push(entry);
    if (info.isDirectory()) for (const name of (await readdir(filename)).sort()) await visit(path.join(filename, name), path.join(relative, name));
  }
  await visit(root, '.');
  return entries;
}

async function assertUnpublished(home) {
  await assert.rejects(lstat(path.join(home, '.local/bin/claude')), { code: 'ENOENT' });
  assert.deepEqual(await readdir(path.join(home, '.local/share/claude/versions')), [],
    'A refused local source must leave no native version or staging file.');
}

export async function verifyClaudeInstallSource({ ensureClaudeInstallation, claudeInstallationStatus, executable, temporary, proof, check }) {
  assert.equal(typeof ensureClaudeInstallation, 'function');
  assert.equal(typeof claudeInstallationStatus, 'function');
  assert(path.isAbsolute(executable), 'Pass the previously verified real native binary.');
  assert(path.isAbsolute(temporary), 'The verification fixture needs an owned absolute temporary directory.');
  const canonical = await realpath(executable), version = path.basename(canonical);
  assert(/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(version));
  const original = await lstat(canonical), checksum = await digest(canonical);
  assert(original.isFile() && !original.isSymbolicLink());

  const root = path.join(temporary, 'source-selection');
  await mkdir(root, { mode: 0o700 });
  const evidence = proof.installSourceSelection = { passed: false, mode: 'owned-local-source-selection-fixture', version, checksum,
    binaryProvenance: 'Previously downloaded genuine native binary supplied by the acceptance harness; this verifier does not independently verify its signature.',
    localDownloadCalls: 0, reuseHostCalls: 0, reuseDownloadCalls: 0, statusDownloadCalls: 0, unavailableLocalSources: [], statusCases: [] };
  const makeHome = async name => {
    const home = path.join(root, name);
    await mkdir(home, { mode: 0o700 });
    return home;
  };
  const inspectStatus = async (name, home, expected) => {
    const before = await tree(home);
    const status = await claudeInstallationStatus({ home, downloadContext: DOWNLOAD_CONTEXT,
      downloadNative: async () => { evidence.statusDownloadCalls++; throw new Error('A read-only status check must not download.'); } });
    assert.deepEqual(status, expected);
    assert.deepEqual(await tree(home), before, 'Status must not initialize directories, replace entries or repair an installation.');
    assert.equal(evidence.statusDownloadCalls, 0);
    evidence.statusCases.push({ name, ...status, treeUnchanged: true });
  };

  try {
    await inspectStatus('missing-home', path.join(root, 'missing-home'), { installed: false });
    const empty = await makeHome('empty-home');
    await inspectStatus('empty-home', empty, { installed: false });
    await mkdir(path.join(empty, '.local'), { mode: 0o700 });
    await inspectStatus('partial-directories', empty, { installed: false });
    check('Claude installation status leaves missing homes, empty homes and partial installation directories unchanged, with no downloader call.');

    const home = await makeHome('local-home');
    await mkdir(path.join(home, '.claude'), { mode: 0o700 });
    const configuration = [path.join(home, '.claude/settings.json'), path.join(home, '.claude.json')];
    for (const filename of configuration) await writeFile(filename, CONFIGURATION_MARKER, { mode: 0o600, flag: 'wx' });
    const configurationBefore = await Promise.all(configuration.map(filename => tree(filename)));
    let localHostCalls = 0;
    const installation = await ensureClaudeInstallation({ home, source: 'local', downloadContext: DOWNLOAD_CONTEXT,
      findHostExecutable: async () => { localHostCalls++; return canonical; },
      downloadNative: async () => { evidence.localDownloadCalls++; throw new Error('An explicit local source must never download.'); } });
    const installed = await realpath(installation.entryPath), copied = await lstat(installed);
    assert.equal(localHostCalls, 1);
    assert.equal(evidence.localDownloadCalls, 0);
    assert.equal(path.basename(installed), version);
    assert.equal(path.dirname(installed), installation.versionsDirectory);
    assert.equal(copied.nlink, 1);
    assert.equal(copied.dev === original.dev && copied.ino === original.ino, false);
    assert.equal(await digest(installed), checksum);
    assert.deepEqual(await readdir(installation.versionsDirectory), [version]);
    evidence.localCopy = { hostCalls: localHostCalls, independentInode: true, nlink: copied.nlink, checksumMatches: true, downloadCalls: evidence.localDownloadCalls };
    check('Explicit local installation copies the genuine native Claude binary into an independent single-link inode with the same SHA-256, without downloading despite a supplied route.');

    const installedBefore = await tree(home);
    for (const source of ['download', 'local']) {
      const reused = await ensureClaudeInstallation({ home, source, downloadContext: DOWNLOAD_CONTEXT,
        findHostExecutable: async () => { evidence.reuseHostCalls++; throw new Error('An existing install must not inspect the host.'); },
        downloadNative: async () => { evidence.reuseDownloadCalls++; throw new Error('An existing install must not download.'); } });
      assert.deepEqual(reused, installation);
      assert.equal(await realpath(reused.entryPath), installed);
      assert.deepEqual(await tree(home), installedBefore);
    }
    assert.equal(evidence.reuseHostCalls, 0);
    assert.equal(evidence.reuseDownloadCalls, 0);
    for (let index = 0; index < configuration.length; index++) {
      assert.equal(await readFile(configuration[index], 'utf8'), CONFIGURATION_MARKER);
      assert.deepEqual(await tree(configuration[index]), configurationBefore[index]);
    }
    evidence.reusedSources = ['download', 'local'];
    evidence.syntheticConfigurationUnchanged = true;
    check('Both explicit download and local sources reuse a valid environment install without host lookup, download or changes to synthetic configuration.');

    for (const [name, finder] of [
      ['finder-omitted', undefined],
      ['finder-empty', async () => undefined],
      ['finder-unavailable', async () => { throw Object.assign(new Error('The fixture has no host install.'), { code: 'CLAUDE_CODE_NOT_INSTALLED' }); }],
    ]) {
      const missingHome = await makeHome(name);
      let downloadCalls = 0;
      await assert.rejects(ensureClaudeInstallation({ home: missingHome, source: 'local', downloadContext: DOWNLOAD_CONTEXT,
        ...(finder ? { findHostExecutable: finder } : {}),
        downloadNative: async () => { downloadCalls++; throw new Error('Unavailable local source must not fall back to download.'); } }),
      { code: 'CLAUDE_CODE_LOCAL_INSTALL_UNAVAILABLE' });
      assert.equal(downloadCalls, 0);
      await assertUnpublished(missingHome);
      evidence.unavailableLocalSources.push({ name, errorCode: 'CLAUDE_CODE_LOCAL_INSTALL_UNAVAILABLE', downloadCalls, noEntryOrStaging: true });
    }
    check('Missing, empty and unavailable local finders refuse with CLAUDE_CODE_LOCAL_INSTALL_UNAVAILABLE, with zero downloads and no installed entry or staging file.');

    await inspectStatus('valid-installation', home, { installed: true });
    check('Read-only Claude installation status recognizes the real native installation without changing its files.');
    await rm(installation.entryPath);
    await inspectStatus('missing-entry-with-retained-version', home, { installed: false });
    await symlink('../share/claude/versions/0.0.0', installation.entryPath);
    await inspectStatus('broken-entry-with-retained-version', home, { installed: false, errorCode: 'CLAUDE_CODE_INSTALLATION_INVALID' });
    assert.equal(await digest(installed), checksum);
    assert.equal(evidence.statusDownloadCalls, 0);
    check('Missing and broken installation entries remain uninstalled and unrepaired during status checks; the broken entry reports CLAUDE_CODE_INSTALLATION_INVALID.');

    const originalAfter = await lstat(canonical);
    for (const field of ['dev', 'ino', 'nlink', 'size', 'mode', 'mtimeMs', 'ctimeMs']) assert.equal(originalAfter[field], original[field], `The supplied binary's ${field} must remain unchanged.`);
    assert.equal(await digest(canonical), checksum);
    evidence.sourceBinaryUnchanged = true;
    evidence.passed = true;
  } finally {
    await rm(root, { recursive: true, force: true });
    evidence.temporaryFixtureRemoved = true;
  }
}
