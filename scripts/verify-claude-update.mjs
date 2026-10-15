/** Real native-CLI installation switching inside the existing offline acceptance
 * harness. This simulates the official updater's final version/link replacement;
 * it deliberately performs no official download, user login or inference. */
import assert from 'node:assert/strict';
import { createReadStream } from 'node:fs';
import { copyFile, lstat, readFile, readlink, realpath, rename, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { stripVTControlCharacters } from 'node:util';

const hashFile = async filename => {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(filename)) hash.update(chunk);
  return hash.digest('hex');
};
const nativeVersion = /\b(\d+\.\d+\.\d+)\s+\(Claude Code\)/g;
const linkTo = async (entry, target) => {
  const temporary = `${entry}.envara-verification-${randomBytes(6).toString('hex')}`;
  await symlink(target, temporary);
  await rename(temporary, entry);
};

export async function verifyClaudeUpdate({ updatedExecutable, hostExecutable, terminal, selected, other, created, workingDirectory, launches, output, waitFor, preparation, proof, check }) {
  assert(path.isAbsolute(updatedExecutable) && path.isAbsolute(hostExecutable));
  const installedHost = await realpath(hostExecutable);
  const hostBefore = await lstat(installedHost);
  const hostDigest = await hashFile(installedHost);
  const hostLink = path.join(path.dirname(path.dirname(path.dirname(path.dirname(installedHost)))), 'bin/claude');
  const hostLinkBefore = await readlink(hostLink).catch(() => null);
  const sourceInfo = await lstat(updatedExecutable);
  assert(sourceInfo.isFile() && sourceInfo.size > 1024 * 1024, 'Use a real installed native Claude binary, never a shell stub.');
  const sourceDigest = await hashFile(updatedExecutable);
  const dirs = await terminal.directories(selected.id);
  const localEntry = path.join(dirs.home, '.local/bin/claude');
  const initialTarget = await realpath(localEntry);
  assert(initialTarget.startsWith(dirs.home + path.sep), 'The environment executable must already be owned by its private home.');
  const initialInfo = await lstat(initialTarget);
  assert(initialInfo.isFile() && initialInfo.nlink === 1);
  assert(initialInfo.dev !== hostBefore.dev || initialInfo.ino !== hostBefore.ino, 'The environment installation must not be a hard link to the host binary.');
  assert.equal(await hashFile(initialTarget), hostDigest, 'The new environment must begin with an independent copy of the real host CLI.');
  const markerFile = path.join(dirs.claude, '.credentials.json');
  const syntheticLogin = JSON.stringify({ envaraVerification: { marker: randomBytes(24).toString('hex'), note: 'Synthetic storage sentinel; no real account credentials.' } }) + '\n';
  await writeFile(markerFile, syntheticLogin, { mode: 0o600, flag: 'wx' });
  const originalBinding = preparation(terminal, created.sessionId);
  const originalToken = originalBinding.environment.ENVARA_BROWSER_TOKEN;
  const originalMcp = originalBinding.args[originalBinding.args.indexOf('--mcp-config') + 1];
  const originalConfig = await readFile(originalMcp, 'utf8');
  const originalPid = terminal.sessions.get(created.sessionId).pty?.pid;
  assert(Number.isInteger(originalPid) && originalPid > 0);
  const versions = async session => {
    const from = output.get(session.sessionId)?.length ?? 0;
    const marker = `ENVARA_UPDATE_${randomBytes(8).toString('hex')}`;
    await terminal.write({ sessionId: session.sessionId, data: `claude --version; envara_status=$?; printf '\\n${marker}:%s\\n' "$envara_status"\r` });
    let segment;
    await waitFor(() => { segment = stripVTControlCharacters((output.get(session.sessionId) ?? '').slice(from)); return new RegExp(`(?:^|[\\r\\n])${marker}:([0-9]+)(?:[\\r\\n])`).test(segment); }, 'The real Claude version invocation did not return to its existing shell.', 30000);
    const status = Number(segment.match(new RegExp(`(?:^|[\\r\\n])${marker}:([0-9]+)(?:[\\r\\n])`))[1]);
    return { status, versions: [...segment.matchAll(nativeVersion)].map(match => match[1]), text: segment };
  };
  const expectVersion = async (session, version) => {
    const result = await versions(session);
    assert.equal(result.status, 0, 'The native CLI --version must succeed.');
    assert.deepEqual(result.versions, [version]);
    return version;
  };
  let otherSession, reopened;
  try {
    await expectVersion(created, '2.1.296');
    otherSession = await terminal.create({ id: other.id, directory: workingDirectory, kind: 'claude-code', browserProfileId: other.id, claudeInstallSource: 'local', fresh: true });
    await expectVersion(otherSession, '2.1.296');
    const otherDirs = await terminal.directories(other.id);
    const otherEntry = path.join(otherDirs.home, '.local/bin/claude');
    const otherTarget = await realpath(otherEntry);
    assert.notEqual(otherTarget, initialTarget);
    const otherBefore = await lstat(otherTarget), otherLinkBefore = await readlink(otherEntry), otherDigest = await hashFile(otherTarget);
    const upgraded = path.join(path.dirname(initialTarget), '2.1.300');
    await copyFile(updatedExecutable, upgraded);
    const upgradedInfo = await lstat(upgraded);
    assert(upgradedInfo.isFile() && upgradedInfo.nlink === 1 && (upgradedInfo.dev !== sourceInfo.dev || upgradedInfo.ino !== sourceInfo.ino));
    assert.equal(await hashFile(upgraded), sourceDigest);
    await linkTo(localEntry, upgraded);
    await expectVersion(created, '2.1.300');
    assert.equal(preparation(terminal, created.sessionId).environment.ENVARA_BROWSER_TOKEN, originalToken);
    assert.equal(await readFile(originalMcp, 'utf8'), originalConfig);
    assert.equal(terminal.metadata(terminal.sessions.get(created.sessionId)).networkFence, true);
    assert.equal(terminal.metadata(terminal.sessions.get(created.sessionId)).browserProfileId, selected.id);
    assert.equal(terminal.sessions.get(created.sessionId).pty?.pid, originalPid);
    assert.equal(await readFile(markerFile, 'utf8'), syntheticLogin);
    check('Switching the private native installation from real Claude 2.1.296 to 2.1.300 makes the same shell use 2.1.300 on its next command, retaining its browser binding, configuration, network fence and synthetic login-storage sentinel.');
    reopened = await terminal.create({ id: selected.id, directory: workingDirectory, kind: 'claude-code', browserProfileId: selected.id, claudeInstallSource: 'local', fresh: true });
    await expectVersion(reopened, '2.1.300');
    assert.equal(preparation(terminal, reopened.sessionId).environment.CLAUDE_CONFIG_DIR, originalBinding.environment.CLAUDE_CONFIG_DIR);
    assert.equal(await readFile(markerFile, 'utf8'), syntheticLogin);
    await terminal.close({ sessionId: reopened.sessionId }); reopened = null;
    check('A fresh shell in the same environment uses the persisted 2.1.300 installation and unchanged configuration directory.');
    await linkTo(localEntry, path.join(path.dirname(initialTarget), 'missing-owned-version'));
    const refused = await versions(created);
    assert.equal(refused.status, 126, 'A broken environment-native entry must be refused.');
    assert.match(refused.text, /CLAUDE_CODE_INSTALLATION_INVALID/);
    assert.deepEqual(refused.versions, [], 'A broken local installation must never silently fall back to host Claude.');
    await linkTo(localEntry, upgraded);
    await expectVersion(created, '2.1.300');
    await expectVersion(otherSession, '2.1.296');
    assert.equal(await realpath(otherEntry), otherTarget); assert.equal(await readlink(otherEntry), otherLinkBefore);
    assert.equal(await hashFile(otherTarget), otherDigest);
    const otherAfter = await lstat(otherTarget); assert.equal(otherAfter.ino, otherBefore.ino); assert.equal(otherAfter.mtimeMs, otherBefore.mtimeMs);
    assert.equal(await hashFile(installedHost), hostDigest);
    const hostAfter = await lstat(installedHost); assert.equal(hostAfter.ino, hostBefore.ino); assert.equal(hostAfter.mtimeMs, hostBefore.mtimeMs);
    assert.equal(await readlink(hostLink).catch(() => null), hostLinkBefore);
    assert.equal(await readFile(markerFile, 'utf8'), syntheticLogin);
    check('A broken environment entry is refused without host fallback; restoring it resumes 2.1.300 while the real host installation and another environment remain unchanged at 2.1.296.');
    proof.nativeUpdate = { mode: 'owned-final-installation-switch-simulation', before: '2.1.296', after: '2.1.300', reopened: '2.1.300', otherEnvironment: '2.1.296', hostUnchanged: true,
      copiedHostSha256: hostDigest, copiedUpdateSha256: sourceDigest, sameShell: true, brokenLinkRefused: true, syntheticLoginUnchanged: true,
      officialDownloadTested: false, actualAuthenticatedLoginTested: false };
    proof.limitations.push('Native update acceptance swaps an owned version link between two real official CLI binaries. No official update download or real authenticated login persistence is tested.');
    return { markerFile, syntheticLogin, verifyAfterClosing: async () => {
      const restored = await terminal.create({ id: selected.id, directory: workingDirectory, kind: 'claude-code', browserProfileId: selected.id, claudeInstallSource: 'local', fresh: true });
      try {
        await expectVersion(restored, '2.1.300');
        assert.equal(await readFile(markerFile, 'utf8'), syntheticLogin);
        check('After the original terminal closes, reopening the environment still uses 2.1.300 and preserves its synthetic login-storage sentinel.');
      } finally { await terminal.close({ sessionId: restored.sessionId }); }
    } };
  } finally {
    if (reopened) await terminal.close({ sessionId: reopened.sessionId });
    if (otherSession) await terminal.close({ sessionId: otherSession.sessionId });
  }
}
