/** Named Claude login-profile acceptance inside the isolated terminal harness.
 * Uses synthetic storage sentinels and idle native shells only: no user account,
 * authentication, inference, browser navigation or public download is exercised.
 */
import assert from 'node:assert/strict';
import { access, readFile, realpath, writeFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';

export async function verifyClaudeAccounts({ terminal, selected, other, created, launches, workingDirectory, preparation, assertIdleClaudeShell, proof, check }) {
  // Refuse to place even a synthetic marker in a non-fixture account directory.
  const temporaryRoot = await realpath(os.tmpdir());
  const fixtureRoot = await realpath(path.dirname(workingDirectory));
  assert.equal(path.dirname(fixtureRoot), temporaryRoot);
  assert(path.basename(fixtureRoot).startsWith('envara-claude-check-'));
  assert((await realpath(terminal.root)).startsWith(fixtureRoot + path.sep));
  assert.notEqual(selected.id, other.id);
  assert.equal(created.claudeAccountId, 'default');
  assert.equal(terminal.sessions.get(created.sessionId)?.status, 'running');

  const initialSessions = new Set(terminal.sessions.keys());
  const defaultPrepared = preparation(terminal, created.sessionId);
  const defaultDirectories = await terminal.directories(selected.id);
  const markerName = `.envara-account-verification-${randomBytes(12).toString('hex')}.json`;
  const defaultMarker = path.join(defaultDirectories.claude, markerName);
  const defaultSentinel = JSON.stringify({ verificationOnly: true, account: 'default', marker: randomBytes(24).toString('hex') }) + '\n';
  assert.equal(defaultDirectories.claude, path.join(defaultDirectories.root, 'claude'), 'The default profile must retain the original Claude directory.');
  assert.equal(defaultPrepared.environment.CLAUDE_CONFIG_DIR, defaultDirectories.claude);
  await writeFile(defaultMarker, defaultSentinel, { mode: 0o600, flag: 'wx' });

  const launchFor = session => {
    const pid = terminal.sessions.get(session.sessionId)?.pty?.pid;
    assert(Number.isInteger(pid) && pid > 0, 'An accepted session must have a real PTY process.');
    const launch = launches.find(item => item.pid === pid);
    assert(launch, 'The session process must belong to the harness launch record.');
    return launch;
  };
  const start = accountId => terminal.create({ id: selected.id, directory: workingDirectory, kind: 'claude-code', browserProfileId: selected.id, claudeAccountId: accountId, claudeInstallSource: 'local', fresh: true });
  const accountRow = async accountId => (await terminal.listClaudeAccounts({ id: selected.id })).accounts.find(account => account.id === accountId);
  const assertNamedSession = async (session, account, directories) => {
    assert.equal(session.kind, 'claude-code');
    assert.equal(session.profileId, selected.id);
    assert.equal(session.browserProfileId, selected.id);
    assert.equal(session.networkFence, true);
    assert.equal(session.cwd, workingDirectory);
    assert.equal(session.claudeAccountId, account.id);
    assert.equal(session.claudeAccountName, account.name);
    assert.equal(session.claudeInstallSource, 'local');
    assert.equal(session.claudeInstall, undefined, 'An existing shared installation must be reused without installation progress.');
    const launch = launchFor(session);
    const prepared = preparation(terminal, session.sessionId);
    assert.equal(launch.options.env.CLAUDE_CONFIG_DIR, directories.claude);
    assert.equal(launch.options.env.HOME, defaultDirectories.home);
    assert.equal(launch.options.env.HISTFILE, defaultDirectories.history);
    assert.equal(prepared.installation.entryPath, defaultPrepared.installation.entryPath, 'Login profiles in one environment must share its managed installation.');
    assert.equal(await realpath(prepared.installation.entryPath), await realpath(defaultPrepared.installation.entryPath));
    assert.notEqual(prepared.environment.ENVARA_BROWSER_TOKEN, defaultPrepared.environment.ENVARA_BROWSER_TOKEN);
    await assertIdleClaudeShell(terminal, session, launch);
    const snapshot = await terminal.snapshot({ id: selected.id });
    const visible = snapshot.profiles.find(profile => profile.profileId === selected.id)?.sessions.find(item => item.sessionId === session.sessionId);
    assert.equal(visible?.claudeAccountId, account.id);
    assert.equal(visible?.claudeAccountName, account.name);
    assert.equal(visible?.claudeInstallSource, 'local');
    assert.equal(visible?.claudeInstall, undefined);
    return { launch, prepared };
  };
  let failure;
  try {
    assert.equal((await accountRow('default')).inUse, true);
    const name = `Acceptance ${randomBytes(6).toString('hex')}`;
    const { account } = await terminal.createClaudeAccount({ id: selected.id, name });
    assert.match(account.id, /^account_[a-f0-9]{32}$/);
    assert.equal(account.name, name); assert.equal(account.default, false); assert.equal(account.inUse, false);
    const namedDirectories = await terminal.directories(selected.id, account.id);
    assert.notEqual(namedDirectories.claude, defaultDirectories.claude);
    assert.equal(namedDirectories.claude, path.join(defaultDirectories.root, 'claude-accounts', account.id));
    for (const key of ['root', 'home', 'config', 'cache', 'data', 'state', 'temp', 'history']) assert.equal(namedDirectories[key], defaultDirectories[key]);
    const namedMarker = path.join(namedDirectories.claude, markerName);
    await assert.rejects(access(namedMarker), { code: 'ENOENT' }, 'A new account must not copy the default account sentinel.');
    const namedSentinel = JSON.stringify({ verificationOnly: true, account: 'named', marker: randomBytes(24).toString('hex') }) + '\n';
    await writeFile(namedMarker, namedSentinel, { mode: 0o600, flag: 'wx' });
    const assertMarkers = async () => {
      assert.equal(await readFile(defaultMarker, 'utf8'), defaultSentinel);
      assert.equal(await readFile(namedMarker, 'utf8'), namedSentinel);
    };

    const named = await start(account.id);
    const namedState = await assertNamedSession(named, account, namedDirectories);
    assert.notEqual(namedState.launch.pid, launchFor(created).pid);
    assert.equal((await accountRow(account.id)).inUse, true);
    await assertMarkers();
    check('A named Claude login profile has a separate configuration directory without copying the default sentinel, while sharing its environment home, history, managed installation and bound browser; its explicit local source reuses that installation without installation progress.');

    const duplicate = await terminal.duplicate({ sessionId: named.sessionId });
    const duplicateState = await assertNamedSession(duplicate, account, namedDirectories);
    assert.notEqual(duplicate.sessionId, named.sessionId);
    assert.notEqual(duplicateState.launch.pid, namedState.launch.pid);
    assert.notEqual(duplicateState.prepared.environment.ENVARA_BROWSER_TOKEN, namedState.prepared.environment.ENVARA_BROWSER_TOKEN);
    assert.equal(duplicateState.launch.options.env.CLAUDE_CONFIG_DIR, namedState.launch.options.env.CLAUDE_CONFIG_DIR);
    await assert.rejects(terminal.renameClaudeAccount({ id: selected.id, accountId: account.id, name: `${name} renamed` }), { code: 'CLAUDE_ACCOUNT_IN_USE' });
    await terminal.close({ sessionId: named.sessionId });
    assert.equal((await accountRow(account.id)).inUse, true, 'A remaining duplicate must keep the account in use.');
    await assert.rejects(terminal.renameClaudeAccount({ id: selected.id, accountId: account.id, name: `${name} renamed` }), { code: 'CLAUDE_ACCOUNT_IN_USE' });
    assert.equal((await accountRow(account.id)).name, name, 'A refused rename must leave the existing name intact.');
    await terminal.close({ sessionId: duplicate.sessionId });
    assert.equal((await accountRow(account.id)).inUse, false);
    check('Duplicating a named-profile terminal creates an independent idle process and browser token, retains its login-profile metadata, and blocks renaming until every using session closes.');

    const renamedName = `${name} renamed`;
    const { account: renamed } = await terminal.renameClaudeAccount({ id: selected.id, accountId: account.id, name: renamedName });
    assert.equal(renamed.id, account.id); assert.equal(renamed.name, renamedName); assert.equal(renamed.inUse, false);
    // Reload through the actual source or packaged class used by this service.
    const reloadedStore = new terminal.claudeAccounts.constructor({ root: terminal.root });
    assert.equal((await reloadedStore.get(selected.id, account.id)).name, renamedName);
    const reopened = await start(account.id);
    const reopenedState = await assertNamedSession(reopened, renamed, namedDirectories);
    assert.notEqual(reopenedState.launch.pid, namedState.launch.pid);
    await assertMarkers();
    await terminal.close({ sessionId: reopened.sessionId });
    const reopenedDefault = await start('default');
    assert.equal(reopenedDefault.claudeAccountId, 'default');
    assert.equal(reopenedDefault.claudeInstallSource, 'local');
    assert.equal(reopenedDefault.claudeInstall, undefined);
    assert.equal(launchFor(reopenedDefault).options.env.CLAUDE_CONFIG_DIR, defaultDirectories.claude);
    await assertIdleClaudeShell(terminal, reopenedDefault, launchFor(reopenedDefault));
    await assertMarkers();
    await terminal.close({ sessionId: reopenedDefault.sessionId });
    check('After closing and reopening a named profile, its stable id, renamed metadata and synthetic storage persist; reopening the default retains its original directory and independent sentinel.');

    const unknownId = `account_${randomBytes(16).toString('hex')}`;
    for (const [id, accountId] of [[selected.id, unknownId], [other.id, account.id]]) {
      const beforeLaunches = launches.length;
      const beforeSessions = terminal.sessions.size;
      await assert.rejects(terminal.create({ id, directory: workingDirectory, kind: 'claude-code', browserProfileId: id, claudeAccountId: accountId, claudeInstallSource: 'local', fresh: true }), { code: 'CLAUDE_ACCOUNT_NOT_FOUND' });
      assert.equal(launches.length, beforeLaunches, 'Unknown or foreign-environment accounts must be refused before process launch.');
      assert.equal(terminal.sessions.size, beforeSessions, 'A refused account must not reserve a terminal session.');
    }
    assert(!(await terminal.listClaudeAccounts({ id: other.id })).accounts.some(item => item.id === account.id));
    await assertMarkers();
    assert.equal(terminal.sessions.get(created.sessionId)?.status, 'running');
    check('Unknown and cross-environment Claude login profiles are refused before creating a session or spawning a process; the original default shell and storage remain intact.');
    proof.claudeAccounts = { namedProfileCreated: true, separateConfigurationDirectories: true, sharedEnvironmentHome: true, sharedManagedInstallation: true,
      installationSource: 'local', duplicatePreservesInstallationSource: true, sharedInstallationReusedWithoutProgress: true,
      duplicatePreservesAccount: true, duplicateStartsIndependentIdleShell: true, activeRenameRefused: true, closedRenamePersisted: true,
      reopenPreservesSyntheticStorage: true, defaultDirectoryUnchanged: true, unknownAccountRefusedBeforeLaunch: true, foreignEnvironmentAccountRefusedBeforeLaunch: true,
      originalDefaultSessionRetained: true, actualAuthenticatedLoginTested: false };
    proof.limitations.push('Named Claude login-profile acceptance uses synthetic storage sentinels in a temporary fixture and real idle shells. It does not prove real account authentication or authenticated-login persistence.');
  } catch (error) { failure = error; }
  finally {
    const ownedSessions = [...terminal.sessions.keys()].filter(sessionId => !initialSessions.has(sessionId));
    const cleanup = await Promise.allSettled(ownedSessions.map(sessionId => terminal.close({ sessionId })));
    const errors = cleanup.filter(result => result.status === 'rejected').map(result => result.reason);
    if (errors.length) failure = new AggregateError([...(failure ? [failure] : []), ...errors], 'Claude account acceptance or owned-session cleanup failed.');
  }
  if (failure) throw failure;
}
