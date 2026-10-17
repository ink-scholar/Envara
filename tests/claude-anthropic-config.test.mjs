import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { ClaudeAccountStore } from '../electron/claude-account-store.mjs';
import { TerminalService } from '../electron/terminal-service.mjs';
import { readEnvironmentExport } from '../electron/environment-export.mjs';
import { checkedExportManifest, exportEnvironment, restoreEnvironment } from '../electron/environment-transfer.mjs';

const SOURCE = 'anthropic_source';
const DESTINATION = 'anthropic_imported';
const PASSWORD = 'synthetic anthropic archive password';

async function absent(filename) {
  await assert.rejects(lstat(filename), { code: 'ENOENT' });
}

async function seedState(directory, label) {
  // Synthetic profile/configuration bytes only; no official CLI or account is used.
  const files = new Map([
    ['configs/fixture.json', Buffer.from(JSON.stringify({ version: '1.0', authentication: { type: 'user_oauth' }, syntheticOnly: label }) + '\r\n')],
    ['credentials/fixture.json', Buffer.from(JSON.stringify({ version: '1.0', syntheticOnly: label,
      access_token: `synthetic-access-${label}`, refresh_token: `synthetic-refresh-${label}` }) + '\n')],
    ['active_config', Buffer.from(`fixture-${label}\r\n`)],
  ]);
  for (const [relative, bytes] of files) {
    const filename = path.join(directory, relative);
    await mkdir(path.dirname(filename), { recursive: true, mode: 0o700 });
    await writeFile(filename, bytes, { mode: 0o600 });
  }
  return files;
}

async function assertState(directory, files) {
  for (const [relative, bytes] of files) assert.deepEqual(await readFile(path.join(directory, relative)), bytes);
}

async function fixture(t) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-anthropic-config-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  const dataDir = path.join(root, 'data');
  const terminalRoot = path.join(dataDir, 'terminal');
  const profilesDir = path.join(terminalRoot, 'profiles');
  await mkdir(profilesDir, { recursive: true, mode: 0o700 });
  const accounts = new ClaudeAccountStore({ root: terminalRoot });
  await accounts.ready;
  const namedA = await accounts.create(SOURCE, 'Synthetic Work');
  const namedB = await accounts.create(SOURCE, 'Synthetic Personal');
  const choices = [{ id: 'default', name: '默认' }, namedA, namedB];
  const legacy = path.join(profilesDir, SOURCE, 'home', '.config', 'anthropic');
  const legacyFiles = await seedState(legacy, 'legacy-shared');
  // Exercise production directory/environment construction without creating a
  // service lifecycle, PTY, CLI, proxy, browser, or any other process.
  const terminal = Object.create(TerminalService.prototype);
  Object.assign(terminal, {
    profilesDir, claudeAccounts: accounts,
    hostHome: path.join(root, 'unused-owned-host-home'),
    additionalExecutablePaths: [], availableLocales: ['C'],
    async snapshot({ id }) { return { profiles: [{ profileId: id, sessions: [] }] }; },
  });
  const directories = new Map();
  for (const choice of choices) directories.set(choice.id, await terminal.directories(SOURCE, choice.id));
  const profile = { id: SOURCE, name: 'Synthetic Anthropic source', status: 'stopped' };
  const service = {
    async call(method, request) {
      assert.equal(method, 'exportProfiles');
      assert.deepEqual(request, { id: SOURCE });
      return { schema: 'envara.profiles', version: 2, profiles: [{ id: SOURCE, name: profile.name }] };
    },
  };
  return { root, dataDir, profilesDir, accounts, choices, directories, legacy, legacyFiles, terminal, profile, service };
}

test('default and named Claude profiles receive distinct private Anthropic directories without migrating legacy state', async t => {
  const f = await fixture(t);
  const homes = new Set(), anthropicDirectories = new Set();
  for (const choice of f.choices) {
    const directories = f.directories.get(choice.id);
    assert.equal(directories.anthropic, path.join(directories.claude, 'anthropic'));
    const info = await lstat(directories.anthropic);
    assert(info.isDirectory());
    assert(!info.isSymbolicLink());
    if (process.platform !== 'win32') assert.equal(info.mode & 0o777, 0o700);
    assert.deepEqual(await readdir(directories.anthropic), []);
    const environment = f.terminal.childEnvironment(directories, 'UTC', null);
    assert.equal(environment.ANTHROPIC_CONFIG_DIR, directories.anthropic);
    assert.equal(environment.CLAUDE_CONFIG_DIR, directories.claude);
    homes.add(environment.HOME);
    anthropicDirectories.add(environment.ANTHROPIC_CONFIG_DIR);
  }
  assert.equal(homes.size, 1, 'named profiles retain the shared environment shell HOME');
  assert.equal(anthropicDirectories.size, 3, 'default and both named profiles have separate Anthropic state');
  await assertState(f.legacy, f.legacyFiles);
});

test('selected terminal exports preserve Anthropic profile bytes and omit other profiles and legacy shared state', async t => {
  for (const selection of [0, 1, 2]) await t.test(['default', 'named Work', 'named Personal'][selection], async subtest => {
    const f = await fixture(subtest);
    const selected = f.choices[selection];
    const states = new Map();
    for (const [index, choice] of f.choices.entries()) {
      states.set(choice.id, await seedState(f.directories.get(choice.id).anthropic, `profile-${index}`));
    }
    const file = path.join(f.root, 'selected-terminal.envara');
    await exportEnvironment({ ...f, file, password: PASSWORD, scope: 'terminal', accountId: selected.id, platform: 'darwin' });
    const staging = path.join(f.root, 'decrypted');
    const manifest = checkedExportManifest(await readEnvironmentExport({ file, password: PASSWORD, staging }));
    assert.equal(manifest.scope, 'terminal');
    assert.equal(manifest.terminal.selectedAccountId, selected.id);
    assert.equal(manifest.keychainIncluded, false);
    const selectedRelative = path.relative(path.join(f.profilesDir, SOURCE), f.directories.get(selected.id).anthropic);
    await assertState(path.join(staging, 'terminal', selectedRelative), states.get(selected.id));
    await absent(path.join(staging, 'terminal', 'home', '.config'));
    for (const choice of f.choices.filter(choice => choice.id !== selected.id)) {
      const relative = path.relative(path.join(f.profilesDir, SOURCE), f.directories.get(choice.id).claude);
      await absent(path.join(staging, 'terminal', relative));
    }
    const restored = await restoreEnvironment({ ...f, staging, manifest, profileId: DESTINATION, platform: 'darwin' });
    assert.equal(restored.terminal, true);
    assert.equal(restored.browser, false);
    const imported = await f.terminal.directories(DESTINATION, selected.id);
    const importedEnvironment = f.terminal.childEnvironment(imported, 'UTC', null);
    assert.equal(importedEnvironment.ANTHROPIC_CONFIG_DIR, imported.anthropic);
    assert.notEqual(imported.anthropic, f.directories.get(selected.id).anthropic);
    await assertState(imported.anthropic, states.get(selected.id));
    await absent(path.join(imported.config, 'anthropic'));
    for (const choice of f.choices.filter(choice => choice.id !== selected.id)) {
      const relative = path.relative(path.join(f.profilesDir, SOURCE), f.directories.get(choice.id).anthropic);
      await absent(path.join(f.profilesDir, DESTINATION, relative));
    }
    const importedAccounts = await f.accounts.list(DESTINATION);
    assert.deepEqual(importedAccounts.filter(account => !account.default).map(({ id }) => id), selected.id === 'default' ? [] : [selected.id]);
    for (const choice of f.choices) await assertState(f.directories.get(choice.id).anthropic, states.get(choice.id));
    await assertState(f.legacy, f.legacyFiles);
  });
});

test('Anthropic directory creation refuses links and ordinary files without touching their contents or outside data', async t => {
  for (const selection of [0, 1, 2]) for (const kind of ['symlink', 'file']) {
    await t.test(`${['default', 'named Work', 'named Personal'][selection]} ${kind}`, async subtest => {
      const f = await fixture(subtest);
      const choice = f.choices[selection];
      const anthropic = f.directories.get(choice.id).anthropic;
      const outside = path.join(f.root, 'outside-profile');
      const outsideFiles = await seedState(outside, 'outside-owned-marker');
      await rm(anthropic, { recursive: true });
      const blockedBytes = Buffer.from('synthetic ordinary file: preserve me\n');
      if (kind === 'symlink') await symlink(outside, anthropic, 'dir');
      else await writeFile(anthropic, blockedBytes, { mode: 0o600 });
      await assert.rejects(f.terminal.directories(SOURCE, choice.id), { code: 'TERMINAL_UNSAFE_PATH' });
      const info = await lstat(anthropic);
      if (kind === 'symlink') assert(info.isSymbolicLink());
      else { assert(info.isFile()); assert.deepEqual(await readFile(anthropic), blockedBytes); }
      await assertState(outside, outsideFiles);
      await assertState(f.legacy, f.legacyFiles);
    });
  }
});
