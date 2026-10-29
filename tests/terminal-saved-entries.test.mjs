import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { chmod, copyFile, mkdtemp, mkdir, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { TerminalService } from '../electron/terminal-service.mjs';
import { ensureClaudeInstallation } from '../electron/claude-code-installation.mjs';

async function fixture(t) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-saved-terminal-')));
  const cwd = path.join(root, 'project'); await mkdir(cwd);
  const native = path.join(root, '2.1.296'); await copyFile('/usr/bin/true', native); await chmod(native, 0o700);
  const records = [], resolutions = [], contexts = new Map([
    ['chosen', { id: 'chosen', name: 'Workspace', timezone: 'Asia/Manila', locale: 'en-US', proxyId: 'node-one', managedProxy: true,
      proxy: { protocol: 'http', host: '127.0.0.1', port: 45670, username: 'fixture-user', password: 'fixture-secret' } }],
    ['other', { id: 'other', name: 'Other workspace', timezone: 'Asia/Manila', proxy: null }],
  ]);
  let service;
  const create = () => {
    const next = new TerminalService({ dataDir: path.join(root, 'data'), availableLocales: ['C'],
      resolveContext: async id => { resolutions.push(id); if (!contexts.has(id)) throw Object.assign(new Error('missing fixture environment'), { code: 'PROFILE_NOT_FOUND' }); return structuredClone(contexts.get(id)); },
      linkChannel: { executableDirectory: async () => path.join(root, 'links'), environment: () => ({ ENVARA_LINK_SOCKET: '/private/fixture-link.sock', ENVARA_LINK_TOKEN: 'fixture-link-token' }) },
      browserBroker: { createSession: async args => ({ browser: { profileId: args.browserProfileId, name: 'Workspace' },
        environment: { ENVARA_BROWSER_SOCKET: '/private/fixture-browser.sock', ENVARA_BROWSER_TOKEN: 'fixture-browser-token', ENVARA_LINK_SOCKET: '/private/fixture-link.sock', ENVARA_LINK_TOKEN: 'fixture-link-token' },
        mcpServer: { command: process.execPath, args: [path.join(root, 'fixture-mcp.mjs')] }, dispose: async () => {} }) },
      claudeExecutableResolver: async () => native,
      claudeKeychain: { prepare: async () => ({ status: 'ready', changed: false }) },
      claudeInstaller: options => ensureClaudeInstallation({ ...options, downloadNative: async ({ destination }) => { await copyFile(native, destination); return { version: '2.1.296' }; } }),
      networkFence: { wrap: async (launch, options) => ({ ...launch, deviceIdentifierRestrictions: options.restrictDeviceIdentifiers === true }) },
      ptyFactory: (executable, args, options) => {
        const exits = new Set(), record = { executable, args, options, writes: [], closed: false };
        const pty = { pid: 10000 + records.length, onData: () => ({ dispose() {} }), onExit: callback => { exits.add(callback); return { dispose: () => exits.delete(callback) }; },
          write: value => record.writes.push(value), resize() {}, kill() { record.closed = true; for (const callback of exits) callback({ exitCode: 0 }); } };
        records.push(record); record.pty = pty; return pty;
      }, processControl: { capture: async pid => ({ pid }), close: async ({ pty }) => { pty.kill(); return { ok: true }; } },
    });
    service = next; return next;
  };
  const services = [create()]; await service.ready;
  t.after(async () => { for (const item of services) await item.shutdown().catch(() => {}); await rm(root, { recursive: true, force: true }); });
  return { root, cwd, records, resolutions, contexts, get service() { return service; },
    restart: async () => { await service.shutdown(); services.push(create()); await service.ready; return service; },
    saved: async (id = 'chosen') => (await service.snapshot({ id })).profiles[0].savedTerminals,
    start: (options = {}) => service.create({ id: 'chosen', directory: cwd, fresh: true, ...options }) };
}

test('a successful shell creates a durable entry, clicks reuse only its process, and duplicates share one definition', async t => {
  const f = await fixture(t), first = await f.start();
  assert.match(first.savedTerminalId, /^savedterm_[a-f0-9]{32}$/); assert.equal(first.savedTerminalName, 'Workspace');
  assert.equal(f.records.length, 1);
  const reopened = await f.service.reopenSavedTerminal({ id: 'chosen', entryId: first.savedTerminalId });
  assert.equal(reopened.sessionId, first.sessionId); assert.equal(f.records.length, 1);
  await f.service.write({ sessionId: first.sessionId, data: 'fixture-command\r' });
  const duplicate = await f.service.duplicate({ sessionId: first.sessionId });
  assert.notEqual(duplicate.sessionId, first.sessionId); assert.equal(duplicate.savedTerminalId, first.savedTerminalId);
  assert.deepEqual(f.records[1].writes, []); assert.equal((await f.saved()).length, 1);
  assert.equal((await f.saved())[0].activeSessionCount, 2);
  assert.equal((await f.service.reopenSavedTerminal({ id: 'chosen', entryId: first.savedTerminalId })).sessionId, duplicate.sessionId);
  const serialized = await readFile(path.join(f.root, 'data/terminal/saved-terminals.json'), 'utf8');
  for (const secret of ['fixture-secret', 'fixture-command', 'fixture-user', 'fixture-link-token', '127.0.0.1', '45670', 'pid', 'replay']) assert.equal(serialized.includes(secret), false, secret);
});

test('after app restart the entry uses fresh verified context and its own directory without replaying commands', async t => {
  const f = await fixture(t), first = await f.start();
  await f.service.write({ sessionId: first.sessionId, data: 'do-not-replay\r' });
  await f.service.renameSavedTerminal({ id: 'chosen', entryId: first.savedTerminalId, name: 'Named workspace' });
  await f.restart();
  const before = await f.saved(); assert.equal(before.length, 1); assert.equal(before[0].status, 'saved'); assert.equal(before[0].sessionId, null);
  const another = path.join(f.root, 'other-project'); await mkdir(another);
  await f.service.setDirectory({ id: 'chosen', path: another });
  // A managed core may receive a new private loopback endpoint after restart.
  f.contexts.get('chosen').proxy.port = 45671;
  f.contexts.get('chosen').timezone = 'America/New_York';
  const count = f.resolutions.length;
  const next = await f.service.reopenSavedTerminal({ id: 'chosen', entryId: first.savedTerminalId, requestId: 'reopen-fixture' });
  assert.notEqual(next.sessionId, first.sessionId); assert.equal(next.savedTerminalId, first.savedTerminalId); assert.equal(next.savedTerminalName, 'Named workspace');
  assert.equal(next.cwd, f.cwd); assert.equal(next.timezone, 'America/New_York'); assert.equal(next.requestId, 'reopen-fixture');
  assert.equal(f.resolutions.length, count + 1); assert.equal(f.records.at(-1).options.cwd, f.cwd); assert.deepEqual(f.records.at(-1).writes, []);
  assert.equal((await f.service.snapshot({ id: 'chosen' })).profiles[0].cwd, another, 'reopening a saved entry must not change the environment directory default');
  assert.equal((await f.saved()).length, 1);
});

test('named Claude entries retain the exact account data and open a manual idle shell after restart', async t => {
  const f = await fixture(t), { account } = await f.service.createClaudeAccount({ id: 'chosen', name: 'Work login' });
  const first = await f.start({ kind: 'claude-code', browserProfileId: 'chosen', claudeAccountId: account.id });
  const selectedDirectory = f.records[0].options.env.CLAUDE_CONFIG_DIR;
  await writeFile(path.join(selectedDirectory, 'saved-account-marker'), 'synthetic-account-data', { mode: 0o600 });
  await f.service.write({ sessionId: first.sessionId, data: 'claude\r' });
  await f.restart();
  assert.equal((await f.saved())[0].claudeAccountName, 'Work login');
  const next = await f.service.reopenSavedTerminal({ id: 'chosen', entryId: first.savedTerminalId });
  assert.equal(next.kind, 'claude-code'); assert.equal(next.claudeAccountId, account.id); assert.equal(next.savedTerminalName, 'Work login');
  assert.equal(f.records.at(-1).options.env.CLAUDE_CONFIG_DIR, selectedDirectory);
  assert.equal(await readFile(path.join(selectedDirectory, 'saved-account-marker'), 'utf8'), 'synthetic-account-data');
  assert.equal(f.records.at(-1).args.at(-1), '-i'); assert.deepEqual(f.records.at(-1).writes, []);
  assert.ok(!f.records.at(-1).args.some(value => value === 'claude' || value.includes('--resume')));
});

test('removed accounts remain explicit invalid references and never fall back to the default account', async t => {
  const f = await fixture(t), { account } = await f.service.createClaudeAccount({ id: 'chosen', name: 'Temporary login' });
  const session = await f.start({ kind: 'claude-code', browserProfileId: 'chosen', claudeAccountId: account.id });
  await f.service.close({ sessionId: session.sessionId });
  await f.service.deleteClaudeAccount({ id: 'chosen', accountId: account.id, confirmed: true });
  assert.equal((await f.saved())[0].unavailableReason, 'CLAUDE_ACCOUNT_NOT_FOUND');
  const count = f.records.length;
  await assert.rejects(f.service.reopenSavedTerminal({ id: 'chosen', entryId: session.savedTerminalId }), { code: 'CLAUDE_ACCOUNT_NOT_FOUND' });
  assert.equal(f.records.length, count); assert.equal((await f.saved()).length, 1);
});

test('saved route, browser and directory changes refuse before spawning a replacement process', async t => {
  for (const change of ['network', 'direct', 'browser', 'directory', 'profile']) {
    await t.test(change, async t => {
      const f = await fixture(t), session = await f.start(); await f.service.close({ sessionId: session.sessionId });
      if (change === 'network') f.contexts.get('chosen').proxyId = 'other-node';
      if (change === 'direct') { f.contexts.get('chosen').proxy = null; f.contexts.get('chosen').managedProxy = false; }
      if (change === 'browser') await f.service.setLinkBrowser({ id: 'chosen', browserProfileId: 'system' });
      if (change === 'directory') await rm(f.cwd, { recursive: true });
      if (change === 'profile') f.contexts.delete('chosen');
      const count = f.records.length;
      await assert.rejects(f.service.reopenSavedTerminal({ id: 'chosen', entryId: session.savedTerminalId }),
        { code: change === 'directory' ? 'TERMINAL_ENTRY_DIRECTORY_UNAVAILABLE' : change === 'profile' ? 'PROFILE_NOT_FOUND' : 'TERMINAL_ENTRY_CONTEXT_CHANGED' });
      assert.equal(f.records.length, count);
    });
  }
});

test('rename and removing an entry preserve the running process, account files and shared shell history', async t => {
  const f = await fixture(t), session = await f.start();
  const history = f.records[0].options.env.HISTFILE; await writeFile(history, 'synthetic shell history\n');
  await f.service.renameSavedTerminal({ id: 'chosen', entryId: session.savedTerminalId, name: 'Named terminal' });
  assert.equal((await f.service.snapshot({ id: 'chosen' })).profiles[0].sessions[0].savedTerminalName, 'Named terminal');
  await f.service.removeSavedTerminal({ id: 'chosen', entryId: session.savedTerminalId });
  assert.equal((await f.saved()).length, 0); assert.equal(f.records[0].closed, false);
  assert.equal(await readFile(history, 'utf8'), 'synthetic shell history\n');
  assert.equal((await f.service.snapshot({ id: 'chosen' })).profiles[0].sessions[0].savedTerminalId, undefined);
  await assert.rejects(f.service.reopenSavedTerminal({ id: 'chosen', entryId: session.savedTerminalId }), { code: 'TERMINAL_ENTRY_NOT_FOUND' });
});

test('uncertain process cleanup blocks reopening and duplication until explicit cleanup succeeds', async t => {
  const f = await fixture(t), first = await f.start(), second = await f.start();
  const source = f.service.sessions.get(second.sessionId); source.status = 'closing'; source.cleanupError = 'synthetic unconfirmed cleanup';
  await assert.rejects(f.service.reopenSavedTerminal({ id: 'chosen', entryId: first.savedTerminalId }), { code: 'TERMINAL_ENTRY_BUSY' });
  await assert.rejects(f.service.duplicate({ sessionId: first.sessionId }), { code: 'TERMINAL_NOT_RUNNING' });
  assert.equal(f.records.length, 2);
  source.cleanupError = null; await f.service.close({ sessionId: source.sessionId });
});

test('environment deletion removes only its saved entry definitions', async t => {
  const f = await fixture(t), first = await f.start(); await f.service.close({ sessionId: first.sessionId });
  await f.service.create({ id: 'other', directory: f.cwd, fresh: true });
  await f.service.removeProfile({ id: 'chosen' });
  assert.equal((await f.saved()).length, 0); assert.equal((await f.saved('other')).length, 1);
});
