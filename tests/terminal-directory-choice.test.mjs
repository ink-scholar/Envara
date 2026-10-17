import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { mkdir, mkdtemp, readFile, realpath, rm } from 'node:fs/promises';
import { invalidatePickedTerminalDirectory, terminalDirectoryChoice } from '../src/terminal-directory-choice.mjs';
import { TerminalController } from '../electron/terminal-controller.mjs';
import { TerminalService } from '../electron/terminal-service.mjs';

test('a spent picked directory never displays or falls back to the saved folder until a new pick', () => {
  for (const kind of ['shell', 'claude-code']) {
    const initial = { kind, directory: null };
    assert.deepEqual(terminalDirectoryChoice(initial, '/saved/a'), { path: '/saved/a', ready: true });
    const picked = { ...initial, directory: { path: '/picked/b', token: 'native-picker-token' } };
    assert.deepEqual(terminalDirectoryChoice(picked, '/saved/a'), { path: '/picked/b', ready: true });
    const failed = invalidatePickedTerminalDirectory(picked);
    assert.equal(failed.directory, null);
    assert.deepEqual(terminalDirectoryChoice(failed, '/saved/a'), { path: null, ready: false });
    assert.deepEqual(terminalDirectoryChoice({ ...failed, directory: { path: '/picked/c', token: 'new-native-token' }, directoryNeedsSelection: false }, '/saved/a'), { path: '/picked/c', ready: true });
    assert.equal(invalidatePickedTerminalDirectory(initial), initial, 'launches using the saved directory retain their retry behavior');
  }
});

test('a picked folder removed before launch requires a fresh native pick instead of opening the old default', async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'envara-terminal-directory-choice-'));
  let service;
  t.after(async () => { await service?.shutdown(); await rm(root, { recursive: true, force: true }); });
  const saved = path.join(root, 'saved'); const picked = path.join(root, 'picked'); const replacement = path.join(root, 'replacement');
  await Promise.all([saved, picked, replacement].map(directory => mkdir(directory)));
  service = new TerminalService({ dataDir: path.join(root, 'data'), availableLocales: ['C'], networkFence: null,
    resolveContext: async () => { throw new Error('No network is used by directory validation'); },
    ptyFactory: () => { throw new Error('No PTY is used by directory validation'); } });
  await service.ready;
  await service.setDirectory({ id: 'profile_a', path: saved });
  const launches = [];
  service.startSession = async args => { launches.push(args.cwd); return { sessionId: 'fixture_session', cwd: args.cwd }; };
  let selectedPath = picked; let pickerCalls = 0;
  const controller = new TerminalController({ terminal: service, service: { snapshot: async () => ({ profiles: [{ id: 'profile_a' }] }) },
    pickDirectory: async () => { pickerCalls++; return { canceled: false, path: selectedPath }; } });
  const choice = await controller.dispatch('pickTerminalDirectory', { id: 'profile_a' });
  await rm(picked, { recursive: true });
  await assert.rejects(controller.dispatch('openTerminal', { id: 'profile_a', fresh: true, directoryToken: choice.token }), { code: 'ENOENT' });
  let form = invalidatePickedTerminalDirectory({ directory: { path: choice.path, token: choice.token } });
  assert.deepEqual(terminalDirectoryChoice(form, saved), { path: null, ready: false });
  const confirm = () => terminalDirectoryChoice(form, saved).ready
    ? controller.dispatch('openTerminal', { id: 'profile_a', fresh: true, directoryToken: form.directory?.token ?? null }) : null;
  assert.equal(confirm(), null, 'retry stays blocked after the token was spent');
  assert.deepEqual(launches, []);
  selectedPath = replacement;
  const repicked = await controller.dispatch('pickTerminalDirectory', { id: 'profile_a' });
  form = { ...form, directory: { path: repicked.path, token: repicked.token }, directoryNeedsSelection: false };
  await confirm();
  assert.deepEqual(launches, [await realpath(replacement)]);
  assert.equal(pickerCalls, 2);
});

test('the chooser uses the same directory requirement for display, disabled action and submit handler', async () => {
  const source = await readFile(new URL('../src/TerminalPane.jsx', import.meta.url), 'utf8');
  assert.match(source, /const directory = terminalDirectoryChoice\(newSession, directoryFor\(host\?\.id\)\?\.cwd\);\s*const folder = directory\.path;/);
  assert.match(source, /const confirmNewSession = async \(\) => \{[\s\S]*?if \(!host \|\| pending \|\| !terminalDirectoryChoice\(newSession\)\.ready\) return;/);
  assert.match(source, /disabled=\{\!\!pending \|\| !host \|\| !directory\.ready \|\|/);
  assert.match(source, /\.\.\.invalidatePickedTerminalDirectory\(value\), requestId: null/);
  assert.match(source, /directory: \{ path: result\.path, token: result\.token \}, directoryNeedsSelection: false/);
});
