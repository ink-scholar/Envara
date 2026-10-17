import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdtemp, mkdir, realpath, rm } from 'node:fs/promises';
import { build } from 'esbuild';
import { chromium } from 'playwright-core';
import { TerminalService } from '../electron/terminal-service.mjs';
import { TerminalController } from '../electron/terminal-controller.mjs';

const browserPath = process.env.ENVARA_UI_TEST_BROWSER;
const fixtureSource = `
import React, { useState } from 'react';
import { createRoot } from 'react-dom/client';
import { ContextDetail } from './src/workspace-pages.jsx';
import { TerminalDock } from './src/TerminalPane.jsx';
const profiles = [{ id: 'profile_a', name: 'Fixture workspace' }];
const other = [{ id: 'profile_b', name: 'Other fixture workspace' }];
function Fixture() {
  const [workspaces, setWorkspaces] = useState([]);
  return <>
    <aside><ContextDetail profile={profiles[0]} workspace={workspaces.find(item => item.profileId === 'profile_a')} t={value => value} /></aside>
    <TerminalDock profiles={profiles} selectedProfileId="profile_a" visible={false} onProfilesChange={setWorkspaces} />
    <TerminalDock profiles={other} selectedProfileId="profile_b" standalone />
  </>;
}
const root = createRoot(document.querySelector('#root'));
root.render(<Fixture />);
window.fixture.unmount = () => root.unmount();
`;

test('an internal directory choice refreshes the detail while the terminal dock is hidden and leaves another window scoped', {
  skip: !browserPath, timeout: 30000,
}, async t => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'envara-workspace-ui-'));
  const selected = path.join(directory, 'selected-workspace');
  await mkdir(selected);
  let browser, terminal, page;
  t.after(async () => {
    try { await browser?.close(); }
    finally { try { await terminal?.shutdown(); } finally { await rm(directory, { recursive: true, force: true }); } }
  });
  let resolutions = 0, launches = 0;
  const notifications = [], reads = [];
  terminal = new TerminalService({ dataDir: path.join(directory, 'data'), availableLocales: ['C'], networkFence: null,
    resolveContext: async () => { resolutions++; throw new Error('The fixture must not resolve a route'); },
    ptyFactory: () => { launches++; throw new Error('The fixture must not launch a shell'); },
    onEvent: event => { notifications.push(event); return page?.evaluate(value => window.fixture.emit(value), event); },
  });
  await terminal.ready;
  const controller = new TerminalController({ terminal,
    service: { snapshot: async () => ({ profiles: [{ id: 'profile_a' }, { id: 'profile_b' }] }) },
    pickDirectory: async () => ({ canceled: false, path: selected }),
  });
  browser = await chromium.launch({ executablePath: browserPath, headless: true, args: ['--disable-background-networking'],
    env: { PATH: process.env.PATH, HOME: directory, TMPDIR: directory,
      ...(process.platform === 'win32' ? { SystemRoot: process.env.SystemRoot, TEMP: directory, TMP: directory } : {}) },
  });
  const context = await browser.newContext({ serviceWorkers: 'block' });
  await context.route('**/*', route => route.abort());
  page = await context.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  t.after(() => assert.deepEqual(errors, []));
  await page.exposeFunction('readTerminalSnapshot', args => {
    reads.push(args?.id ?? 'workspace');
    return terminal.snapshot(args);
  });
  await page.setContent('<!doctype html><div id="root"></div>');
  await page.evaluate(() => {
    const listeners = new Set();
    window.fixture = { emit: event => listeners.forEach(listener => listener(event)), listenerCount: () => listeners.size };
    window.envara = {
      isDesktop: true,
      onTerminalEvent(listener) { listeners.add(listener); return () => listeners.delete(listener); },
      call(method, args) {
        if (method !== 'terminalSnapshot') throw new Error('Unexpected fixture operation: ' + method);
        return window.readTerminalSnapshot(args);
      },
    };
  });
  const bundle = await build({ stdin: { contents: fixtureSource, resolveDir: fileURLToPath(new URL('../', import.meta.url)), loader: 'jsx' },
    bundle: true, write: false, platform: 'browser', format: 'iife', loader: { '.css': 'empty' },
    define: { 'process.env.NODE_ENV': '"test"' },
  });
  await page.addScriptTag({ content: bundle.outputFiles[0].text });
  await page.waitForFunction(() => window.fixture.listenerCount() === 2 && document.querySelector('aside .context-directory strong')?.textContent === '未选择');
  const otherReads = reads.filter(id => id === 'profile_b').length;

  // This is the same controller call made internally by attached-app launch.
  // It intentionally has no renderer operation reply or workspace broadcast.
  const result = await controller.dispatch('chooseWorkspaceDirectory', { id: 'profile_a' });
  const expected = await realpath(selected);
  assert.equal(result.profiles[0].cwd, expected);
  await page.waitForFunction(value => document.querySelector('aside .context-directory strong')?.textContent === value, expected);
  assert.deepEqual(notifications, [{ type: 'workspace', profileId: 'profile_a' }]);
  assert.equal(reads.filter(id => id === 'profile_b').length, otherReads, 'a standalone view of another environment must ignore the notification');
  assert.equal(resolutions, 0);
  assert.equal(launches, 0);
  assert.deepEqual((await terminal.snapshot({ id: 'profile_a' })).profiles[0].sessions, []);
  await page.evaluate(() => window.fixture.unmount());
  assert.equal(await page.evaluate(() => window.fixture.listenerCount()), 0);
});
