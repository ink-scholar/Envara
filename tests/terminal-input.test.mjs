import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { _electron } from 'playwright-core';

// Real Electron, React, TerminalDock and xterm, but no Envara main process,
// PTY, saved workspace, network, clipboard or system input-method changes.
const noDisplay = process.platform === 'linux' && !process.env.DISPLAY;
const rootDirectory = fileURLToPath(new URL('../', import.meta.url));
let directory, desktop, page;
const errors = [];
const fixtureSource = `
import React from 'react';
import { createRoot } from 'react-dom/client';
import { TerminalDock } from './src/TerminalPane.jsx';
import { TerminalWindowApp } from './src/TerminalWindowApp.jsx';
import { I18nProvider } from './src/i18n.jsx';
import { AppearanceProvider } from './src/appearance.jsx';
const api = window.envara;
const profile = { id: 'input-fixture', name: 'Input fixture', proxyId: 'fixture-route',
  timezone: 'Asia/Shanghai', locale: 'zh-CN' };
const session = { sessionId: 'input-session', profileId: profile.id, status: 'running',
  kind: 'claude-code', browserProfileId: profile.id, browserName: profile.name,
  sequence: 0, replay: '', columns: 100, rows: 12, startedAt: '2026-01-01T00:00:00.000Z' };
let root, options;
function render() {
  const dockProps = { profiles: [profile], selectedProfileId: profile.id,
    visible: options.visible, ...(options.screenReaderMode === undefined ? {} : { screenReaderMode: options.screenReaderMode }) };
  root.render(<I18nProvider api={api}><AppearanceProvider api={api}>
    {options.standalone ? <TerminalWindowApp profileId={profile.id} sessionId={session.sessionId} /> : <TerminalDock {...dockProps} />}
  </AppearanceProvider></I18nProvider>);
}
window.fixture.mount = (next = {}) => {
  root?.unmount();
  options = { visible: true, standalone: false, ...next };
  window.fixture.writes = [];
  window.fixture.unexpected = [];
  window.fixture.snapshot = { profiles: [profile], proxies: [], settings: { language: 'zh-CN', appearance: 'dark' },
    system: { platform: 'darwin', appVersion: 'fixture', accessibilitySupportEnabled: options.screenReaderMode === true } };
  window.fixture.terminalSnapshot = { profiles: [{ profileId: profile.id, name: profile.name,
    sessions: [{ ...session, status: options.status || 'running' }] }] };
  root = createRoot(document.querySelector('#root'));
  render();
};
window.fixture.update = next => { options = { ...options, ...next }; render(); };
window.fixture.publishSettings = (settings = {}, system = {}) => {
  Object.assign(window.fixture.snapshot.settings, settings);
  Object.assign(window.fixture.snapshot.system, system);
  window.fixture.publishSnapshot();
};
window.fixture.unmount = () => { root?.unmount(); root = null; };
`;

before(async () => {
  if (noDisplay) return;
  directory = await mkdtemp(path.join(tmpdir(), 'envara-terminal-input-'));
  const entry = path.join(directory, 'main.cjs');
  await writeFile(entry, `const { app, BrowserWindow, session } = require('electron');
app.setPath('userData', ${JSON.stringify(path.join(directory, 'data'))});
app.whenReady().then(() => {
  app.dock?.hide();
  session.defaultSession.webRequest.onBeforeRequest({ urls: ['http://*/*', 'https://*/*'] }, (_, done) => done({ cancel: true }));
  const window = new BrowserWindow({ show: false, width: 1280, height: 720, webPreferences: { sandbox: true, backgroundThrottling: false } });
  window.loadURL('data:text/html;charset=utf-8,%3C!doctype%20html%3E%3Cdiv%20id%3D%22root%22%3E%3C%2Fdiv%3E');
});`);
  const env = { ...process.env };
  delete env.ELECTRON_RUN_AS_NODE;
  desktop = await _electron.launch({ args: [entry], env, timeout: 15000 });
  page = await desktop.firstWindow();
  page.on('pageerror', error => errors.push(error.message));
  await page.locator('#root').waitFor({ state: 'attached' });
  const css = await Promise.all(['src/styles.css', 'src/terminal.css', 'node_modules/@xterm/xterm/css/xterm.css']
    .map(name => readFile(path.join(rootDirectory, name), 'utf8')));
  await page.addStyleTag({ content: `${css.join('\n')}\nhtml,body,#root{height:100%;margin:0}` });
  await page.evaluate(() => {
    const snapshots = new Set(), terminalEvents = new Set();
    window.fixture = { writes: [], unexpected: [],
      publishSnapshot() { for (const listener of snapshots) listener(structuredClone(this.snapshot)); },
      listenerCount: () => snapshots.size + terminalEvents.size,
    };
    window.envara = { isDesktop: true,
      subscribe(listener) { snapshots.add(listener); return () => snapshots.delete(listener); },
      onTerminalEvent(listener) { terminalEvents.add(listener); return () => terminalEvents.delete(listener); },
      async call(method, args) {
        if (method === 'snapshot') return structuredClone(window.fixture.snapshot);
        if (method === 'terminalSnapshot') return structuredClone(window.fixture.terminalSnapshot);
        if (method === 'writeTerminal') { window.fixture.writes.push(structuredClone(args)); return { ok: true }; }
        if (method === 'resizeTerminal') return { ok: true };
        window.fixture.unexpected.push(method);
        throw new Error('Unexpected input fixture operation: ' + method);
      },
    };
  });
  const bundle = await build({ stdin: { contents: fixtureSource, resolveDir: rootDirectory, loader: 'jsx' },
    bundle: true, write: false, platform: 'browser', format: 'iife', loader: { '.css': 'empty' },
    define: { 'process.env.NODE_ENV': '"test"' },
  });
  await page.addScriptTag({ content: bundle.outputFiles[0].text });
});

after(async () => {
  try {
    if (page && !page.isClosed()) {
      await page.evaluate(() => window.fixture.unmount?.());
      assert.equal(await page.evaluate(() => window.fixture.listenerCount()), 0, 'unmount releases fixture subscriptions');
    }
    assert.deepEqual(errors, [], 'the owned renderer has no uncaught errors');
  } finally {
    try { await desktop?.close(); }
    finally { if (directory) await rm(directory, { recursive: true, force: true }); }
  }
});

async function mount(options = {}) {
  await page.evaluate(value => window.fixture.mount(value), options);
  await page.locator('.xterm-helper-textarea').waitFor({ state: 'attached' });
  // Let effects set disableStdin and settle xterm's asynchronous replay/focus.
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
}

async function events(steps) {
  return page.evaluate(async values => {
    const textarea = document.querySelector('.xterm-helper-textarea');
    const prevented = [];
    for (const step of values) {
      if (step.wait != null) { await new Promise(resolve => setTimeout(resolve, step.wait)); continue; }
      // A prevented keydown suppresses the browser's keypress/default text
      // insertion. Respect that boundary instead of manufacturing extra input.
      if (step.defaultOfPrevious && prevented.at(-1)) continue;
      if (step.value != null) { textarea.value = step.value; continue; }
      if (step.append != null) { textarea.value += step.append; continue; }
      const init = { bubbles: true, cancelable: true, composed: true, ...step };
      const event = step.type.startsWith('composition') ? new CompositionEvent(step.type, init)
        : ['input', 'beforeinput'].includes(step.type) ? new InputEvent(step.type, init) : new KeyboardEvent(step.type, init);
      textarea.dispatchEvent(event);
      prevented.push(event.defaultPrevented);
    }
    await new Promise(resolve => setTimeout(resolve, 40));
    return { prevented, writes: window.fixture.writes.slice(), unexpected: window.fixture.unexpected.slice() };
  }, steps);
}

const key = (type, init = {}) => ({ type, key: 'Enter', code: 'Enter', keyCode: 13, which: 13, ...init });
const input = data => ({ type: 'input', inputType: 'insertText', data, isComposing: false });
const imeKey = type => key(type, { key: 'Unidentified', code: 'Backslash', keyCode: 229, which: 229 });
const backslash = (type, init = {}) => key(type, { key: '\\', code: 'Backslash', keyCode: 220, which: 220, ...init });
const sent = result => {
  assert.deepEqual(result.unexpected, [], 'the fixture never launches or mutates a real session');
  assert.ok(result.writes.every(value => value.sessionId === 'input-session'));
  return result.writes.map(value => value.data).join('');
};

test('input-only Chinese punctuation reaches the actual terminal IPC once by default', { skip: noDisplay }, async () => {
  await mount();
  assert.equal(sent(await events([{ append: '、' }, input('、')])), '、');
});

for (const delivery of ['keypress', 'input', 'keypress-and-input']) {
  for (const screenReaderMode of [false, true]) {
    test(`macOS physical Backslash uses committed Chinese punctuation from ${delivery} (screen reader ${screenReaderMode})`, { skip: noDisplay || process.platform !== 'darwin' }, async () => {
      await mount({ screenReaderMode });
      const commit = [];
      if (delivery.includes('keypress')) commit.push(backslash('keypress', {
        // Captured macOS trace keeps key="\\" while charCode is the IME's
        // committed U+3001. Never derive committed text from key/code here.
        key: '\\', keyCode: 0x3001, which: 0x3001, charCode: 0x3001, defaultOfPrevious: true,
      }));
      if (delivery.includes('input')) commit.push({ ...input('、'), type: 'beforeinput', defaultOfPrevious: true },
        { append: '、', defaultOfPrevious: true }, { ...input('、'), defaultOfPrevious: true });
      const result = await events([backslash('keydown'), ...commit, backslash('keyup')]);
      assert.equal(sent(result), '、', 'the physical US-layout key must not replace the IME-committed character');
    });
  }
}

test('English backslash, pipe and terminal control shortcuts retain their bytes', { skip: noDisplay }, async () => {
  for (const [character, modifiers] of [['\\', {}], ['|', { shiftKey: true }]]) {
    await mount();
    const result = await events([
      backslash('keydown', { key: character, ...modifiers }),
      backslash('keypress', { key: character, keyCode: character.charCodeAt(0), which: character.charCodeAt(0),
        charCode: character.charCodeAt(0), ...modifiers, defaultOfPrevious: true }),
      { append: character, defaultOfPrevious: true }, { ...input(character), defaultOfPrevious: true },
      backslash('keyup', { key: character, ...modifiers }),
    ]);
    assert.equal(sent(result), character);
  }
  await mount();
  assert.equal(sent(await events([backslash('keydown', { ctrlKey: true }), backslash('keyup', { ctrlKey: true })])), '\x1c');
  await mount();
  assert.equal(sent(await events([backslash('keydown', { metaKey: true }), backslash('keyup', { metaKey: true })])), '');
});

test('a deferred macOS printable key yields to composition without duplicating its committed text', { skip: noDisplay || process.platform !== 'darwin' }, async () => {
  await mount();
  assert.equal(sent(await events([
    backslash('keydown'), { type: 'compositionstart', data: '' },
    { type: 'compositionupdate', data: '中文' }, { value: '中文' },
    { type: 'input', inputType: 'insertCompositionText', data: '中文', isComposing: true }, { wait: 4 },
    { type: 'compositionend', data: '中文' }, input('中文'), backslash('keyup'), { wait: 4 },
    backslash('keydown'), backslash('keypress', { keyCode: 0x3001, which: 0x3001, charCode: 0x3001 }),
    { append: '、' }, input('、'), backslash('keyup'),
  ])), '中文、');
});

test('IME punctuation works with keyCode 229 both before and after insertText', { skip: noDisplay }, async () => {
  for (const inputFirst of [false, true]) {
    await mount();
    const insertion = [{ append: '、' }, input('、')];
    const sequence = inputFirst ? [...insertion, imeKey('keydown')] : [imeKey('keydown'), ...insertion];
    assert.equal(sent(await events([...sequence, imeKey('keyup')])), '、', `inputFirst=${inputFirst}`);
  }
});

test('consecutive identical punctuation and a Chinese composition followed by punctuation do not duplicate', { skip: noDisplay }, async () => {
  await mount();
  const punctuation = [imeKey('keydown'), { append: '、' }, input('、'), imeKey('keyup'), { wait: 4 }];
  assert.equal(sent(await events([...punctuation, ...punctuation])), '、、');
  await mount();
  assert.equal(sent(await events([
    imeKey('keydown'), { type: 'compositionstart', data: '' },
    { type: 'compositionupdate', data: '中文' }, { value: '中文' },
    { type: 'input', inputType: 'insertCompositionText', data: '中文', isComposing: true }, { wait: 4 },
    { type: 'compositionend', data: '中文' }, input('中文'), imeKey('keyup'), { wait: 4 },
    ...punctuation,
  ])), '中文、');
});

test('ordinary ASCII key input is delivered once without synthetic duplicate text insertion', { skip: noDisplay }, async () => {
  await mount();
  const result = await events([
    key('keydown', { key: 'a', code: 'KeyA', keyCode: 65, which: 65 }),
    key('keypress', { key: 'a', code: 'KeyA', keyCode: 97, which: 97, charCode: 97, defaultOfPrevious: true }),
    key('keyup', { key: 'a', code: 'KeyA', keyCode: 65, which: 65 }),
  ]);
  assert.equal(sent(result), 'a');
});

test('Shift+Enter sends exactly one alternate Enter in embedded and independent terminal views', { skip: noDisplay }, async () => {
  for (const standalone of [false, true]) {
    await mount({ standalone });
    // Deliberately include a trailing keypress: ordinarily preventDefault on
    // keydown suppresses it, but a late IME keypress must not submit a prompt.
    const result = await events([key('keydown', { shiftKey: true }), key('keypress', { shiftKey: true, charCode: 13 }), key('keyup', { shiftKey: true })]);
    assert.equal(sent(result), '\x1b\r', `standalone=${standalone}`);
    assert.equal(result.prevented[0], true, 'the handled key has no browser default action');
    assert.equal(sent(await events([{ append: '、' }, input('、')])), '\x1b\r、', 'the same view accepts IME punctuation');
  }
});

test('ordinary Enter, Alt+Enter and other modified Enter retain their existing terminal bytes', { skip: noDisplay }, async () => {
  for (const [modifiers, expected] of [[{}, '\r'], [{ altKey: true }, '\x1b\r'],
    [{ shiftKey: true, altKey: true }, '\x1b\r'], [{ shiftKey: true, ctrlKey: true }, '\r'], [{ shiftKey: true, metaKey: true }, '\r']]) {
    await mount();
    assert.equal(sent(await events([key('keydown', modifiers), key('keyup', modifiers)])), expected);
  }
});

test('IME confirmation Enter never sends an extra command or a Shift+Enter sequence', { skip: noDisplay }, async () => {
  for (const modifiers of [{ shiftKey: true }, { shiftKey: true, isComposing: true }, { shiftKey: true, keyCode: 229, which: 229 }]) {
    await mount();
    const result = await events([
      imeKey('keydown'), { type: 'compositionstart', data: '' },
      { type: 'compositionupdate', data: '中' }, { value: '中' }, { wait: 4 },
      key('keydown', modifiers), { type: 'compositionend', data: '中' },
      { type: 'input', inputType: 'insertCompositionText', data: '中', isComposing: false },
      key('keypress', { shiftKey: true, charCode: 13, isComposing: false }),
      key('keyup', modifiers), { wait: 4 },
    ]);
    assert.equal(sent(result), '中');
    assert.equal(result.prevented[3], false, 'candidate confirmation remains available to the IME');
    assert.equal(sent(await events([key('keydown'), key('keyup')])), '中\r', 'the next deliberate Enter still submits');
  }
});

test('hidden and non-running terminals do not forward punctuation or Shift+Enter', { skip: noDisplay }, async () => {
  for (const options of [{ visible: false }, { status: 'starting' }, { status: 'closing' }]) {
    await mount(options);
    assert.equal(sent(await events([{ append: '、' }, input('、'), key('keydown', { shiftKey: true }), key('keyup', { shiftKey: true }),
      backslash('keydown'), { append: '、' }, input('、'), backslash('keyup')])), '');
  }
});

test('language and appearance updates keep the same input element and preserve queued input', { skip: noDisplay }, async () => {
  await mount();
  await page.evaluate(() => {
    window.fixture.savedTextarea = document.querySelector('.xterm-helper-textarea');
    const textarea = window.fixture.savedTextarea;
    textarea.value += '、';
    textarea.dispatchEvent(new InputEvent('input', { data: '、', inputType: 'insertText', composed: true, bubbles: true }));
    window.fixture.publishSettings({ language: 'en', appearance: 'light' });
  });
  await page.waitForFunction(() => document.documentElement.lang === 'en' && document.documentElement.dataset.theme === 'light');
  assert.equal(await page.evaluate(() => document.querySelector('.xterm-helper-textarea') === window.fixture.savedTextarea), true);
  assert.equal(sent(await events([{ append: '、' }, input('、')])), '、、');
  assert.equal(await page.locator('.xterm-helper-textarea').getAttribute('aria-label'), 'Environment terminal input');
});

test('screen reader support toggles accessibility DOM without replacing the terminal', { skip: noDisplay }, async () => {
  for (const standalone of [false, true]) {
    await mount({ standalone, screenReaderMode: false });
    assert.equal(await page.locator('.xterm-accessibility').count(), 0);
    await page.evaluate(() => { window.fixture.savedTextarea = document.querySelector('.xterm-helper-textarea'); });
    for (const enabled of [true, false]) {
      await page.evaluate(({ enabled, standalone }) => {
        if (standalone) window.fixture.publishSettings({}, { accessibilitySupportEnabled: enabled });
        else window.fixture.update({ screenReaderMode: enabled });
      }, { enabled, standalone });
      await page.waitForFunction(value => !!document.querySelector('.xterm-accessibility') === value, enabled);
      assert.equal(await page.evaluate(() => document.querySelector('.xterm-helper-textarea') === window.fixture.savedTextarea), true);
    }
    assert.equal(sent(await events([{ append: '、' }, input('、')])), '、');
  }
});
