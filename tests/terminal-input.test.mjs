import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { _electron } from 'playwright-core';
import { TerminalProtocol } from '../electron/terminal-protocol.mjs';

// Real Electron, React, TerminalDock and xterm, but no Envara main process,
// PTY, saved workspace, network, clipboard or system input-method changes.
const noDisplay = process.platform === 'linux' && !process.env.DISPLAY;
const rootDirectory = fileURLToPath(new URL('../', import.meta.url));
let directory, desktop, page;
const errors = [];
const fixtureSource = `
import React from 'react';
import { createRoot } from 'react-dom/client';
import { Terminal } from '@xterm/xterm';
import { TerminalDock } from './src/TerminalPane.jsx';
import { TerminalWindowApp } from './src/TerminalWindowApp.jsx';
import { I18nProvider } from './src/i18n.jsx';
import { AppearanceProvider } from './src/appearance.jsx';
// The fixture retains the real component-owned terminal through its public
// entry point. Geometry tests only write/resize/read its public API.
const openTerminal = Terminal.prototype.open;
Terminal.prototype.open = function (...args) {
  const result = openTerminal.apply(this, args);
  window.fixture.terminal = this;
  window.fixture.terminals.push(this);
  this.onData(data => window.fixture.rawData.push(data));
  return result;
};
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
    {options.standalone ? <TerminalWindowApp profileId={profile.id} sessionId={session.sessionId} />
      : Array.from({ length: options.views || 1 }, (_, index) => <TerminalDock key={index} {...dockProps} />)}
  </AppearanceProvider></I18nProvider>);
}
window.fixture.mount = (next = {}) => {
  root?.unmount();
  options = { visible: true, standalone: false, ...next };
  window.fixture.writes = [];
  window.fixture.rawData = [];
  window.fixture.terminal = null;
  window.fixture.terminals = [];
  window.fixture.unexpected = [];
  window.fixture.snapshot = { profiles: [profile], proxies: [], settings: { language: 'zh-CN', appearance: 'dark' },
    system: { platform: 'darwin', appVersion: 'fixture', accessibilitySupportEnabled: options.screenReaderMode === true } };
  window.fixture.terminalSnapshot = { profiles: [{ profileId: profile.id, name: profile.name,
    sessions: [{ ...session, status: options.status || 'running', replay: options.replay || '' }] }] };
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
  const css = await Promise.all(['src/styles.css', 'src/terminal.css', 'src/terminal-window.css', 'node_modules/@xterm/xterm/css/xterm.css']
    .map(name => readFile(path.join(rootDirectory, name), 'utf8')));
  await page.addStyleTag({ content: `${css.join('\n')}\nhtml,body,#root{height:100%;margin:0}` });
  await page.evaluate(() => {
    const snapshots = new Set(), terminalEvents = new Set();
    window.fixture = { writes: [], unexpected: [],
      publishSnapshot() { for (const listener of snapshots) listener(structuredClone(this.snapshot)); },
      publishTerminalEvent(event) { for (const listener of terminalEvents) listener(structuredClone(event)); },
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
  await page.locator('.xterm-helper-textarea').first().waitFor({ state: 'attached' });
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

async function geometryTerminal(output, { standalone = false, columns = 20, rows = 5 } = {}) {
  await mount({ standalone });
  // The real component fits after an 80ms debounce. Wait for that initial fit
  // before setting a deterministic grid, without patching its resize logic.
  await page.waitForTimeout(140);
  await page.evaluate(async ({ output, columns, rows }) => {
    const terminal = window.fixture.terminal;
    terminal.resize(columns, rows);
    await new Promise(resolve => terminal.write(output, resolve));
    await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
  }, { output, columns, rows });
  const state = await compositionGeometry();
  assert.equal(state.columns, columns, 'the actual terminal uses the requested column count');
  assert.equal(state.rows, rows, 'the actual terminal uses the requested row count');
  return state;
}

async function compositionGeometry() {
  return page.evaluate(() => {
    const terminal = window.fixture.terminal;
    const screen = terminal.element.querySelector('.xterm-screen');
    const view = terminal.element.querySelector('.composition-view');
    const screenBounds = screen.getBoundingClientRect();
    const relativeBounds = element => {
      const bounds = element.getBoundingClientRect();
      return { left: bounds.left - screenBounds.left, top: bounds.top - screenBounds.top,
        right: bounds.right - screenBounds.left, bottom: bounds.bottom - screenBounds.top,
        width: bounds.width, height: bounds.height };
    };
    const buffer = terminal.buffer.active;
    return {
      columns: terminal.cols, rows: terminal.rows,
      cellWidth: screenBounds.width / terminal.cols, cellHeight: screenBounds.height / terminal.rows,
      screen: { width: screenBounds.width, height: screenBounds.height },
      view: relativeBounds(view), textarea: relativeBounds(terminal.textarea),
      active: view.classList.contains('active'), display: getComputedStyle(view).display,
      floating: view.classList.contains('terminal-composition-floating'), maxWidth: view.style.maxWidth,
      text: view.textContent, rawData: window.fixture.rawData.slice(),
      buffer: { cursorX: buffer.cursorX, cursorY: buffer.cursorY, baseY: buffer.baseY, viewportY: buffer.viewportY,
        lines: Array.from({ length: buffer.length }, (_, row) => {
          const line = buffer.getLine(row);
          return { text: line.translateToString(false), isWrapped: line.isWrapped,
            cells: Array.from({ length: terminal.cols }, (_, column) => {
              const cell = line.getCell(column);
              return { chars: cell.getChars(), width: cell.getWidth() };
            }) };
        }) },
    };
  });
}

async function startComposition(text = '拼音') {
  const alreadySent = await page.evaluate(() => window.fixture.writes.map(value => value.data).join(''));
  const result = await events([
    imeKey('keydown'), { type: 'compositionstart', data: '' }, { type: 'compositionupdate', data: text }, { value: text },
    { type: 'input', inputType: 'insertCompositionText', data: text, isComposing: true },
  ]);
  assert.equal(sent(result), alreadySent, 'preedit must not be sent to the session');
  return compositionGeometry();
}

function near(actual, expected, message) {
  assert.ok(Math.abs(actual - expected) <= 0.75, `${message}: ${actual} vs ${expected}`);
}

function anchoredAt(state, column, row) {
  assert.equal(state.active, true, 'preedit is visible');
  assert.notEqual(state.display, 'none');
  near(state.view.left, column * state.cellWidth, 'preedit column');
  near(state.view.top, row * state.cellHeight, 'preedit row');
  near(state.textarea.left, state.view.left, 'native candidate anchor follows preedit horizontally');
  near(state.textarea.top, state.view.top, 'native candidate anchor follows preedit vertically');
  near(state.textarea.width, Math.max(state.view.width, 1), 'candidate anchor width follows preedit');
  near(state.textarea.height, Math.max(state.view.height, 1), 'candidate anchor height follows preedit');
}

function visibleInsideScreen(state) {
  for (const [name, bounds] of [['preedit', state.view], ['candidate anchor', state.textarea]]) {
    assert.ok(bounds.left >= -0.75 && bounds.top >= -0.75, `${name} starts inside the visible screen`);
    assert.ok(bounds.right <= state.screen.width + 0.75 && bounds.bottom <= state.screen.height + 0.75,
      `${name} ends inside the visible screen`);
    assert.ok(bounds.width >= 1 && bounds.height >= 1, `${name} has usable dimensions`);
  }
}

async function stableComposition(expected) {
  const frames = await page.evaluate(async () => {
    const terminal = window.fixture.terminal;
    const screen = terminal.element.querySelector('.xterm-screen');
    const view = terminal.element.querySelector('.composition-view');
    const frames = [];
    for (let frame = 0; frame < 6; frame++) {
      await new Promise(resolve => requestAnimationFrame(resolve));
      const origin = screen.getBoundingClientRect();
      const bounds = view.getBoundingClientRect(), anchor = terminal.textarea.getBoundingClientRect();
      frames.push({ left: bounds.left - origin.left, top: bounds.top - origin.top,
        textareaLeft: anchor.left - origin.left, textareaTop: anchor.top - origin.top });
    }
    return frames;
  });
  for (const [index, frame] of frames.entries()) {
    near(frame.left, expected.view.left, `preedit stays at its horizontal anchor on frame ${index}`);
    near(frame.top, expected.view.top, `preedit stays at its vertical anchor on frame ${index}`);
    near(frame.textareaLeft, frame.left, `candidate anchor stays aligned horizontally on frame ${index}`);
    near(frame.textareaTop, frame.top, `candidate anchor stays aligned vertically on frame ${index}`);
  }
}

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

test('renderer query replies never reach the PTY while subsequent keyboard input does', { skip: noDisplay }, async () => {
  await mount();
  const raw = await page.evaluate(async () => {
    const terminal = window.fixture.terminal;
    terminal.options.windowOptions = { getWinSizePixels: true, getCellSizePixels: true, getWinSizeChars: true };
    await new Promise(resolve => terminal.write(
      '\x1b[5n\x1b[6n\x1b[?6n\x1b[c\x1b[>c\x1b[4$p\x1b[?25$p' +
      '\x1bP$qm\x1b\\\x1b[14t\x1b[16t\x1b[18t' +
      '\x1b]4;1;?\x07\x1b]10;?\x07\x1b]11;?\x07\x1b]12;?\x07', resolve));
    return window.fixture.rawData.slice();
  });
  // Observe the actual native xterm replies before TerminalDock's filter. This
  // prevents a passing test caused by queries that did not run at all.
  assert.equal(raw.length, 15);
  assert.ok(raw.includes('\x1b[0n'));
  assert.ok(raw.some(data => /^\x1b\]\d+;.*rgb:/.test(data)));
  assert.equal(sent(await events([])), '', 'only the main-process terminal may answer these queries');
  assert.equal(sent(await events([
    key('keydown', { key: 'a', code: 'KeyA', keyCode: 65, which: 65 }),
    key('keyup', { key: 'a', code: 'KeyA', keyCode: 65, which: 65 }),
    { append: '、' }, input('、'),
  ])), 'a、', 'the next task is ordinary input, not a terminal reply');
});

test('query filtering preserves mixed OSC colour changes and their native query results', { skip: noDisplay }, async () => {
  await mount();
  const raw = await page.evaluate(async () => {
    await new Promise(resolve => window.fixture.terminal.write(
      '\x1b]4;1;#123456;2;?\x1b\\\x1b]10;#112233;?;#445566\x1b\\' +
      '\x1b]4;1;?\x1b\\\x1b]10;?\x1b\\\x1b]12;?\x1b\\', resolve));
    return window.fixture.rawData.slice();
  });
  assert.ok(raw.includes('\x1b]4;1;rgb:1212/3434/5656\x1b\\'), 'indexed colour settings are applied');
  assert.ok(raw.includes('\x1b]10;rgb:1111/2222/3333\x1b\\'), 'foreground settings are applied');
  assert.ok(raw.includes('\x1b]12;rgb:4444/5555/6666\x1b\\'), 'cursor settings after a query are applied');
  assert.equal(sent(await events([])), '', 'native colour replies remain local to the view');
});

test('multiple views and replayed or fragmented queries cannot duplicate protocol input', { skip: noDisplay }, async () => {
  await mount({ views: 2, replay: '\x1b[6n' });
  await page.waitForFunction(() => window.fixture.terminals.length === 2 && window.fixture.rawData.length === 2);
  await page.evaluate(() => {
    window.fixture.publishTerminalEvent({ type: 'data', sessionId: 'input-session', profileId: 'input-fixture', sequence: 1, data: '\x1b[' });
    window.fixture.publishTerminalEvent({ type: 'data', sessionId: 'input-session', profileId: 'input-fixture', sequence: 2, data: '6n' });
  });
  await page.waitForFunction(() => window.fixture.rawData.length === 4);
  assert.equal(await page.evaluate(() => window.fixture.rawData.filter(data => /^\x1b\[\d+;\d+R$/.test(data)).length), 4);
  assert.equal(sent(await events([])), '', 'two live renderers and their replay never reply to the PTY');
});

test('focus reports in the same query batch still come from the real view', { skip: noDisplay }, async () => {
  await mount();
  await page.evaluate(async () => {
    const terminal = window.fixture.terminal;
    terminal.blur();
    await new Promise(resolve => terminal.write('\x1b[6n\x1b[?1004h', resolve));
  });
  assert.equal(sent(await events([])), '\x1b[O', 'the query is filtered but the actual unfocused state is reported');
  await page.evaluate(() => window.fixture.terminal.focus());
  assert.equal(sent(await events([])), '\x1b[O\x1b[I', 'later focus changes retain their normal bytes');
});

test('IME composition and paste after query parsing remain user input', { skip: noDisplay }, async () => {
  await mount();
  await page.evaluate(() => new Promise(resolve => window.fixture.terminal.write('\x1b[6n', resolve)));
  assert.equal(sent(await events([
    imeKey('keydown'), { type: 'compositionstart', data: '' },
    { type: 'compositionupdate', data: '中文' }, { value: '中文' },
    { type: 'input', inputType: 'insertCompositionText', data: '中文', isComposing: true }, { wait: 4 },
    { type: 'compositionend', data: '中文' }, input('中文'), imeKey('keyup'), { wait: 4 },
  ])), '中文');
  await page.evaluate(() => window.fixture.terminal.paste('粘贴'));
  assert.equal(sent(await events([])), '中文粘贴');
});

test('canonical and renderer cursor replies agree after long output and resizing', { skip: noDisplay }, async () => {
  const output = Array.from({ length: 60 }, (_, index) => `${index}: 中文abcdef `.repeat(4)).join('\r\n');
  await geometryTerminal(output, { columns: 20, rows: 5 });
  const replies = [];
  const protocol = new TerminalProtocol({ columns: 20, rows: 5, write: data => replies.push(data) });
  try {
    await protocol.write(output);
    for (const [columns, rows] of [[20, 5], [40, 12], [18, 6], [60, 24]]) {
      await protocol.resize(columns, rows);
      const rendererReply = await page.evaluate(async ({ columns, rows }) => {
        const terminal = window.fixture.terminal;
        terminal.resize(columns, rows);
        window.fixture.rawData = [];
        await new Promise(resolve => terminal.write('\x1b[6n', resolve));
        return window.fixture.rawData.at(-1);
      }, { columns, rows });
      await protocol.write('\x1b[6n');
      assert.match(rendererReply, /^\x1b\[\d+;\d+R$/);
      assert.equal(replies.at(-1), rendererReply, `cursor position agrees at ${columns}x${rows}`);
    }
    assert.equal(sent(await events([])), '', 'the renderer remains a display even after reflow');
  } finally { protocol.dispose(); }
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

test('Chinese preedit begins after committed wide glyphs in embedded and independent terminal views', { skip: noDisplay }, async () => {
  for (const standalone of [false, true]) {
    const before = await geometryTerminal('你好', { standalone });
    assert.equal(before.buffer.cursorX, 4);
    const state = await startComposition();
    anchoredAt(state, 4, 0);
    visibleInsideScreen(state);
    assert.deepEqual(state.buffer, before.buffer, 'displaying preedit never edits the real buffer or cursor');
    assert.deepEqual(state.rawData, [], 'displaying preedit does not emit terminal input');
  }
});

test('a cursor in a Chinese continuation cell puts preedit after the glyph without moving the real cursor', { skip: noDisplay }, async () => {
  const before = await geometryTerminal('你好\x1b[1D');
  assert.equal(before.buffer.cursorX, 3);
  assert.deepEqual(before.buffer.lines[0].cells[3], { chars: '', width: 0 });
  let state = await startComposition('拼');
  anchoredAt(state, 4, 0);
  assert.deepEqual(state.buffer, before.buffer);
  assert.equal(sent(await events([
    { type: 'compositionupdate', data: '拼音' }, { value: '拼音' },
    { type: 'input', inputType: 'insertCompositionText', data: '拼音', isComposing: true },
  ])), '');
  state = await compositionGeometry();
  anchoredAt(state, 4, 0);
  assert.deepEqual(state.buffer, before.buffer, 'editing preedit preserves even the width-zero cursor position');
  assert.deepEqual(state.rawData, []);
});

test('editing at the start of a wide glyph retains the intentional cursor column', { skip: noDisplay }, async () => {
  const before = await geometryTerminal('你好\x1b[2D');
  assert.equal(before.buffer.cursorX, 2);
  assert.equal(before.buffer.lines[0].cells[2].width, 2);
  const state = await startComposition('拼');
  anchoredAt(state, 2, 0);
  assert.deepEqual(state.buffer, before.buffer, 'a real editing position is not advanced across the next glyph');
});

for (const [label, output] of [['Chinese', '你'.repeat(10)], ['ASCII', 'x'.repeat(20)]]) {
  test(`${label} pending wrap places preedit at the next visible row rather than on the final glyph`, { skip: noDisplay }, async () => {
    for (const standalone of [false, true]) {
      const before = await geometryTerminal(output, { standalone });
      assert.equal(before.buffer.cursorX, 20, 'fixture reaches xterm pending-wrap state');
      assert.equal(before.buffer.cursorY, 0);
      const state = await startComposition();
      anchoredAt(state, 0, 1);
      visibleInsideScreen(state);
      await stableComposition(state);
      assert.deepEqual(state.buffer, before.buffer, 'the preedit row does not cause an actual terminal wrap');
      assert.deepEqual(state.rawData, []);
    }
  });
}

test('resizing during composition keeps the displayed preedit and native candidate anchor synchronized', { skip: noDisplay }, async () => {
  await geometryTerminal('你'.repeat(10));
  anchoredAt(await startComposition('拼'), 0, 1);
  await page.evaluate(async () => {
    window.fixture.terminal.resize(30, 5);
    await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
  });
  // Both xterm's deferred composition update and its render callback have run.
  await page.waitForTimeout(30);
  const state = await compositionGeometry();
  assert.equal(state.columns, 30);
  assert.equal(state.buffer.cursorX, 20);
  assert.equal(state.buffer.cursorY, 0);
  anchoredAt(state, 20, 0);
  visibleInsideScreen(state);
  await stableComposition(state);
  assert.deepEqual(state.rawData, [], 'resize does not submit a composition');
  assert.equal(state.buffer.lines[0].text.trimEnd(), '你'.repeat(10));
});

test('composition end hides the overlay and the next composition starts from the current terminal position', { skip: noDisplay }, async () => {
  for (const row of [0, 4]) {
    await geometryTerminal(`\x1b[${row + 1};1H` + '你'.repeat(10));
    anchoredAt(await startComposition('中'), 0, row === 4 ? 3 : 1);
    assert.equal(sent(await events([{ type: 'compositionend', data: '中' }, input('中'), imeKey('keyup')])), '中');
    const ended = await compositionGeometry();
    assert.equal(ended.active, false);
    assert.equal(ended.display, 'none');
    assert.equal(ended.floating, false, 'composition end removes the floating treatment');
    assert.equal(ended.maxWidth, '', 'composition end releases the preedit width constraint');
    near(ended.textarea.left, 19 * ended.cellWidth, 'candidate anchor returns to xterm\'s last-column cursor anchor');
    near(ended.textarea.top, row * ended.cellHeight, 'candidate anchor returns to the real cursor row');
    assert.deepEqual(ended.rawData, ['中'], 'composition commits through the existing xterm input path exactly once');
    await page.evaluate(() => new Promise(resolve => window.fixture.terminal.write('\r\nready ', resolve)));
    const state = await startComposition('文');
    anchoredAt(state, 6, Math.min(row + 1, 4));
    visibleInsideScreen(state);
    assert.deepEqual(state.rawData, ['中'], 'opening another composition does not repeat the previous commit');
  }
});

test('final-row and long preedit remain visible without covering the latest committed glyph', { skip: noDisplay }, async () => {
  const longPreedit = '这是一段超过终端可见宽度的输入法预编辑文本'.repeat(3);
  for (const [output, preedit, glyphColumn, glyphRow] of [
    ['\x1b[5;1H' + '你'.repeat(10), '拼音', 18, 4],
    ['\x1b[5;1H' + '你'.repeat(10), longPreedit, 18, 4],
    ['你好', longPreedit, 2, 0],
  ]) {
    const before = await geometryTerminal(output);
    const state = await startComposition(preedit);
    assert.equal(state.active, true);
    visibleInsideScreen(state);
    await stableComposition(state);
    near(state.textarea.left, state.view.left, 'candidate anchor tracks floated preedit horizontally');
    near(state.textarea.top, state.view.top, 'candidate anchor tracks floated preedit vertically');
    near(state.textarea.width, state.view.width, 'candidate anchor tracks clipped preedit width');
    const glyph = { left: glyphColumn * state.cellWidth, right: (glyphColumn + 2) * state.cellWidth,
      top: glyphRow * state.cellHeight, bottom: (glyphRow + 1) * state.cellHeight };
    const overlapWidth = Math.min(state.view.right, glyph.right) - Math.max(state.view.left, glyph.left);
    const overlapHeight = Math.min(state.view.bottom, glyph.bottom) - Math.max(state.view.top, glyph.top);
    assert.ok(overlapWidth <= 0.75 || overlapHeight <= 0.75, 'preedit does not paint over the latest committed glyph');
    assert.deepEqual(state.buffer, before.buffer, 'floating or clipping preedit does not change terminal content');
    assert.deepEqual(state.rawData, []);
  }
});
