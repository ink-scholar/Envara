import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { build } from 'esbuild';
import { chromium } from 'playwright-core';
import { translate } from '../src/i18n.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const appFile = fileURLToPath(new URL('../src/App.jsx', import.meta.url));
// Explicitly opt into an automation-owned Chromium, never a personal profile.
// The fixture runs entirely in memory and refuses all network requests.
const browserPath = process.env.ENVARA_UI_TEST_BROWSER;
const fixtureSource = `
import React, { useEffect, useLayoutEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { Modal } from './src/App.jsx';
import { I18nProvider, useI18n } from './src/i18n.jsx';

const listeners = new Set();
let current = { profiles: [], proxies: [], settings: { language: 'en', closeBrowsersOnExit: true },
  system: { platform: 'darwin', appVersion: '0.5.0' } };
const fixture = window.fixture = { calls: [], submitted: 0, renders: 0, translationChanges: 0 };
fixture.emit = (language = current.settings.language) => {
  current = { ...current, settings: { ...current.settings, language }, profiles: [...current.profiles],
    events: [{ type: 'fixture-refresh', revision: fixture.renders }] };
  listeners.forEach(listener => listener(current));
};
const api = {
  subscribe(listener) { listeners.add(listener); return () => listeners.delete(listener); },
  async call(method) {
    if (method === 'snapshot') return current;
    if (method !== 'saveSettings') throw new Error('Unexpected fixture operation');
    return new Promise((_resolve, reject) => { fixture.failSave = () => reject(new Error('Fixture save failure')); });
  },
};
function Fixture() {
  const i18n = useI18n();
  const [revision, setRevision] = useState(0);
  const [visible, setVisible] = useState(true);
  const [name, setName] = useState('');
  useEffect(() => api.subscribe(() => setRevision(value => value + 1)), []);
  useLayoutEffect(() => {
    if (fixture.t && fixture.t !== i18n.t) fixture.translationChanges++;
    Object.assign(fixture, { t: i18n.t, language: i18n.language, saving: i18n.saving, error: i18n.error,
      revision, renders: fixture.renders + 1, ready: true,
      changeLanguage: value => i18n.setLanguage(value).catch(() => false),
      replaceCallback: () => setRevision(value => value + 1), hide: () => setVisible(false) });
  });
  return visible && <Modal title="网络出口" onClose={() => fixture.calls.push({ revision, label: i18n.t('网络出口') })}>
    <form onSubmit={event => { event.preventDefault(); fixture.submitted++; }}>
      <label>Name<input id="name" value={name} onChange={event => setName(event.target.value)} /></label>
      <label>Protocol<select id="protocol" defaultValue="http"><option value="http">HTTP</option><option value="https">HTTPS</option><option value="socks5">SOCKS5</option></select></label>
      <details id="advanced"><summary>Advanced</summary><button type="button">Extra option</button></details>
      <button id="save" type="submit">Save</button>
    </form>
  </Modal>;
}
const app = createRoot(document.querySelector('#root'));
app.render(<I18nProvider api={api}><Fixture /></I18nProvider>);
fixture.unmount = () => app.unmount();
`;

async function bundleFixture() {
  const result = await build({ stdin: { contents: fixtureSource, resolveDir: root, loader: 'jsx' },
    bundle: true, write: false, platform: 'browser', format: 'iife', loader: { '.css': 'empty' },
    define: { 'process.env.NODE_ENV': '"test"', 'import.meta.env.BASE_URL': '"/"' },
    plugins: [{ name: 'expose-actual-modal-for-test', setup(builder) {
      builder.onLoad({ filter: /[/\\]src[/\\]App\.jsx$/ }, async args => {
        assert.equal(args.path, appFile);
        return { contents: `${await readFile(args.path, 'utf8')}\nexport { Modal };`, loader: 'jsx' };
      });
    } }],
  });
  return result.outputFiles[0].text;
}

async function fixture(t) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'envara-modal-focus-'));
  let browser;
  t.after(async () => {
    try { await browser?.close(); } finally { await rm(directory, { recursive: true, force: true }); }
  });
  browser = await chromium.launch({ executablePath: browserPath, headless: true,
    args: ['--disable-background-networking'],
    env: { PATH: process.env.PATH, HOME: directory, TMPDIR: directory,
      ...(process.platform === 'win32' ? { SystemRoot: process.env.SystemRoot, TEMP: directory, TMP: directory } : {}) },
  });
  const context = await browser.newContext({ serviceWorkers: 'block' });
  await context.route('**/*', route => route.abort());
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  t.after(() => assert.deepEqual(errors, [], 'the actual React components must render without errors'));
  await page.setContent('<!doctype html><button id="opener">Open network</button><div id="root"></div>');
  await page.locator('#opener').focus();
  await page.addScriptTag({ content: await bundleFixture() });
  await page.waitForFunction(() => window.fixture?.ready && document.activeElement?.id === 'name');
  return page;
}

const frames = page => page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
const focus = page => page.evaluate(() => document.activeElement?.id);

test('background snapshots retain draft focus and expanded controls without submitting', {
  skip: !browserPath, timeout: 30000,
}, async t => {
  const page = await fixture(t);
  await page.locator('#name').fill('Proxy draft');
  await page.locator('#advanced summary').click();
  await page.locator('#protocol').click();
  const before = await page.evaluate(() => ({ renders: fixture.renders, translations: fixture.translationChanges }));
  for (let count = 0; count < 5; count++) {
    await page.evaluate(() => fixture.emit());
    await frames(page);
    assert.equal(await focus(page), 'protocol');
  }
  assert.equal(await page.locator('#name').inputValue(), 'Proxy draft');
  assert.equal(await page.locator('#advanced').getAttribute('open'), '');
  assert.equal(await page.evaluate(() => fixture.translationChanges), before.translations);
  assert.ok(await page.evaluate(value => fixture.renders > value, before.renders), 'snapshot updates must really rerender the provider and parent');
  assert.equal(await focus(page), 'protocol');
  assert.equal(await page.evaluate(() => fixture.submitted), 0);
  // The native popup's visual lifetime and keyboard selection are desktop checks.
  // Headless Chromium still verifies that refreshes leave the select usable.
  await page.locator('#protocol').selectOption('https');
  assert.equal(await page.locator('#protocol').inputValue(), 'https');

  await page.locator('#name').focus();
  await page.locator('#name').evaluate(input => input.setSelectionRange(2, 6));
  await page.evaluate(() => fixture.emit());
  await frames(page);
  assert.deepEqual(await page.locator('#name').evaluate(input => [document.activeElement === input, input.selectionStart, input.selectionEnd]), [true, 2, 6]);
});

test('callback and language changes keep focus; Escape uses the current callback and unmount restores the opener', {
  skip: !browserPath, timeout: 30000,
}, async t => {
  const page = await fixture(t);
  await page.locator('#protocol').focus();
  await page.evaluate(() => fixture.replaceCallback());
  await frames(page);
  assert.equal(await focus(page), 'protocol');
  await page.keyboard.press('Escape');
  assert.deepEqual(await page.evaluate(() => fixture.calls), [{ revision: 1, label: translate('网络出口', 'en') }]);

  const baseline = await page.evaluate(() => fixture.translationChanges);
  await page.evaluate(() => { void fixture.changeLanguage('en'); });
  await page.waitForFunction(() => fixture.saving);
  assert.equal(await page.evaluate(() => fixture.translationChanges), baseline, 'saving alone must not recreate t');
  await page.evaluate(() => fixture.failSave());
  await page.waitForFunction(() => !fixture.saving && fixture.error);
  assert.equal(await page.evaluate(() => fixture.translationChanges), baseline, 'save errors must not recreate t');
  assert.equal(await focus(page), 'protocol');

  await page.evaluate(() => fixture.emit('ja'));
  await page.waitForFunction(() => fixture.language === 'ja');
  await frames(page);
  assert.equal(await page.locator('#modal-title').textContent(), translate('网络出口', 'ja'));
  assert.equal(await page.evaluate(() => document.documentElement.lang), 'ja');
  assert.equal(await page.evaluate(() => fixture.translationChanges), baseline + 1);
  assert.equal(await focus(page), 'protocol');
  await page.keyboard.press('Escape');
  assert.deepEqual(await page.evaluate(() => fixture.calls.at(-1)), { revision: 2, label: translate('网络出口', 'ja') });

  await page.evaluate(() => fixture.hide());
  await frames(page);
  assert.equal(await focus(page), 'opener');
  const calls = await page.evaluate(() => fixture.calls.length);
  await page.keyboard.press('Escape');
  assert.equal(await page.evaluate(() => fixture.calls.length), calls, 'unmounted dialogs leave no Escape handler');
});
