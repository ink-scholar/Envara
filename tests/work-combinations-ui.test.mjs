import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { _electron } from 'playwright-core';
import { languages } from '../shared/interface-languages.mjs';
import { workCombinationEnglish, workCombinationTranslations } from '../src/work-combinations-translations.mjs';

const noDisplay = process.platform === 'linux' && !process.env.DISPLAY;
const comboId = `workcombo_${'a'.repeat(32)}`;
const entries = [0, 1].map(index => ({ id: `savedterm_${String(index).repeat(32)}`, profileId: 'environment_a',
  name: `Saved terminal ${index + 1}`, cwd: `/synthetic/project-${index}`, claudeAccountName: index ? 'Synthetic login' : null }));
const combination = { id: comboId, profileId: 'environment_a', name: 'Synthetic daily work', entryIds: entries.map(entry => entry.id), includeBrowser: true };
let directory, desktop, page;

test('work combination messages cover all interface languages with matching interpolation fields', () => {
  const fields = text => [...text.matchAll(/\{([^}]+)\}/g)].map(match => match[1]).sort();
  for (const language of languages.filter(language => language !== 'zh-CN')) {
    const dictionary = language === 'en' ? workCombinationEnglish : workCombinationTranslations[language];
    assert.deepEqual(Object.keys(dictionary), Object.keys(workCombinationEnglish));
    for (const [source, value] of Object.entries(dictionary)) {
      assert.equal(typeof value, 'string'); assert.ok(value.trim()); assert.deepEqual(fields(value), fields(source), `${language}: ${source}`);
    }
  }
});

before(async () => {
  if (noDisplay) return;
  directory = await mkdtemp(path.join(tmpdir(), 'envara-work-combinations-ui-'));
  const component = fileURLToPath(new URL('../src/WorkCombinations.jsx', import.meta.url));
  const i18n = fileURLToPath(new URL('../src/i18n.mjs', import.meta.url));
  const translations = fileURLToPath(new URL('../src/work-combinations-translations.mjs', import.meta.url));
  const output = await build({ stdin: { loader: 'jsx', resolveDir: path.dirname(component), contents: `
import React, { useLayoutEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { WorkCombinations } from ${JSON.stringify(component)};
const root = createRoot(document.getElementById('root'));
const clone = value => JSON.parse(JSON.stringify(value));
window.workApi = async (method, args) => {
  window.workCalls.push({ method, args: clone(args) });
  const fixture = window.workFixture;
  if (method === 'listWorkCombinations') {
    if (fixture.deferList && args.id === 'environment_a') return new Promise(resolve => { window.finishWorkList = () => resolve({ combinations: clone(fixture.combinations) }); });
    return { combinations: clone(fixture.combinations.filter(item => item.profileId === args.id)) };
  }
  if (method === 'saveWorkCombination') {
    const combination = { id: ${JSON.stringify(comboId)}, profileId: args.id, name: args.name, entryIds: args.entryIds, includeBrowser: args.includeBrowser };
    fixture.combinations.push(clone(combination)); return { combination };
  }
  if (method === 'deleteWorkCombination') { fixture.combinations = fixture.combinations.filter(item => item.id !== args.combinationId); return { removed: true }; }
  if (method === 'openWorkCombination') {
    if (fixture.failTransportOnce) { fixture.failTransportOnce = false; throw new Error('Synthetic transport failure'); }
    const result = fixture.openResult || { status: 'opened', profileId: args.id, combinationId: args.combinationId, requestId: args.requestId,
      sessions: [{ profileId: args.id, sessionId: 'synthetic_session', savedTerminalId: fixture.entries[0].id }], browserOpened: true, error: null };
    if (fixture.deferOpen) return new Promise(resolve => { window.finishWorkOpen = () => resolve(clone(result)); });
    return clone(result);
  }
  throw new Error('Unexpected synthetic API');
};
function Fixture() {
  const [profileId, setProfileId] = useState('environment_a');
  useLayoutEffect(() => { window.setWorkProfile = setProfileId; }, []);
  return <WorkCombinations profileId={profileId} savedTerminals={window.workFixture.entries}
    onOpened={result => window.workOpened.push(clone(result))} />;
}
let revision = 0;
window.mountWork = value => {
  window.workFixture = value; window.workCalls = []; window.workOpened = [];
  window.finishWorkList = null; window.finishWorkOpen = null;
  document.documentElement.dataset.theme = value.theme || 'dark';
  root.render(<Fixture key={++revision} />);
};
window.workReady = true;
` }, bundle: true, platform: 'browser', format: 'iife', write: false, mainFields: ['module', 'main'], loader: { '.css': 'empty' },
    plugins: [{ name: 'isolated-work-combination-ipc', setup(builder) {
      builder.onResolve({ filter: /^\.\/(client\.js|i18n\.jsx)$/ }, args => ({ path: args.path, namespace: 'work-fixture' }));
      builder.onLoad({ filter: /.*/, namespace: 'work-fixture' }, args => ({ contents: args.path.endsWith('client.js')
        ? 'export const api = { isDesktop: true, call: (...args) => window.workApi(...args) };'
        : `import { translate } from ${JSON.stringify(i18n)}; import { workCombinationEnglish, workCombinationTranslations } from ${JSON.stringify(translations)};
export const useI18n = () => ({ t: (text, vars = {}) => {
  const language = window.workFixture.language || 'zh-CN';
  const dictionary = language === 'en' ? workCombinationEnglish : workCombinationTranslations[language];
  let result = dictionary?.[text] || translate(text, language, vars);
  for (const [key, value] of Object.entries(vars)) result = result.replaceAll('{' + key + '}', String(value)); return result;
} });`, resolveDir: path.dirname(component), loader: 'js' }));
    } }],
  });
  await writeFile(path.join(directory, 'renderer.js'), output.outputFiles[0].text);
  const css = await Promise.all(['styles.css', 'terminal.css', 'work-combinations.css'].map(file => readFile(new URL(`../src/${file}`, import.meta.url), 'utf8')));
  await writeFile(path.join(directory, 'index.html'), `<html data-theme="dark"><head><meta charset="utf-8"><style>${css.join('\n')} #root { width: min(320px, calc(100vw - 40px)); margin: 20px; }</style></head><body><div id="root"></div><script src="renderer.js"></script></body></html>`);
  const main = path.join(directory, 'main.cjs');
  await writeFile(main, `process.on('uncaughtException', error => { process.stderr.write(String(error?.stack || error)); process.exit(1); }); process.on('unhandledRejection', error => { process.stderr.write(String(error?.stack || error)); process.exit(1); }); const { app, BrowserWindow } = require('electron'); app.setPath('userData', ${JSON.stringify(path.join(directory, 'data'))}); app.whenReady().then(() => { app.dock?.hide(); const view = new BrowserWindow({ ...(process.platform === 'win32' ? { show: true, x: -3000, y: 0, frame: false, thickFrame: false } : { show: false }), width: 640, height: 850, webPreferences: { sandbox: true, backgroundThrottling: false } }); view.loadFile(${JSON.stringify(path.join(directory, 'index.html'))}); });`);
  const env = { ...process.env }; delete env.ELECTRON_RUN_AS_NODE;
  desktop = await _electron.launch({ args: [main], env, timeout: 15000 }); page = await desktop.firstWindow(); page.setDefaultTimeout(5000);
  await page.waitForFunction(() => window.workReady === true);
});
after(async () => { try { await desktop?.close(); } finally { if (directory) await rm(directory, { recursive: true, force: true }); } });
async function mount(options = {}) {
  await page.evaluate(value => window.mountWork(value), { combinations: [], entries, ...options });
  await page.locator('.work-combinations > summary').click();
  if (!options.deferList) await page.waitForFunction(() => !document.querySelector('.work-combinations-body > p[role="status"]'));
}
const calls = () => page.evaluate(() => window.workCalls);

test('saving and deleting a work combination sends only chosen references and never changes terminal data', { skip: noDisplay }, async () => {
  await mount();
  const introduction = page.getByText('一起打开常用终端，可带上此环境的浏览器。', { exact: true });
  assert.equal(await introduction.count(), 1);
  await page.getByRole('button', { name: '保存工作组合', exact: true }).click();
  await page.getByRole('textbox', { name: '组合名称', exact: true }).fill('Morning work');
  await page.locator('.work-combination-choices input').nth(1).check(); await page.locator('.work-combination-choices input').first().check();
  await page.getByRole('checkbox', { name: '同时打开此环境浏览器', exact: true }).check();
  await page.getByRole('button', { name: '保存组合', exact: true }).focus(); await page.keyboard.press('Enter');
  await page.getByRole('button', { name: '打开组合「Morning work」', exact: true }).waitFor();
  assert.equal(await introduction.count(), 0);
  assert.deepEqual((await calls()).filter(call => call.method === 'saveWorkCombination'), [{ method: 'saveWorkCombination',
    args: { id: 'environment_a', name: 'Morning work', entryIds: [entries[1].id, entries[0].id], includeBrowser: true } }]);
  await page.getByRole('button', { name: '删除组合「Morning work」', exact: true }).click();
  assert.equal((await calls()).some(call => call.method === 'deleteWorkCombination'), false);
  await page.getByRole('button', { name: '确认删除组合', exact: true }).click();
  await page.waitForFunction(() => document.querySelectorAll('.work-combination-row').length === 0);
  assert.equal(await introduction.count(), 1);
  assert.ok((await calls()).every(call => ['listWorkCombinations', 'saveWorkCombination', 'deleteWorkCombination'].includes(call.method)));
});

test('opening a combination reports partial completion and transport retries retain the same request ID', { skip: noDisplay }, async () => {
  await mount({ combinations: [combination], deferOpen: true, openResult: { status: 'partial', profileId: 'environment_a',
    sessions: [{ sessionId: 'kept_session' }], browserOpened: false, error: { code: 'WORK_COMBINATION_OPEN_FAILED' } } });
  const button = page.getByRole('button', { name: '打开组合「Synthetic daily work」', exact: true });
  await button.click(); await page.waitForFunction(() => typeof window.finishWorkOpen === 'function');
  assert.equal(await button.isDisabled(), true); await page.evaluate(() => window.finishWorkOpen());
  await page.getByRole('status').waitFor(); assert.match(await page.getByRole('status').innerText(), /已保留 1/);
  assert.equal((await calls()).filter(call => call.method === 'openWorkCombination').length, 1);
  assert.equal(await page.evaluate(() => window.workOpened.length), 1);
  await mount({ combinations: [combination], failTransportOnce: true });
  await button.click(); await page.getByRole('alert').waitFor(); await button.click();
  await page.getByRole('status').waitFor();
  const attempts = (await calls()).filter(call => call.method === 'openWorkCombination');
  assert.equal(attempts.length, 2); assert.equal(attempts[0].args.requestId, attempts[1].args.requestId);
  await button.click(); await page.waitForFunction(() => window.workCalls.filter(call => call.method === 'openWorkCombination').length === 3);
  assert.notEqual((await calls()).filter(call => call.method === 'openWorkCombination')[2].args.requestId, attempts[0].args.requestId);
});

test('late list and launch responses cannot overwrite a different environment or steal its view', { skip: noDisplay }, async () => {
  const foreign = { ...combination, id: `workcombo_${'b'.repeat(32)}`, profileId: 'environment_b', name: 'Other environment' };
  await mount({ combinations: [combination, foreign], deferList: true });
  await page.waitForFunction(() => typeof window.finishWorkList === 'function');
  await page.evaluate(() => window.setWorkProfile('environment_b'));
  await page.getByRole('button', { name: '打开组合「Other environment」', exact: true }).waitFor();
  await page.evaluate(() => window.finishWorkList());
  assert.equal(await page.locator('.work-combination-row').count(), 1);
  assert.equal(await page.getByRole('button', { name: '打开组合「Synthetic daily work」', exact: true }).count(), 0);
  await mount({ combinations: [combination, foreign], deferOpen: true });
  await page.getByRole('button', { name: '打开组合「Synthetic daily work」', exact: true }).click();
  await page.waitForFunction(() => typeof window.finishWorkOpen === 'function');
  await page.evaluate(() => window.setWorkProfile('environment_b'));
  await page.getByRole('button', { name: '打开组合「Other environment」', exact: true }).waitFor();
  await page.evaluate(() => window.finishWorkOpen());
  assert.equal(await page.evaluate(() => window.workOpened.length), 0);
  assert.equal(await page.getByRole('status').count(), 0);
});

test('work combination controls stay bounded across nine languages and both appearances', { skip: noDisplay }, async () => {
  // The desktop has an intentional 900px minimum; exercise a narrow 320px
  // workspace column inside it without changing the production body rules.
  await desktop.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].setContentSize(900, 850));
  for (const language of languages) for (const theme of ['dark', 'light']) {
    await mount({ language, theme, combinations: [{ ...combination, name: 'Synthetic long work combination '.repeat(6) }] });
    await page.locator('.work-combinations-body > button').click();
    await page.locator('.work-combination-form input:not([type="checkbox"])').fill('Synthetic set');
    await page.locator('.work-combination-choices input').first().check();
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `${language}/${theme}: no horizontal overflow`);
    assert.equal(await page.locator('#root').evaluate(element => element.scrollWidth <= element.clientWidth), true, `${language}/${theme}: the narrow column contains its contents`);
    for (const locator of [page.locator('.work-combination-form button[type="submit"]'), page.locator('.work-combination-browser input')]) {
      await locator.scrollIntoViewIfNeeded(); await locator.focus();
      assert.equal(await locator.evaluate(element => document.activeElement === element), true);
    }
  }
});
