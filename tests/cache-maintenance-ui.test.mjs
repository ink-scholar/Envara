import { before, after, test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { build } from 'esbuild';
import { _electron } from 'playwright-core';
import electron from 'electron';
import { cacheMaintenanceEnglish, cacheMaintenanceTranslations } from '../src/cache-maintenance-translations.mjs';

const noDisplay = process.platform === 'linux' && !process.env.DISPLAY;
const project = fileURLToPath(new URL('../', import.meta.url));
let directory, desktop, page;
before(async () => {
  if (noDisplay) return;
  directory = await mkdtemp(path.join(tmpdir(), 'envara-cache-ui-'));
  const output = await build({ stdin: { resolveDir: project, loader: 'jsx', contents: `
import React from 'react'; import { createRoot } from 'react-dom/client';
import { CacheMaintenance } from './src/CacheMaintenance.jsx';
const root = createRoot(document.querySelector('#root'));
window.calls = []; window.language = 'zh-CN'; window.pending = false;
window.inventory = {inventoryId:'inventory-one',maintenanceAvailable:true,entries:[
 {id:'cache-one',profileId:'fixture',profileName:'Synthetic environment',cacheName:'Default/Cache',bytes:4096,status:'ready'},
 {id:'cache-busy',profileId:'busy',profileName:'Busy fixture',cacheName:'Default/Cache',bytes:null,status:'busy'}],
 batches:[{id:'batch-one',createdAt:'2026-11-16T12:00:00Z',bytes:8192,entryCount:1,status:'ready'}]};
const call = method => args => window.calls.push({method,args});
window.render = () => root.render(<CacheMaintenance inventory={window.inventory} pending={window.pending}
 onRefresh={call('inventory')} onQuarantine={call('quarantine')} onRestore={call('restore')} onPurge={call('purge')} />);
window.render();` }, bundle: true, write: false, platform: 'browser', format: 'iife', loader: { '.css': 'empty' },
    define: { 'process.env.NODE_ENV': '"test"' }, plugins: [{ name: 'cache-fixture-i18n', setup(builder) {
      builder.onResolve({ filter: /^\.\/i18n.jsx$/ }, () => ({ path: 'i18n', namespace: 'cache-fixture' }));
      builder.onLoad({ filter: /.*/, namespace: 'cache-fixture' }, () => ({ resolveDir: project, contents: `
import { cacheMaintenanceEnglish, cacheMaintenanceTranslations } from './src/cache-maintenance-translations.mjs';
export const useI18n=()=>({language:window.language,t:(source,vars={})=>{
 const catalogs={en:cacheMaintenanceEnglish,...cacheMaintenanceTranslations};
 const text=catalogs[window.language]?.[source]??source;
 return text.replace(/\\{(\\w+)\\}/g,(_,key)=>vars[key]??'{'+key+'}');
}});` }));
    } }],
  });
  await writeFile(path.join(directory, 'fixture.js'), output.outputFiles[0].text);
  await writeFile(path.join(directory, 'styles.css'), `${await readFile(path.join(project, 'src/styles.css'))}\n${await readFile(path.join(project, 'src/cache-maintenance.css'))}`);
  await writeFile(path.join(directory, 'index.html'), '<!doctype html><html data-theme="dark"><meta charset="utf-8"><link rel="stylesheet" href="styles.css"><body style="min-width:0"><main id="root" style="width:min(700px,100vw);padding:24px;box-sizing:border-box"></main><script src="fixture.js"></script></body></html>');
  await writeFile(path.join(directory, 'main.cjs'), `process.on('uncaughtException', error => { process.stderr.write(String(error?.stack || error)); process.exit(1); }); process.on('unhandledRejection', error => { process.stderr.write(String(error?.stack || error)); process.exit(1); }); const {app,BrowserWindow}=require('electron'); app.setPath('userData',${JSON.stringify(path.join(directory, 'data'))});app.whenReady().then(()=>{app.dock?.hide();const w=new BrowserWindow({show:false,width:900,height:1000,webPreferences:{sandbox:true}});w.webContents.session.webRequest.onBeforeRequest((details,cb)=>cb({cancel:!details.url.startsWith(${JSON.stringify(pathToFileURL(directory + path.sep).href)})}));w.loadURL(${JSON.stringify(pathToFileURL(path.join(directory, 'index.html')).href)});});`);
  const env = { ...process.env }; delete env.ELECTRON_RUN_AS_NODE;
  desktop = await _electron.launch({ executablePath: electron, args: [path.join(directory, 'main.cjs')], env, timeout: 15000 });
  page = await desktop.firstWindow(); page.setDefaultTimeout(5000);
  await page.waitForFunction(() => typeof window.render === 'function');
  await page.locator('summary').click();
});
after(async () => { await desktop?.close(); if (directory) await rm(directory, { recursive: true, force: true }); });

test('nine-language cache catalogs cover every source key and retain interpolation variables', () => {
  const keys = Object.keys(cacheMaintenanceEnglish);
  assert.equal(keys.length, 23);
  for (const catalog of [cacheMaintenanceEnglish, ...Object.values(cacheMaintenanceTranslations)]) {
    assert.deepEqual(Object.keys(catalog), keys);
    for (const key of keys) { assert.ok(catalog[key]); assert.deepEqual(catalog[key].match(/\{\w+\}/g), key.match(/\{\w+\}/g)); }
  }
});

test('cache cleanup requires explicit selection and sends IDs only; refreshed inventory invalidates selection', { skip: noDisplay }, async () => {
  assert.deepEqual(await page.evaluate(() => window.calls), []);
  const move = page.getByRole('button', { name: '移入恢复批次' });
  assert.equal(await move.isDisabled(), true);
  assert.equal(await page.getByRole('checkbox').nth(1).isDisabled(), true);
  await page.getByRole('checkbox').first().check(); await move.click();
  assert.deepEqual(await page.evaluate(() => window.calls), [{ method: 'quarantine', args: { inventoryId: 'inventory-one', entryIds: ['cache-one'] } }]);
  await page.evaluate(() => { window.inventory = { ...window.inventory, inventoryId: 'inventory-two' }; window.render(); });
  await page.waitForFunction(() => !document.querySelector('input').checked);
  assert.equal(await move.isDisabled(), true);
  await page.getByRole('button', { name: '检查缓存', exact: true }).click();
  assert.deepEqual(await page.evaluate(() => window.calls.at(-1)), { method: 'inventory', args: undefined });
});

test('permanent deletion needs a separate confirmation, cancellation changes nothing, and recovery uses batch ID', { skip: noDisplay }, async () => {
  await page.evaluate(() => { window.calls = []; });
  await page.getByRole('button', { name: '永久删除', exact: true }).click();
  assert.deepEqual(await page.evaluate(() => window.calls), []);
  await page.getByRole('button', { name: '取消', exact: true }).click();
  assert.equal(await page.getByRole('button', { name: '确认永久删除', exact: true }).count(), 0);
  await page.getByRole('button', { name: '永久删除', exact: true }).click();
  await page.getByRole('button', { name: '确认永久删除', exact: true }).click();
  assert.deepEqual(await page.evaluate(() => window.calls), [{ method: 'purge', args: { batchId: 'batch-one', confirmed: true } }]);
  await page.getByRole('button', { name: '恢复缓存', exact: true }).click();
  assert.deepEqual(await page.evaluate(() => window.calls.at(-1)), { method: 'restore', args: { batchId: 'batch-one' } });
  assert.equal(await page.getByText('恢复批次仍占用磁盘。永久删除后无法恢复。', { exact: true }).count(), 1);
});

test('recovery overwrite guidance appears only when there is a recovery batch', { skip: noDisplay }, async () => {
  const guidance = page.getByText('恢复时若已有新缓存，将保留新缓存与恢复批次，不会覆盖。', { exact: true });
  assert.equal(await guidance.count(), 1);
  await page.evaluate(() => { window.savedBatches = window.inventory.batches; window.inventory = { ...window.inventory, batches: [] }; window.render(); });
  await page.getByText('没有恢复批次。', { exact: true }).waitFor();
  assert.equal(await guidance.count(), 0);
  assert.equal(await page.getByText('恢复批次仍占用磁盘。永久删除后无法恢复。', { exact: true }).count(), 1);
  await page.evaluate(() => { window.inventory = { ...window.inventory, batches: window.savedBatches }; window.render(); });
  await guidance.waitFor();
});

test('pending work disables all actions and checkboxes; unavailable maintenance disables restore', { skip: noDisplay }, async () => {
  await page.evaluate(() => { window.pending = true; window.render(); });
  await page.waitForFunction(() => document.querySelector('[aria-busy="true"]'));
  assert.equal(await page.locator('button:not(:disabled), input:not(:disabled)').count(), 0);
  await page.evaluate(() => { window.pending = false; window.inventory = { ...window.inventory, maintenanceAvailable: false }; window.render(); });
  await page.waitForFunction(() => !document.querySelector('[aria-busy="true"]'));
  assert.equal(await page.getByRole('button', { name: '恢复缓存', exact: true }).isDisabled(), true);
  assert.equal(await page.getByRole('checkbox').first().isDisabled(), true);
});

test('nine languages retain usable wrapped controls in both themes at narrow width', { skip: noDisplay }, async () => {
  await page.setViewportSize({ width: 520, height: 1200 });
  for (const language of ['zh-CN', 'en', 'zh-TW', 'ja', 'ko', 'es', 'fr', 'de', 'pt-BR']) {
    for (const theme of ['light', 'dark']) {
      await page.evaluate(({ language, theme }) => { window.language = language; document.documentElement.dataset.theme = theme; window.render(); }, { language, theme });
      const title = language === 'zh-CN' ? '缓存维护' : (language === 'en' ? cacheMaintenanceEnglish : cacheMaintenanceTranslations[language])['缓存维护'];
      await page.waitForFunction(title => document.querySelector('summary').textContent === title, title);
      const layout = await page.evaluate(() => ({ page: document.documentElement.scrollWidth, viewport: window.innerWidth,
        badButtons: [...document.querySelectorAll('button')].filter(button => button.scrollWidth > button.clientWidth + 2 || button.getBoundingClientRect().width > window.innerWidth).length }));
      assert.equal(layout.badButtons, 0, `${language}/${theme} button overflow`);
      assert.ok(layout.page <= layout.viewport + 2, `${language}/${theme} page overflow`);
    }
  }
});
