import { before, after, test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { build } from 'esbuild';
import { _electron } from 'playwright-core';
import electron from 'electron';

const noDisplay = process.platform === 'linux' && !process.env.DISPLAY;
let directory, desktop, page;
const project = fileURLToPath(new URL('../', import.meta.url));
before(async () => {
  if (noDisplay) return;
  directory = await mkdtemp(path.join(tmpdir(), 'envara-site-data-'));
  const output = await build({ stdin: { resolveDir: project, loader: 'jsx', contents: `
import React from 'react'; import { createRoot } from 'react-dom/client';
import { BrowserSiteData } from './src/BrowserSiteData.jsx';
const root = createRoot(document.querySelector('#root'));
window.calls = []; window.delayLists = false; window.pending = [];
window.report = {instanceId: 'a'.repeat(32), runtime:'cloakbrowser', canClear:true, checkedAt:new Date().toISOString(), cookies: [
{name:'fixture-login',domain:'.example.test',path:'/',expires:-1,httpOnly:true,secure:true,sameSite:'Lax',partitionState:'unpartitioned'},
{name:'other-login',domain:'other.test',path:'/',expires:-1,httpOnly:true,secure:true,sameSite:'Lax',partitionState:'partitioned',partitionKey:'https://top.test'}]};
const call = async (method, args) => { window.calls.push({method,args});
 if (method === 'listBrowserSiteData') { if(window.delayLists) return new Promise(resolve=>window.pending.push(resolve)); return structuredClone(window.report); }
 if (method === 'clearBrowserSiteCookies') { window.report.cookies = window.report.cookies.filter(row=>row.domain !== args.domain); return {removed:1}; }
 throw new Error('unexpected fixture operation'); };
window.mount = id => root.render(<BrowserSiteData profileId={id} call={call} />);
window.mount('fixture');` }, bundle: true, write: false, platform: 'browser', format: 'iife', loader: { '.css': 'empty' },
    define: { 'process.env.NODE_ENV': '"test"' }, plugins: [{ name: 'site-i18n', setup(builder) {
      builder.onResolve({ filter: /^\.\/i18n.jsx$/ }, () => ({ path: 'i18n', namespace: 'site' }));
      builder.onLoad({ filter: /.*/, namespace: 'site' }, () => ({ contents: `export const useI18n=()=>({t:(s,v={})=>s.replace(/\\{(\\w+)\\}/g,(_,k)=>v[k]??'{'+k+'}')});` }));
    } }],
  });
  await writeFile(path.join(directory, 'fixture.js'), output.outputFiles[0].text);
  await writeFile(path.join(directory, 'styles.css'), `${await readFile(path.join(project, 'src/styles.css'))}\n${await readFile(path.join(project, 'src/browser-site-data.css'))}`);
  await writeFile(path.join(directory, 'index.html'), '<!doctype html><html data-theme="dark"><meta charset="utf-8"><link rel="stylesheet" href="styles.css"><body><main id="root" style="width:700px;padding:24px"></main><script src="fixture.js"></script></body></html>');
  await writeFile(path.join(directory, 'main.cjs'), `process.on('uncaughtException', error => { process.stderr.write(String(error?.stack || error)); process.exit(1); }); process.on('unhandledRejection', error => { process.stderr.write(String(error?.stack || error)); process.exit(1); }); const {app,BrowserWindow}=require('electron'); app.setPath('userData',${JSON.stringify(path.join(directory, 'data'))});app.whenReady().then(()=>{app.dock?.hide();const w=new BrowserWindow({...(process.platform === 'win32' ? { show: true, x: -3000, y: 0, frame: false, thickFrame: false } : { show: false }),width:1100,height:850,webPreferences:{sandbox:true}});w.loadURL(${JSON.stringify(pathToFileURL(path.join(directory, 'index.html')).href)});});`);
  const env = { ...process.env }; delete env.ELECTRON_RUN_AS_NODE;
  desktop = await _electron.launch({ executablePath: electron, args: [path.join(directory, 'main.cjs')], env });
  page = await desktop.firstWindow(); await page.waitForFunction(() => typeof window.mount === 'function');
});
after(async () => { await desktop?.close(); if (directory) await rm(directory, { recursive: true, force: true }); });

test('cookie panel reads on request, filters, requires explicit domain confirmation and preserves other sites', { skip: noDisplay }, async () => {
  assert.deepEqual(await page.evaluate(() => window.calls), []);
  await page.getByRole('button', { name: '刷新 Cookie' }).click();
  await page.getByText('.example.test', { exact: true }).click();
  await page.getByRole('button', { name: '清理此网站 Cookie', exact: true }).click();
  assert.equal((await page.evaluate(() => window.calls)).filter(c => c.method.startsWith('clear')).length, 0);
  await page.getByRole('button', { name: '取消', exact: true }).click();
  await page.getByRole('button', { name: '清理此网站 Cookie', exact: true }).click();
  await page.getByRole('button', { name: '确认清理网站 Cookie', exact: true }).click();
  await page.waitForFunction(() => window.calls.length === 3);
  assert.equal(await page.getByText('.example.test', { exact: true }).count(), 0);
  assert.equal(await page.getByText('other.test', { exact: true }).count(), 1);
  assert.deepEqual((await page.evaluate(() => window.calls))[1], { method: 'clearBrowserSiteCookies', args: { profileId: 'fixture', instanceId: 'a'.repeat(32), domain: '.example.test' } });
  await page.getByRole('searchbox').fill('no-such-cookie');
  assert.equal(await page.getByText('没有匹配的 Cookie。').count(), 1);
});
test('late cookie reply cannot populate a newly selected environment', { skip: noDisplay }, async () => {
  await page.evaluate(() => { window.delayLists = true; });
  await page.getByRole('button', { name: '刷新 Cookie' }).click();
  await page.evaluate(() => window.mount('second'));
  await page.waitForFunction(() => !document.querySelector('button').disabled);
  await page.evaluate(() => window.pending.shift()(structuredClone(window.report)));
  assert.equal(await page.getByRole('searchbox').count(), 0);
  await page.evaluate(() => { window.delayLists = false; window.report.canClear = false; window.report.runtime = 'camoufox'; });
  await page.getByRole('button', { name: '刷新 Cookie' }).click();
  await page.getByText('other.test', { exact: true }).click();
  assert.equal(await page.getByRole('button', { name: '清理此网站 Cookie', exact: true }).count(), 0);
  assert.equal(await page.getByText('此内核仅支持查看；定点清理及分区信息尚不可用。').count(), 1);
});
test('real Chromium CDP targets one stored domain and retains another domain and its partition cookie', { skip: noDisplay }, async () => {
  const cdp = await page.context().newCDPSession(page);
  try {
    const cookies = [
      { name:'owned-fixture', value:'one', domain:'.example.test', path:'/', secure:true, sameSite:'None' },
      { name:'owned-fixture', value:'two', domain:'other.test', path:'/', secure:true, sameSite:'None' },
      { name:'partition-fixture', value:'three', domain:'other.test', path:'/', secure:true, sameSite:'None', partitionKey:{topLevelSite:'https://top.test',hasCrossSiteAncestor:true} },
    ];
    await cdp.send('Network.setCookies', { cookies });
    const before = (await cdp.send('Network.getAllCookies')).cookies;
    assert.equal(before.length, 3);
    for (const cookie of before.filter(row => row.domain === '.example.test')) {
      await cdp.send('Network.deleteCookies', { name:cookie.name, domain:cookie.domain, path:cookie.path, ...(cookie.partitionKey ? {partitionKey:cookie.partitionKey} : {}) });
    }
    const after = (await cdp.send('Network.getAllCookies')).cookies;
    assert.deepEqual(after, before.filter(row => row.domain !== '.example.test'));
  } finally { await cdp.detach(); }
});
