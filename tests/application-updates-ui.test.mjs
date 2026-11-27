import { before, after, test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { build } from 'esbuild';
import { _electron } from 'playwright-core';
import electron from 'electron';
import { languages, translate } from '../src/i18n.mjs';
import { applicationUpdatesEnglish, applicationUpdatesTranslations } from '../src/application-updates-translations.mjs';

const noDisplay = process.platform === 'linux' && !process.env.DISPLAY;
const project = fileURLToPath(new URL('../', import.meta.url));
let directory, desktop, page;
const errors = [];
const idle = { status: 'idle', currentVersion: '1.2.3', latestVersion: null, progress: null, error: null, canInstall: false };
const ready = { ...idle, status: 'ready', latestVersion: '1.2.4', canInstall: true };
before(async () => {
  if (noDisplay) return;
  directory = await mkdtemp(path.join(tmpdir(), 'envara-update-ui-'));
  const result = await build({ stdin: { resolveDir: project, loader: 'jsx', contents: `
import React from 'react'; import {createRoot} from 'react-dom/client';
import {ApplicationUpdates} from './src/ApplicationUpdates.jsx'; import {I18nProvider} from './src/i18n.jsx';
const root=createRoot(document.querySelector('#root'));let version=0;
window.calls=[]; window.pending=[]; window.delay=new Set();window.next={};
const call=async(method,args)=>{window.calls.push({method,args});
 if(window.delay.has(method))return new Promise((resolve,reject)=>window.pending.push({method,resolve,reject}));
 if(window.next[method]){const value=window.next[method];delete window.next[method];if(value.throw)throw Object.assign(new Error('private/raw/updater/error'),{code:value.throw});window.state=value;return structuredClone(value);}
 const phases={checkApplicationUpdate:'checking',downloadApplicationUpdate:'downloading',cancelApplicationUpdate:'available',installApplicationUpdate:'installing'};
 if(method!=='applicationUpdateStatus'){if(!phases[method])throw new Error('Unexpected fixture method: '+method);window.state={...window.state,status:phases[method],error:null};}
 return structuredClone(window.state);
};
window.mountUpdate=(state,language='zh-CN',theme='dark')=>{window.state=state;window.calls=[];window.pending=[];window.delay=new Set();window.next={};document.documentElement.lang=language;document.documentElement.dataset.theme=theme;
 root.render(<I18nProvider key={++version} language={language}><ApplicationUpdates call={call}/></I18nProvider>);};
window.unmountUpdate=()=>root.render(null);window.updateReady=true;
` }, bundle: true, write: false, format: 'iife', platform: 'browser', loader: { '.css': 'empty' }, define: { 'process.env.NODE_ENV': '"test"' } });
  await writeFile(path.join(directory, 'fixture.js'), result.outputFiles[0].text);
  await writeFile(path.join(directory, 'styles.css'), `${await readFile(path.join(project, 'src/styles.css'))}\n${await readFile(path.join(project, 'src/application-updates.css'))}`);
  await writeFile(path.join(directory, 'index.html'), '<!doctype html><html><meta charset="utf-8"><link rel="stylesheet" href="styles.css"><main style="width:min(760px,100%);margin:auto;padding:24px"><div id="root"></div></main><script src="fixture.js"></script></html>');
  const entry = path.join(directory, 'main.cjs');
  await writeFile(entry, `process.on('uncaughtException',error=>{process.stderr.write(String(error?.stack||error));process.exit(1)});process.on('unhandledRejection',error=>{process.stderr.write(String(error?.stack||error));process.exit(1)});const{app,BrowserWindow}=require('electron');app.setPath('userData',${JSON.stringify(path.join(directory, 'data'))});app.whenReady().then(()=>{app.dock?.hide();const w=new BrowserWindow({...(process.platform === 'win32' ? { show: true, x: -3000, y: 0, frame: false, thickFrame: false } : { show: false }),width:1024,height:760,webPreferences:{sandbox:true}});w.loadURL(${JSON.stringify(pathToFileURL(path.join(directory, 'index.html')).href)});});`);
  const env = { ...process.env }; delete env.ELECTRON_RUN_AS_NODE;
  desktop = await _electron.launch({ executablePath: electron, args: [entry], env }); page = await desktop.firstWindow(); page.setDefaultTimeout(5000);
  page.on('pageerror', error => errors.push(error.message));
  await page.context().route('**/*', route => route.request().url().startsWith(pathToFileURL(directory + path.sep).href) ? route.continue() : route.abort());
  await page.waitForFunction(() => window.updateReady === true);
});
after(async () => { try { await desktop?.close(); } finally { if (directory) await rm(directory, { recursive: true, force: true }); } });
async function mount(state = idle, language = 'zh-CN', theme = 'dark') {
  await page.evaluate(({ state, language, theme }) => window.mountUpdate(state, language, theme), { state, language, theme });
  await page.getByRole('heading', { name: translate('应用更新', language), exact: true }).waitFor();
  await page.waitForFunction(() => window.calls.some(item => item.method === 'applicationUpdateStatus'));
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(resolve)));
}
const calls = () => page.evaluate(() => window.calls);
const wait = ms => page.evaluate(ms => new Promise(resolve => setTimeout(resolve, ms)), ms);

test('opening the updater only reads local status and update checks require a click', { skip: noDisplay }, async () => {
  await mount(); await wait(850); assert.deepEqual(await calls(), [{ method: 'applicationUpdateStatus', args: {} }]);
  await page.getByRole('button', { name: '检查更新', exact: true }).click();
  await page.getByText('正在检查更新…', { exact: true }).waitFor();
  await page.evaluate(() => { window.state = { ...window.state, status: 'available', latestVersion: '1.2.4' }; });
  await page.getByRole('button', { name: '下载更新', exact: true }).waitFor();
  const count = (await calls()).length; await wait(850); assert.equal((await calls()).length, count, 'idle updater must stop polling');
  assert.deepEqual(errors, []);
});

test('download progress is observed, cancellation stops polling and stale polls cannot restore a cancelled download', { skip: noDisplay }, async () => {
  await mount({ ...idle, status: 'available', latestVersion: '1.2.4' });
  await page.getByRole('button', { name: '下载更新', exact: true }).click();
  await page.evaluate(() => { window.state.progress = { percent: 37, received: 37, total: 100 }; });
  await page.waitForFunction(() => document.querySelector('progress')?.value === 37);
  await page.evaluate(() => window.delay.add('applicationUpdateStatus'));
  await page.waitForFunction(() => window.pending.some(item => item.method === 'applicationUpdateStatus'));
  await page.getByRole('button', { name: '取消下载', exact: true }).click();
  await page.getByRole('button', { name: '下载更新', exact: true }).waitFor();
  await page.evaluate(value => window.pending.shift().resolve(value), ready);
  assert.equal(await page.getByRole('button', { name: '安装并重启', exact: true }).count(), 0);
  assert.equal(await page.getByRole('button', { name: '下载更新', exact: true }).count(), 1);
});

test('a pending download can be cancelled and its delayed action reply is ignored', { skip: noDisplay }, async () => {
  await mount({ ...idle, status: 'available', latestVersion: '1.2.4' });
  await page.evaluate(() => window.delay.add('downloadApplicationUpdate'));
  await page.getByRole('button', { name: '下载更新', exact: true }).click();
  await page.getByRole('button', { name: '取消下载', exact: true }).click();
  await page.getByRole('button', { name: '下载更新', exact: true }).waitFor();
  await page.evaluate(value => window.pending.shift().resolve(value), ready);
  assert.equal(await page.getByRole('button', { name: '安装并重启', exact: true }).count(), 0);
});

test('install requires confirmation, busy errors remain actionable, and installing is never optimistic success', { skip: noDisplay }, async () => {
  await mount(ready); await page.getByRole('button', { name: '安装并重启', exact: true }).click();
  assert.equal((await calls()).filter(call => call.method === 'installApplicationUpdate').length, 0);
  await page.getByRole('button', { name: '取消', exact: true }).click();
  await page.getByRole('button', { name: '安装并重启', exact: true }).click();
  await page.evaluate(value => { window.next.installApplicationUpdate = { ...value, error: 'APP_UPDATE_BUSY' }; }, ready);
  await page.getByRole('button', { name: '确认安装并重启', exact: true }).click();
  await page.getByText('请先保存并结束运行任务，再重试安装。', { exact: true }).waitFor();
  await page.getByRole('button', { name: '安装并重启', exact: true }).click();
  await page.getByRole('button', { name: '确认安装并重启', exact: true }).click();
  await page.getByText('正在安装；完成后应用会重新启动。', { exact: true }).waitFor();
  assert.equal(await page.getByRole('button').count(), 0);
  assert.equal((await page.textContent('body')).includes('安装成功'), false);
  assert.equal((await calls()).filter(call => call.method === 'installApplicationUpdate').length, 2);
});

test('error retry follows the prepared candidate and unsupported builds never expose install', { skip: noDisplay }, async () => {
  await mount({ ...ready, canInstall: false });
  assert.equal(await page.getByRole('button', { name: '安装并重启', exact: true }).isDisabled(), true);
  await mount({ ...idle, status: 'error', latestVersion: '1.2.4', error: 'APP_UPDATE_HASH_MISMATCH' });
  await page.getByText('更新包校验未通过，请重新下载。', { exact: true }).waitFor();
  await page.getByRole('button', { name: '下载更新', exact: true }).click();
  assert.equal((await calls()).filter(call => call.method === 'downloadApplicationUpdate').length, 1);
  await mount({ ...idle, status: 'error', error: 'PRIVATE_RAW_TOKEN' });
  assert.equal((await page.textContent('body')).includes('PRIVATE_RAW_TOKEN'), false);
  assert.equal(await page.getByRole('button', { name: '检查更新', exact: true }).count(), 1);
  await mount({ ...idle, status: 'unsupported', error: 'APP_UPDATE_DEVELOPMENT' });
  await page.getByText('开发版本不执行应用替换，请使用完整安装包。', { exact: true }).waitFor();
  assert.equal(await page.getByRole('button').count(), 0);
  await mount({ ...idle, status: 'current', currentVersion: '2.0.0', latestVersion: '1.2.4' });
  assert.equal(await page.getByText('当前已是最新版本。', { exact: true }).count(), 1);
  assert.equal((await page.textContent('body')).includes('可更新至'), false, 'an older public release must not be offered as an update');
});

test('unmount cancels polling and ignores delayed replies', { skip: noDisplay }, async () => {
  await mount({ ...idle, status: 'checking' });
  await page.evaluate(() => window.delay.add('applicationUpdateStatus'));
  await page.waitForFunction(() => window.pending.length > 0);
  await page.evaluate(() => window.unmountUpdate());
  await page.locator('.application-updates').waitFor({ state: 'detached' });
  await page.evaluate(value => window.pending.shift().resolve(value), ready);
  const count = (await calls()).length; await wait(900); assert.equal((await calls()).length, count); assert.deepEqual(errors, []);
  await mount({ ...idle, status: 'available', latestVersion: '1.2.4' });
  await page.evaluate(() => window.delay.add('downloadApplicationUpdate'));
  await page.getByRole('button', { name: '下载更新', exact: true }).click();
  await page.waitForFunction(() => window.pending.length > 0);
  await page.evaluate(() => window.unmountUpdate());
  await page.locator('.application-updates').waitFor({ state: 'detached' });
  const actionCount = (await calls()).length;
  await page.evaluate(() => window.pending.shift().reject(new Error('late unmounted failure')));
  await wait(50); assert.equal((await calls()).length, actionCount, 'unmounted action must not start another status read');
});

test('uncertain updater cleanup requires a manual restart and exposes no retry or install action', { skip: noDisplay }, async () => {
  await mount({ ...ready, canInstall: false, restartRequired: true, error: 'APP_UPDATE_CLEANUP' });
  await page.getByText('更新准备未完成，请手动重启境舱后再试。', { exact: true }).waitFor();
  assert.equal(await page.getByRole('button').count(), 0);
  assert.equal(await page.getByText('更新已下载并验证，可以安装。', { exact: true }).count(), 0);
  const count = (await calls()).length; await wait(850); assert.equal((await calls()).length, count);
});

test('an installation reply revoked by shutdown reads authoritative status instead of reporting a false failure', { skip: noDisplay }, async () => {
  await mount(ready); await page.getByRole('button', { name: '安装并重启', exact: true }).click();
  await page.evaluate(() => { window.delay.add('installApplicationUpdate'); });
  await page.getByRole('button', { name: '确认安装并重启', exact: true }).click();
  await page.waitForFunction(() => window.pending.some(item => item.method === 'installApplicationUpdate'));
  await page.evaluate(() => { window.state = { ...window.state, status:'installing' }; window.pending.shift().reject(Object.assign(new Error('private shutdown error'),{code:'APP_CLOSING'})); });
  await page.getByText('正在安装；完成后应用会重新启动。', { exact: true }).waitFor();
  assert.equal(await page.getByRole('alert').count(), 0);
  await page.evaluate(() => { window.state = { ...window.state, status:'ready', error:'APP_UPDATE_CLEANUP', restartRequired:true, canInstall:false }; });
  await page.getByText('更新准备未完成，请手动重启境舱后再试。', { exact: true }).waitFor();
  assert.equal(await page.getByRole('button').count(), 0);
});

test('updater translations cover every locale with matching placeholders', () => {
  const keys = Object.keys(applicationUpdatesEnglish), placeholders = text => [...text.matchAll(/\{\w+\}/g)].map(item => item[0]).sort();
  for (const [language, entries] of Object.entries(applicationUpdatesTranslations)) {
    assert.deepEqual(Object.keys(entries), keys, language);
    for (const key of keys) { assert.ok(entries[key]); assert.deepEqual(placeholders(entries[key]), placeholders(key), `${language} ${key}`); }
  }
});

test('previous install receipts are independent from current download and install authority', { skip: noDisplay }, async () => {
  for (const [status, label] of [['installed', '上次更新已完成：9.9.9'], ['failed', '上次更新未完成：9.9.9'], ['pending', '上次更新结果尚未确认：9.9.9']]) {
    await mount({ ...idle, lastResult: { status, version: '9.9.9', error: 'PRIVATE_RECEIPT_ERROR' } });
    await page.getByText(label, { exact: true }).waitFor();
    assert.equal(await page.getByRole('button', { name: '检查更新', exact: true }).count(), 1);
    assert.equal(await page.getByRole('button', { name: '安装并重启', exact: true }).count(), 0);
    assert.equal(await page.getByRole('button', { name: '下载更新', exact: true }).count(), 0);
    assert.equal((await page.textContent('body')).includes('PRIVATE_RECEIPT_ERROR'), false);
    assert.deepEqual(await calls(), [{ method: 'applicationUpdateStatus', args: {} }]);
  }
});

test('missing release assets can be checked again and native install errors give safe actionable guidance', { skip: noDisplay }, async () => {
  await mount({ ...idle, status: 'unsupported', error: 'APP_UPDATE_ASSET_UNAVAILABLE' });
  await page.getByText('此版本尚无适合当前平台的更新包。', { exact: true }).waitFor();
  assert.equal(await page.getByText('此安装方式暂不支持应用内更新。', { exact: true }).count(), 0);
  assert.equal(await page.getByRole('button', { name: '检查更新', exact: true }).isEnabled(), true);
  await page.getByRole('button', { name: '检查更新', exact: true }).click();
  assert.equal((await calls()).filter(call => call.method === 'checkApplicationUpdate').length, 1);
  await mount({ ...ready, error: 'APP_UPDATE_LOCATION' });
  await page.getByText('当前位置无法更新。请将境舱移到有写入权限的“应用程序”目录后重试。', { exact: true }).waitFor();
  assert.equal(await page.getByText('请先保存并结束运行任务，再重试安装。', { exact: true }).count(), 0);
  await mount({ ...ready, error: 'APP_UPDATE_APP_RUNNING' });
  await page.getByText('请先保存并结束运行任务，再重试安装。', { exact: true }).waitFor();
  await page.getByRole('button', { name: '安装并重启', exact: true }).waitFor();
  await mount({ ...idle, status: 'error', latestVersion: '1.2.4', error: 'APP_UPDATE_SYSTEM_UNSUPPORTED' });
  await page.getByText('当前 macOS 版本不满足新版要求，未安装更新。', { exact: true }).waitFor();
  assert.equal(await page.getByRole('button', { name: '安装并重启', exact: true }).count(), 0);
});

for (const language of languages) for (const theme of ['dark', 'light']) test(`updater ${language} ${theme} confirmation is readable and contained`, { skip: noDisplay }, async () => {
  await mount(ready, language, theme);
  await page.getByRole('button', { name: translate('安装并重启', language), exact: true }).click();
  await page.getByRole('button', { name: translate('确认安装并重启', language), exact: true }).waitFor();
  const overflow = await page.evaluate(() => [...document.querySelectorAll('.application-updates,.application-updates-heading,.application-update-confirm')]
    .filter(el => el.scrollWidth > el.clientWidth + 2).map(el => el.className));
  assert.deepEqual(overflow, []); assert.equal(await page.evaluate(() => document.documentElement.lang), language); assert.deepEqual(errors, []);
  if (['zh-CN', 'en', 'de'].includes(language)) {
    const target = path.join(project, 'test-artifacts/application-updates-ui'); await mkdir(target, { recursive: true });
    await page.screenshot({ path: path.join(target, `${language}-${theme}.png`) });
  }
});
