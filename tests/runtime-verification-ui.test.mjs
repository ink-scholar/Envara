import { before, after, test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { build } from 'esbuild';
import { _electron } from 'playwright-core';
import electron from 'electron';

const noDisplay = process.platform === 'linux' && !process.env.DISPLAY;
let directory, desktop, page, proxy;
const proxyRequests = [];
before(async () => {
  if (noDisplay) return;
  directory = await mkdtemp(path.join(tmpdir(), 'envara-runtime-verification-'));
  proxy = http.createServer((_req, res) => { res.writeHead(502); res.end(); });
  proxy.on('connect', (request, socket) => { proxyRequests.push(request.url); socket.end('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n'); });
  await new Promise(resolve => proxy.listen(0, '127.0.0.1', resolve));
  const bundle = await build({ stdin: { resolveDir: fileURLToPath(new URL('../', import.meta.url)), loader: 'jsx', contents: `
import React from 'react'; import { createRoot } from 'react-dom/client';
import { RuntimeVerification } from './src/RuntimeVerification.jsx';
const root = createRoot(document.querySelector('#root'));
window.calls = []; window.reads = []; window.checks = [];
window.report = { profileId:'first',checkedAt:'2026-11-16T12:00:00.000Z',stale:false,expected:{locale:'en-US',timezone:'UTC',ip:'8.8.8.8'},browser:{scope:'browser-owned-page',status:'observed',observed:{locale:'en-US',timezone:'UTC',ip:'8.8.8.8'},checks:{locale:'match',timezone:'match',ip:'match'}},terminal:{scope:'terminal-launch-context',status:'unknown',sessions:[]} };
const call = (method, args) => { window.calls.push({method,args}); return new Promise(resolve => (method === 'runtimeVerificationSnapshot' ? window.reads : window.checks).push({args,resolve})); };
window.mount = () => root.render(<RuntimeVerification profiles={[{id:'first',name:'First'},{id:'second',name:'Second'}]} api={call}/>);
window.mount();` }, bundle: true, write: false, format: 'iife', platform: 'browser', loader: { '.css': 'empty' }, define: { 'process.env.NODE_ENV': '"test"' } });
  await writeFile(path.join(directory, 'fixture.js'), bundle.outputFiles[0].text);
  await writeFile(path.join(directory, 'index.html'), '<!doctype html><div id="root"></div><script src="./fixture.js"></script>');
  await writeFile(path.join(directory, 'main.cjs'), `process.on('uncaughtException',error=>{process.stderr.write(String(error?.stack||error));process.exit(1);});process.on('unhandledRejection',error=>{process.stderr.write(String(error?.stack||error));process.exit(1);});
const {app,BrowserWindow,session}=require('electron');if(!app||!BrowserWindow){process.stderr.write('Electron fixture API unavailable');process.exit(1);}
app.setPath('userData',${JSON.stringify(path.join(directory, 'data'))});app.disableHardwareAcceleration();app.commandLine.appendSwitch('disable-background-networking');
app.whenReady().then(async()=>{app.dock?.hide();await session.defaultSession.setProxy({mode:'fixed_servers',proxyRules:'http://127.0.0.1:${proxy.address().port}',proxyBypassRules:'<-loopback>'});const w=new BrowserWindow({show:false,width:1100,height:850,webPreferences:{sandbox:true}});await w.loadURL(${JSON.stringify(pathToFileURL(path.join(directory, 'index.html')).href)});});`);
  const env = { ...process.env }; delete env.ELECTRON_RUN_AS_NODE;
  desktop = await _electron.launch({ executablePath: electron, args: [path.join(directory, 'main.cjs')], env, timeout: 15000 });
  page = await desktop.firstWindow({ timeout: 10000 }); await page.waitForFunction(() => window.reads?.length === 1, { timeout: 10000 });
});
after(async () => { try { await desktop?.close(); } finally { if (proxy) await new Promise(resolve => proxy.close(resolve)); if (directory) await rm(directory, { recursive: true, force: true }); } });

test('runtime panel is manual and a late snapshot cannot overwrite a completed check', { skip: noDisplay }, async () => {
  assert.deepEqual(await page.evaluate(() => window.calls.map(call => call.method)), ['runtimeVerificationSnapshot']);
  await page.getByRole('button', { name: '核验当前运行状态' }).click();
  await page.waitForFunction(() => window.checks.length === 1);
  await page.evaluate(() => window.checks.shift().resolve(structuredClone(window.report)));
  await page.getByText('8.8.8.8').first().waitFor();
  await page.evaluate(() => { const old = structuredClone(window.report); old.browser.observed.ip = '9.9.9.9'; window.reads.shift().resolve({results:[old],pending:[]}); });
  assert.equal(await page.getByText('9.9.9.9', { exact: true }).count(), 0);
  assert.equal(await page.getByText('8.8.8.8', { exact: true }).count(), 2);
});

test('duplicate clicks and late replies cannot change another selected environment', { skip: noDisplay }, async () => {
  await page.getByRole('button', { name: '核验当前运行状态' }).evaluate(button => { button.click(); button.click(); });
  assert.equal(await page.evaluate(() => window.checks.length), 1);
  await page.getByRole('combobox').selectOption('second');
  await page.waitForFunction(() => window.reads.length === 1);
  await page.evaluate(() => { window.checks.shift().resolve(structuredClone(window.report)); window.reads.shift().resolve({results:[],pending:[]}); });
  await page.getByText('尚无实测结果。').waitFor();
  assert.equal(await page.getByText('8.8.8.8', { exact: true }).count(), 0);
});

test('production observation script runs in a real disposable Chromium document and refuses unavailable egress', { skip: noDisplay }, async () => {
  const source = await readFile(new URL('../third_party/browseforge/internal/api/runtime_verification.go', import.meta.url), 'utf8');
  const script = source.match(/const runtimeVerificationScript = `([\s\S]*?)`/)[1];
  const before = await page.evaluate(() => ({ locale: navigator.language, timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, url: location.href }));
  const observed = await page.evaluate(script);
  assert.equal(observed.locale, before.locale); assert.equal(observed.timezone, before.timezone); assert.equal(observed.ip, null);
  assert.equal(await page.url(), before.url);
  assert.ok(proxyRequests.includes('ipwho.is:443'), 'the fixed browser fetch used the owned rejecting proxy');
});
