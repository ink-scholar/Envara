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
import { languages } from '../shared/interface-languages.mjs';
import { translate } from '../src/i18n.mjs';

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
import { I18nProvider } from './src/i18n.jsx';
const root = createRoot(document.querySelector('#root'));
window.calls = []; window.reads = []; window.checks = []; window.language = 'zh-CN';
window.report = { profileId:'first',checkedAt:'2026-11-16T12:00:00.000Z',stale:false,expected:{locale:'en-US',timezone:'UTC',ip:'8.8.8.8'},browser:{scope:'browser-owned-page',status:'observed',observed:{locale:'en-US',timezone:'UTC',ip:'8.8.8.8'},checks:{locale:'match',timezone:'match',ip:'match'}},terminal:{scope:'terminal-launch-context',status:'unknown',sessions:[]} };
const call = (method, args) => { window.calls.push({method,args}); return new Promise(resolve => (method === 'runtimeVerificationSnapshot' ? window.reads : window.checks).push({args,resolve})); };
window.mount = () => root.render(<I18nProvider language={window.language}><RuntimeVerification profiles={[{id:'first',name:'First'},{id:'second',name:'Second'}]} api={call}/></I18nProvider>);
window.mount();` }, bundle: true, write: false, format: 'iife', platform: 'browser', loader: { '.css': 'empty' }, define: { 'process.env.NODE_ENV': '"test"' } });
  await writeFile(path.join(directory, 'fixture.js'), bundle.outputFiles[0].text);
  const styles = await Promise.all(['styles.css', 'runtime-verification.css'].map(name => readFile(new URL(`../src/${name}`, import.meta.url), 'utf8')));
  await writeFile(path.join(directory, 'index.html'), `<html data-theme="dark"><head><meta charset="utf-8"><style>${styles.join('\n')} #root{width:680px;margin:20px}</style></head><body><div id="root"></div><script src="./fixture.js"></script></body></html>`);
  await writeFile(path.join(directory, 'main.cjs'), `process.on('uncaughtException',error=>{process.stderr.write(String(error?.stack||error));process.exit(1);});process.on('unhandledRejection',error=>{process.stderr.write(String(error?.stack||error));process.exit(1);});
const {app,BrowserWindow,session}=require('electron');if(!app||!BrowserWindow){process.stderr.write('Electron fixture API unavailable');process.exit(1);}
app.setPath('userData',${JSON.stringify(path.join(directory, 'data'))});app.disableHardwareAcceleration();app.commandLine.appendSwitch('disable-background-networking');
app.whenReady().then(async()=>{app.dock?.hide();await session.defaultSession.setProxy({mode:'fixed_servers',proxyRules:'http://127.0.0.1:${proxy.address().port}',proxyBypassRules:'<-loopback>'});const w=new BrowserWindow({...(process.platform === 'win32' ? { show: true, x: -3000, y: 0, frame: false, thickFrame: false } : { show: false }),width:1100,height:850,webPreferences:{sandbox:true}});await w.loadURL(${JSON.stringify(pathToFileURL(path.join(directory, 'index.html')).href)});});`);
  const env = { ...process.env }; delete env.ELECTRON_RUN_AS_NODE;
  desktop = await _electron.launch({ executablePath: electron, args: [path.join(directory, 'main.cjs')], env, timeout: 15000 });
  page = await desktop.firstWindow({ timeout: 10000 }); await page.waitForFunction(() => window.reads?.length === 1, { timeout: 10000 });
});
after(async () => { try { await desktop?.close(); } finally { if (proxy) await new Promise(resolve => proxy.close(resolve)); if (directory) await rm(directory, { recursive: true, force: true }); } });

test('runtime panel is manual and a late snapshot cannot overwrite a completed check', { skip: noDisplay }, async () => {
  assert.deepEqual(await page.evaluate(() => window.calls.map(call => call.method)), ['runtimeVerificationSnapshot']);
  const instructions = page.locator('.runtime-verification-instructions');
  assert.equal(await instructions.evaluate(element => element.open), false);
  assert.equal(await instructions.locator('p').isVisible(), false);
  await instructions.locator('summary').focus(); await page.keyboard.press('Enter');
  assert.equal(await instructions.locator('p').isVisible(), true);
  assert.match(await instructions.innerText(), /ipwho\.is/);
  await page.keyboard.press('Enter');
  assert.deepEqual(await page.evaluate(() => window.calls.map(call => call.method)), ['runtimeVerificationSnapshot'], 'reading instructions does not start a check');
  await page.getByRole('button', { name: '核验当前运行状态' }).click();
  await page.waitForFunction(() => window.checks.length === 1);
  assert.equal(await page.getByRole('status').textContent(), '正在核验…');
  assert.ok(await page.getByRole('status').evaluate(element => element.getBoundingClientRect().height <= 1), 'pending remains announced without a duplicate visual paragraph');
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

test('runtime controls adapt to their container in nine languages without changing the check or workspace', { skip: noDisplay }, async () => {
  const before = await page.evaluate(() => window.calls.length);
  for (const language of languages) for (const width of [320, 680]) {
    await page.evaluate(({ language, width }) => {
      window.language = language; document.querySelector('#root').style.width = `${width}px`; window.mount();
    }, { language, width });
    await page.waitForFunction(language => document.documentElement.lang === language, language);
    await page.getByRole('button', { name: translate('核验当前运行状态', language), exact: true }).waitFor();
    const layout = await page.locator('.runtime-verification').evaluate(element => {
      const bounds = element.getBoundingClientRect(), heading = element.querySelector('.runtime-verification-heading');
      return { direction: getComputedStyle(heading).flexDirection, viewport: innerWidth, overflow: element.scrollWidth > element.clientWidth + 1,
        controlsInside: [...element.querySelectorAll('button,select')].every(control => {
          const rect = control.getBoundingClientRect(); return rect.left >= bounds.left && rect.right <= bounds.right && control.scrollWidth <= control.clientWidth + 1;
        }) };
    });
    assert.equal(layout.direction, width === 320 ? 'column' : 'row', `${language}: follows the container rather than the wide window`);
    assert.ok(layout.viewport > 760); assert.equal(layout.overflow, false, language); assert.equal(layout.controlsInside, true, language);
    const summary = page.locator('.runtime-verification-instructions > summary');
    await summary.focus(); assert.equal(await summary.evaluate(element => document.activeElement === element), true);
    assert.equal(await summary.textContent(), translate('使用说明', language));
  }
  assert.equal(await page.evaluate(() => window.calls.length), before, 'layout and language changes do not start any backend operation');
});
