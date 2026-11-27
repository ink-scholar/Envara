import { before, after, test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { mkdtemp, realpath, mkdir, writeFile, readFile, rm } from 'node:fs/promises';
import { build } from 'esbuild';
import { _electron } from 'playwright-core';

// Windows accepts attachments only for a PowerShell foreground.
const shellForeground = process.platform === 'win32' ? 'powershell.exe' : 'zsh';
// Actual production preload, TerminalDock, xterm, attachment controller and
// storage in an isolated Electron window. Synthetic clipboard events use real
// DOM File objects; the host clipboard and user terminals are never touched.
const noDisplay = process.platform === 'linux' && !process.env.DISPLAY;
const id = index => `term_${String(index).repeat(32)}`;
let directory, desktop, page;
before(async () => {
  if (noDisplay) return;
  directory = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-attachment-ui-')));
  const profilesDir = path.join(directory, 'profiles'); await mkdir(profilesDir); await mkdir(path.join(profilesDir, 'owned'));
  const pane = fileURLToPath(new URL('../src/TerminalPane.jsx', import.meta.url));
  const preload = fileURLToPath(new URL('../electron/preload.cjs', import.meta.url));
  const controller = new URL('../electron/terminal-controller.mjs', import.meta.url).href;
  const output = await build({ stdin: { resolveDir: path.dirname(pane), loader: 'jsx', contents: `
import React from 'react'; import {createRoot} from 'react-dom/client';
import {TerminalDock} from ${JSON.stringify(pane)};
createRoot(document.querySelector('#root')).render(<TerminalDock standalone profiles={[{id:'owned',name:'Synthetic attachment environment',timezone:'UTC'}]} selectedProfileId="owned" onProfilesChange={value=>{window.fixtureRendered=value}} />);
window.fixtureReady=true;
` }, bundle: true, platform: 'browser', format: 'iife', write: false, loader: { '.css': 'empty' } });
  await writeFile(path.join(directory, 'renderer.js'), output.outputFiles[0].text);
  const styles = await Promise.all(['../src/styles.css', '../src/terminal.css', '../src/terminal-window.css', '../node_modules/@xterm/xterm/css/xterm.css'].map(name => readFile(new URL(name, import.meta.url), 'utf8')));
  await writeFile(path.join(directory, 'index.html'), `<html lang="zh-CN" data-theme="dark"><head><meta charset="utf-8"><style>${styles.join('\n')}</style></head><body class="terminal-window-shell"><input id="fixture-file" type="file" hidden><div id="root" style="height:100vh"></div><script src="renderer.js"></script></body></html>`);
  const sessions = [1, 2].map(index => ({ sessionId: id(index), profileId: 'owned', kind: 'shell', status: 'running', cwd: directory, columns: 80, rows: 24, sequence: 0, replay: 'Synthetic prompt\r\n', startedAt: '2026-01-01T00:00:00Z', savedTerminalName: `Attachment session ${index}` }));
  await writeFile(path.join(directory, 'main.cjs'), `
process.on('uncaughtException', error => { process.stderr.write(String(error?.stack || error)); process.exit(1); });
process.on('unhandledRejection', error => { process.stderr.write(String(error?.stack || error)); process.exit(1); });
const {app,BrowserWindow,ipcMain}=require('electron');
app.setPath('userData',${JSON.stringify(path.join(directory, 'data'))});
app.whenReady().then(async()=>{
  app.dock?.hide(); const {TerminalController}=await import(${JSON.stringify(controller)});
  const sessions=${JSON.stringify(sessions)}; const owned=new Map(sessions.map(item=>[item.sessionId,{...item,pty:{process:${JSON.stringify(shellForeground)}},abortController:new AbortController()}]));
  globalThis.fixtureWrites=[]; globalThis.fixtureStages=[]; globalThis.fixtureDelay=false; globalThis.fixtureReleases=[]; globalThis.fixtureWriteDelay=false; globalThis.fixtureWriteReleases=[]; globalThis.fixtureOwned=owned;
  const terminal={ready:Promise.resolve(), profilesDir:${JSON.stringify(profilesDir)}, session:id=>{const session=owned.get(id);if(!session)throw new Error('unknown fixture');return session;}, snapshot:async()=>({profiles:[{profileId:'owned',cwd:${JSON.stringify(directory)},savedTerminals:[],sessions}]}), write:async args=>{globalThis.fixtureWrites.push(args);if(globalThis.fixtureWriteDelay)await new Promise(resolve=>globalThis.fixtureWriteReleases.push(resolve));return {accepted:true}}, resize:async()=>({}), listClaudeAccounts:async()=>({accounts:[]}), listTerminalSshConnections:async()=>({supported:false,connections:[]})};
  const service={snapshot:async()=>({profiles:[{id:'owned',name:'Synthetic attachment environment'}],proxies:[]})};
  const controller=new TerminalController({terminal,service}); globalThis.fixtureController=controller;
  const view=new BrowserWindow({...(process.platform === 'win32' ? { show: true, x: -3000, y: 0, frame: false, thickFrame: false } : { show: false }),width:1100,height:720,webPreferences:{preload:${JSON.stringify(preload)},contextIsolation:true,sandbox:true,backgroundThrottling:false}});
  ipcMain.handle('envara:call',async(event,{method,args})=>{try{
    if(event.sender!==view.webContents||event.senderFrame!==event.sender.mainFrame)throw new Error('invalid sender');
    if(method==='stageTerminalAttachments') { globalThis.fixtureStages.push({sessionId:args.sessionId,files:args.files.map(file=>({name:file.name,path:!!file.path,bytes:file.bytes?.byteLength}))}); if(globalThis.fixtureDelay)await new Promise(resolve=>globalThis.fixtureReleases.push(resolve)); }
    const value=method==='snapshot'?await service.snapshot():await controller.dispatch(method,args,{window:view});return {ok:true,value};
  }catch(error){return {ok:false,error:{message:error.message,code:error.code}}}});
  await view.loadFile(${JSON.stringify(path.join(directory, 'index.html'))});
});
`);
  const env = { ...process.env }; delete env.ELECTRON_RUN_AS_NODE;
  desktop = await _electron.launch({ args: [path.join(directory, 'main.cjs')], env, timeout: 15000 });
  page = await desktop.firstWindow(); page.setDefaultTimeout(5000);
  await page.waitForFunction(() => window.fixtureReady && window.fixtureRendered);
  await page.locator('.terminal-session-view:not([hidden]) .xterm').waitFor();
});
after(async () => { try { await desktop?.close(); } finally { if (directory) await rm(directory, { recursive: true, force: true }); } });
const activeInput = () => page.locator('.terminal-session-view:not([hidden]) .xterm-helper-textarea');
const writes = () => desktop.evaluate(() => globalThis.fixtureWrites);
const waitIdle = () => page.waitForFunction(() => !document.querySelector('.terminal-attachment-status'));
async function imagePaste() {
  await activeInput().evaluate(element => {
    const data = new DataTransfer(); data.items.add(new File([new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10])], 'screen.png', { type: 'image/png' }));
    element.dispatchEvent(new ClipboardEvent('paste', { bubbles: true, cancelable: true, clipboardData: data }));
  });
}
async function reset() { await waitIdle(); await desktop.evaluate(() => { globalThis.fixtureWrites = []; globalThis.fixtureStages = []; globalThis.fixtureDelay = false; }); }

test('image paste crosses the real File bridge and inserts one owned quoted path without Enter', { skip: noDisplay }, async () => {
  await page.locator('.terminal-session-tabs [role="tab"]').nth(0).click();
  await reset(); await imagePaste();
  await waitIdle();
  for (let index = 0; index < 100 && !(await writes()).length; index++) await new Promise(resolve => setTimeout(resolve, 10));
  const sent = await writes(); assert.equal(sent.length, 1); assert.equal(sent[0].sessionId, id(1));
  assert.match(sent[0].data, /^'.*[\\/]owned[\\/]attachments[\\/]batch-.*[\\/]1-screen\.png' $/);
  assert.equal(/[\r\n]/.test(sent[0].data), false);
  const stages = await desktop.evaluate(() => globalThis.fixtureStages); assert.deepEqual(stages[0].files, [{ name: 'screen.png', path: false, bytes: 8 }]);
  assert.equal((await readFile(sent[0].data.slice(1, -2))).length, 8);
});

test('native selected file drop copies bytes and generic calls cannot forge a host path', { skip: noDisplay }, async () => {
  await reset(); const source = path.join(directory, 'selected source.txt'); await writeFile(source, 'selected owned fixture');
  await page.locator('#fixture-file').setInputFiles(source);
  await activeInput().evaluate(element => { const data = new DataTransfer(); data.items.add(document.querySelector('#fixture-file').files[0]); element.dispatchEvent(new DragEvent('drop', { bubbles: true, cancelable: true, dataTransfer: data })); });
  for (let index = 0; index < 100 && !(await writes()).length; index++) await new Promise(resolve => setTimeout(resolve, 10));
  const sent = await writes(); assert.equal(sent.length, 1); assert.equal(await readFile(sent[0].data.slice(1, -2), 'utf8'), 'selected owned fixture');
  assert.equal((await desktop.evaluate(() => globalThis.fixtureStages))[0].files[0].path, true);
  const refused = await page.evaluate(async () => { try { await window.envara.call('stageTerminalAttachments', { sessionId: 'forged', transferId: 'forged', files: [{ path: '/host/private', name: 'private' }] }); return false; } catch { return true; } });
  assert.equal(refused, true);
});

test('pending attachment blocks keyboard input and switching tabs discards the late path', { skip: noDisplay }, async () => {
  await reset(); await desktop.evaluate(() => { globalThis.fixtureDelay = true; });
  await imagePaste();
  for (let index = 0; index < 100 && !(await desktop.evaluate(() => globalThis.fixtureReleases.length)); index++) await new Promise(resolve => setTimeout(resolve, 10));
  await activeInput().focus(); await page.keyboard.type('must-not-send'); await page.keyboard.press('Enter');
  assert.deepEqual(await writes(), []);
  const tabs = page.locator('.terminal-session-tabs [role="tab"]');
  assert.equal(await tabs.count(), 2); await tabs.nth(1).click();
  await desktop.evaluate(() => { globalThis.fixtureReleases.splice(0).forEach(release => release()); globalThis.fixtureDelay = false; });
  await new Promise(resolve => setTimeout(resolve, 100));
  assert.deepEqual(await writes(), []);
  await activeInput().focus(); await page.keyboard.type('new-tab');
  // Typed input may arrive in more than one write; wait for all of it.
  for (let index = 0; index < 200 && (await writes()).map(item => item.data).join('').length < 'new-tab'.length; index++) await new Promise(resolve => setTimeout(resolve, 10));
  const sent = await writes(); assert.ok(sent.length); assert.ok(sent.every(item => item.sessionId === id(2))); assert.equal(sent.map(item => item.data).join(''), 'new-tab');
});

test('SSH foreground refuses attachments and regular text paste remains ordinary terminal input', { skip: noDisplay }, async () => {
  await reset(); await desktop.evaluate((_electron, sessionId) => { globalThis.fixtureOwned.get(sessionId).pty.process = 'ssh'; }, id(2));
  await imagePaste(); await page.getByText('附件仅支持本地终端；SSH 会话请先将文件传到远端。', { exact: true }).waitFor();
  assert.deepEqual(await writes(), []);
  await activeInput().evaluate(element => { const data = new DataTransfer(); data.setData('text/plain', 'plain text'); element.dispatchEvent(new ClipboardEvent('paste', { bubbles: true, cancelable: true, clipboardData: data })); });
  for (let index = 0; index < 100 && !(await writes()).length; index++) await new Promise(resolve => setTimeout(resolve, 10));
  assert.equal((await writes()).map(item => item.data).join(''), 'plain text');
  await desktop.evaluate((_electron, [sessionId, foreground]) => { globalThis.fixtureOwned.get(sessionId).pty.process = foreground; }, [id(2), shellForeground]);
});

test('a tab switch during the write acknowledgement keeps files already committed to the former terminal', { skip: noDisplay }, async () => {
  await reset(); await desktop.evaluate(() => { globalThis.fixtureWriteDelay = true; });
  await imagePaste();
  for (let index = 0; index < 100 && !(await writes()).length; index++) await new Promise(resolve => setTimeout(resolve, 10));
  const sent = await writes(); assert.equal(sent.length, 1); const target = sent[0].data.slice(1, -2);
  assert.equal((await readFile(target)).length, 8);
  await page.locator('.terminal-session-tabs [role="tab"]').nth(0).click();
  await desktop.evaluate(() => { globalThis.fixtureWriteDelay = false; globalThis.fixtureWriteReleases.splice(0).forEach(release => release()); });
  await new Promise(resolve => setTimeout(resolve, 50));
  assert.equal((await readFile(target)).length, 8); assert.equal((await writes()).length, 1);
});

test('Escape cancels pending image work and bracketed paste uses only the terminal framing', { skip: noDisplay }, async () => {
  await reset(); await desktop.evaluate(() => { globalThis.fixtureDelay = true; }); await imagePaste();
  for (let index = 0; index < 100 && !(await desktop.evaluate(() => globalThis.fixtureReleases.length)); index++) await new Promise(resolve => setTimeout(resolve, 10));
  await activeInput().focus(); await page.keyboard.press('Escape');
  await desktop.evaluate(() => { globalThis.fixtureDelay = false; globalThis.fixtureReleases.splice(0).forEach(release => release()); });
  await new Promise(resolve => setTimeout(resolve, 50)); assert.deepEqual(await writes(), []);
  await desktop.evaluate(({ BrowserWindow }, sessionId) => BrowserWindow.getAllWindows()[0].webContents.send('envara:terminal-event', { type: 'data', sessionId, profileId: 'owned', sequence: 1, data: '\x1b[?2004h' }), id(1));
  await new Promise(resolve => setTimeout(resolve, 20)); await imagePaste();
  for (let index = 0; index < 100 && !(await writes()).length; index++) await new Promise(resolve => setTimeout(resolve, 10));
  const sent = await writes(); assert.equal(sent.length, 1); assert.match(sent[0].data, /^\x1b\[200~'.*' \x1b\[201~$/); assert.equal(/[\r\n]/.test(sent[0].data), false);
});
