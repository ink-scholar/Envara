import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { build } from 'esbuild';
import { _electron } from 'playwright-core';
import electron from 'electron';
import { languages, translate } from '../src/i18n.mjs';

const noDisplay = process.platform === 'linux' && !process.env.DISPLAY;
const project = fileURLToPath(new URL('../', import.meta.url));
const id = 'tools-fixture', openedSessionId = `term_${'b'.repeat(32)}`;
const snapshot = (language = 'zh-CN', appearance = 'dark') => ({
  networkRevision: 0,
  profiles: [{ id, name: 'Synthetic project workspace', group: 'Fixture projects', engine: 'cloakbrowser', status: 'stopped',
    proxyId: 'fixture-route', locale: 'ja-JP', timezone: 'Asia/Tokyo', seed: 123456, platform: 'macos', createdAt: '2026-01-01T00:00:00.000Z' }],
  proxies: [{ id: 'fixture-route', name: 'Synthetic route', protocol: 'socks5', host: 'route.invalid', port: 1080,
    network: { ok: true, ip: '203.0.113.9', countryCode: 'JP', timezone: 'Asia/Tokyo', checkedAt: '2026-01-01T00:00:00.000Z' } }],
  engines: [{ id: 'cloakbrowser', displayName: 'CloakBrowser', installed: true, supported: true, enabled: true, version: 'fixture-1', family: 'chromium' }],
  settings: { language, appearance, closeBrowsersOnExit: false, defaultEngine: 'cloakbrowser' },
  system: { platform: 'darwin', appVersion: '1.3.1', dataDir: '/synthetic/envara', proxyCore: { supported: true, version: 'fixture-core' } },
  applications: [], groups: [{ name: 'Fixture projects', proxyId: 'fixture-route' }],
  events: [{ id: 'event1', type: 'browser', time: '2026-01-01T00:00:01.000Z', message: 'Synthetic launch success' },
    { id: 'event2', type: 'error', time: '2026-01-01T00:00:02.000Z', message: 'Synthetic route failure' },
    { id: 'event3', type: 'error', time: '2026-01-01T00:00:03.000Z', message: 'Synthetic attachment failure' }],
});
let directory, desktop, page;
const browserErrors = [];
before(async () => {
  if (noDisplay) return;
  directory = await mkdtemp(path.join(tmpdir(), 'envara-workspace-tools-'));
  const output = await build({ stdin: { resolveDir: project, loader: 'jsx', contents: `
import React from 'react'; import { createRoot } from 'react-dom/client';
import { WorkspaceApp } from './src/App.jsx'; import { I18nProvider } from './src/i18n.jsx'; import { AppearanceProvider } from './src/appearance.jsx';
import { api } from './src/client.js';
const root=createRoot(document.querySelector('#root')); let version=0;
window.mountWorkspaceTools = value => {
  window.fixture=value; window.calls=[]; window.unexpected=[]; window.combinations=[]; window.cacheMoved=false; window.cachePurged=false; window.inventoryRevision=0;
  window.terminalFixture=[{profileId:'${id}',name:value.profiles[0].name,cwd:'/synthetic/project',sessions:[],savedTerminals:[
    {id:'entry_frontend',profileId:'${id}',name:'Frontend',kind:'shell',cwd:'/synthetic/project/frontend',browserProfileId:'${id}',status:'saved'},
    {id:'entry_backend',profileId:'${id}',name:'Backend',kind:'claude-code',cwd:'/synthetic/project/backend',claudeAccountName:'Project login',browserProfileId:'${id}',status:'saved'}]}];
  document.documentElement.lang=value.settings.language; document.documentElement.dataset.theme=value.settings.appearance; document.documentElement.dataset.appearance=value.settings.appearance;
  root.render(<AppearanceProvider key={++version} api={api}><I18nProvider language={value.settings.language} api={api}><WorkspaceApp /></I18nProvider></AppearanceProvider>);
}; window.toolsReady=true;
` }, bundle: true, write: false, platform: 'browser', format: 'iife', loader: { '.css': 'empty' },
    define: { 'process.env.NODE_ENV': '"test"', 'import.meta.env.BASE_URL': '"./"' }, plugins: [{ name: 'owned-workspace-tools', setup(builder) {
      builder.onLoad({ filter: /[/\\]src[/\\]App\.jsx$/ }, async args => ({ contents: `${await readFile(args.path, 'utf8')}\nexport { WorkspaceApp };`, loader: 'jsx' }));
      const stubs = {
        client: `const listeners=new Set();
export const api={isDesktop:true,subscribe(fn){listeners.add(fn);return()=>listeners.delete(fn);},getAppearance(){return {preference:window.fixture.settings.appearance,effective:window.fixture.settings.appearance};},
async call(method,args={}) { window.calls.push({method,args}); const copy=value=>structuredClone(value);
 switch(method){
 case 'snapshot': return copy(window.fixture);
 case 'terminalSnapshot': return {profiles:copy(window.terminalFixture)};
 case 'linkRouterStatus': return {enabled:false,preference:true,available:true};
 case 'saveSettings': Object.assign(window.fixture.settings,args.settings); for(const listener of listeners)listener(copy(window.fixture)); return copy(window.fixture);
 case 'listWorkCombinations': return {combinations:copy(window.combinations)};
 case 'saveWorkCombination': { const combination={id:'workcombo_fixture',profileId:args.id,name:args.name,entryIds:args.entryIds,includeBrowser:args.includeBrowser,createdAt:new Date().toISOString()};window.combinations.push(combination);return {combination:copy(combination)}; }
 case 'openWorkCombination': return {status:'opened',profileId:args.id,combinationId:args.combinationId,requestId:args.requestId,sessions:[{profileId:args.id,sessionId:'${openedSessionId}',savedTerminalId:'entry_frontend'}],browserOpened:true,error:null};
 case 'deleteWorkCombination': window.combinations=window.combinations.filter(c=>c.id!==args.combinationId);return {removed:true};
 case 'listBrowserSiteData': return {instanceId:'a'.repeat(32),runtime:'cloakbrowser',canClear:true,checkedAt:new Date().toISOString(),cookies:[{name:'fixture-login',domain:'.example.test',path:'/',expires:-1,httpOnly:true,secure:true,sameSite:'Lax',partitionState:'unpartitioned'}]};
 case 'clearBrowserSiteCookies': return {removed:1,domain:args.domain,instanceId:args.instanceId};
 case 'runtimeVerificationSnapshot': return {results:[],pending:[]};
 case 'checkRuntimeVerification': return {profileId:args.id,checkedAt:new Date().toISOString(),stale:false,expected:{locale:'ja-JP',timezone:'Asia/Tokyo',ip:'203.0.113.9'},browser:{observed:{locale:'ja-JP',timezone:'Asia/Tokyo',ip:null},checks:{locale:'match',timezone:'match',ip:'unknown'},reason:'partial'},terminal:{sessions:[]}};
 case 'exportSupportDiagnostics': return {canceled:false,exported:true};
 case 'applicationUpdateStatus': return {status:'idle',currentVersion:'1.3.1',latestVersion:null,error:null,canInstall:false};
 case 'componentVersions': return {schema:'envara.component-versions',version:1,checkedAt:new Date().toISOString(),rows:[
 {id:'app',kind:'application',name:'Envara',version:'1.3.1',runningVersion:'1.3.1',status:'running',versionSource:'running-app',support:'supported',impact:'application',sessions:[],sessionsKnown:true,action:'application-update',blocked:false},
 {id:'cloakbrowser',kind:'browser',name:'CloakBrowser',version:'fixture-1',runningVersion:null,status:'installed',versionSource:'installation-record',support:'supported',impact:'browser',sessions:[{id:'browser_fixture',kind:'browser',name:'Fixture browser',profileName:'Synthetic project workspace'}],sessionsKnown:true,action:'install-engine',blocked:true},
 {id:'proxy',kind:'proxy',name:'Mihomo',version:'fixture-core',runningVersion:null,status:'ready',versionSource:'bundled-package',support:'supported',impact:'bundled',sessions:[],sessionsKnown:true},
 {id:'claude_fixture',kind:'claude',name:'Claude Code',profileId:'${id}',profileName:'Synthetic project workspace',version:null,runningVersion:null,status:'unknown',versionSource:'unknown',support:'unknown',impact:'claude',sessions:[],sessionsKnown:true,action:'terminal',blocked:false}]};
 case 'cacheMaintenanceInventory': return {inventoryId:'inventory_'+(++window.inventoryRevision),maintenanceAvailable:true,entries:window.cacheMoved?[]:[{id:'cache_fixture',profileId:'${id}',profileName:'Synthetic project workspace',cacheName:'GPUCache',status:'ready',bytes:2048}],batches:window.cacheMoved&&!window.cachePurged?[{id:'batch_fixture',createdAt:'2026-01-01T00:00:00.000Z',status:'ready',entryCount:1,bytes:2048}]:[]};
 case 'quarantineBrowserCaches': window.cacheMoved=true;return {complete:true};
 case 'restoreBrowserCaches': return {complete:false,conflicts:1};
 case 'purgeBrowserCacheBatch': if(args.confirmed!==true)throw Error('missing fixture confirmation');window.cachePurged=true;return {complete:true};
 default: window.unexpected.push(method);throw Error('Unexpected synthetic operation: '+method);
 }
}};`,
        terminal: `import React,{useEffect}from'react';export function TerminalDock({visible,openRequest,refreshKey,onProfilesChange}){useEffect(()=>{onProfilesChange(window.terminalFixture)},[onProfilesChange,refreshKey]);return <div hidden={!visible} className="terminal-dock" data-testid="terminal-request">{JSON.stringify(openRequest)}</div>;}`,
      };
      builder.onResolve({ filter: /(?:^|\/)client\.js$/ }, () => ({ path: 'client', namespace: 'tools-fixture' }));
      builder.onResolve({ filter: /^\.\/TerminalPane\.jsx$/ }, () => ({ path: 'terminal', namespace: 'tools-fixture' }));
      builder.onLoad({ filter: /.*/, namespace: 'tools-fixture' }, args => ({ contents: stubs[args.path], resolveDir: project, loader: 'jsx' }));
    } }],
  });
  await mkdir(path.join(directory, 'assets'));
  await writeFile(path.join(directory, 'assets/envara-icon.png'), await readFile(path.join(project, 'public/assets/envara-icon.png')));
  await writeFile(path.join(directory, 'fixture.js'), output.outputFiles[0].text);
  const cssFiles = ['styles.css', 'terminal.css', 'work-combinations.css', 'browser-site-data.css', 'component-versions.css', 'cache-maintenance.css', 'runtime-verification.css', 'application-updates.css'];
  await writeFile(path.join(directory, 'styles.css'), (await Promise.all(cssFiles.map(file => readFile(path.join(project, 'src', file), 'utf8')))).join('\n'));
  await writeFile(path.join(directory, 'index.html'), '<!doctype html><html><meta charset="utf-8"><link rel="stylesheet" href="styles.css"><div id="root"></div><script src="fixture.js"></script></html>');
  const entry = path.join(directory, 'main.cjs');
  await writeFile(entry, `process.on('uncaughtException', error => { process.stderr.write(String(error?.stack || error)); process.exit(1); }); process.on('unhandledRejection', error => { process.stderr.write(String(error?.stack || error)); process.exit(1); }); const{app,BrowserWindow}=require('electron');app.setPath('userData',${JSON.stringify(path.join(directory, 'data'))});app.whenReady().then(()=>{app.dock?.hide();const w=new BrowserWindow({show:false,width:1280,height:900,webPreferences:{sandbox:true}});w.loadURL(${JSON.stringify(pathToFileURL(path.join(directory, 'index.html')).href)});});`);
  const env = { ...process.env }; delete env.ELECTRON_RUN_AS_NODE;
  desktop = await _electron.launch({ executablePath: electron, args: [entry], env });
  page = await desktop.firstWindow(); page.setDefaultTimeout(5000);
  page.on('pageerror', error => browserErrors.push(error.message));
  await page.context().route('**/*', route => route.request().url().startsWith(pathToFileURL(directory + path.sep).href) ? route.continue() : route.abort());
  await page.waitForFunction(() => window.toolsReady === true);
});
after(async () => { try { await desktop?.close(); } finally { if (directory) await rm(directory, { recursive: true, force: true }); } });
async function mount(language = 'zh-CN', theme = 'dark') {
  await page.evaluate(value => window.mountWorkspaceTools(value), snapshot(language, theme));
  await page.getByRole('heading', { name: translate('环境', language), exact: true }).waitFor();
  await page.locator('.profile-row').waitFor();
}
const nav = (key, language = 'zh-CN') => page.locator('.sidebar').getByRole('button', { name: translate(key, language), exact: true }).click();
async function healthy() { assert.deepEqual(browserErrors, []); assert.deepEqual(await page.evaluate(() => window.unexpected), []); }
async function noHorizontalOverflow(label) {
  const issues = await page.evaluate(() => {
    const nodes = [...document.querySelectorAll('.app-shell,.main-panel,.detail-panel,.settings-content,.settings-column,.settings-row,.settings-row > *, .application-updates,.application-updates-heading,.component-version-card summary,.component-version-card summary > *,.work-combinations,.component-versions,.cache-maintenance,.runtime-verification')];
    return nodes.filter(el => el.getBoundingClientRect().width > 0 && el.scrollWidth > el.clientWidth + 2).map(el => ({ className: el.className, width: el.clientWidth, content: el.scrollWidth }));
  });
  assert.deepEqual(issues, [], label);
}

test('workspace saves a work combination and opens its returned session in the terminal page', { skip: noDisplay }, async () => {
  await mount(); await page.locator('.work-combinations > summary').click();
  await page.getByRole('button', { name: '保存工作组合', exact: true }).click();
  await page.getByRole('textbox', { name: '组合名称', exact: true }).fill('Fixture project');
  await page.getByRole('checkbox', { name: /Frontend/ }).check(); await page.getByRole('checkbox', { name: /Backend/ }).check();
  await page.getByRole('checkbox', { name: '同时打开此环境浏览器', exact: true }).check();
  await page.getByRole('button', { name: '保存组合', exact: true }).click();
  await page.getByRole('button', { name: '打开组合「Fixture project」', exact: true }).click();
  await page.getByTestId('terminal-request').waitFor({ state: 'visible' });
  const request = JSON.parse(await page.getByTestId('terminal-request').textContent());
  assert.equal(request.profileId, id); assert.equal(request.sessionId, openedSessionId);
  const save = await page.evaluate(() => window.calls.find(call => call.method === 'saveWorkCombination'));
  assert.deepEqual(save.args, { id, name: 'Fixture project', entryIds: ['entry_frontend', 'entry_backend'], includeBrowser: true });
  assert.equal(await page.locator('.app-shell.terminal-workspace').count(), 1); await healthy();
});

test('settings fills the workspace and adapts every language to wide and narrow windows', { skip: noDisplay }, async () => {
  for (const language of languages) for (const theme of ['dark', 'light']) {
    const value = snapshot(language, theme);
    value.system.dataDir = '/synthetic/' + 'long-workspace-directory-'.repeat(8);
    await page.evaluate(value => window.mountWorkspaceTools(value), value);
    await nav('设置', language);
    await page.locator('.component-version-card').first().waitFor();
    for (const width of [900, 1120, 1500, 2560]) {
      await page.setViewportSize({ width, height: width === 1120 ? 720 : 940 });
      for (const collapsed of [false, true]) {
        const shell = page.locator('.app-shell');
        if ((await shell.getAttribute('class')).includes('sidebar-collapsed') !== collapsed) await page.locator('.sidebar-toggle').click();
        await noHorizontalOverflow(`${language} ${theme} ${width} ${collapsed}`);
        const geometry = await page.evaluate(() => {
          const main = document.querySelector('.main-panel').getBoundingClientRect();
          const content = document.querySelector('.settings-content').getBoundingClientRect();
          const columns = [...document.querySelectorAll('.settings-column')].map(node => {
            const box = node.getBoundingClientRect(); return { x: box.x, y: box.y, width: box.width };
          });
          return { main: main.width, content: content.width, columns };
        });
        assert.ok(geometry.main - geometry.content < 80, `unused workspace width: ${JSON.stringify(geometry)}`);
        if (width >= 1500) assert.ok(geometry.columns[1].x > geometry.columns[0].x + geometry.columns[0].width, 'wide settings uses both columns');
        if (width === 900) assert.equal(geometry.columns[0].x, geometry.columns[1].x, 'narrow settings uses one column');
        if (language === 'zh-CN' && theme === 'dark' && !collapsed && [1120, 1500, 2560].includes(width)) {
          const output = path.join(project, 'test-artifacts/settings-responsive'); await mkdir(output, { recursive: true });
          await page.locator('.main-panel').evaluate(node => { node.scrollTop = 0; });
          await page.screenshot({ path: path.join(output, `${language}-${theme}-${width}.png`) });
        }
      }
    }
    assert.equal(await page.locator('.application-update-help').getAttribute('open'), null);
    await page.locator('.application-update-help > summary').click();
    assert.equal(await page.getByText(translate('更新只替换应用，保留环境、配置和登录资料。', language), { exact: true }).isVisible(), true);
    assert.equal(await page.evaluate(() => window.calls.some(call => /^(check|download|install)ApplicationUpdate$/.test(call.method))), false);
    await healthy();
  }
});

test('browser navigation reveals selected-environment cookie controls without background inspection', { skip: noDisplay }, async () => {
  await mount(); await nav('浏览器');
  assert.equal(await page.evaluate(() => window.calls.filter(call => call.method === 'listBrowserSiteData').length), 0);
  await page.locator('.workspace-tool-disclosure > summary').click();
  await page.getByRole('button', { name: '刷新 Cookie', exact: true }).click();
  await page.getByText('.example.test', { exact: true }).click();
  await page.getByRole('button', { name: '清理此网站 Cookie', exact: true }).click();
  assert.equal(await page.evaluate(() => window.calls.filter(call => call.method === 'clearBrowserSiteCookies').length), 0);
  await page.getByRole('button', { name: '确认清理网站 Cookie', exact: true }).click();
  await page.waitForFunction(() => window.calls.some(call => call.method === 'clearBrowserSiteCookies'));
  assert.deepEqual((await page.evaluate(() => window.calls.find(call => call.method === 'clearBrowserSiteCookies'))).args, { profileId: id, instanceId: 'a'.repeat(32), domain: '.example.test' });
  await noHorizontalOverflow('browser site controls'); await healthy();
});

test('monitor record controls filter production events and runtime verification stays manual and scoped', { skip: noDisplay }, async () => {
  await mount(); await nav('运行监控');
  assert.equal(await page.locator('.activity-row').count(), 3);
  await page.getByRole('checkbox', { name: '仅显示错误', exact: true }).check(); assert.equal(await page.locator('.activity-row').count(), 2);
  await page.getByRole('searchbox', { name: '搜索运行记录', exact: true }).fill('route'); assert.equal(await page.locator('.activity-row').count(), 1);
  assert.equal(await page.locator('.activity-message').textContent(), 'Synthetic route failure');
  assert.equal(await page.evaluate(() => window.calls.filter(call => call.method === 'checkRuntimeVerification').length), 0);
  await page.getByRole('button', { name: '核验当前运行状态', exact: true }).click();
  await page.locator('.runtime-verification-table').waitFor();
  assert.equal(await page.locator('.runtime-verification-check.match').count(), 2); assert.equal(await page.locator('.runtime-verification-check.unknown').count(), 1);
  assert.deepEqual((await page.evaluate(() => window.calls.find(call => call.method === 'checkRuntimeVerification'))).args, { id });
  await noHorizontalOverflow('monitor verification'); await healthy();
});

test('settings exports support data, explains component impact and preserves recovery batches on restore conflict', { skip: noDisplay }, async () => {
  await mount(); await nav('设置'); await page.locator('.component-version-card').first().waitFor();
  const appVersion = page.locator('.component-version-card').filter({ hasText: 'Envara' });
  await appVersion.locator('summary').click(); await appVersion.getByRole('button', { name: '应用更新', exact: true }).click();
  await page.waitForFunction(() => document.activeElement?.id === 'application-updates');
  assert.equal(await page.evaluate(() => window.calls.filter(call => call.method === 'openDocumentation').length), 0);
  await page.getByRole('button', { name: '导出支持诊断', exact: true }).click();
  await page.waitForFunction(() => window.calls.some(call => call.method === 'exportSupportDiagnostics'));
  await page.locator('.component-version-card').filter({ hasText: 'CloakBrowser' }).locator('summary').click();
  assert.equal(await page.getByRole('button', { name: '手动更新内核', exact: true }).isDisabled(), true);
  assert.equal(await page.getByText('Fixture browser', { exact: true }).count(), 1);
  await page.locator('.cache-maintenance > summary').click(); await page.getByRole('button', { name: '检查缓存', exact: true }).click();
  await page.locator('.cache-maintenance-choice input').check();
  await page.getByRole('button', { name: '移入恢复批次', exact: false }).click();
  await page.locator('.cache-maintenance-batch').waitFor();
  await page.getByRole('button', { name: '恢复缓存', exact: true }).click();
  await page.getByText('目标位置已有新缓存，恢复副本已保留。', { exact: true }).waitFor();
  assert.equal(await page.locator('.cache-maintenance-batch').count(), 1);
  await page.getByRole('button', { name: '永久删除', exact: true }).click();
  assert.equal(await page.evaluate(() => window.calls.filter(call => call.method === 'purgeBrowserCacheBatch').length), 0);
  await page.getByRole('button', { name: '取消', exact: true }).click();
  await page.getByRole('button', { name: '永久删除', exact: true }).click(); await page.getByRole('button', { name: '确认永久删除', exact: true }).click();
  await page.getByText('没有恢复批次。', { exact: true }).waitFor();
  assert.deepEqual((await page.evaluate(() => window.calls.find(call => call.method === 'purgeBrowserCacheBatch'))).args, { batchId: 'batch_fixture', confirmed: true });
  await noHorizontalOverflow('settings lifecycle'); await healthy();
});

for (const language of languages) for (const theme of ['dark', 'light']) test(`workspace tools preserve ${language} ${theme} settings and environment layout`, { skip: noDisplay }, async () => {
  await page.setViewportSize({ width: language === 'de' ? 1040 : 1280, height: 900 });
  await mount(language, theme);
  await page.locator('.work-combinations > summary').click();
  await page.getByRole('button', { name: translate('保存工作组合', language), exact: true }).click();
  await noHorizontalOverflow(`${language} ${theme} environment`);
  assert.equal(await page.locator('.detail-panel').count(), 1);
  const output = path.join(project, 'test-artifacts/workspace-tools-ui');
  if (['zh-CN', 'en', 'de'].includes(language)) { await mkdir(output, { recursive: true }); await page.screenshot({ path: path.join(output, `${language}-${theme}-environment.png`) }); }
  await nav('设置', language); await page.locator('.component-version-card').first().waitFor();
  await page.locator('.component-version-card').filter({ hasText: 'CloakBrowser' }).locator('summary').click();
  await page.locator('.cache-maintenance > summary').click();
  await page.getByRole('button', { name: translate('检查缓存', language), exact: true }).click();
  await page.locator('.cache-maintenance-choice').waitFor();
  await noHorizontalOverflow(`${language} ${theme} settings`);
  assert.equal(await page.evaluate(() => document.documentElement.dataset.theme), theme);
  assert.equal(await page.evaluate(() => document.documentElement.lang), language);
  if (['zh-CN', 'en', 'de'].includes(language)) { await page.locator('.component-versions').scrollIntoViewIfNeeded(); await page.screenshot({ path: path.join(output, `${language}-${theme}-settings.png`) }); }
  await healthy();
});
