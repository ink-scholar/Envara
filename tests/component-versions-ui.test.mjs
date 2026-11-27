import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { _electron } from 'playwright-core';
import electron from 'electron';
import { languages, translate } from '../src/i18n.mjs';
import { componentVersionSnapshot } from '../shared/component-versions.mjs';

// Real hidden Electron renderer, synthetic snapshots and action callbacks only.
const noDisplay = process.platform === 'linux' && !process.env.DISPLAY;
const project = fileURLToPath(new URL('../', import.meta.url));
const artifactRoot = path.join(project, 'test-artifacts') + path.sep;
const screenshots = process.env.ENVARA_COMPONENT_UI_SCREENSHOTS ? path.resolve(process.env.ENVARA_COMPONENT_UI_SCREENSHOTS) : null;
if (screenshots && !screenshots.startsWith(artifactRoot)) throw new Error('Component screenshots must use the owned test-artifacts directory.');
let directory, desktop, page;
const rendererErrors = [];
const fixture = () => componentVersionSnapshot({ checkedAt: '2026-11-16T17:20:30.000Z',
  snapshot: { system: { appVersion: '0.5.18', proxyCore: { version: 'v1.19.5', supported: true } },
    engines: [{ id: 'camoufox', installed: true, version: '135.0-beta.24', supported: true }, { id: 'cloakbrowser', installed: false, supported: true }],
    profiles: [{ id: 'first', name: 'Synthetic environment — 研究工作空间 / shared review / Produktionsumgebung mit langem Namen', status: 'stopped' }],
    applications: [], applicationRouting: { installed: false, component: { name: 'Envara PF', version: '1.0.0', available: true, verified: true } } },
  terminals: { profiles: [{ profileId: 'first', sessions: [{ sessionId: 'term', kind: 'claude-code', status: 'running',
    savedTerminalName: 'Synthetic running terminal — Arbeitsbereich mit einem sehr langen Namen / 登录档案会话' }] }] },
  claude: [{ profileId: 'first', installed: true, version: '2.1.7', supported: true }] });

before(async () => {
  if (noDisplay) return;
  directory = await mkdtemp(path.join(tmpdir(), 'envara-component-ui-'));
  const output = await build({ stdin: { resolveDir: project, loader: 'jsx', contents: `
import React, { useState } from 'react'; import { createRoot } from 'react-dom/client';
import { ComponentVersions } from './src/ComponentVersions.jsx';
const root = createRoot(document.querySelector('#root')); let generation = 0;
function Fixture() {
 const [tick, setTick] = useState(0); window.rerender = () => setTick(value => value + 1);
 return <div data-render={tick} style={{width:window.panelWidth || undefined,maxWidth:'100%'}}><ComponentVersions load={async () => { window.loads++; if(window.deferLoad) return new Promise(resolve => window.pendingLoads.push(resolve)); return structuredClone(window.report); }}
  onInstallEngine={id => { window.actions.push(['engine',id]); }} onSetupRouting={() => { window.actions.push(['routing']); }}
  onOpenTerminal={id => { window.actions.push(['terminal',id]); }} onOpenProject={() => { window.actions.push(['project']); }}
  onOpenUpdates={() => { window.actions.push(['updates']); }} /></div>;
}
window.mount = ({report, language='zh-CN', theme='dark',panelWidth=null}) => { window.report=report; window.language=language; window.panelWidth=panelWidth; window.loads=0; window.actions=[]; window.deferLoad=false; window.pendingLoads=[];
 document.documentElement.dataset.theme=theme; document.documentElement.lang=language; root.render(<Fixture key={++generation}/>); };
window.ready=true;` }, bundle: true, write: false, format: 'iife', platform: 'browser', loader: { '.css': 'empty' },
    define: { 'process.env.NODE_ENV': '"test"' }, plugins: [{ name: 'component-i18n', setup(builder) {
      builder.onResolve({ filter: /^\.\/i18n.jsx$/ }, () => ({ path: 'i18n', namespace: 'components' }));
      builder.onLoad({ filter: /.*/, namespace: 'components' }, () => ({ resolveDir: project, contents: `import { translate } from './src/i18n.mjs'; export const useI18n=()=>({language:window.language,t:(s,v)=>translate(s,window.language,v)});` }));
    } }],
  });
  await writeFile(path.join(directory, 'fixture.js'), output.outputFiles[0].text);
  const css = (await Promise.all(['styles.css', 'component-versions.css'].map(name => readFile(path.join(project, 'src', name), 'utf8')))).join('\n');
  await writeFile(path.join(directory, 'index.html'), `<!doctype html><html><meta charset="utf-8"><style>${css}\nbody{overflow:auto;min-width:0}#root{max-width:880px;padding:24px;margin:auto}</style><body><main id="root"></main><script src="fixture.js"></script></body></html>`);
  await writeFile(path.join(directory, 'main.cjs'), `process.on('uncaughtException', error => { process.stderr.write(String(error?.stack || error)); process.exit(1); }); process.on('unhandledRejection', error => { process.stderr.write(String(error?.stack || error)); process.exit(1); }); const {app,BrowserWindow}=require('electron');app.setPath('userData',${JSON.stringify(path.join(directory, 'data'))});app.whenReady().then(()=>{app.dock?.hide();const view=new BrowserWindow({...(process.platform === 'win32' ? { show: true, x: -3000, y: 0, frame: false, thickFrame: false } : { show: false }),width:1100,height:1000,useContentSize:true,webPreferences:{sandbox:true,backgroundThrottling:false}});view.loadFile(${JSON.stringify(path.join(directory, 'index.html'))});});`);
  const env = { ...process.env }; delete env.ELECTRON_RUN_AS_NODE;
  desktop = await _electron.launch({ executablePath: electron, args: [path.join(directory, 'main.cjs')], env });
  page = await desktop.firstWindow(); page.on('pageerror', error => rendererErrors.push(error.message)); await page.waitForFunction(() => window.ready === true);
});
after(async () => { try { await desktop?.close(); } finally { if (directory) await rm(directory, { recursive: true, force: true }); } assert.deepEqual(rendererErrors, []); });

async function mount(report = fixture(), language = 'zh-CN', theme = 'dark', panelWidth = null) {
  await page.evaluate(value => window.mount(value), { report, language, theme, panelWidth });
  await page.waitForFunction(() => window.loads === 1 && document.querySelectorAll('.component-version-card').length === window.report.rows.length && !document.querySelector('.component-versions-heading button').disabled);
}

test('inline load callback rerenders read once, disclosure clicks do not update and explicit actions target the selected component', { skip: noDisplay }, async () => {
  await mount();
  assert.equal(await page.locator('.component-versions-intro,.component-versions-note,.component-versions-time').count(), 0);
  assert.match(await page.getByRole('button', { name: '刷新', exact: true }).getAttribute('title'), /^读取时间：/);
  assert.equal(await page.locator('.component-impact:visible').count(), 0);
  await page.evaluate(() => { window.rerender(); window.rerender(); });
  await page.waitForFunction(() => document.querySelector('[data-render]').dataset.render === '2');
  assert.equal(await page.evaluate(() => window.loads), 1);
  const engine = page.locator('.component-version-card').nth(1);
  await engine.locator('summary').click();
  assert.equal(await engine.getByRole('button', { name: '手动更新内核' }).isDisabled(), true);
  assert.equal(await engine.locator('li').count(), 1);
  assert.deepEqual(await page.evaluate(() => window.actions), []);
  const cli = page.locator('.component-version-card').last(); await cli.locator('summary').click();
  await cli.getByRole('button', { name: '打开终端' }).click();
  assert.deepEqual(await page.evaluate(() => window.actions), [['terminal', 'first']]);
  const clean = fixture(); for (const item of clean.rows) { item.sessions = []; if(item.action==='install-engine' && item.support==='supported') item.blocked=false; }
  await mount(clean);
  const install = page.locator('.component-version-card').nth(2); await install.locator('summary').click();
  await install.getByRole('button', { name: '安装内核', exact: true }).click();
  await page.waitForFunction(() => window.loads === 2);
  assert.deepEqual(await page.evaluate(() => window.actions), [['engine', 'cloakbrowser']]);
  assert.equal(await desktop.evaluate(({BrowserWindow}) => BrowserWindow.getAllWindows().some(view=>view.isVisible()&&view.getBounds().x>-1000)), false);
});

test('nine languages and both appearances preserve long names, unknown values and bounded layouts', { skip: noDisplay }, async () => {
  if (screenshots) await mkdir(screenshots, { recursive: true });
  for (const language of languages) for (const theme of ['dark', 'light']) {
    await desktop.evaluate(({BrowserWindow}, width) => BrowserWindow.getAllWindows()[0].setContentSize(width, 1000), 1100);
    await mount(fixture(), language, theme);
    assert.equal(await page.getByRole('heading', { name: translate('组件版本', language), exact: true }).count(), 1);
    const engine = page.locator('.component-version-card').nth(1); await engine.locator('summary').click();
    const cli = page.locator('.component-version-card').last(); await cli.locator('summary').click();
    assert.equal(await engine.getByText(translate('未观测', language), { exact: true }).count(), 1);
    assert.equal(await cli.locator('li').count(), 1);
    assert.deepEqual(await page.evaluate(() => window.actions), []);
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true, `${language}/${theme} wide overflow`);
    if (screenshots && ['zh-CN','en','de'].includes(language)) await page.screenshot({ path: path.join(screenshots, `${language}-${theme}.png`), fullPage: true });
    await desktop.evaluate(({BrowserWindow}, width) => BrowserWindow.getAllWindows()[0].setContentSize(width, 1000), 500);
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true, `${language}/${theme} narrow overflow`);
  }
});

test('wide windows adapt narrow component columns in nine languages and both appearances without hiding details or actions', { skip: noDisplay }, async () => {
  if (screenshots) await mkdir(screenshots, { recursive: true });
  await desktop.evaluate(({BrowserWindow}) => BrowserWindow.getAllWindows()[0].setContentSize(1100, 1000));
  for (const language of languages) for (const theme of ['dark', 'light']) {
    const report = fixture();
    report.rows[1].version = '135.0-beta.24-build.with.long.version.metadata';
    report.rows[1].sessionsKnown = false;
    await mount(report, language, theme, 320);
    const engine = page.locator('.component-version-card').nth(1); await engine.locator('summary').click();
    const routing = page.locator('.component-version-card').nth(report.rows.findIndex(row => row.kind === 'routing')); await routing.locator('summary').click();
    const cli = page.locator('.component-version-card').last(); await cli.locator('summary').click();
    assert.equal(await engine.getByText(translate('部分运行状态未知，请先确认任务已结束。', language), { exact: true }).isVisible(), true);
    assert.equal(await engine.getByText(translate('安装或更新内核会重启浏览器服务；请先结束运行会话。', language), { exact: true }).isVisible(), true);
    assert.equal(await engine.getByRole('button', { name: translate('手动更新内核', language), exact: true }).isDisabled(), true);
    const layout = await page.evaluate(() => {
      const panel = document.querySelector('.component-versions');
      const elements = [...panel.querySelectorAll('summary,.component-name,.component-version-value,.component-status,.component-version-detail,.component-version-fields,.component-version-actions,.button')].filter(node => node.getClientRects().length);
      const summary = panel.querySelector('summary');
      return { viewport: window.innerWidth, width: panel.clientWidth,
        overflow: elements.some(node => node.scrollWidth > node.clientWidth + 1),
        versionBelowName: summary.querySelector('.component-version-value').getBoundingClientRect().top >= summary.querySelector('.component-name').getBoundingClientRect().bottom,
        fields: getComputedStyle(panel.querySelector('.component-version-card[open] .component-version-fields')).gridTemplateColumns.trim().split(/\s+/).length };
    });
    assert.equal(layout.viewport, 1100); assert.equal(layout.width, 320);
    assert.equal(layout.overflow, false, `${language}/${theme} column overflow`);
    assert.equal(layout.versionBelowName, true, `${language}/${theme} summary stacking`);
    assert.equal(layout.fields, 1, `${language}/${theme} details use one column`);
    await cli.getByRole('button', { name: translate('打开终端', language), exact: true }).click();
    assert.deepEqual(await page.evaluate(() => window.actions), [['terminal', 'first']]);
    if (screenshots && ['zh-CN','en','de'].includes(language)) await page.screenshot({ path: path.join(screenshots, `${language}-${theme}-column.png`), fullPage: true });
  }
});

test('a late snapshot after remount cannot replace the newly selected status', { skip: noDisplay }, async () => {
  await mount();
  await page.evaluate(() => { window.deferLoad=true; });
  await page.getByRole('button', { name: '刷新', exact: true }).click();
  await page.waitForFunction(() => window.pendingLoads.length === 1);
  await page.evaluate(() => { window.oldLoad = window.pendingLoads[0]; });
  const current = fixture(); current.rows[0].version = '9.9.9'; await mount(current);
  await page.evaluate(old => window.oldLoad(old), fixture());
  assert.equal(await page.locator('.component-version-card').first().locator('.component-version-value').textContent(), '9.9.9');
});
