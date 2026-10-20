import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { build } from 'esbuild';
import { _electron } from 'playwright-core';
import { languages, translate } from '../src/i18n.mjs';

// Actual sidebar/navigation state and CSS in a disposable hidden renderer.
// Production main, IPC, accounts, terminals and personal browsers are not used.
const noDisplay = process.platform === 'linux' && !process.env.DISPLAY;
const project = fileURLToPath(new URL('../', import.meta.url));
const preferenceKey = 'envara.sidebar.collapsed.v1';
const labels = ['环境', '网络出口', '浏览器', '终端', 'SSH 连接', '附加软件', '运行监控', '设置'];
let directory, desktop, page;

before(async () => {
  if (noDisplay) return;
  directory = await mkdtemp(path.join(tmpdir(), 'envara-sidebar-ui-'));
  const output = await build({ stdin: { resolveDir: project, loader: 'jsx', contents: `
import React, { useState } from 'react';
import { createRoot } from 'react-dom/client';
import { WorkspaceSidebar, useSidebarPreference, WorkspaceApp } from './src/App.jsx';
import { translate } from './src/i18n.mjs';
const root = createRoot(document.querySelector('#root'));
window.fixtureLanguage = 'zh-CN';
function Fixture({ detail = true, terminal = false, expanded = false }) {
  const [collapsed, setCollapsed] = useSidebarPreference();
  const [page, setPage] = useState('profiles');
  const t = value => translate(value, window.fixtureLanguage);
  return <div className={\`app-shell is-desktop \${detail ? 'with-detail' : ''} \${collapsed ? 'sidebar-collapsed' : ''} \${terminal ? 'terminal-visible' : ''} \${expanded ? 'terminal-expanded' : ''}\`}>
    <WorkspaceSidebar collapsed={collapsed} onToggle={() => setCollapsed(value => !value)} page={page}
      onNavigate={setPage} count={12} totalBytes={1024} language={window.fixtureLanguage} t={t} />
    <main className="main-panel"><h1>{t(page === 'settings' ? '设置' : '环境')}</h1></main>
    {detail && <aside className="detail-panel">Synthetic detail</aside>}
    {terminal && <div className="terminal-dock">Synthetic terminal layout only</div>}
  </div>;
}
let revision = 0;
window.mountSidebar = (options = {}) => {
  window.fixtureLanguage = options.language || 'zh-CN';
  document.documentElement.lang = window.fixtureLanguage;
  document.documentElement.dataset.theme = options.theme || 'dark';
  root.render(<Fixture key={++revision} {...options} />);
};
window.mountWorkspace = () => {
  window.fixtureLanguage = 'zh-CN';
  window.fixtureCalls = [];
  root.render(<WorkspaceApp key={++revision} />);
};
window.mountSidebar();
` }, bundle: true, write: false, platform: 'browser', format: 'iife', loader: { '.css': 'empty' },
    define: { 'process.env.NODE_ENV': '"test"', 'import.meta.env.BASE_URL': '"./"' },
    plugins: [{ name: 'isolated-production-sidebar', setup(builder) {
      builder.onLoad({ filter: /[/\\]src[/\\]App\.jsx$/ }, async args => ({
        contents: `${await readFile(args.path, 'utf8')}\nexport { WorkspaceSidebar, useSidebarPreference, WorkspaceApp };`, loader: 'jsx',
      }));
      const stubs = {
        './client.js': `
const profiles = ['a', 'b'].map(id => ({ id: 'env-' + id, name: 'Demo ' + id.toUpperCase(), status: 'stopped', engine: 'cloakbrowser' }));
export const api = { isDesktop: true, subscribe: () => () => {}, call: async (method, args) => {
  (window.fixtureCalls ||= []).push({ method, args });
  if (method === 'snapshot') return { profiles, proxies: [], settings: {}, system: { platform: 'darwin' } };
  if (method === 'listClaudeAccounts') return { accounts: [{ id: 'default', name: '默认' }] };
  throw new Error('Unexpected fixture operation: ' + method);
} };
`,
        './i18n.jsx': `
import { translate } from ${JSON.stringify(path.join(project, 'src/i18n.mjs'))};
export const useI18n = () => ({ language: window.fixtureLanguage, phase: 'ready', t: (value, vars) => translate(value, window.fixtureLanguage, vars) });
`,
        './TerminalPane.jsx': `
import React, { useEffect, useRef } from 'react';
export function TerminalDock(props) {
  const instance = useRef(null);
  if (!instance.current) instance.current = ++window.fixtureDockInstances || (window.fixtureDockInstances = 1);
  window.fixtureDockProps = props;
  useEffect(() => { props.onProfilesChange?.([{ profileId: 'env-a', sessions: [{ sessionId: 'fixture-a', status: 'running' }] }, { profileId: 'env-b', sessions: [] }]); }, [props.onProfilesChange]);
  return <section className="terminal-dock" hidden={!props.visible} data-instance={instance.current}
    data-profile={props.selectedProfileId || ''} data-workspace={String(props.workspace)} data-expanded={String(props.expanded)}>
    <button onClick={props.onHide}>Fixture close view</button>
    <button disabled={props.exportDisabled} onClick={() => props.onExport?.(props.selectedProfileId)}>Fixture export terminal</button>
    <button onClick={() => props.onConfigureLinkBrowser?.(props.selectedProfileId)}>Fixture link browser</button>
  </section>;
}
`,
        './TerminalSshConnections.jsx': `
import React from 'react';
export function SshWorkspace({ profiles, selectedId, onSelect, terminalProfiles, onOpenTerminal }) {
  return <div className="fixture-ssh-workspace" data-terminal-profiles={terminalProfiles.length}>
    <select aria-label="Fixture SSH environment" value={selectedId || ''} onChange={event => onSelect(event.target.value)}>{profiles.map(profile => <option key={profile.id} value={profile.id}>{profile.name}</option>)}</select>
    <button onClick={() => onOpenTerminal(selectedId)}>Fixture open terminal</button>
  </div>;
}
`,
        './workspace-pages.jsx': `
import React from 'react';
export function EnvironmentOverview({ profiles, onSelect }) { return <div>{profiles.map(profile => <button key={profile.id} onClick={() => onSelect(profile.id)}>{'Select ' + profile.name}</button>)}</div>; }
export function ContextDetail({ profile, onNavigate }) { return <button onClick={() => onNavigate('terminals')}>{'Open ' + (profile?.name || '') + ' terminal'}</button>; }
export const ApplicationsWorkspace = () => null;
export const MonitorWorkspace = () => null;
`,
      };
      builder.onResolve({ filter: /^\.\/(client\.js|i18n\.jsx|TerminalPane\.jsx|TerminalSshConnections\.jsx|workspace-pages\.jsx)$/ }, args => ({ path: args.path, namespace: 'sidebar-fixture' }));
      builder.onLoad({ filter: /.*/, namespace: 'sidebar-fixture' }, args => ({ contents: stubs[args.path], resolveDir: project, loader: 'jsx' }));
    } }],
  });
  await writeFile(path.join(directory, 'fixture.js'), output.outputFiles[0].text);
  await writeFile(path.join(directory, 'styles.css'), (await Promise.all(['styles.css', 'terminal.css'].map(name => readFile(new URL(`../src/${name}`, import.meta.url), 'utf8')))).join('\n'));
  await writeFile(path.join(directory, 'index.html'), '<!doctype html><meta charset="utf-8"><link rel="stylesheet" href="styles.css"><div id="root"></div><script src="fixture.js"></script>');
  const entry = path.join(directory, 'main.cjs');
  await writeFile(entry, `const { app, BrowserWindow } = require('electron');
app.setPath('userData', ${JSON.stringify(path.join(directory, 'data'))});
app.whenReady().then(() => { app.dock?.hide(); const window = new BrowserWindow({ show: false, width: 1440, height: 900, webPreferences: { sandbox: true } }); window.loadURL(${JSON.stringify(pathToFileURL(path.join(directory, 'index.html')).href)}); });`);
  const env = { ...process.env }; delete env.ELECTRON_RUN_AS_NODE;
  desktop = await _electron.launch({ args: [entry], env, timeout: 15000 });
  page = await desktop.firstWindow();
  await page.context().route('**/*', route => route.request().url().startsWith(pathToFileURL(directory + path.sep).href) ? route.continue() : route.abort());
  await page.locator('.sidebar-toggle').waitFor();
  await page.emulateMedia({ reducedMotion: 'reduce' });
});

after(async () => {
  try { await desktop?.close(); }
  finally { if (directory) await rm(directory, { recursive: true, force: true }); }
});

async function mount(options = {}, saved = 'false') {
  await page.evaluate(({ options, saved, preferenceKey }) => {
    localStorage.setItem(preferenceKey, saved);
    window.mountSidebar(options);
  }, { options, saved, preferenceKey });
  await page.waitForFunction(expected => document.querySelector('.sidebar-toggle')?.getAttribute('aria-expanded') === expected, saved === 'true' ? 'false' : 'true');
}
const columns = () => page.locator('.app-shell').evaluate(element => getComputedStyle(element).gridTemplateColumns.split(' ').map(Number.parseFloat));

test('keyboard collapse keeps named navigation, current page and bottom settings usable, and persists on reload', { skip: noDisplay }, async () => {
  await mount();
  assert.deepEqual(await page.locator('.sidebar .nav-item').evaluateAll(items => items.map(item => item.getAttribute('aria-label'))), labels);
  assert.ok((await columns())[0] === 210);
  const toggle = page.getByRole('button', { name: '收起侧栏', exact: true });
  await toggle.focus(); await page.keyboard.press('Enter');
  await page.getByRole('button', { name: '展开侧栏', exact: true }).waitFor();
  assert.equal((await columns())[0], 64);
  assert.equal(await page.evaluate(key => localStorage.getItem(key), preferenceKey), 'true');
  for (const label of labels) {
    const action = page.getByRole('button', { name: label, exact: true });
    assert.equal(await action.getAttribute('title'), label);
    await action.click(); assert.equal(await action.getAttribute('aria-current'), 'page');
  }
  const bounds = await page.locator('.settings-navigation').boundingBox();
  const navigation = await page.locator('.navigation').boundingBox();
  assert.ok(bounds.y > navigation.y + navigation.height, 'Settings stays below the workspace navigation');
  await page.reload();
  await page.getByRole('button', { name: '展开侧栏', exact: true }).waitFor();
  assert.equal((await columns())[0], 64);
  await page.getByRole('button', { name: '展开侧栏', exact: true }).press('Space');
  await page.getByRole('button', { name: '收起侧栏', exact: true }).waitFor();
  assert.equal(await page.evaluate(key => localStorage.getItem(key), preferenceKey), 'false');
});

test('denied localStorage reads and writes preserve interactive navigation without throwing', { skip: noDisplay }, async () => {
  await mount();
  const errors = []; const onError = error => errors.push(error.message); page.on('pageerror', onError);
  try {
    await page.evaluate(() => {
      window.sidebarStorageDescriptor = Object.getOwnPropertyDescriptor(window, 'localStorage');
      Object.defineProperty(window, 'localStorage', { configurable: true, get() { throw new Error('Synthetic storage denial'); } });
      window.mountSidebar();
    });
    await page.getByRole('button', { name: '收起侧栏', exact: true }).click();
    await page.getByRole('button', { name: '展开侧栏', exact: true }).waitFor();
    await page.getByRole('button', { name: '网络出口', exact: true }).click();
    assert.equal(await page.getByRole('button', { name: '网络出口', exact: true }).getAttribute('aria-current'), 'page');
    assert.deepEqual(errors, []);
  } finally {
    await page.evaluate(() => Object.defineProperty(window, 'localStorage', window.sidebarStorageDescriptor));
  }
  try {
    await page.evaluate(() => {
      window.sidebarSetItem = Storage.prototype.setItem;
      Storage.prototype.setItem = function () { throw new DOMException('Synthetic quota refusal', 'QuotaExceededError'); };
      window.mountSidebar();
    });
    await page.getByRole('button', { name: '收起侧栏', exact: true }).click();
    await page.getByRole('button', { name: '展开侧栏', exact: true }).waitFor();
    assert.deepEqual(errors, [], 'failed persistence must not disable the current navigation');
  } finally {
    await page.evaluate(() => { Storage.prototype.setItem = window.sidebarSetItem; });
    page.off('pageerror', onError);
  }
});

test('all nine languages keep icon hit targets and three columns within wide and narrow desktop layouts in both themes', { skip: noDisplay }, async () => {
  for (const language of Object.keys(languages)) for (const theme of ['light', 'dark']) {
    await mount({ language, theme });
    assert.deepEqual(await page.locator('.sidebar .nav-item').evaluateAll(items => items.map(item => item.getAttribute('aria-label'))), labels.map(label => translate(label, language)));
    const ssh = page.getByRole('button', { name: translate('SSH 连接', language), exact: true });
    await ssh.click();
    assert.equal(await ssh.getAttribute('aria-current'), 'page');
    for (const width of [900, 1280, 1720]) {
      await page.setViewportSize({ width, height: 900 });
      for (const collapsed of [false, true]) {
        const name = translate(collapsed ? '展开侧栏' : '收起侧栏', language);
        if (await page.getByRole('button', { name, exact: true }).count() === 0)
          await page.locator('.sidebar-toggle').click();
        const values = await columns();
        assert.equal(values.length, 3); assert.equal(values[0], collapsed ? 64 : 210);
        assert.ok(values[1] > 300 && values[2] > 0);
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true);
        for (const label of labels) {
          const action = page.getByRole('button', { name: translate(label, language), exact: true });
          assert.equal(await action.getAttribute('title'), translate(label, language));
          assert.equal(await action.evaluate(element => element.scrollWidth <= element.clientWidth), true);
          assert.ok((await action.boundingBox()).height >= 40);
        }
      }
    }
  }
});

test('collapsed sidebar preserves terminal grid placement and expansion', { skip: noDisplay }, async () => {
  await mount({ terminal: true }, 'true');
  assert.equal(await page.locator('.terminal-dock').evaluate(element => element.getBoundingClientRect().x), 64);
  assert.equal(await page.locator('.sidebar').evaluate(element => getComputedStyle(element).gridRow), '1 / 3');
  await mount({ terminal: true, expanded: true }, 'true');
  assert.equal(await page.locator('.terminal-dock').evaluate(element => element.getBoundingClientRect().x), 64);
  assert.equal(await page.locator('.main-panel').isVisible(), false);
  assert.equal(await page.locator('.detail-panel').isVisible(), false);
});

test('SSH navigation and environment terminal entries open the full right workspace without starting or ending sessions', { skip: noDisplay }, async () => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.evaluate(() => { localStorage.setItem('envara.sidebar.collapsed.v1', 'false'); window.mountWorkspace(); });
  await page.getByRole('button', { name: 'Select Demo A', exact: true }).waitFor();
  await page.waitForFunction(() => window.fixtureDockProps.selectedProfileId === 'env-a');
  const instance = await page.locator('.terminal-dock').getAttribute('data-instance');
  await page.getByRole('button', { name: 'SSH 连接', exact: true }).click();
  assert.equal(await page.locator('main.ssh-main-panel h1').textContent(), 'SSH 连接');
  assert.equal(await page.locator('.terminal-dock').isVisible(), false);
  assert.equal(await page.locator('.fixture-ssh-workspace').getAttribute('data-terminal-profiles'), '2');
  await page.getByLabel('Fixture SSH environment').selectOption('env-b');
  await page.getByRole('button', { name: 'Fixture open terminal', exact: true }).click();
  const dock = page.locator('.terminal-dock');
  assert.equal(await dock.getAttribute('data-profile'), 'env-b');
  assert.equal(await dock.getAttribute('data-workspace'), 'true');
  assert.equal(await dock.getAttribute('data-expanded'), 'true');
  assert.equal(await page.locator('.app-shell').evaluate(element => element.classList.contains('terminal-expanded')), true);
  assert.equal(await page.locator('.page-header').count(), 0);
  assert.equal(await page.locator('.terminal-page-context').count(), 0);
  assert.equal(await page.locator('.main-panel').isVisible(), false);
  const area = await dock.boundingBox(), sidebar = await page.locator('.sidebar').boundingBox();
  assert.equal(area.x, sidebar.width); assert.equal(area.width + area.x, 1280); assert.equal(area.height, 900);
  assert.deepEqual(await page.evaluate(() => ({ id: window.fixtureDockProps.openRequest.profileId, instance: window.fixtureDockInstances })), { id: 'env-b', instance: Number(instance) });
  await page.getByRole('button', { name: 'Fixture export terminal', exact: true }).click();
  await page.getByRole('dialog', { name: '导出终端', exact: true }).waitFor();
  await page.waitForFunction(() => window.fixtureCalls.some(call => call.method === 'listClaudeAccounts' && call.args.id === 'env-b'));
  await page.getByRole('button', { name: '取消', exact: true }).click();
  await page.getByRole('button', { name: 'Fixture link browser', exact: true }).click();
  await page.getByRole('dialog', { name: '选择此环境的浏览器', exact: true }).waitFor();
  await page.getByRole('button', { name: '关闭', exact: true }).click();
  await page.getByRole('button', { name: 'Fixture close view', exact: true }).click();
  assert.equal(await dock.isVisible(), false);
  assert.equal(await page.getByRole('button', { name: '环境', exact: true }).getAttribute('aria-current'), 'page');
  await page.getByRole('button', { name: 'Open Demo B terminal', exact: true }).click();
  assert.equal(await dock.getAttribute('data-profile'), 'env-b');
  assert.equal(await dock.getAttribute('data-expanded'), 'true');
  assert.equal(await dock.getAttribute('data-instance'), instance);
  await page.getByRole('button', { name: 'Fixture close view', exact: true }).click();
  await page.getByRole('button', { name: 'Select Demo A', exact: true }).click();
  await page.getByRole('button', { name: 'Open Demo A terminal', exact: true }).click();
  assert.equal(await page.getByRole('button', { name: 'Fixture export terminal', exact: true }).isDisabled(), true);
  assert.deepEqual(await page.evaluate(() => [...new Set(window.fixtureCalls.map(call => call.method))]), ['snapshot', 'listClaudeAccounts']);
});
