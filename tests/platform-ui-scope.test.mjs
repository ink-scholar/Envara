import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { pageAvailable } from '../src/workspace-navigation.mjs';
import { windowsAuxiliaryExecutable } from '../electron/local-application-catalog.mjs';
import { engineInstallDiagnostic, engineInstallProgress } from '../electron/sidecar-manager.mjs';
import { TerminalService } from '../electron/terminal-service.mjs';
import { claudeErrorMessage } from '../src/claude-account-choice.mjs';
import { componentVersionSnapshot } from '../shared/component-versions.mjs';

const source = file => readFile(new URL(`../${file}`, import.meta.url), 'utf8');

test('the SSH page is offered only on macOS, and an unknown platform keeps every page', () => {
  assert.equal(pageAvailable('ssh', 'darwin'), true);
  assert.equal(pageAvailable('ssh', 'win32'), false);
  assert.equal(pageAvailable('ssh', 'linux'), false);
  assert.equal(pageAvailable('ssh', undefined), true);
  for (const page of ['profiles', 'proxies', 'browsers', 'terminals', 'applications', 'monitor', 'settings']) assert.equal(pageAvailable(page, 'win32'), true, page);
});

test('the sidebar, the page fallback and the terminal window all use the platform rule', async () => {
  assert.match(await source('src/WorkspaceSidebar.jsx'), /navItemsFor\(platform\)\.map/);
  const app = await source('src/App.jsx');
  assert.match(app, /if \(!pageAvailable\(page, system\.platform\)\) setPage\("profiles"\);/);
  assert.match(app, /platform=\{system\.platform\}/);
  assert.match(await source('src/TerminalWindowApp.jsx'), /pageAvailable\('ssh', snapshot\?\.system\?\.platform\)\?\['terminal','ssh'\]:\['terminal'\]/);
});

test('Windows catalog omits uninstallers, installers, updaters, crash reporters and helpers but keeps applications', () => {
  for (const name of ['unins000.exe', 'Uninstall.exe', 'Uninstall Foo.exe', 'Foo-Uninstaller.exe', 'Setup Foo.exe', 'setup.exe', 'FooSetup.exe', 'Update.exe', 'GoogleUpdater.exe',
    'crashpad_handler.exe', 'CrashReporter.exe', 'notification_helper.exe', 'elevation_service.exe', 'Steam Helper.exe', 'vc_redist.x64.exe',
    'node.exe', 'python3.exe', 'javaw.exe', 'msedgewebview2.exe', 'maintenancetool.exe', 'Squirrel.exe', 'CefSharp.BrowserSubprocess.exe']) {
    assert.equal(windowsAuxiliaryExecutable(name), true, name);
  }
  for (const name of ['chrome.exe', 'Notion.exe', 'Code.exe', 'Telegram.exe', 'WeChat.exe', 'Discord.exe', 'slack.exe', 'Obsidian.exe',
    'Epic Games Launcher.exe', 'Spotify.exe', 'firefox.exe', 'msedge.exe', 'WINWORD.EXE', 'Feishu.exe', 'Cursor.exe', 'Docker Desktop.exe', 'HelpViewer.exe']) {
    assert.equal(windowsAuxiliaryExecutable(name), false, name);
  }
});

test('engine installation reports a numeric percentage and failures omit repeated progress updates', () => {
  assert.equal(engineInstallProgress('\r  12 / 300 MB (4%)\r  40 / 300 MB (13%)'), 13);
  assert.equal(engineInstallProgress('Installing Camoufox...', 13), 13);
  assert.equal(engineInstallProgress('📥 Downloading CloakBrowser (x.zip)...'), null);
  assert.equal(engineInstallProgress('\r 300 / 300 MB (100%)'), 100);
  const noisy = '📥 Downloading Camoufox (x.zip)...\n' + Array.from({ length: 60 }, (_, i) => `\r  ${i} / 300 MB (${i}%)`).join('') + '\nError: unexpected EOF';
  assert.equal(engineInstallDiagnostic(noisy), '📥 Downloading Camoufox (x.zip)...\nError: unexpected EOF');
  assert.ok(engineInstallDiagnostic('x'.repeat(900)).length <= 500);
});

test('Claude Code sessions are refused outside macOS before any installation, with a clear message', async t => {
  const dataDir = await mkdtemp(path.join(os.tmpdir(), 'envara-claude-platform-'));
  t.after(() => rm(dataDir, { recursive: true, force: true }));
  let installs = 0;
  const service = new TerminalService({ dataDir, resolveContext: async () => { throw new Error('not reached'); },
    claudeInstaller: async () => { installs++; }, claudePlatform: 'win32' });
  await assert.rejects(service.create({ id: 'prof_1', columns: 80, rows: 24, kind: 'claude-code', browserProfileId: 'prof_1' }),
    { code: 'CLAUDE_CODE_UNSUPPORTED_PLATFORM', message: 'Claude Code 会话目前仅支持 macOS。' });
  assert.equal(installs, 0);
  await service.shutdown().catch(() => {});
  assert.equal(claudeErrorMessage('', 'CLAUDE_CODE_UNSUPPORTED_PLATFORM'), 'Claude Code 会话目前仅支持 macOS。');
  const chooser = await source('src/terminal-session-chooser.jsx');
  assert.match(chooser, /disabled=\{!!pending \|\| !claudeSupported\}/);
  assert.match(chooser, /const claudeSupported = !systemPlatform \|\| systemPlatform === 'darwin';/);
});

test('link settings state platform limits instead of hiding them', async () => {
  const main = await source('electron/main.mjs');
  assert.match(main, /systemRoutingSupported: process\.platform === 'darwin', terminalLinks: linkChannel !== null/);
  const app = await source('src/App.jsx');
  assert.match(app, /linkRouter\.systemRoutingSupported === false && <div className="settings-row">/);
  assert.match(app, /t\("系统链接接管目前仅支持 macOS。"\)/);
  assert.match(app, /linkRouter\.terminalLinks === false \? "境舱内的链接使用所选浏览器；/);
});

test('components a platform does not support read as unavailable rather than missing or needing a check', async () => {
  const snapshot = { profiles: [], applicationRouting: { backend: 'windivert', installed: false, ready: false } };
  const routing = platform => componentVersionSnapshot({ snapshot, platform, arch: 'x64' }).rows.find(item => item.id === 'application-routing');
  assert.equal(routing('win32').support, 'unsupported');
  assert.equal(routing('linux').support, 'unknown');
  const view = await source('src/ComponentVersions.jsx');
  assert.match(view, /const shownStatus = row => row\.support === 'unsupported' && !\['installed', 'running', 'ready', 'updating'\]\.includes\(row\.status\) \? 'unavailable' : row\.status;/);
  assert.match(view, /t\(statusLabels\[shownStatus\(row\)\] \|\| '未知'\)/);
});
