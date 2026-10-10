// Opt-in development acceptance harness. Never enabled in a packaged release.
import assert from 'node:assert/strict';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { mkdir, realpath, writeFile } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';
import { BrowserWindow } from 'electron';
import { languages } from '../shared/interface-languages.mjs';
import { translate } from '../src/i18n.mjs';

const chineseNavigation = ['环境', '网络出口', '浏览器', '终端', '附加软件', '运行监控'];
const englishNavigation = ['Environments', 'Networks', 'Browsers', 'Terminals', 'Applications', 'Monitor'];

export async function runWorkspaceSmoke({ app, window, service, terminal, applications, shutdown }) {
  const artifactDir = process.env.ENVARA_WORKSPACE_SMOKE_ARTIFACTS;
  const selectedDirectory = await realpath(process.env.ENVARA_WORKSPACE_SMOKE_CWD);
  const result = { platform: `${process.platform}-${process.arch}`, appVersion: app.getVersion(), passed: false,
    scope: 'Production Electron UI/IPC, real local PTYs and unavailable native application-routing gate. Egress is an offline fixture; no browser/kernel download or node connection.', checks: [], screenshots: [], screenshotEvidence: [] };
  const terminalIds = new Set(); let independentWindow;
  const evaluate = (source, target = window) => target.webContents.executeJavaScript(source);
  const call = (method, args = {}, target = window) => evaluate(`window.envara.call(${JSON.stringify(method)}, ${JSON.stringify(args)})`, target);
  const waitFor = async (test, label, timeoutMs = 15000) => {
    const deadline = Date.now() + timeoutMs; let lastError;
    while (Date.now() < deadline) {
      try { if (await test()) return; } catch (error) { lastError = error; }
      await delay(75);
    }
    throw new Error(`Timed out waiting for ${label}${lastError ? `: ${lastError.message}` : ''}`);
  };
  const navigation = () => evaluate("Array.from(document.querySelectorAll('.navigation .nav-item')).map(button => button.querySelector('span')?.textContent?.trim())");
  const ready = async (target = window) => waitFor(() => evaluate("Boolean(window.envara?.isDesktop && document.querySelector('.app-shell, .terminal-window-shell'))", target), 'desktop renderer');
  const navigate = async (index, language = 'zh-CN') => {
    const expected = (language === 'en' ? englishNavigation : chineseNavigation)[index];
    await evaluate(`document.querySelectorAll('.navigation .nav-item')[${index}].click()`);
    await waitFor(() => evaluate(`document.querySelector('.page-header h1')?.textContent?.trim() === ${JSON.stringify(expected)}`), `${expected} page`);
  };
  const capture = async (name, target = window, expectedHeading, headingSelector = '.page-header h1, .terminal-window-heading h1') => {
    target.show(); target.focus();
    // DOM updates can precede native presentation, especially while the window
    // is occluded. Wait for renderer frames and an invalidated compositor frame.
    await evaluate("new Promise((resolve, reject) => { const timer = setTimeout(() => reject(new Error('Renderer paint frames timed out')), 3000); requestAnimationFrame(() => requestAnimationFrame(() => { clearTimeout(timer); resolve(); })); })", target);
    await new Promise((resolve, reject) => {
      const contents = target.webContents;
      const timer = setTimeout(() => { contents.endFrameSubscription(); reject(new Error('Native presentation frame timed out')); }, 3000);
      contents.beginFrameSubscription(false, () => { clearTimeout(timer); contents.endFrameSubscription(); resolve(); });
      contents.invalidate();
    });
    await delay(80);
    const filename = path.join(artifactDir, name);
    const pixels = await target.webContents.capturePage(); assert.equal(pixels.isEmpty(), false);
    await writeFile(filename, pixels.toPNG()); result.screenshots.push(filename);
    const actualHeading = await evaluate(`document.querySelector(${JSON.stringify(headingSelector)})?.textContent?.trim()`, target);
    if (expectedHeading != null) assert.equal(actualHeading, expectedHeading, `Heading after native screenshot ${name}`);
    result.screenshotEvidence.push({ path: filename, expectedHeading, actualHeading, nativePresentation: true, pixels: pixels.getSize() });
  };
  const switchLanguage = async language => {
    await evaluate("document.querySelector('.settings-navigation').click()");
    await waitFor(() => evaluate("Boolean(document.querySelector('.language-select:not(:disabled)'))"), `interactive language selector before ${language}`);
    await evaluate(`(() => { const select = document.querySelector('.language-select'); if (!select || select.disabled) throw new Error('Language selector is not interactive'); select.value = ${JSON.stringify(language)}; select.dispatchEvent(new Event('change', { bubbles: true })); })()`);
    await waitFor(async () => (await call('snapshot')).settings?.language === language, `persisted ${language} language preference`);
    await waitFor(async () => JSON.stringify(await navigation()) === JSON.stringify(chineseNavigation.map(label => translate(label, language))), `${language} translated navigation`);
    assert.equal(await evaluate('document.documentElement.lang'), language);
    // The store snapshot and optimistic translation can arrive before the save
    // IPC promise completes. A user cannot submit the disabled selector during
    // that interval; keep each test change subject to the same UI boundary.
    await waitFor(() => evaluate(`(() => { const select = document.querySelector('.language-select'); return Boolean(select && !select.disabled && select.value === ${JSON.stringify(language)}); })()`), `completed ${language} language selection`);
  };
  try {
    assert.equal(process.env.ENVARA_WORKSPACE_SMOKE, '1', 'Harness requires an explicit development flag');
    assert.equal(app.isPackaged, false, 'Harness cannot run in a release');
    assert.ok(path.isAbsolute(artifactDir ?? ''), 'Artifact directory must be absolute');
    await mkdir(artifactDir, { recursive: true }); await ready();
    await waitFor(async () => (await navigation()).length === 6, 'six navigation destinations');
    const initial = await call('snapshot');
    assert.equal(initial.profiles.length, 0); assert.equal(initial.proxies.length, 0); assert.equal(initial.applications.length, 0);
    assert.equal(initial.settings.language, undefined);
    await waitFor(() => evaluate("document.querySelectorAll('.language-welcome-card input[name=interface-language]').length === 9"), 'first-launch nine-language dialog');
    assert.deepEqual(await evaluate("Array.from(document.querySelectorAll('.language-welcome-card input')).map(input => input.value)"), [...languages]);
    await evaluate("document.querySelector('.language-welcome-card input[value=en]').click()");
    await waitFor(() => evaluate("document.querySelector('.language-welcome-card h1')?.textContent === 'Welcome to Envara'"), 'English preview before confirmation');
    assert.equal((await call('snapshot')).settings.language, undefined);
    await capture('first-launch.png', window, 'Welcome to Envara', '.language-welcome-card h1');
    await evaluate("document.querySelector('.language-welcome-card input[value=fr]').click()");
    await waitFor(() => evaluate("document.documentElement.lang === 'fr'"), 'French first-launch preview');
    assert.equal((await call('snapshot')).settings.language, undefined);
    await evaluate("document.querySelector('.language-start-button').click()");
    await waitFor(() => evaluate("!document.querySelector('.language-welcome-layer')"), 'confirmed first-launch language');
    assert.equal((await call('snapshot')).settings.language, 'fr');
    result.checks.push('First native launch offers nine languages; English/French preview is not persisted until confirmation succeeds through real IPC');

    for (const language of languages) {
      await switchLanguage(language);
      assert.equal(await evaluate("document.querySelectorAll('.language-select option').length"), 9);
    }
    result.checks.push('All nine interface languages switch through real Settings IPC, with matching navigation and document language');

    await switchLanguage('en');
    await capture('settings-en.png', window, 'Settings');
    const reloaded = new Promise((resolve, reject) => {
      const contents = window.webContents;
      const finished = () => { contents.removeListener('did-fail-load', failed); resolve(); };
      const failed = (_event, code, message, _url, isMainFrame) => {
        if (!isMainFrame || code === -3) return;
        contents.removeListener('did-finish-load', finished); contents.removeListener('did-fail-load', failed);
        reject(new Error(`Renderer reload failed: ${code} ${message}`));
      };
      contents.once('did-finish-load', finished); contents.on('did-fail-load', failed);
    });
    window.webContents.reload(); await reloaded; await ready();
    await waitFor(async () => JSON.stringify(await navigation()) === JSON.stringify(englishNavigation), 'English after renderer reload');
    assert.equal((await call('snapshot')).settings.language, 'en');
    assert.equal(await evaluate("Boolean(document.querySelector('.language-welcome-layer'))"), false);
    result.checks.push('Language selector saves English through production IPC and restores it after renderer reload');
    await switchLanguage('zh-CN');

    const created = await call('createProfile', { profile: { name: '境舱 · 本机验收' } });
    assert.equal(created.profiles.length, 1);
    const profile = created.profiles[0];
    assert.equal(profile.timezoneMode, 'auto'); assert.equal(profile.localeMode, 'auto');
    const detected = await call('checkEnvironmentNetwork', { id: profile.id });
    const resolved = detected.profiles.find(item => item.id === profile.id);
    assert.equal(resolved.resolvedTimezone, 'Asia/Manila'); assert.equal(resolved.resolvedLocale, 'en-PH');
    assert.equal(resolved.network.ok, true); assert.equal(resolved.network.countryCode, 'PH');
    assert.deepEqual(resolved.geolocation, { latitude: 14.6, longitude: 121, accuracy: 50000 });
    result.checks.push('Name-only environment defaults to automatic locale/timezone and uses parsed offline PH egress coordinates at 50 km accuracy');

    const directory = await call('chooseWorkspaceDirectory', { id: profile.id });
    assert.equal(directory.canceled, false);
    assert.equal(directory.profiles.find(item => item.profileId === profile.id).cwd, selectedDirectory);
    const source = await call('openTerminal', { id: profile.id, columns: 100, rows: 24 });
    terminalIds.add(source.sessionId); assert.equal(source.status, 'running'); assert.equal(source.cwd, selectedDirectory); assert.equal(source.timezone, 'Asia/Manila');
    const marker = `ENVARA_SOURCE_${randomUUID().replaceAll('-', '')}`;
    await call('writeTerminal', { sessionId: source.sessionId, data: process.platform === 'win32' ? `echo ${marker}\r` : `printf '%s\\n' '${marker}'\r` });
    await waitFor(async () => new RegExp(`(?:^|[\\r\\n])${marker}[\\r\\n]`).test((await call('terminalSnapshot', { id: profile.id })).profiles[0].sessions.find(item => item.sessionId === source.sessionId)?.replay ?? ''), 'real source PTY command output');
    const duplicate = await call('duplicateTerminal', { sessionId: source.sessionId });
    terminalIds.add(duplicate.sessionId);
    assert.notEqual(duplicate.sessionId, source.sessionId); assert.equal(duplicate.status, 'running');
    assert.equal(duplicate.cwd, source.cwd); assert.equal(duplicate.timezone, source.timezone);
    // A new real shell can already have emitted its own prompt. Its replay must
    // contain no source output or commands, rather than requiring an empty prompt.
    assert.equal(duplicate.replay.includes(marker), false);
    const nativeSnapshot = await terminal.snapshot({ id: profile.id });
    assert.equal(nativeSnapshot.profiles[0].sessions.filter(item => item.status === 'running').length, 2);
    result.checks.push('Real PTY launches in the selected directory; duplicate owns a fresh process/session and does not replay source commands or output');

    const chosenPath = process.platform === 'darwin' ? '/System/Applications/TextEdit.app' : process.platform === 'win32' ? path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32/notepad.exe') : '/usr/bin/true';
    const attached = await call('saveApplication', { application: { profileId: profile.id, path: chosenPath, name: '本地软件 · 授权验证' } });
    assert.equal(attached.applications.length, 1);
    const application = attached.applications[0];
    const routingStatus = await call('getApplicationRoutingStatus'); assert.equal(routingStatus.ready, false);
    const denied = await evaluate(`window.envara.call('startApplication', { id: ${JSON.stringify(application.id)} }).then(() => ({ unexpectedlyLaunched: true }), error => ({ code: error.code, message: error.message }))`);
    assert.equal(denied.unexpectedlyLaunched, undefined);
    // Electron's context bridge preserves Error.message, but custom Error
    // properties need not survive its cross-realm serialization. The service's
    // persisted public error metadata is the authoritative refusal code.
    assert.equal(typeof denied.message, 'string'); assert.ok(denied.message.length > 0);
    const afterDenied = (await call('snapshot')).applications.find(item => item.id === application.id);
    assert.equal(afterDenied.status, 'error'); assert.equal(afterDenied.pid, null); assert.equal(afterDenied.sessionId, null);
    assert.match(afterDenied.lastError?.code, /^APPLICATION_ROUTING_(UNAVAILABLE|AUTHORIZATION_REQUIRED|NOT_READY)$/);
    assert.equal(applications.hasActiveProfile(profile.id), false);
    result.applicationRouting = { ready: routingStatus.ready, status: routingStatus.status, refusalCode: afterDenied.lastError.code };
    result.checks.push('Real local application binding is saved; unverified/unauthorized native routing refuses launch without a PID or direct fallback');

    for (let index = 0; index < 6; index++) { await navigate(index); await capture(`${index + 1}-${['environments', 'networks', 'browsers', 'terminals', 'applications', 'monitor'][index]}-zh.png`, window, chineseNavigation[index]); }
    await navigate(3);
    await waitFor(() => evaluate("document.querySelectorAll('.terminal-session-tab').length === 2"), 'two terminal tabs');
    await evaluate("document.querySelector('[aria-label=\"放大终端\"]').click()");
    await waitFor(() => evaluate("Boolean(document.querySelector('.terminal-dock.is-expanded'))"), 'expanded terminal');
    await waitFor(() => evaluate("Boolean(document.querySelector('.app-shell.terminal-expanded') && getComputedStyle(document.querySelector('.main-panel')).display === 'none' && document.querySelector('.terminal-dock').getBoundingClientRect().top < 40)"), 'expanded terminal occupying main area');
    result.terminalExpandedLayout = await evaluate("(() => { const rect = document.querySelector('.terminal-dock').getBoundingClientRect(); return { top: rect.top, height: rect.height, viewportHeight: innerHeight, mainDisplay: getComputedStyle(document.querySelector('.main-panel')).display }; })()");
    assert.ok(result.terminalExpandedLayout.height >= result.terminalExpandedLayout.viewportHeight - 40);
    await capture('terminal-expanded-zh.png', window, '终端');
    await evaluate("document.querySelector('[aria-label=\"还原终端大小\"]').click()");
    await waitFor(() => evaluate("!document.querySelector('.terminal-dock.is-expanded')"), 'restored terminal');
    result.checks.push('Six production pages render in the native window; terminal expands and restores');

    const opened = await call('openTerminalWindow', { id: profile.id, sessionId: duplicate.sessionId });
    assert.equal(opened.ok, true); assert.equal(opened.profileId, profile.id); assert.equal(opened.sessionId, duplicate.sessionId);
    independentWindow = BrowserWindow.fromId(opened.windowId); assert.ok(independentWindow); await ready(independentWindow);
    await waitFor(() => evaluate("Boolean(document.querySelector('.terminal-dock.is-standalone'))", independentWindow), 'standalone terminal renderer');
    for (const language of ['ja', 'pt-BR', 'zh-CN']) {
      await switchLanguage(language);
      await waitFor(() => evaluate(`document.documentElement.lang === ${JSON.stringify(language)}`, independentWindow), 'independent window language synchronization');
      assert.equal(await evaluate("Boolean(document.querySelector('.language-welcome-layer'))", independentWindow), false);
    }
    result.checks.push('An existing independent terminal follows Japanese, Portuguese and Chinese settings without showing first-run onboarding');
    await capture('terminal-independent-zh.png', independentWindow, profile.name);
    const forbidden = await evaluate("window.envara.call('createProfile', {profile:{name:'forbidden'}}).then(() => ({allowed:true}), () => ({allowed:false}))", independentWindow);
    assert.equal(forbidden.allowed, false);
    independentWindow.close(); independentWindow = null;
    const retained = await call('terminalSnapshot', { id: profile.id });
    assert.equal(retained.profiles[0].sessions.filter(item => item.status === 'running').length, 2);
    result.checks.push('Independent native terminal window uses the existing session, rejects unrelated IPC actions, and closing its view preserves both PTYs');

    await switchLanguage('en'); await navigate(3, 'en'); await capture('terminal-en.png', window, 'Terminals');
    assert.deepEqual(await navigation(), englishNavigation);
    const dom = await evaluate("({lang:document.documentElement.lang, heading:document.querySelector('.page-header h1')?.textContent, terminalTabs:Array.from(document.querySelectorAll('.terminal-session-tab')).map(tab=>tab.textContent.trim())})");
    assert.equal(dom.lang, 'en'); assert.equal(dom.heading, 'Terminals'); assert.ok(dom.terminalTabs.every(item => item.includes('Session')));
    result.checks.push('Active terminal view and session labels switch to English without restarting either process');
    for (const sessionId of terminalIds) await call('closeTerminal', { sessionId });
    assert.equal((await call('terminalSnapshot', { id: profile.id })).profiles[0].sessions.some(item => ['running', 'starting', 'closing'].includes(item.status)), false);
    result.checks.push('Explicitly closing sessions ends both owned PTYs');
    result.passed = true;
  } catch (error) { result.error = error.stack ?? error.message; console.error(result.error); }
  finally {
    if (independentWindow && !independentWindow.isDestroyed()) independentWindow.close();
    try {
      if (typeof shutdown === 'function') await shutdown();
      else { await applications?.shutdown(); await terminal?.shutdown(); await service?.shutdown(); }
    } catch (error) { result.cleanupError = error.message; result.passed = false; }
    try { await mkdir(artifactDir, { recursive: true }); await writeFile(path.join(artifactDir, 'workspace-smoke.json'), JSON.stringify(result, null, 2)); }
    finally { app.exit(result.passed ? 0 : 1); }
  }
}
