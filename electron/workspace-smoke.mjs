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
const englishNavigation = ['Environments', 'Networks', 'Browsers', 'Terminals', 'Attached applications', 'Monitor'];

export async function runWorkspaceSmoke({ app, window, service, terminal, applications, shutdown }) {
  const artifactDir = process.env.ENVARA_WORKSPACE_SMOKE_ARTIFACTS;
  const selectedDirectory = await realpath(process.env.ENVARA_WORKSPACE_SMOKE_CWD);
  const result = { platform: `${process.platform}-${process.arch}`, appVersion: app.getVersion(), passed: false,
    scope: 'Production Electron UI/IPC, real local PTYs and native application eligibility gates. Egress and address results are offline fixtures; no browser/kernel download or node connection.', checks: [], screenshots: [], screenshotEvidence: [] };
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

    // Address conversion uses deterministic provider data in this UI harness;
    // the transport has separate authenticated socket and public-service checks.
    await navigate(1);
    const clickText = async (label, selector = 'button') => evaluate(`(() => { const button = Array.from(document.querySelectorAll(${JSON.stringify(selector)})).find(item => item.textContent.trim() === ${JSON.stringify(label)}); if (!button || button.disabled) throw new Error('Interactive button missing: ' + ${JSON.stringify(label)}); button.click(); })()`);
    const fillField = async (label, value) => evaluate(`(() => { const field = Array.from(document.querySelectorAll('.proxy-modal .field')).find(item => item.querySelector('.field-label')?.textContent === ${JSON.stringify(label)}); const input = field?.querySelector('input'); if (!input) throw new Error('Input missing: ' + ${JSON.stringify(label)}); Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, ${JSON.stringify(value)}); input.dispatchEvent(new Event('input', { bubbles: true })); })()`);
    await clickText('添加网络出口', '.page-header button');
    await waitFor(() => evaluate("Boolean(document.querySelector('.proxy-modal'))"), 'new network dialog');
    await fillField('名称', 'Synthetic address network'); await fillField('服务器地址', '127.0.0.1'); await fillField('端口', '9');
    await clickText('检测并继续', '.proxy-modal button');
    await waitFor(() => evaluate("Boolean(document.querySelector('.location-mode-control'))"), 'verified network location step');
    await clickText('手动选择位置', '.proxy-modal button'); await fillField('街道、地址或地点', 'Synthetic public landmark');
    await clickText('查询地址', '.proxy-modal button');
    await waitFor(() => evaluate("document.querySelectorAll('.address-search-results > button').length === 1"), 'address candidates from production IPC');
    assert.equal(await evaluate("document.querySelector('.location-confirmation input').checked"), false);
    await evaluate("document.querySelector('.address-search-results > button').click()");
    await waitFor(() => evaluate("!document.querySelector('.address-search-results') && document.querySelector('.location-manual-fields input[type=number]')?.value === '14.58'"), 'chosen candidate coordinates');
    assert.equal(await evaluate("document.querySelector('.location-confirmation input').checked"), false);
    await fillField('Google Maps 链接（选填）', 'https://www.google.com/maps/search/?api=1&query=14.6,121');
    assert.equal(await evaluate("document.querySelector('.location-manual-fields input').value"), '', 'replacing a map pin discards the previous candidate label');
    await fillField('街道、地址或地点', 'Synthetic public landmark'); await clickText('查询地址', '.proxy-modal button');
    await waitFor(() => evaluate("document.querySelectorAll('.address-search-results > button').length === 1"), 'replacement address candidates');
    await evaluate("document.querySelector('.address-search-results > button').click()");
    for (const language of languages) {
      await call('saveSettings', { settings: { language } });
      await waitFor(() => evaluate(`document.documentElement.lang === ${JSON.stringify(language)}`), `address form ${language}`);
      await waitFor(() => evaluate(`Array.from(document.querySelectorAll('.proxy-modal button')).some(button => button.textContent.trim() === ${JSON.stringify(translate('查询地址', language))})`), `translated address action ${language}`);
      assert.equal(await evaluate("document.querySelector('.proxy-modal').scrollWidth <= document.querySelector('.proxy-modal').clientWidth + 1"), true, `address dialog horizontal overflow in ${language}`);
      await capture(`address-${language}.png`, window, translate('创建网络环境', language), '.proxy-modal h2');
    }
    await call('saveSettings', { settings: { language: 'zh-CN' } });
    await waitFor(() => evaluate("document.documentElement.lang === 'zh-CN'"), 'Chinese address confirmation');
    await evaluate("document.querySelector('.location-confirmation input').click()");
    await clickText('保存网络环境', '.proxy-modal button');
    await waitFor(() => evaluate("!document.querySelector('.proxy-modal')"), 'confirmed address saved');
    const addressNetwork = (await call('snapshot')).proxies.find(item => item.name === 'Synthetic address network');
    assert.equal(addressNetwork.location.latitude, 14.58); assert.equal(addressNetwork.location.longitude, 120.98);
    assert.equal(addressNetwork.location.timezone, 'Asia/Manila'); assert.equal(addressNetwork.location.source, 'manual');
    result.checks.push('Text address search returns candidates through verified-route IPC; selection requires confirmation, saves manual coordinates, and fits all nine interface languages');

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
    if (process.platform === 'darwin') {
      const denied = await evaluate(`window.envara.call('saveApplication', {application:{profileId:${JSON.stringify(profile.id)},path:${JSON.stringify(chosenPath)},name:'Unsupported fixture'}}).then(() => ({unexpectedlyBound:true}), error => ({message:error.message}))`);
      assert.equal(denied.unexpectedlyBound, undefined); assert.ok(denied.message);
      assert.equal((await call('snapshot')).applications.length, 0);
      assert.equal(applications.hasActiveProfile(profile.id), false);
      result.applicationRouting = { eligibilityRejected: true, launched: false };
      result.checks.push('An unsupported native app is rejected before binding or activation; no unrelated user application is launched');
    } else {
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
    }

    for (let index = 0; index < 6; index++) { await navigate(index); await capture(`${index + 1}-${['environments', 'networks', 'browsers', 'terminals', 'applications', 'monitor'][index]}-zh.png`, window, chineseNavigation[index]); }
    await navigate(3);
    await waitFor(() => evaluate("document.querySelectorAll('.terminal-session-tab').length === 2"), 'two terminal tabs');
    // Account-management acceptance uses a disposable saved route/profile but
    // never installs, starts or signs into Claude. No request uses this route.
    const accountProxyName = 'Claude metadata fixture';
    const accountProxy = (await call('saveProxy', { proxy: { name: accountProxyName, protocol: 'http', host: '127.0.0.1', port: 65534 } })).proxies.find(item => item.name === accountProxyName);
    const accountProfileName = 'Claude 档案管理验收';
    const accountProfile = (await call('createProfile', { profile: { name: accountProfileName, proxyId: accountProxy.id } })).profiles.find(item => item.name === accountProfileName);
    await waitFor(() => evaluate(`Boolean(document.getElementById(${JSON.stringify(`terminal-env-${accountProfile.id}`)}))`), 'disposable account environment');
    await evaluate("document.querySelector('.terminal-context-bar .terminal-start-button').click()");
    await waitFor(() => evaluate("Boolean(document.querySelector('.terminal-new-session'))"), 'new terminal chooser for account management');
    await evaluate("Array.from(document.querySelectorAll('.terminal-session-kind button')).find(button => button.textContent === 'Claude Code').click()");
    await waitFor(() => evaluate("Boolean(document.querySelector('.terminal-account-field select[aria-label=\"登录档案\"]:not(:disabled)'))"), 'loaded Claude account selector');
    const accountSelect = '.terminal-account-field select[aria-label="登录档案"]';
    const selectAccount = value => evaluate(`(() => { const select = document.querySelector(${JSON.stringify(accountSelect)}); select.value = ${JSON.stringify(value)}; select.dispatchEvent(new Event('change', { bubbles: true })); })()`);
    const fillAccountName = (label, value) => evaluate(`(() => { const input = document.querySelector('input[aria-label=' + ${JSON.stringify(JSON.stringify(label))} + ']'); Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, ${JSON.stringify(value)}); input.dispatchEvent(new Event('input', { bubbles: true })); })()`);
    const accountButton = text => evaluate(`(() => { const button = Array.from(document.querySelectorAll('.terminal-account-field button')).find(item => item.textContent === ${JSON.stringify(text)}); if (!button || button.disabled) throw new Error('Account action is not interactive'); button.click(); })()`);
    await selectAccount('__new__');
    await waitFor(() => evaluate("Boolean(document.querySelector('input[aria-label=\"档案名称\"]'))"), 'new account name field');
    await fillAccountName('档案名称', '工作档案'); await accountButton('创建档案');
    await waitFor(async () => (await call('listClaudeAccounts', { id: accountProfile.id })).accounts.some(item => item.name === '工作档案'), 'created account metadata');
    const managedAccount = (await call('listClaudeAccounts', { id: accountProfile.id })).accounts.find(item => item.name === '工作档案');
    await waitFor(() => evaluate(`document.querySelector(${JSON.stringify(accountSelect)})?.value === ${JSON.stringify(managedAccount.id)}`), 'newly created selection');
    await accountButton('管理档案'); await fillAccountName('修改档案名称', '团队档案'); await accountButton('保存名称');
    await waitFor(() => evaluate(`document.querySelector(${JSON.stringify(accountSelect)})?.selectedOptions[0]?.textContent === '团队档案' && !document.querySelector('.terminal-account-editor')`), 'saved renamed account selection');
    assert.equal((await call('listClaudeAccounts', { id: accountProfile.id })).accounts.find(item => item.id === managedAccount.id).name, '团队档案');
    const unconfirmed = await evaluate(`window.envara.call('deleteClaudeAccount', {id:${JSON.stringify(accountProfile.id)}, accountId:${JSON.stringify(managedAccount.id)}}).then(() => false, () => true)`);
    assert.equal(unconfirmed, true, 'The actual IPC cannot delete an unconfirmed account');
    await accountButton('管理档案'); await accountButton('删除档案');
    await waitFor(() => evaluate("document.querySelector('.terminal-account-editor strong')?.textContent === '删除「团队档案」？'"), 'named deletion confirmation');
    await capture('claude-account-delete-confirmation-zh.png', window, '终端');
    for (const language of languages) {
      await call('saveSettings', { settings: { language } });
      await waitFor(() => evaluate(`document.documentElement.lang === ${JSON.stringify(language)}`), `Claude account confirmation ${language}`);
      await waitFor(() => evaluate(`Array.from(document.querySelectorAll('.terminal-account-editor button')).some(button => button.textContent.trim() === ${JSON.stringify(translate('确认删除档案', language))})`), `translated Claude deletion action ${language}`);
      assert.equal(await evaluate("document.querySelector('.terminal-account-editor').scrollWidth <= document.querySelector('.terminal-account-editor').clientWidth + 1"), true, `Claude account confirmation overflow in ${language}`);
      await capture(`claude-account-${language}.png`, window, translate('终端', language));
    }
    await call('saveSettings', { settings: { language: 'zh-CN' } });
    await waitFor(() => evaluate("document.documentElement.lang === 'zh-CN'"), 'Chinese account confirmation');
    await accountButton('取消');
    assert.equal((await call('listClaudeAccounts', { id: accountProfile.id })).accounts.some(item => item.id === managedAccount.id), true);
    await accountButton('删除档案'); await accountButton('确认删除档案');
    await waitFor(() => evaluate(`document.querySelector(${JSON.stringify(accountSelect)})?.value === 'default' && !document.querySelector('.terminal-account-editor')`), 'selected deletion falls back to the remaining default');
    assert.deepEqual((await call('listClaudeAccounts', { id: accountProfile.id })).accounts.map(item => item.id), ['default']);
    await accountButton('管理档案');
    assert.equal(await evaluate("document.querySelector('.terminal-account-editor .terminal-account-delete').disabled"), true);
    await fillAccountName('修改档案名称', '主档案'); await accountButton('保存名称');
    await waitFor(() => evaluate(`document.querySelector(${JSON.stringify(accountSelect)})?.selectedOptions[0]?.textContent === '主档案' && !document.querySelector('.terminal-account-editor')`), 'renamed default label');
    await evaluate("document.querySelector('.terminal-new-session-head button').click()");
    await waitFor(() => evaluate("!document.querySelector('.terminal-new-session')"), 'closed account chooser');
    assert.equal((await call('terminalSnapshot', { id: accountProfile.id })).profiles[0]?.sessions.length ?? 0, 0, 'Account management never invokes Claude');
    await call('deleteProfile', { id: accountProfile.id }); await call('deleteProxy', { id: accountProxy.id });
    await evaluate(`document.getElementById(${JSON.stringify(`terminal-env-${profile.id}`)}).click()`);
    await waitFor(() => evaluate("document.querySelectorAll('.terminal-session-tab').length === 2"), 'original PTYs retained after account management');
    result.checks.push('Claude account creation, rename, named delete confirmation/cancellation and default rename use production UI/IPC; unconfirmed deletion is rejected, the default is retained, and no Claude process or login is started');
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
  } catch (error) {
    result.error = error.stack ?? error.message;
    try { result.rendererFailure = await evaluate("({language: document.documentElement.lang, navigation: Array.from(document.querySelectorAll('.navigation .nav-item')).map(item => item.textContent.trim()), heading: document.querySelector('.page-header h1')?.textContent, dialog: document.querySelector('[role=dialog]')?.textContent?.slice(0, 3000)})"); } catch {}
    console.error(result.error);
  }
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
