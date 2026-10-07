// Opt-in development test harness. Never reachable in packaged builds.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { setTimeout } from 'node:timers/promises';
import { EnvaraService } from './service.mjs';

export async function runSmoke({ app, window, service, runtime }) {
  const artifactDir = process.env.ENVARA_SMOKE_ARTIFACTS;
  const result = { platform: `${process.platform}-${process.arch}`, appVersion: app.getVersion(), checks: [], passed: false };
  const server = createServer((_req, res) => {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.end('<!doctype html><html><head><title>Envara isolation test</title></head><body><h1>Envara · Native browser</h1><p>Local verification fixture</p></body></html>');
  });
  let proxyRequests = 0;
  const proxyServer = createServer((req, res) => {
    if (req.headers['proxy-authorization'] !== `Basic ${Buffer.from('test-user:test-pass').toString('base64')}`) {
      res.writeHead(407, { 'Proxy-Authenticate': 'Basic realm="Envara test"' });
      res.end();
      return;
    }
    proxyRequests++;
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<!doctype html><title>Envara proxy verified</title><h1>Authenticated proxy route verified</h1>');
  });
  try {
    await mkdir(artifactDir, { recursive: true });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const url = `http://127.0.0.1:${server.address().port}/`;
    for (let attempt = 0; attempt < 50; attempt++) {
      const text = await window.webContents.executeJavaScript('document.body.innerText');
      if (text.includes('新建环境')) break;
      await setTimeout(100);
    }
    const initial = await window.webContents.executeJavaScript("window.envara.call('snapshot')");
    assert.equal(initial.profiles.length, 0);
    assert.equal(await window.webContents.executeJavaScript('window.envara.isDesktop'), true);
    result.checks.push('Production renderer loads in Electron with isolated native IPC bridge; first-run workspace empty');
    await runtime.install();
    assert.equal(runtime.isInstalled(), true);
    result.engine = runtime.snapshot();
    result.checks.push('Official fingerprint browser baseline is installed and executable');
    let state = await service.call('createProfile', { profile: { name: '本机验证 · 上海', seed: 348297, locale: 'zh-CN', timezone: 'Asia/Shanghai', startUrl: url, width: 1440, height: 900 } });
    const first = state.profiles.at(-1);
    state = await service.call('createProfile', { profile: { name: '隔离验证 · 纽约', seed: 987312, locale: 'en-US', timezone: 'America/New_York', startUrl: url, width: 1920, height: 1080 } });
    const second = state.profiles.at(-1);
    await service.call('startProfile', { id: first.id });
    await service.call('startProfile', { id: second.id });
    const firstContext = runtime.sessions.get(first.id).context;
    const secondContext = runtime.sessions.get(second.id).context;
    result.startupPages = [firstContext.pages().map(page => page.url()), secondContext.pages().map(page => page.url())];
    assert.equal(firstContext.pages().length, 1);
    assert.equal(secondContext.pages().length, 1);
    const firstPage = firstContext.pages()[0];
    const secondPage = secondContext.pages()[0];
    const info = page => page.evaluate(() => ({ userAgent: navigator.userAgent, language: navigator.language, languages: navigator.languages, intlLocale: Intl.DateTimeFormat().resolvedOptions().locale, timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, width: screen.width, height: screen.height, platform: navigator.platform, webdriver: navigator.webdriver }));
    result.fingerprints = [await info(firstPage), await info(secondPage)];
    assert.equal(result.fingerprints[0].timezone, 'Asia/Shanghai');
    assert.equal(result.fingerprints[1].timezone, 'America/New_York');
    assert.equal(result.fingerprints[0].language, 'zh-CN');
    assert.equal(result.fingerprints[1].language, 'en-US');
    assert.equal(result.fingerprints[0].intlLocale, 'zh-CN');
    assert.equal(result.fingerprints[1].intlLocale, 'en-US');
    assert.equal(result.fingerprints[0].width, 1440);
    assert.equal(result.fingerprints[1].width, 1920);
    result.checks.push('Two headed native sessions apply independent locale/timezone/screen fingerprint settings');
    await firstContext.addCookies([{ name: 'envara_isolation', value: 'first-only', url, expires: Math.floor(Date.now() / 1000) + 86400 }]);
    assert.equal((await secondContext.cookies(url)).some(cookie => cookie.name === 'envara_isolation'), false);
    await firstPage.evaluate(() => localStorage.setItem('envara-isolation', 'first-only'));
    assert.equal(await secondPage.evaluate(() => localStorage.getItem('envara-isolation')), null);
    result.checks.push('Cookies and localStorage are isolated between profiles');
    await service.call('focusProfile', { id: first.id });
    state = await service.call('snapshot');
    assert.equal(state.profiles.filter(p => p.status === 'running').length, 2);
    await service.call('stopProfile', { id: first.id });
    await service.call('startProfile', { id: first.id });
    const resumed = runtime.sessions.get(first.id).context;
    assert.equal((await resumed.cookies(url)).find(cookie => cookie.name === 'envara_isolation')?.value, 'first-only');
    assert.equal(await resumed.pages()[0].evaluate(() => localStorage.getItem('envara-isolation')), 'first-only');
    result.checks.push('Browser cookies and localStorage persist after stop/restart');
    await service.call('stopProfile', { id: first.id });
    await service.call('stopProfile', { id: second.id });
    await new Promise(resolve => proxyServer.listen(0, '127.0.0.1', resolve));
    state = await service.call('saveProxy', { proxy: { name: '本地认证代理验证', protocol: 'http', host: '127.0.0.1', port: proxyServer.address().port, username: 'test-user', password: 'test-pass' } });
    const proxy = state.proxies.at(-1);
    state = await service.call('updateProfile', { id: second.id, profile: { proxyId: proxy.id, startUrl: 'http://envara-test.invalid/' } });
    await service.call('startProfile', { id: second.id });
    assert.equal(await runtime.getSession(second.id).context.pages()[0].title(), 'Envara proxy verified');
    assert.ok(proxyRequests > 0);
    await service.call('stopProfile', { id: second.id });
    result.checks.push('Authenticated HTTP proxy routes a real browser request through the configured proxy');
    await service.call('cloneProfile', { id: first.id });
    state = await service.call('snapshot');
    assert.notEqual(state.profiles.at(-1).seed, first.seed);
    const exported = await service.call('exportProfiles');
    assert.equal(exported.schema, 'envara.profiles');
    const reread = new EnvaraService(service.system.dataDir, runtime, service.system);
    const persisted = await reread.snapshot();
    assert.equal(persisted.profiles.length, 3);
    result.checks.push('Clone changes fingerprint seed; export and workspace reload preserve configurations');
    await setTimeout(250);
    const screenshot = await window.webContents.capturePage();
    await writeFile(path.join(artifactDir, 'native-app.png'), screenshot.toPNG());
    assert.equal(await window.webContents.executeJavaScript("!!document.querySelector('.sidebar') || document.body.innerText.includes('境舱')"), true);
    result.passed = true;
  } catch (error) {
    result.error = error.stack || error.message;
    console.error(result.error);
    process.exitCode = 1;
  } finally {
    await writeFile(path.join(artifactDir, 'native-smoke.json'), JSON.stringify(result, null, 2));
    await service.shutdown();
    await runtime.closeAll();
    server.close();
    proxyServer.close();
    app.exit(result.passed ? 0 : 1);
  }
}
