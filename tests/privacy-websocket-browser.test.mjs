import test from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright-core';
import { applyBrowserPrivacy, privacyLaunchArgs, snapshotPrivacy } from '../electron/privacy-policy.mjs';
import { createPrivacyWebSocketFixture } from './fixtures/privacy-websocket.mjs';

// Set a local disposable Chromium kernel. Nothing is downloaded or persisted.
test('real page and popup WS/WSS enforce tiers and first party without contacting blocked upstreams', { skip: !process.env.ENVARA_PRIVACY_TEST_BROWSER, timeout: 60000 }, async t => {
  const fixture = await createPrivacyWebSocketFixture(); let browser;
  t.after(async () => { await browser?.close(); await fixture.close(); });
  try {
    browser = await chromium.launch({ executablePath: process.env.ENVARA_PRIVACY_TEST_BROWSER, headless: true,
      args: [...privacyLaunchArgs('standard'), '--disable-background-networking'], proxy: { server: fixture.proxy, bypass: '<-loopback>' },
      env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', HOME: fixture.root, ...(process.platform === 'win32' ? { SystemRoot: process.env.SystemRoot ?? 'C:\\Windows' } : {}) } });
    for (const mode of ['standard', 'strict', 'off']) {
      const context = await browser.newContext({ ignoreHTTPSErrors: true, serviceWorkers: mode === 'off' ? 'allow' : 'block' });
      const websocketRouting = process.env.ENVARA_PRIVACY_TEST_WEBSOCKET_ROUTING || 'playwright';
      const state = await applyBrowserPrivacy(context, { websocketRouting, privacy: mode, geolocation: { latitude: 0, longitude: 0, accuracy: 50000 } });
      const page = await context.newPage();
      const cases = [['api.segment.io', 'example.test', mode !== 'off'], ['api.segment.io', 'app.segment.com', false], ['api.mixpanel.com', 'example.test', mode === 'strict'], ['chat.example.test', 'example.test', false]];
      for (const scheme of ['ws', 'wss']) {
        for (const [host, first, blocked] of cases) {
          const name = `${mode}-${scheme}-${host}-${first}`, target = fixture.socketURL(scheme, host, name);
          await page.goto(`http://${first}/?socket=${encodeURIComponent(target)}`);
          assert.equal(await page.waitForFunction(() => document.documentElement.dataset.wsResult).then(handle => handle.jsonValue()), blocked ? (websocketRouting.startsWith('constructor') ? 'SecurityError' : 'closed') : 'hello', name);
          assert.equal(fixture.received.some(row => row.path === `/${name}`), !blocked, `upstream ${name}`);
        }
        const name = `${mode}-${scheme}-popup`, target = fixture.socketURL(scheme, 'api.segment.io', name);
        const popupPromise = context.waitForEvent('page');
        await page.evaluate(url => window.open(url), `http://example.test/?socket=${encodeURIComponent(target)}`);
        const popup = await popupPromise; await popup.waitForLoadState();
        assert.equal(await popup.waitForFunction(() => document.documentElement.dataset.wsResult).then(handle => handle.jsonValue()), mode === 'off' ? 'hello' : (websocketRouting.startsWith('constructor') ? 'SecurityError' : 'closed'), name);
        assert.equal(fixture.received.some(row => row.path === `/${name}`), mode === 'off');
        await popup.close();
      }
      // A cross-origin embedded tracker cannot use its own origin as a
      // first-party exemption. Same-origin frames follow the same top policy.
      for (const frameHost of ['example.test', 'chat.example.test']) {
        await page.goto('http://example.test/');
        const name = `${mode}-frame-${frameHost}`, target = fixture.socketURL('wss', 'api.segment.io', name);
        await page.evaluate(url => { const frame = document.createElement('iframe'); frame.src = url; document.body.append(frame); }, `http://${frameHost}/?socket=${encodeURIComponent(target)}`);
        const frame = await new Promise((resolve, reject) => {
          const timer = setTimeout(() => { page.off('framenavigated', listener); reject(Error('Fixture frame did not navigate')); }, 5000);
          const find = () => page.frames().find(value => value.url().includes(`socket=${encodeURIComponent(target)}`));
          const existing = find(); if (existing) { clearTimeout(timer); resolve(existing); return; }
          const listener = value => { if (value.url().includes(`socket=${encodeURIComponent(target)}`)) { page.off('framenavigated', listener); clearTimeout(timer); resolve(value); } };
          page.on('framenavigated', listener);
        });
        await frame.waitForLoadState();
        assert.equal(await frame.waitForFunction(() => document.documentElement.dataset.wsResult).then(handle => handle.jsonValue()), mode === 'off' ? 'hello' : (websocketRouting.startsWith('constructor') ? 'SecurityError' : 'closed'), name);
        assert.equal(fixture.received.some(row => row.path === `/${name}`), mode === 'off');
      }
      await page.goto('http://example.test/');
      const native = await page.evaluate(target => new Promise(resolve => {
        const socket = new WebSocket(target, ['fixture-echo']); socket.binaryType = 'arraybuffer';
        const result = { instance: socket instanceof WebSocket, prototype: Object.getPrototypeOf(socket) === WebSocket.prototype, constructor: socket.constructor === WebSocket,
          constants: [WebSocket.CONNECTING, WebSocket.OPEN, WebSocket.CLOSING, WebSocket.CLOSED], binaryType: socket.binaryType, events: [] };
        socket.addEventListener('open', () => { result.events.push('open'); result.protocol = socket.protocol; socket.send('ping'); });
        socket.addEventListener('message', event => { result.events.push(event.data); if (event.data === 'ping') socket.close(1000, 'done'); });
        socket.addEventListener('close', event => { result.events.push('close'); result.code = event.code; resolve(result); });
        socket.addEventListener('error', () => resolve({ error: true }));
        setTimeout(() => resolve({ timeout: true }), 3000);
      }), fixture.socketURL('wss', 'chat.example.test', `${mode}-native`));
      assert.deepEqual(native, { instance: true, prototype: true, constructor: true, constants: [0, 1, 2, 3], binaryType: 'arraybuffer', events: ['open', 'hello', 'ping', 'close'], protocol: 'fixture-echo', code: 1000 });
      assert.equal(snapshotPrivacy(state).blockedWebSockets, websocketRouting.startsWith('constructor') && mode !== 'off' ? null : mode === 'strict' ? 8 : mode === 'standard' ? 6 : 0);
      await context.close();
    }
  } finally { await browser?.close(); await fixture.close(); }
});
