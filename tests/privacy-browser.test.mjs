import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { mkdtemp, rm } from 'node:fs/promises';
import { chromium } from 'playwright-core';
import { applyBrowserPrivacy, privacyLaunchArgs, snapshotPrivacy } from '../electron/privacy-policy.mjs';

// Set an existing local Chromium executable. This test never downloads a kernel
// or treats Chromium verification as a Cloak/Camoufox acceptance pass.
test('real Chromium blocks a tracker, preserves normal requests, applies coarse geo and denies host location across new tabs', { skip: !process.env.ENVARA_PRIVACY_TEST_BROWSER }, async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'envara-real-privacy-test-'));
  const server = http.createServer((_request, response) => { response.writeHead(200, { 'content-type': 'text/html' }); response.end('<!doctype html><title>Envara local privacy check</title>'); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${server.address().port}/`; let browser;
  try {
    browser = await chromium.launch({ executablePath: process.env.ENVARA_PRIVACY_TEST_BROWSER, headless: true, args: privacyLaunchArgs('standard'),
      env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', HOME: root, ...(process.platform === 'win32' ? { SystemRoot: process.env.SystemRoot ?? 'C:\\Windows' } : {}) } });
    const context = await browser.newContext({ serviceWorkers: 'block' });
    const expected = { latitude: 14.6, longitude: 121, accuracy: 50000 };
    const state = await applyBrowserPrivacy(context, { privacy: { mode: 'standard' }, geolocation: expected });
    const page = await context.newPage(); await page.goto(url);
    const actual = await page.evaluate(() => new Promise(resolve => navigator.geolocation.getCurrentPosition(p => resolve({ latitude: p.coords.latitude, longitude: p.coords.longitude, accuracy: p.coords.accuracy }), e => resolve({ error: e.code }), { timeout: 1500 })));
    assert.deepEqual(actual, expected);
    assert.equal(await page.evaluate(async () => { try { await fetch('https://www.google-analytics.com/g/collect'); return 'allowed'; } catch { return 'blocked'; } }), 'blocked');
    assert.equal(snapshotPrivacy(state).blockedRequests, 1);
    assert.equal(await page.evaluate(async () => (await fetch('/normal?keyword=google-analytics.com')).status), 200);
    await context.close();
    for (const mode of ['standard', 'off']) {
      const own = await browser.newContext({ serviceWorkers: mode === 'off' ? 'allow' : 'block' });
      await applyBrowserPrivacy(own, { privacy: { mode }, geolocation: null });
      for (let tab = 0; tab < 2; tab++) {
        const pg = await own.newPage(); await pg.goto(url);
        const result = await pg.evaluate(async () => ({ permission: (await navigator.permissions.query({ name: 'geolocation' })).state,
          position: await new Promise(resolve => navigator.geolocation.getCurrentPosition(() => resolve({ unexpectedPosition: true }), e => resolve({ error: e.code }), { timeout: 1500 })) }));
        assert.equal(result.permission, 'denied'); assert.deepEqual(result.position, { error: 1 });
      }
      await own.close();
    }
  } finally { await browser?.close(); await new Promise(resolve => server.close(resolve)); await rm(root, { recursive: true, force: true }); }
});

test('real Chromium permits top-level tracker-site navigation through a loopback-only fixture proxy while fetch remains blocked', { skip: !process.env.ENVARA_PRIVACY_TEST_BROWSER }, async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'envara-privacy-navigation-'));
  const served = [], sockets = new Set(); let browser;
  // This proxy returns fixture responses itself. It has no forwarding path and
  // rejects HTTPS CONNECT, so tracker hostnames never reach a public server.
  const proxy = http.createServer((request, response) => {
    let target;
    try { target = new URL(request.url); } catch { response.writeHead(400); response.end(); return; }
    if (target.protocol !== 'http:' || !['example.test', 'api.segment.io'].includes(target.hostname)) { response.writeHead(403); response.end(); return; }
    served.push(target.href);
    response.writeHead(200, { 'content-type': 'text/html', 'access-control-allow-origin': '*' });
    response.end('<!doctype html><title>Envara navigation fixture</title>');
  });
  proxy.on('connect', (_request, socket) => socket.destroy());
  proxy.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  await new Promise(resolve => proxy.listen(0, '127.0.0.1', resolve));
  try {
    browser = await chromium.launch({ executablePath: process.env.ENVARA_PRIVACY_TEST_BROWSER, headless: true,
      args: [...privacyLaunchArgs('standard'), '--disable-background-networking'], proxy: { server: `http://127.0.0.1:${proxy.address().port}`, bypass: '<-loopback>' },
      env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', HOME: root, ...(process.platform === 'win32' ? { SystemRoot: process.env.SystemRoot ?? 'C:\\Windows' } : {}) } });
    const context = await browser.newContext({ serviceWorkers: 'block' });
    const state = await applyBrowserPrivacy(context, { privacy: { mode: 'standard' }, geolocation: { latitude: 0, longitude: 0, accuracy: 50000 } });
    const page = await context.newPage();
    await page.goto('http://example.test/start');
    const fetchTracker = () => page.evaluate(async () => { try { await fetch('http://api.segment.io/third-party-fetch'); return 'allowed'; } catch { return 'blocked'; } });
    assert.equal(await fetchTracker(), 'blocked');
    assert.equal(snapshotPrivacy(state).blockedRequests, 1);
    const response = await page.goto('http://api.segment.io/own-page');
    assert.equal(response.status(), 200); assert.equal(page.url(), 'http://api.segment.io/own-page');
    assert.equal(served.includes('http://api.segment.io/own-page'), true);
    assert.equal(snapshotPrivacy(state).blockedRequests, 1);
    await page.goto('http://example.test/back');
    assert.equal(await fetchTracker(), 'blocked');
    assert.equal(snapshotPrivacy(state).blockedRequests, 2);
    assert.equal(served.some(url => url.includes('third-party-fetch')), false);
  } finally {
    await browser?.close();
    for (const socket of sockets) socket.destroy();
    await new Promise(resolve => proxy.close(resolve));
    await rm(root, { recursive: true, force: true });
  }
});
