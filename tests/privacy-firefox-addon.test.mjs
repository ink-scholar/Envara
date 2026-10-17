import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { runInNewContext } from 'node:vm';

const source = await readFile(new URL('../third_party/browseforge/internal/browser/privacy_firefox_addon.go', import.meta.url), 'utf8');
const background = /const firefoxWebSocketBackground = `([\s\S]*?)`/.exec(source)[1];
const readiness = /const firefoxWebSocketReadiness = `([\s\S]*?)`/.exec(source)[1];

test('Firefox native socket policy keeps top-party exemptions, tiers and the loopback fence', () => {
  for (const mode of ['standard', 'strict', 'off']) {
    let onRequest;
    const policy = { mode, domains: ['api.segment.io', ...(mode === 'strict' ? ['api.mixpanel.com'] : [])], serviceRoots: { 'api.segment.io': ['segment.com', 'segment.io'] }, readinessURL: 'file:///owned/readiness.html' };
    runInNewContext(background, { URL, policy, browser: { webRequest: { onBeforeRequest: { addListener(callback, filter) { onRequest = callback; assert.deepEqual([...filter.types], ['websocket']); } } }, runtime: { onMessage: { addListener() {} } } } });
    const blocked = (url, documentUrl = 'https://example.test/', frameAncestors, frameId = 0) => onRequest({ url, documentUrl, frameAncestors, frameId }).cancel;
    assert.equal(blocked('wss://api.segment.io/live'), mode !== 'off');
    assert.equal(blocked('wss://api.mixpanel.com/live'), mode === 'strict');
    assert.equal(blocked('wss://api.segment.io/live', 'https://app.segment.com/'), false);
    assert.equal(blocked('wss://api.segment.io/live', 'https://api.segment.io/', [{ frameId: 0, url: 'https://example.test/' }], 3), mode !== 'off');
    assert.equal(blocked('wss://api.segment.io/live', 'https://api.segment.io/', [], 3), mode !== 'off');
    assert.equal(blocked('wss://chat.example.test/live'), false);
    for (const host of ['localhost', '127.0.0.1', '127.1', '[::1]', '[::ffff:127.0.0.1]']) assert.equal(blocked(`ws://${host}/live`), true, host);
    for (const host of ['localhost.example.test', '127.example.test', '[::2]']) assert.equal(blocked(`ws://${host}/live`), false, host);
    assert.equal(blocked('ws://127.0.0.1/live', 'http://localhost/'), false);
    assert.equal(blocked('not a url'), true);
  }
});

test('Firefox startup marker requires the registered background and exact owned document', async () => {
  const readyURL = 'file:///owned/readiness.html';
  let onMessage, registered = false;
  runInNewContext(background, { URL, policy: { readinessURL: readyURL }, browser: { webRequest: { onBeforeRequest: { addListener() { registered = true; } } }, runtime: { onMessage: { addListener(callback) { assert.equal(registered, true); onMessage = callback; } } } } });
  assert.equal(await onMessage('envara-websocket-privacy-ready', { url: readyURL }), true);
  for (const url of ['https://example.test/', 'file:///other/readiness.html', `${readyURL}?forged`]) assert.equal(onMessage('envara-websocket-privacy-ready', { url }), undefined);
  assert.equal(onMessage({ type: 'fetch', url: 'http://127.0.0.1/' }, { url: readyURL }), undefined);
  for (const reply of [true, false, undefined, 'true']) {
    const document = { documentElement: { dataset: {} } };
    await runInNewContext(readiness, { document, browser: { runtime: { sendMessage: async () => reply } } });
    assert.equal(document.documentElement.dataset.envaraPrivacyReady, reply === true ? 'true' : undefined);
  }
  const document = { documentElement: { dataset: {} } };
  await runInNewContext(readiness, { document, browser: { runtime: { sendMessage: async () => { throw Error('no background'); } } } });
  assert.equal(document.documentElement.dataset.envaraPrivacyReady, undefined);
});
