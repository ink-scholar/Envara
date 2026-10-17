import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { createPrivacyWebSocketFixture } from './fixtures/privacy-websocket.mjs';

test('production Go launchers enforce WS/WSS without blocked upstream connections', { skip: !process.env.ENVARA_PRIVACY_GO_TEST_BROWSER, timeout: 150000 }, async t => {
  const fixture = await createPrivacyWebSocketFixture(); t.after(fixture.close);
  const engine = process.env.ENVARA_PRIVACY_GO_TEST_ENGINE;
  const fixtureConfig = { proxy: fixture.proxy, ws: fixture.socketURL('ws', 'HOST', '').replace(/\/$/, ''), wss: fixture.socketURL('wss', 'HOST', '').replace(/\/$/, '') };
  const env = { ...process.env, ENVARA_PRIVACY_WS_FIXTURE: JSON.stringify(fixtureConfig),
    ENVARA_PRIVACY_GO_DRIVER: process.env.ENVARA_PRIVACY_GO_DRIVER || fileURLToPath(new URL('../build/backend/playwright-driver', import.meta.url)) };
  const result = await promisify(execFile)('go', ['test', './internal/browser', '-run', '^TestPrivacyWebSocketLive$', '-count=1', '-v', '-timeout', '120s'], { cwd: fileURLToPath(new URL('../third_party/browseforge', import.meta.url)), env, timeout: 140000, maxBuffer: 2 * 1024 * 1024 });
  t.diagnostic(result.stdout.trim());
  for (const mode of ['standard', 'strict', 'off']) for (const scheme of ['ws', 'wss']) {
    for (const [host, first, allowed] of [['api.segment.io', 'example.test', mode === 'off'], ['api.segment.io', 'app.segment.com', true], ['api.mixpanel.com', 'example.test', mode !== 'strict'], ['chat.example.test', 'example.test', true]]) {
      const path = `/go-${engine}-${mode}-${scheme}-${host}-${first}`;
      assert.equal(fixture.received.some(row => row.path === path), allowed, path);
    }
    for (const frameHost of ['example.test', 'chat.example.test']) assert.equal(fixture.received.some(row => row.path === `/go-${engine}-${mode}-${scheme}-frame-${frameHost}`), mode === 'off');
    assert.ok(fixture.received.some(row => row.path === `/go-${engine}-${mode}-${scheme}-native`));
    assert.ok(fixture.received.some(row => row.path === `/go-${engine}-${mode}-${scheme}-popup-first`));
    const baseRows = fixture.received.filter(row => row.path === `/go-${engine}-${mode}-${scheme}-base`);
    assert.equal(baseRows.length, engine === 'camoufox' || mode === 'off' ? 1 : 0);
    if (baseRows.length) {
      assert.equal(baseRows[0].host, engine === 'camoufox' ? 'example.test' : 'api.segment.io');
      assert.equal(baseRows[0].secure, engine !== 'camoufox' && scheme === 'wss');
    }
  }
});
