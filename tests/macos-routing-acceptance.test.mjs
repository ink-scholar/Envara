import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { execFileSync, spawnSync } from 'node:child_process';
import { randomUUID, createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { fingerprintProvider, productionIdentity } from '../native/macos-app-routing/provider-reuse.mjs';
import { NativeApplicationRouting } from '../electron/application-routing.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const output = path.join(root, 'build/acceptance-app-routing/macos');
const manifestPath = path.join(output, 'manifest.json');
const manifest = existsSync(manifestPath) ? JSON.parse(readFileSync(manifestPath, 'utf8')) : null;
const helper = manifest ? path.join(output, manifest.helper) : '';
const compiledUnsigned = process.platform === 'darwin' && manifest?.signed === false && manifest?.acceptanceOnly === true && existsSync(helper);

test('desktop RPC does not expose native acceptance methods', async () => {
  let spawns = 0;
  const adapter = new NativeApplicationRouting({ spawn: () => { spawns++; throw new Error('must not spawn'); } });
  for (const method of ['prepareFixture', 'launchFixture', 'setupProfiles', 'activateExtension']) {
    await assert.rejects(adapter.request(method, {}), { code: 'APPLICATION_ROUTING_PROTOCOL_ERROR' });
  }
  assert.equal(spawns, 0); await adapter.shutdown();
});

test('diagnostic builds reject production receipts before compiling or touching output', () => {
  const result = spawnSync(process.execPath, [path.join(root, 'scripts/build-macos-app-routing.mjs'), '--acceptance'], {
    encoding: 'utf8', timeout: 3000,
    env: { PATH: process.env.PATH, ENVARA_MAC_ACCEPTANCE_RECEIPT: '/nonexistent-owned-unit-fixture.plist' },
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /acceptance.*production acceptance receipt/i);
});

test('unsigned fixture tool reuses exact production provider and refuses activation and launch', { skip: !compiledUnsigned }, async () => {
  for (const key of ['hostIdentifier', 'providerIdentifier', 'applicationGroup']) assert.equal(manifest[key], productionIdentity[key]);
  assert.equal(manifest.runtimeNamespace, 'owned-fixture-acceptance');
  const provider = await fingerprintProvider(path.join(output, manifest.provider.bundle));
  assert.equal(provider.bundleSHA256, manifest.provider.bundleSHA256);
  assert.equal(provider.binarySHA256, manifest.provider.binarySHA256);
  const production = JSON.parse(readFileSync(path.join(root, 'build/app-routing/macos/manifest.json'), 'utf8'));
  assert.equal(provider.bundleSHA256, production.provider.bundleSHA256);
  assert.equal(provider.binarySHA256, production.provider.binarySHA256);
  assert.equal(manifest.productionReceiptAllowed, false);
  const secret = randomUUID();
  const call = (method, params = {}) => {
    const raw = execFileSync(helper, ['--acceptance-rpc'], {
      input: JSON.stringify({ protocol: 'envara.routing-acceptance', version: 1, id: 'fixture-gates', method, params }),
      encoding: 'utf8', timeout: 6000, env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin' },
    });
    assert.ok(!raw.includes(secret)); return JSON.parse(raw);
  };
  const state = call('status').result;
  assert.equal(state.ready, false); assert.equal(state.authorized, false);
  assert.equal(state.runtimeNamespace, 'owned-fixture-acceptance');
  assert.equal(state.acceptanceOnly, true); assert.equal(state.productionReceiptAllowed, false);
  for (const [method, params] of [
    ['setupProfiles', {}], ['activateExtension', { activate: true }],
    ['prepareFixture', { fixture: 'one', route: { password: secret } }],
    ['launchFixture', { routeId: randomUUID() }], ['stopFixture', { routeId: randomUUID() }],
    ['revokeFixture', { routeId: randomUUID() }],
  ]) { const result = call(method, params); assert.equal(result.result, undefined); assert.equal(result.error?.code, 'notReady'); }
  for (const [method, params] of [['prepareFixture', { application: { path: '/Applications/Notion.app' } }], ['launch', {}]]) {
    assert.equal(call(method, params).result, undefined);
  }
  const wrongEntry = spawnSync(helper, ['--rpc'], { encoding: 'utf8', timeout: 3000 });
  assert.equal(wrongEntry.status, 64);
  const host = path.dirname(path.dirname(helper));
  const fixtureManifest = JSON.parse(readFileSync(path.join(host, 'Resources/acceptance-fixtures.json'), 'utf8'));
  for (const [slot, entry] of Object.entries(fixtureManifest.fixtures)) {
    assert.equal(entry.identifier, `io.envara.routing.fixture.${slot}`);
    const bytes = readFileSync(path.join(host, 'Helpers', entry.bundle, 'Contents/MacOS/EnvaraRoutingAcceptanceFixture'));
    assert.equal(entry.sha256, createHash('sha256').update(bytes).digest('hex'));
  }
  assert.equal(existsSync(path.join(host, 'Resources/routing-acceptance.plist')), false);
});
