import assert from 'node:assert/strict';
import test from 'node:test';
import os from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { mkdtemp, readdir, rm } from 'node:fs/promises';
import { HTTP_PROXY_USERNAME_ERROR, HTTP_PROXY_USERNAME_ERROR_CODE } from '../shared/proxy-auth.mjs';
import { proxyFormError } from '../src/proxy-form-state.mjs';
import { managedProxySettings, proxyCoreConfig, ProxyCoreManager } from '../electron/proxy-core-manager.mjs';
import { createProxyAgent, proxyFingerprint, ProxyNetworkProbe } from '../electron/proxy-network.mjs';
import { BrowseForgeService } from '../electron/browseforge-service.mjs';
import { EnvaraService } from '../electron/service.mjs';

const proxy = { name: 'Fixture', protocol: 'http', host: 'proxy.example.test', port: 8080, username: 'fixture:private-user', password: 'private:password:with:colons' };
const local = { port: 40000, username: 'owned', password: 'local' };
const rejected = value => {
  assert.equal(value.code, HTTP_PROXY_USERNAME_ERROR_CODE);
  assert.equal(value.message, HTTP_PROXY_USERNAME_ERROR);
  for (const secret of [proxy.host, proxy.username, proxy.password]) assert.equal(value.message.includes(secret), false);
  return true;
};

for (const protocol of ['http', 'https']) test(`${protocol} rejects ambiguous Basic usernames before agent, probe or core startup`, async t => {
  const input = { ...proxy, protocol };
  assert.equal(proxyFormError(input), HTTP_PROXY_USERNAME_ERROR);
  assert.throws(() => managedProxySettings(input), rejected);
  assert.throws(() => proxyCoreConfig(input, local), rejected);
  assert.throws(() => createProxyAgent(input, 100), rejected);
  let transports = 0, starts = 0;
  const probe = new ProxyNetworkProbe({ transport: async () => { transports++; throw new Error('must not call'); } });
  t.after(() => probe.close());
  await assert.rejects(probe.probe(input), rejected);
  assert.equal(transports, 0);
  assert.match(proxyFingerprint(input), /^[a-f0-9]{64}$/);
  assert.equal(probe.peek(input), null);
  assert.doesNotThrow(() => probe.invalidate(input));
  const directory = await mkdtemp(path.join(os.tmpdir(), 'envara-auth-core-'));
  const manager = new ProxyCoreManager({ dataDir: directory, resourcesDir: directory, spawn: () => { starts++; throw new Error('must not spawn'); } });
  t.after(async () => { await manager.close(); await rm(directory, { recursive: true, force: true }); });
  await assert.rejects(manager.ensure(input), rejected);
  assert.equal(starts, 0); assert.deepEqual(await readdir(directory), []);
  assert.equal(manager.routingIdentity(input), null);
  await manager.release(input); // Legacy invalid values must not prevent cleanup.
});

test('password colons keep exact Basic bytes and other protocols retain their rules', () => {
  for (const protocol of ['http', 'https']) {
    const input = { ...proxy, protocol, username: 'valid-user' };
    assert.equal(proxyFormError(input), '');
    const settings = managedProxySettings(input);
    const config = proxyCoreConfig(settings, local);
    const expected = `Basic ${Buffer.from(`${input.username}:${input.password}`).toString('base64')}`;
    assert.equal(config.proxies[0].headers['Proxy-Authorization'], expected);
    const agent = createProxyAgent(input, 100);
    assert.equal(agent.proxyHeaders()['Proxy-Authorization'], expected);
    agent.destroy();
  }
  const socks = { ...proxy, protocol: 'socks5' };
  assert.equal(proxyFormError(socks), '');
  assert.equal(managedProxySettings(socks).username, proxy.username);
  const agent = createProxyAgent(socks, 100); agent.destroy();
  const anytls = { protocol: 'anytls', host: proxy.host, port: 443, password: proxy.password };
  assert.equal(managedProxySettings(anytls).password, proxy.password);
  assert.equal(proxyFormError(anytls), '');
});

async function serviceFixture(t, kind) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'envara-auth-service-'));
  let transports = 0;
  const networkProbe = new ProxyNetworkProbe({ transport: async () => { transports++; throw new Error('must not connect'); } });
  const client = { request: async (method, route) => {
    if (method === 'GET' && ['/api/profiles', '/api/sessions', '/api/runtimes', '/api/groups'].includes(route)) return { data: [] };
    if (method === 'POST' && route === '/api/shutdown') return { data: 'closed' };
    throw new Error('unexpected backend operation');
  } };
  const runtime = { closeAll: async () => {} };
  const service = kind === 'browseforge'
    ? new BrowseForgeService(directory, client, {}, () => {}, { networkProbe })
    : new EnvaraService(directory, runtime, {}, () => {}, { networkProbe });
  await service.ready;
  t.after(async () => { await service.shutdown(); await rm(directory, { recursive: true, force: true }); });
  return { service, transports: () => transports };
}

for (const kind of ['browseforge', 'legacy']) test(`${kind} rejects new ambiguous credentials but preserves old values for repair and deletion`, async t => {
  const { service, transports } = await serviceFixture(t, kind);
  const before = await service.store.read();
  for (const protocol of ['http', 'https']) {
    await assert.rejects(service.call('saveProxy', { proxy: { ...proxy, protocol } }), rejected);
    await assert.rejects(service.call('previewProxyNetwork', { proxy: { ...proxy, protocol } }), rejected);
  }
  assert.deepEqual(await service.store.read(), before);
  assert.equal(transports(), 0);
  const old = { ...proxy, id: randomUUID() };
  await service.store.transaction(workspace => { workspace.proxies.push(old); });
  if (kind === 'legacy') await service.validateWorkspace();
  assert.equal((await service.snapshot()).proxies[0].username, old.username);
  await assert.rejects(service.call('checkProxy', { id: old.id }), rejected);
  if (kind === 'browseforge') {
    await assert.rejects(service.prepareProxy(old, { requireManagedRoute: true }), rejected);
    await service.releaseProxy(old);
  }
  const repaired = { ...old, username: 'corrected-user' };
  await service.call('saveProxy', { proxy: repaired });
  assert.equal((await service.store.read()).proxies[0].password, old.password);
  await service.store.transaction(workspace => { workspace.proxies[0].username = old.username; });
  await service.call('deleteProxy', { id: old.id });
  assert.deepEqual((await service.store.read()).proxies, []);
  assert.equal(transports(), 0);
});
