import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { chmod, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
import { NativeApplicationRouting, APPLICATION_ROUTING_CHECKS, applicationRoutingReady, publicApplicationRoutingStatus } from '../electron/application-routing.mjs';

async function helper(t, script, options = {}) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-routing-rpc-')));
  const filename = path.join(root, 'helper');
  await writeFile(filename, `#!${process.execPath}\n${script}\n`); await chmod(filename, 0o700);
  const adapter = new NativeApplicationRouting({ helperPath: filename, timeoutMs: 5000, ...options });
  t.after(async () => { await adapter.shutdown(); await rm(root, { recursive: true, force: true }); }); return adapter;
}
test('readiness requires complete capabilities and a versioned successful real verification record', () => {
  const capabilities = Object.fromEntries(APPLICATION_ROUTING_CHECKS.map(key => [key, true]));
  const good = { installed: true, authorized: true, ready: true, capabilities, verification: { passed: true, version: 'fixture/1', checks: capabilities } };
  assert.equal(applicationRoutingReady(good), true); assert.equal(applicationRoutingReady({ ...good, verification: null }), false);
  for (const key of APPLICATION_ROUTING_CHECKS) assert.equal(applicationRoutingReady({ ...good, verification: { ...good.verification, checks: { ...capabilities, [key]: false } } }), false);
  assert.equal(publicApplicationRoutingStatus({ ...good, password: 'private', extra: 'secret' }).password, undefined);
});
test('helper RPC carries credentials only in private stdin; argv and helper env contain no host secrets', async t => {
  const adapter = await helper(t, `let raw='';process.stdin.on('data',c=>raw+=c);process.stdin.on('end',()=>{const r=JSON.parse(raw);process.stdout.write(JSON.stringify({protocol:r.protocol,version:r.version,id:r.id,result:{method:r.method,received:r.params.route.password,argv:process.argv.slice(2),env:Object.keys(process.env)}}));});`);
  const result = await adapter.prepareRoute({ route: { password: 'fixture-runtime-secret' } });
  assert.equal(result.received, 'fixture-runtime-secret'); assert.deepEqual(result.argv, ['--rpc']);
  assert.equal(result.env.includes('ANTHROPIC_API_KEY'), false); assert.equal(result.env.includes('HTTP_PROXY'), false);
});
test('missing helper reports unavailable and native launch never falls back to direct spawning', async () => {
  const adapter = new NativeApplicationRouting(); const state = await adapter.status(); assert.equal(state.installed, false);
  await assert.rejects(adapter.launch({ routeId: 'route_a' }), { code: 'APPLICATION_ROUTING_UNAVAILABLE' }); await adapter.shutdown();
});
test('malformed responses, mismatched IDs and oversized output are rejected', async t => {
  const cases = ['process.stdout.write("not JSON");', 'process.stdout.write(JSON.stringify({protocol:"envara.application-routing",version:1,id:"wrong",result:{}}));', 'process.stdout.write("x".repeat(4096));'];
  for (const script of cases) { const adapter = await helper(t, script, { maxBytes: 512 }); await assert.rejects(adapter.request('status'), { code: 'APPLICATION_ROUTING_PROTOCOL_ERROR' }); }
});
test('helper timeout and native errors return credential-free public failures', async t => {
  const timeout = await helper(t, 'setTimeout(()=>{},60000)', { timeoutMs: 40 });
  await assert.rejects(timeout.request('status'), { code: 'APPLICATION_ROUTING_TIMEOUT' });
  const secretError = await helper(t, `let raw='';process.stdin.on('data',c=>raw+=c);process.stdin.on('end',()=>{const r=JSON.parse(raw);process.stdout.write(JSON.stringify({protocol:r.protocol,version:r.version,id:r.id,error:{code:'APPLICATION_ROUTING_NOT_READY',message:'fixture-runtime-secret'}}));});`);
  await assert.rejects(secretError.launch({}), error => error.code === 'APPLICATION_ROUTING_NOT_READY' && !error.message.includes('fixture-runtime-secret'));
});
