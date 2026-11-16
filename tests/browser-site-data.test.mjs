import test from 'node:test';
import assert from 'node:assert/strict';
import { BrowserSiteData } from '../electron/browser-site-data.mjs';

const instanceId = 'a'.repeat(32);
const cookie = { name: 'login', domain: '.example.test', path: '/', expires: -1, httpOnly: true, secure: true, sameSite: 'Lax', partitionState: 'unpartitioned', value: 'secret' };
function fixture() {
  const calls = [], session = { session_id: 'sess_fixture', instance_id: instanceId, profile_id: 'fixture', runtime_id: 'cloakbrowser' };
  const data = { instanceId, runtime: 'cloakbrowser', canClear: true, checkedAt: new Date().toISOString(), cookies: [cookie] };
  const service = { remote: async () => ({ profiles: [{ id: 'fixture' }], sessions: [session] }), request: async (...args) => {
    calls.push(args); return { data: args[1].endsWith('/clear') ? { instanceId, domain: args[2].domain, removed: 1 } : data };
  } };
  return { api: new BrowserSiteData({ getService: () => service }), calls, service, session, data };
}
test('site cookie inventory projects metadata only and reads the selected running session', async () => {
  const { api, calls } = fixture(); const output = await api.list({ profileId: 'fixture' });
  assert.equal(output.cookies[0].domain, '.example.test'); assert.equal(JSON.stringify(output).includes('secret'), false); assert.equal('value' in output.cookies[0], false);
  assert.deepEqual(calls, [['POST', '/api/sessions/sess_fixture/site-cookies', { instance_id: instanceId }]]);
});
test('cookie clear forwards exact domain and launch identity without broad fallback', async () => {
  const { api, calls } = fixture(); await api.clear({ profileId: 'fixture', instanceId, domain: '.example.test' });
  assert.deepEqual(calls, [['POST', '/api/sessions/sess_fixture/site-cookies/clear', { instance_id: instanceId, domain: '.example.test' }]]);
});
test('stopped, restarted and unsupported browsers never clear or launch', async () => {
  const { api, session, calls, service } = fixture();
  session.instance_id = 'b'.repeat(32);
  await assert.rejects(api.clear({ profileId: 'fixture', instanceId, domain: '.example.test' }), { code: 'SITE_DATA_STALE' });
  session.instance_id = instanceId; session.runtime_id = 'camoufox';
  await assert.rejects(api.clear({ profileId: 'fixture', instanceId, domain: '.example.test' }), { code: 'SITE_DATA_UNSUPPORTED' });
  service.remote = async () => ({ profiles: [{ id: 'fixture' }], sessions: [] });
  await assert.rejects(api.list({ profileId: 'fixture' }), { code: 'SITE_DATA_NOT_RUNNING' }); assert.equal(calls.length, 0);
});
test('request schema rejects extra fields, missing domain and traversal', async () => {
  const { api, calls } = fixture();
  for (const input of [{ profileId: '../fixture' }, { profileId: 'fixture', path: '/private' }, null]) await assert.rejects(api.list(input), { code: 'SITE_DATA_INVALID' });
  for (const domain of ['', 'example.test/path', 'example.test\n', null]) await assert.rejects(api.clear({ profileId: 'fixture', instanceId, domain }), { code: 'SITE_DATA_INVALID' });
  assert.equal(calls.length, 0);
});
test('invalid and stale backend inventories fail closed', async () => {
  for (const mutate of [data => { data.instanceId = 'b'.repeat(32); }, data => { data.cookies = null; }, data => { data.cookies = [{...cookie, domain: 'x/'}]; }, data => { data.cookies = Array(10001).fill(cookie); }]) {
    const { api, data } = fixture(); mutate(data); await assert.rejects(api.list({ profileId: 'fixture' }), { code: 'SITE_DATA_UNAVAILABLE' });
  }
});
