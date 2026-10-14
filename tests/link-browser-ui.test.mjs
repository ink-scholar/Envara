import test from 'node:test';
import assert from 'node:assert/strict';
import { SYSTEM_BROWSER, linkBrowsersFor, linkBrowserChoice, terminalNetworks } from '../src/link-browser.mjs';

const profiles = [
  { id: 'prof_test', name: '测试境舱', group: '菲律宾', proxyId: 'node_ph', networkName: '菲律宾 02 家宽', networkEgress: { ip: '203.0.113.55', country: 'Philippines', timezone: 'Asia/Manila' } },
  { id: 'prof_b', name: 'B 境舱', group: '菲律宾', proxyId: 'node_ph', networkName: '菲律宾 02 家宽' },
  { id: 'prof_us', name: '美国', group: '美国', proxyId: 'node_us', networkName: '美国节点' },
  { id: 'prof_local', name: '本机', group: '', proxyId: null }];

test('the page offers an environment its own browser first, as the router uses it', () => {
  assert.deepEqual(linkBrowsersFor(profiles, profiles[0]).map(item => item.id), ['prof_test', 'prof_b']);
  assert.deepEqual(linkBrowsersFor(profiles, profiles[2]).map(item => item.id), ['prof_us'], 'alone on its network it still has its own');
  const candidates = linkBrowsersFor(profiles, profiles[0]);
  assert.equal(linkBrowserChoice(candidates, null), 'prof_test', 'unset means its own browser');
  assert.equal(linkBrowserChoice(candidates, 'prof_b'), 'prof_b');
  assert.equal(linkBrowserChoice(candidates, 'prof_us'), 'prof_test', 'a browser of another network is not used');
  assert.equal(linkBrowserChoice(candidates, SYSTEM_BROWSER), SYSTEM_BROWSER);
});

test('a terminal chooses among the networks environments use, with their browsers and measured egress', () => {
  const networks = terminalNetworks(profiles);
  assert.deepEqual(networks.map(item => item.id), ['node_ph', 'node_us', 'direct']);
  const ph = networks[0];
  assert.equal(ph.name, '菲律宾 02 家宽');
  assert.equal(ph.egress.ip, '203.0.113.55');
  assert.deepEqual(ph.profiles.map(item => item.id), ['prof_b', 'prof_test'].sort((a, b) => profiles.find(p => p.id === a).name.localeCompare(profiles.find(p => p.id === b).name)));
  assert.equal(networks[2].name, null, 'the local network has no node name; the page labels it');
});
