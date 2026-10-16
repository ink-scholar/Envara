import test from 'node:test';
import assert from 'node:assert/strict';
import { initialProxyForm, proxyConfig, proxyFormError } from '../src/proxy-form-state.mjs';

test('AnyTLS form defaults to certificate verification and preserves exact authentication text', () => {
  const form = { ...initialProxyForm(), name: ' Tokyo ', protocol: 'anytls', host: ' node.example.test ', port: '443', password: ' literal password ', username: 'ordinary-user' };
  const config = proxyConfig(form);
  assert.deepEqual(config, { name: 'Tokyo', protocol: 'anytls', host: 'node.example.test', port: 443, password: ' literal password ', region: '', serverName: 'node.example.test', skipCertVerify: false, clientFingerprint: 'chrome', alpn: [], udp: true });
  assert.equal(proxyFormError(form), '');
  assert.equal(proxyFormError({ ...form, password: '' }), '请填写 AnyTLS 节点密码。');
});

test('Editing AnyTLS retains explicit SNI and TLS choice; changing to a normal proxy removes AnyTLS-only settings', () => {
  const form = initialProxyForm({ id: 'saved', name: 'Office', protocol: 'anytls', host: '192.0.2.8', port: 8443, password: 'test-only', serverName: ' cert.example.test ', skipCertVerify: true, alpn: ['h2', 'http/1.1'], udp: false, network: { ok: true, ip: '192.0.2.20' } });
  assert.equal(form.network, undefined);
  assert.equal(proxyConfig(form).serverName, 'cert.example.test');
  assert.equal(proxyConfig(form).skipCertVerify, true);
  assert.deepEqual(proxyConfig(form).alpn, ['h2', 'http/1.1']);
  assert.equal(proxyConfig(form).udp, false);
  const ordinary = proxyConfig({ ...form, protocol: 'socks5', username: 'operator' });
  assert.deepEqual(ordinary, { id: 'saved', name: 'Office', protocol: 'socks5', host: '192.0.2.8', port: 8443, password: 'test-only', region: '', username: 'operator' });
  assert.equal(proxyFormError({ ...form, port: 0 }), '请先填写服务器地址和有效端口。');
});

test('ALPN text becomes an ordered list and rejects values outside the runtime limits', () => {
  const form = { ...initialProxyForm(), protocol: 'anytls', host: 'node.example.test', port: 443, password: 'test-only', alpn: 'h2, http/1.1' };
  assert.deepEqual(proxyConfig(form).alpn, ['h2', 'http/1.1']);
  assert.equal(proxyFormError(form), '');
  assert.equal(proxyFormError({ ...form, alpn: Array.from({ length: 8 }, () => 'a'.repeat(64)) }), '');
  for (const alpn of [Array(9).fill('h2'), ['a'.repeat(65)], ['http 1'], ['非ASCII'], ['h2\n'], [true], true]) {
    assert.match(proxyFormError({ ...form, alpn }), /^ALPN 最多 8 项/);
  }
});

test('editing or renaming AnyTLS keeps every supported saved TLS client fingerprint', () => {
  for (const clientFingerprint of ['chrome', 'firefox', 'safari', 'ios', 'android', 'edge', 'random', 'randomized']) {
    const form = initialProxyForm({ id: 'saved', name: 'Original', protocol: 'anytls', host: 'node.example.test', port: 443, password: 'fixture-only', clientFingerprint });
    const result = proxyConfig({ ...form, name: 'Renamed' });
    assert.equal(result.name, 'Renamed');
    assert.equal(result.clientFingerprint, clientFingerprint);
    assert.equal(proxyFormError(form), '');
  }
});
