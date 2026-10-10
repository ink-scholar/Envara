import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdtempSync, readFileSync, statSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import { pfTunnelCoreConfig } from './controller.mjs';

const directory = path.dirname(fileURLToPath(import.meta.url));
const executable = process.env.ENVARA_PF_NATIVE_TEST_BINARY
  ? path.resolve(process.env.ENVARA_PF_NATIVE_TEST_BINARY) : path.join(directory, 'build/envara-pf-native');
const run = (...args) => {
  const result = spawnSync(executable, args, { encoding: 'utf8', timeout: 10000 });
  if (result.error) throw result.error;
  return { code: result.status, report: JSON.parse(result.stdout) };
};
const status = run('status');
assert.equal(status.code, 0);
assert.equal(status.report.ready, false);
assert.equal(status.report.protected, false);
assert.ok(Object.values(status.report.gates).every(gate => gate === false));
const fixture = run('fixture');
assert.equal(fixture.code, 0);
assert.equal(fixture.report.protected, false);
assert.equal(fixture.report.activatesSystem, false);
assert.ok(Object.values(fixture.report.fixture).every(check => check === true));
assert.ok(fixture.report.unverified.includes('rootCredentialTransition'));
const identity = run('identity', '--pid', String(process.pid));
assert.equal(identity.code, 0);
assert.equal(identity.report.pid, process.pid);
assert.equal(identity.report.uid, process.getuid());
assert.equal(identity.report.gid, process.getgid());
assert.match(identity.report.birth, /^\d+:\d{6}$/);
const temporary = mkdtempSync(path.join(tmpdir(), 'envara-pf-native-fixture-'));
try {
  const configPath = path.join(temporary, 'fixture.json');
  const generated = run('transport-config-fixture', '--output', configPath);
  assert.equal(generated.code, 0);
  assert.equal(generated.report.activatesSystem, false);
  assert.equal(statSync(configPath).mode & 0o777, 0o600);
  const config = JSON.parse(readFileSync(configPath, 'utf8'));
  assert.equal(config.tun['file-descriptor'], 3);
  assert.equal(config.tun.mtu, 9000);
  assert.equal(config.tun['auto-route'], false);
  assert.equal(config.tun['auto-redirect'], false);
  assert.equal(config.tun['auto-detect-interface'], false);
  assert.equal(config.dns.enable, false);
  assert.equal(config['mixed-port'], 0);
  assert.equal(config.proxies[0].server, '127.0.0.1');
  assert.equal(config.proxies[0].username, 'fixture-user');
  const expected = pfTunnelCoreConfig({ proxy: { host: '127.0.0.1', port: 1080, username: 'fixture-user', password: 'fixture-password' }, ipv4Address: '198.18.1.1' });
  // The native guardian must name its allocated FD-backed device; all other
  // fixed security and routing fields equal the controller's strict contract.
  expected.tun.device = 'utun9999';
  assert.deepEqual(config, expected);
  // The 4096-byte controlled UDP fixture plus IPv4/UDP headers fits the owned
  // interface and gvisor MTU. This is not an arbitrary-fragmentation proof.
  assert.ok(config.tun.mtu > 4096 + 20 + 8);
  assert.deepEqual(config.rules, ['NETWORK,UDP,REJECT', 'MATCH,ENVARA_MANAGED_ROUTE']);
  const coreDirectory = path.resolve(directory, '../../build/proxy-core');
  const corePath = path.join(coreDirectory, 'mihomo');
  if (existsSync(corePath)) {
    const provenance = JSON.parse(readFileSync(path.join(coreDirectory, 'provenance.json'), 'utf8'));
    assert.equal(createHash('sha256').update(readFileSync(corePath)).digest('hex'), provenance.sha256.binary);
    // Fixed main.go:175 test branch parses configuration and exits before
    // executor applies it. No TUN socket, listener, PF, or route is started.
    const checked = spawnSync(corePath, ['-t', '-d', temporary, '-f', configPath], { encoding: 'utf8', timeout: 15000 });
    if (checked.error) throw checked.error;
    assert.equal(checked.status, 0, 'Bundled Mihomo rejected the private transport configuration');
  }
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
const cwd = '/tmp/境舱 "fixture"';
const plan = run('plan', '--uid', String(process.getuid()), '--gid', '7100', '--cwd', cwd, '--exec', '/usr/bin/true');
assert.equal(plan.code, 0);
assert.equal(plan.report.cwd, cwd);
assert.equal(plan.report.protected, false);
assert.equal(plan.report.activatesSystem, false);
for (const args of [
  ['plan', '--uid', '0', '--gid', '7100', '--cwd', '/tmp', '--exec', '/usr/bin/true'],
  ['plan', '--uid', '501x', '--gid', '7100', '--cwd', '/tmp', '--exec', '/usr/bin/true'],
  ['plan', '--uid', '501', '--uid', '501', '--gid', '7100', '--cwd', '/tmp', '--exec', '/usr/bin/true'],
  ['plan', '--uid', '501', '--gid', '20', '--cwd', '/tmp', '--exec', '/usr/bin/true'],
  ['launch'], ['utun-open'], ['identity', '--pid', '-1'], ['tunnel-core'],
  ['launch-fixture', '--uid', '501', '--gid', '7100', '--cwd', '/tmp', '--executable', '/usr/bin/true'],
]) {
  const rejected = run(...args);
  assert.equal(rejected.code, 1);
  assert.equal(rejected.report.protected, false);
}
console.log('macOS PF native: unprivileged execution and fail-closed CLI fixtures passed; no PF, utun, sudo, or installation.');
