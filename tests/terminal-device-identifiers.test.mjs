import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { mkdtemp, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { TERMINAL_FENCE_EXECUTABLE, TerminalNetworkFence, terminalFenceProfile } from '../electron/terminal-network-fence.mjs';

const execute = promisify(execFile);
const onlyMac = { skip: process.platform !== 'darwin', timeout: 45000 };
const fixture = fileURLToPath(new URL('../scripts/fixtures/terminal-device-identifier-probe.c', import.meta.url));
const booleanOnly = value => typeof value === 'boolean' || value && typeof value === 'object' && !Array.isArray(value) && Object.values(value).every(booleanOnly);

test('real Seatbelt restricts named device reads, preserves ordinary hardware queries and follows child processes', onlyMac, async t => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'envara-terminal-device-identifiers-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const binary = path.join(directory, 'probe');
  await execute('/usr/bin/xcrun', ['clang', '-Wall', '-Wextra', '-Werror', '-Wno-deprecated-declarations', fixture,
    '-framework', 'IOKit', '-framework', 'CoreFoundation', '-o', binary], { timeout: 30000, maxBuffer: 16384 });
  const options = { timeout: 10000, maxBuffer: 16384, env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', LC_ALL: 'C' } };
  const probe = async (profile, child = false) => {
    const command = child ? ['/bin/sh', '-c', '"$1"', 'envara-owned-identifier-probe', binary] : [binary];
    const { stdout } = await execute(TERMINAL_FENCE_EXECUTABLE, ['-p', profile, ...command], options);
    const result = JSON.parse(stdout);
    assert.equal(booleanOnly(result), true, 'the native probe may report booleans only, never hardware values');
    return result;
  };
  const baseline = await probe(terminalFenceProfile());
  const wrapped = await new TerminalNetworkFence({ environment: {} }).wrap({ executable: binary, args: [], environment: {} },
    { routePort: 50000, restrictDeviceIdentifiers: true });
  assert.equal(wrapped.deviceIdentifierRestrictions, true);
  const restricted = await probe(wrapped.args[1]);
  const child = await probe(wrapped.args[1], true);
  assert.equal(baseline.platformEntryPresent, true);
  assert.equal(baseline.registryRootPresent, true);
  for (const surface of ['single', 'searchDirect', 'searchRecursive', 'bytes']) {
    for (const key of ['serial', 'uuid']) {
      assert.equal(baseline[surface][key].present, true, `${surface}.${key} baseline is required to prove denial`);
      assert.equal(restricted[surface][key].present, false, `${surface}.${key} must not return the identifier`);
    }
  }
  for (const key of ['serial', 'uuid']) assert.equal(restricted.bytes[key].denied, true);
  assert.equal(baseline.batch.serialPresent, true);
  assert.equal(baseline.batch.uuidPresent, true);
  assert.equal(restricted.batch.present, true, 'batch queries still return a filtered dictionary');
  assert.equal(restricted.batch.serialPresent, false);
  assert.equal(restricted.batch.uuidPresent, false);
  assert.equal(restricted.batch.modelPresent, true);
  assert.equal(restricted.single.model.present, true);
  for (const method of ['library', 'syscall']) {
    assert.equal(baseline.hostUuid[method].present, true);
    assert.deepEqual(restricted.hostUuid[method], { present: false, denied: true });
  }
  for (const method of ['byName', 'numericMib']) {
    assert.equal(baseline.sysctl['kern.uuid'][method].present, true);
    assert.deepEqual(restricted.sysctl['kern.uuid'][method], { present: false, denied: true, absent: false });
  }
  for (const key of ['hw.model', 'hw.memsize', 'hw.logicalcpu', 'kern.hostname', 'kern.bootsessionuuid']) {
    for (const method of ['byName', 'numericMib']) assert.equal(restricted.sysctl[key][method].present, true, `${key} is not replaced or denied`);
  }
  assert.deepEqual(child, restricted, 'an independently forked child inherits the same combined network and read restrictions');
});
