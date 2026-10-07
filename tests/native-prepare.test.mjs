import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { copyDependencyLicenses } from '../scripts/prepare-native.mjs';

test('license preparation includes runtime dependency graph and safely replaces read-only previous output', async t => {
  const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'envara-license-test-'));
  t.after(() => fs.rm(temporary, { recursive: true, force: true }));
  const directory = path.join(temporary, 'licenses');
  const first = await copyDependencyLicenses(directory);
  const firstManifest = await fs.readFile(path.join(directory, 'manifest.json'), 'utf8');
  assert(first.some(item => item.name === 'node-addon-api'));
  assert(first.some(item => item.name === 'proxy-agent-negotiate' && item.notices.some(name => name.includes('supplementary'))));
  assert(first.some(item => item.name === 'node-pty' && item.notices.some(name => name.includes('Microsoft-Terminal'))));
  assert(first.some(item => item.name === '@xterm/xterm' && item.renderer));
  assert(!first.some(item => item.name === '@electron/rebuild' || item.name === 'kerberos'));
  for (const item of first) {
    for (const notice of item.notices) assert((await fs.readFile(path.join(directory, notice), 'utf8')).length > 100);
  }
  for (const filename of await fs.readdir(directory)) await fs.chmod(path.join(directory, filename), 0o444);
  await copyDependencyLicenses(directory);
  assert.equal(await fs.readFile(path.join(directory, 'manifest.json'), 'utf8'), firstManifest);
});
