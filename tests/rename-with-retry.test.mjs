import test from 'node:test';
import assert from 'node:assert/strict';
import { renameWithRetry } from '../scripts/rename-with-retry.mjs';

const failing = (codes) => {
  const calls = [];
  return { calls, rename: async (from, to) => { calls.push([from, to]); const code = codes.shift(); if (code) throw Object.assign(new Error(code), { code }); } };
};
const noWait = async () => {};

test('Windows retries a briefly held tree and then succeeds', async () => {
  const f = failing(['EPERM', 'EBUSY']);
  await renameWithRetry('stage', 'out', { platform: 'win32', rename: f.rename, wait: noWait });
  assert.equal(f.calls.length, 3);
});

test('other errors, other platforms and exhausted attempts fail at once', async () => {
  const missing = failing(['ENOENT']);
  await assert.rejects(renameWithRetry('a', 'b', { platform: 'win32', rename: missing.rename, wait: noWait }), { code: 'ENOENT' });
  assert.equal(missing.calls.length, 1);
  const mac = failing(['EPERM']);
  await assert.rejects(renameWithRetry('a', 'b', { platform: 'darwin', rename: mac.rename, wait: noWait }), { code: 'EPERM' });
  assert.equal(mac.calls.length, 1);
  const held = failing(Array(10).fill('EACCES'));
  await assert.rejects(renameWithRetry('a', 'b', { platform: 'win32', attempts: 4, rename: held.rename, wait: noWait }), { code: 'EACCES' });
  assert.equal(held.calls.length, 4);
});
