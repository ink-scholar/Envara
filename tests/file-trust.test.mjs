import test from 'node:test';
import assert from 'node:assert/strict';
import { accessibleByOthers, currentUid, hasExecuteBit, ownedBy, writableByOthers } from '../electron/file-trust.mjs';

const stat = (mode, uid = 501) => ({ mode, uid });
const big = (mode, uid = 501n) => ({ mode: BigInt(mode), uid });

test('POSIX mode bits are enforced on macOS and Linux', () => {
  for (const platform of ['darwin', 'linux']) {
    assert.equal(writableByOthers(stat(0o40755), platform), false);
    assert.equal(writableByOthers(stat(0o40775), platform), true);
    assert.equal(writableByOthers(stat(0o100666), platform), true);
    assert.equal(accessibleByOthers(stat(0o40700), platform), false);
    assert.equal(accessibleByOthers(stat(0o100640), platform), true);
    assert.equal(hasExecuteBit(stat(0o100644), platform), false);
    assert.equal(hasExecuteBit(stat(0o100755), platform), true);
    assert.equal(writableByOthers(big(0o100666), platform), true);
  }
});

test('Windows synthesized mode bits are not treated as permissions', () => {
  // Node on Windows reports 0o666 for every writable entry and uid 0.
  for (const info of [stat(0o40666, 0), stat(0o100666, 0), stat(0o40777, 0), big(0o100666, 0n)]) {
    assert.equal(writableByOthers(info, 'win32'), false);
    assert.equal(accessibleByOthers(info, 'win32'), false);
    assert.equal(hasExecuteBit(info, 'win32'), true);
  }
  assert.equal(currentUid('win32'), undefined);
});

test('ownership compares numeric and BigInt owners, and has no owner without a uid', () => {
  assert.equal(ownedBy(stat(0, 501), 501), true);
  assert.equal(ownedBy(stat(0, 0), 501), false);
  assert.equal(ownedBy(big(0, 501n), 501), true);
  assert.equal(ownedBy(big(0, 0n), 501), false);
  assert.equal(ownedBy(stat(0, 0), undefined), true);
});
