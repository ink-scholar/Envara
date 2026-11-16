import test from 'node:test';
import assert from 'node:assert/strict';
import { applicationVersionParts, compareApplicationVersions } from '../shared/application-version.mjs';

test('stable release versions preserve their exact accepted format and numeric bounds', () => {
  for (const value of ['0.0.0', '1.3.0', '999999999.999999999.999999999']) assert.ok(applicationVersionParts(value));
  for (const value of [undefined, null, 123, '', 'v1.3.0', '1.3', '1.3.0-beta', '1.3.0+build', '01.3.0', '1.03.0', '1.3.00', '1.3.0\n', '1000000000.0.0']) {
    assert.equal(applicationVersionParts(value), null, String(value));
  }
});

test('release selection and startup recovery share numeric rather than lexical ordering', () => {
  const ascending = ['0.0.0', '1.2.9', '1.2.10', '1.3.0', '1.9.0', '1.10.0', '2.0.0', '999999999.0.0'];
  for (let i = 0; i < ascending.length; i++) for (let j = 0; j < ascending.length; j++)
    assert.equal(compareApplicationVersions(ascending[i], ascending[j]), Math.sign(i - j));
});
