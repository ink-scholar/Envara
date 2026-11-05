import assert from 'node:assert/strict';
import { randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';
import test from 'node:test';
import { createSshPasswordStorage, validSshPasswordCiphertext } from '../electron/terminal-ssh-password-storage.mjs';

const record = { id: 'ssh_fixture', alias: 'envara-000000000001', host: 'fixture.invalid', port: 22, user: 'fixture',
  route: { kind: 'host' }, hostFingerprints: ['SHA256:synthetic'] };
const secret = Buffer.from('synthetic-storage-secret');
function provider() {
  const key = randomBytes(32);
  return { isEncryptionAvailable: () => true,
    encryptString(value) { const iv = randomBytes(12), cipher = createCipheriv('aes-256-gcm', key, iv);
      const bytes = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]); return Buffer.concat([iv, cipher.getAuthTag(), bytes]); },
    decryptString(value) { const decipher = createDecipheriv('aes-256-gcm', key, value.subarray(0, 12));
      decipher.setAuthTag(value.subarray(12, 28)); return Buffer.concat([decipher.update(value.subarray(28)), decipher.final()]).toString(); } };
}
const code = expected => error => error.code === expected && !error.message.includes(secret.toString());

test('OS-backed adapter binds ciphertext to environment, record, destination, route and confirmed identity', () => {
  const storage = createSshPasswordStorage(provider()), passwordCiphertext = storage.encrypt('profile-a', record, secret);
  assert.equal(validSshPasswordCiphertext(passwordCiphertext), true);
  assert.equal(Buffer.from(passwordCiphertext, 'base64').includes(secret), false);
  assert.deepEqual(storage.decrypt('profile-a', { ...record, passwordCiphertext }), secret);
  for (const change of [{ id: 'different' }, { alias: 'envara-000000000002' }, { host: 'different.invalid' }, { port: 2222 }, { user: 'another' },
    { route: { kind: 'environment', profileId: 'profile-b' } }, { hostFingerprints: ['SHA256:different'] }]) {
    assert.throws(() => storage.decrypt('profile-a', { ...record, ...change, passwordCiphertext }), code('SSH_PASSWORD_DECRYPT_FAILED'));
  }
  assert.throws(() => storage.decrypt('profile-b', { ...record, passwordCiphertext }), code('SSH_PASSWORD_DECRYPT_FAILED'));
});

test('missing, locked and plaintext OS backends fail closed without a plaintext fallback or native error disclosure', () => {
  for (const adapter of [null, {}, { ...provider(), isEncryptionAvailable: () => false },
    { ...provider(), getSelectedStorageBackend: () => 'basic_text' },
    { ...provider(), isEncryptionAvailable() { throw new Error(secret.toString()); } },
    { ...provider(), encryptString() { throw new Error(secret.toString()); } },
    { ...provider(), encryptString: () => secret.toString() },
    { ...provider(), encryptString: () => Buffer.alloc(0) },
    { ...provider(), encryptString: () => Buffer.alloc(16385) }]) {
    assert.throws(() => createSshPasswordStorage(adapter).encrypt('profile-a', record, secret), code('SSH_PASSWORD_STORAGE_UNAVAILABLE'));
  }
});

test('corrupt ciphertext, unusable decrypted data and native decryption failures are secret-free', () => {
  for (const value of ['', '!', '===', 'YQ=', 'YQ', 'a'.repeat(30000), null, 5]) assert.equal(validSshPasswordCiphertext(value), false);
  const adapter = provider(), storage = createSshPasswordStorage(adapter);
  const passwordCiphertext = storage.encrypt('profile-a', record, secret), changed = Buffer.from(passwordCiphertext, 'base64'); changed[30] ^= 1;
  assert.throws(() => storage.decrypt('profile-a', { ...record, passwordCiphertext: changed.toString('base64') }), code('SSH_PASSWORD_DECRYPT_FAILED'));
  for (const text of [secret.toString(), '{}', JSON.stringify({ version: 9 }), 'null']) {
    const invalid = createSshPasswordStorage({ ...adapter, decryptString: () => text });
    assert.throws(() => invalid.decrypt('profile-a', { ...record, passwordCiphertext }), code('SSH_PASSWORD_DECRYPT_FAILED'));
  }
  const failure = createSshPasswordStorage({ ...adapter, decryptString() { throw new Error(secret.toString()); } });
  assert.throws(() => failure.decrypt('profile-a', { ...record, passwordCiphertext }), code('SSH_PASSWORD_DECRYPT_FAILED'));
});
