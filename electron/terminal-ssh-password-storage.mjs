// Main-process only. The OS-backed encryption provider is injected by Electron;
// ciphertext remains in the private, non-exported SSH metadata store.
const MAX_CIPHERTEXT_BYTES = 16 * 1024;
const unavailable = () => Object.assign(new Error('系统密码存储不可用，密码未保存。请检查后重试。'), { code: 'SSH_PASSWORD_STORAGE_UNAVAILABLE' });
const unreadable = () => Object.assign(new Error('已保存的密码暂不可用，请检查系统凭据存储或重新提供密码。'), { code: 'SSH_PASSWORD_DECRYPT_FAILED' });
const binding = (profileId, record) => JSON.stringify({ profileId, id: record.id, alias: record.alias,
  host: record.host, port: record.port, user: record.user, route: record.route, hostFingerprints: record.hostFingerprints });

export function validSshPasswordCiphertext(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= MAX_CIPHERTEXT_BYTES * 4 / 3 + 4
    && /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)
    && Buffer.from(value, 'base64').length <= MAX_CIPHERTEXT_BYTES;
}

export function createSshPasswordStorage(safeStorage) {
  const available = () => {
    try {
      return safeStorage?.isEncryptionAvailable?.() === true
        && safeStorage.getSelectedStorageBackend?.() !== 'basic_text'
        && typeof safeStorage.encryptString === 'function' && typeof safeStorage.decryptString === 'function';
    } catch { return false; }
  };
  return {
    encrypt(profileId, record, secret) {
      if (!available()) throw unavailable();
      try {
        const encrypted = safeStorage.encryptString(JSON.stringify({ version: 1, binding: binding(profileId, record), password: secret.toString('utf8') }));
        if (!Buffer.isBuffer(encrypted) || !encrypted.length || encrypted.length > MAX_CIPHERTEXT_BYTES) throw unavailable();
        return encrypted.toString('base64');
      } catch { throw unavailable(); }
    },
    decrypt(profileId, record) {
      if (!available()) throw unavailable();
      let secret;
      try {
        if (!validSshPasswordCiphertext(record.passwordCiphertext)) throw unreadable();
        const value = JSON.parse(safeStorage.decryptString(Buffer.from(record.passwordCiphertext, 'base64')));
        if (value?.version !== 1 || value.binding !== binding(profileId, record)
          || typeof value.password !== 'string' || !value.password.length || Buffer.byteLength(value.password) > 1024
          || /[\x00\r\n]/.test(value.password)) throw unreadable();
        secret = Buffer.from(value.password, 'utf8');
        return secret;
      } catch { secret?.fill(0); throw unreadable(); }
    },
  };
}
