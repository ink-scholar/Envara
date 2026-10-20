// Strict public SSH key parsing shared by trust probes and saved connections.
import { createHash } from 'node:crypto';

const MAX_PUBLIC_BYTES = 16 * 1024;
const KEY_TYPES = new Set(['ssh-ed25519', 'ssh-rsa', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521']);
const fail = (code, message) => Object.assign(new Error(message), { code });
const fingerprint = blob => `SHA256:${createHash('sha256').update(blob).digest('base64').replace(/=+$/, '')}`;

export function parseSshPublicKey(text) {
  if (typeof text !== 'string' || text.length > MAX_PUBLIC_BYTES || /[\x00\r]/.test(text)) throw fail('SSH_KEY_INVALID', 'SSH 公钥格式不受支持。');
  const lines = text.trim().split('\n');
  const match = lines.length === 1 && /^(\S+)\s+([A-Za-z0-9+/]+={0,2})(?:\s+[^\n]*)?$/.exec(lines[0]);
  if (!match || !KEY_TYPES.has(match[1])) throw fail('SSH_KEY_INVALID', 'SSH 公钥格式不受支持。');
  const blob = Buffer.from(match[2], 'base64');
  if (blob.length > MAX_PUBLIC_BYTES || blob.toString('base64').replace(/=+$/, '') !== match[2].replace(/=+$/, '')) throw fail('SSH_KEY_INVALID', 'SSH 公钥格式不受支持。');
  let offset = 0;
  const field = () => {
    if (offset + 4 > blob.length) throw fail('SSH_KEY_INVALID', 'SSH 公钥格式不受支持。');
    const length = blob.readUInt32BE(offset); offset += 4;
    if (length < 1 || offset + length > blob.length) throw fail('SSH_KEY_INVALID', 'SSH 公钥格式不受支持。');
    const value = blob.subarray(offset, offset + length); offset += length; return value;
  };
  if (field().toString() !== match[1]) throw fail('SSH_KEY_INVALID', 'SSH 公钥格式不受支持。');
  if (match[1] === 'ssh-ed25519') { if (field().length !== 32) throw fail('SSH_KEY_INVALID', 'SSH 公钥格式不受支持。'); }
  else if (match[1] === 'ssh-rsa') { field(); field(); }
  else { if (field().toString() !== match[1].slice('ecdsa-sha2-'.length)) throw fail('SSH_KEY_INVALID', 'SSH 公钥格式不受支持。'); field(); }
  if (offset !== blob.length) throw fail('SSH_KEY_INVALID', 'SSH 公钥格式不受支持。');
  return { text: `${match[1]} ${blob.toString('base64')}`, fingerprint: fingerprint(blob) };
}

