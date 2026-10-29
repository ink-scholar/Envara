import { machineLocalApplicationEntry } from './application-transfer-policy.mjs';

/** A default-Keychain selector, vault and preparation locks belong to one Mac.
 * Apply on both export and legacy import, including case-insensitive aliases. */
export function machineLocalTerminalEntry(relative) {
  if (typeof relative !== 'string') return false;
  if (machineLocalApplicationEntry(relative)) return true;
  const parts = relative.normalize('NFD').toLowerCase().split('/');
  return parts[0] === 'home' && (parts[1] === '.envara-keychain.lock' || parts[1]?.startsWith('.envara-keychain-'));
}
