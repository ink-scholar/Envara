import { rename as fsRename } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';

const TRANSIENT = new Set(['EPERM', 'EBUSY', 'EACCES']);

/** Rename that tolerates Windows briefly holding a file in the tree open
 * (antivirus scans, indexers): retry only those transient errors, only on
 * Windows, a few times. Every other failure, and every failure elsewhere, is
 * reported at once. */
export async function renameWithRetry(from, to, { platform = process.platform, attempts = 8, delayMs = 250, rename = fsRename, wait = delay } = {}) {
  for (let attempt = 1; ; attempt++) {
    try { return await rename(from, to); }
    catch (error) {
      if (platform !== 'win32' || !TRANSIENT.has(error?.code) || attempt >= attempts) throw error;
      await wait(delayMs * attempt);
    }
  }
}
