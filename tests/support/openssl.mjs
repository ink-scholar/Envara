import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';

/** The OpenSSL CLI used to mint throwaway localhost certificates in tests.
 * macOS and Linux provide it on PATH. Windows usually does not, but Git for
 * Windows ships one; use it when present. `null` when none is available. */
function locate() {
  if (!spawnSync('openssl', ['version'], { windowsHide: true }).error) return 'openssl';
  if (process.platform !== 'win32') return null;
  const roots = [process.env.ProgramFiles, process.env['ProgramFiles(x86)'], process.env.LOCALAPPDATA && path.join(process.env.LOCALAPPDATA, 'Programs')];
  for (const root of roots.filter(Boolean)) {
    const candidate = path.join(root, 'Git', 'usr', 'bin', 'openssl.exe');
    if (existsSync(candidate) && !spawnSync(candidate, ['version'], { windowsHide: true }).error) return candidate;
  }
  return null;
}

export const opensslCommand = locate();
/** `skip` value for tests that need the OpenSSL CLI. */
export const opensslUnavailable = opensslCommand ? false : 'OpenSSL CLI is not available';
