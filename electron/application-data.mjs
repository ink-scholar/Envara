import path from 'node:path';
import { readdir, lstat, rm } from 'node:fs/promises';
import { pfAttachEnvironmentId } from '../native/macos-pf-routing/policy.mjs';

export const ATTACHED_APPLICATION_DATA_ROOT = '/Library/PrivilegedHelperTools/io.envara.pf-app-data';

/** Empties the sign-in data an environment keeps for its attached
 * applications: every application when the environment is deleted, or one
 * registration when the user clears that application's sign-in data. Only the
 * user-owned UserData directories are touched; the root-owned layout above
 * them stays. A folder that is not empty afterwards is reported, not cleared. */
export async function eraseAttachedApplicationData(profileId, { registrationId = null, root = ATTACHED_APPLICATION_DATA_ROOT,
  uid = process.getuid?.(), platform = process.platform, fs = { readdir, lstat, rm } } = {}) {
  if (platform !== 'darwin' || typeof profileId !== 'string' || !profileId) return [];
  const environment = path.join(root, pfAttachEnvironmentId(profileId)), erased = [], incomplete = [];
  let registrations; try { registrations = await fs.readdir(environment); } catch { return erased; }
  for (const registration of registrations) {
    if (registrationId && registration !== registrationId) continue;
    const leaf = path.join(environment, registration, 'UserData');
    let info; try { info = await fs.lstat(leaf); } catch { continue; }
    if (!info.isDirectory() || info.isSymbolicLink() || info.uid !== uid) continue;
    for (const entry of await fs.readdir(leaf).catch(() => [])) await fs.rm(path.join(leaf, entry), { recursive: true, force: true }).catch(() => {});
    const left = await fs.readdir(leaf).catch(() => null);
    (left?.length === 0 ? erased : incomplete).push(registration);
  }
  if (incomplete.length) throw Object.assign(new Error('登录数据没有全部清除，请退出这个软件后重试。'), { code: 'APPLICATION_DATA_NOT_CLEARED', erased, incomplete });
  return erased;
}
