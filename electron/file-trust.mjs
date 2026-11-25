/** Platform-aware ownership and permission predicates for lstat results.
 *
 * POSIX mode bits and numeric owners are meaningful on macOS/Linux. On Windows
 * Node synthesizes them: every writable entry reports 0o666 (0o777 for some
 * directories), `uid` is always 0 and `process.getuid` is undefined. Access is
 * governed by NTFS ACLs, which these predicates do not inspect; Envara's data
 * lives under the user's profile (%APPDATA%), whose default ACL already limits
 * access to that user, SYSTEM and Administrators. Callers keep their type,
 * symbolic-link, hard-link and realpath checks on every platform. */

const modeOf = info => Number(info.mode);
const posix = platform => platform !== 'win32';

/** True when group/other may write (mode & 0o022). Never true on Windows. */
export function writableByOthers(info, platform = process.platform) {
  return posix(platform) && (modeOf(info) & 0o022) !== 0;
}

/** True when group/other have any access (mode & 0o077). Never true on Windows. */
export function accessibleByOthers(info, platform = process.platform) {
  return posix(platform) && (modeOf(info) & 0o077) !== 0;
}

/** True when an execute bit is present. Windows has no execute bit; callers
 * that need an executable there must check the file type themselves. */
export function hasExecuteBit(info, platform = process.platform) {
  return !posix(platform) || (modeOf(info) & 0o111) !== 0;
}

/** Current numeric user, or undefined where the platform has none. */
export function currentUid(platform = process.platform) {
  return posix(platform) ? process.getuid?.() : undefined;
}

/** True when the entry belongs to `uid`; undefined uid (Windows) always matches. */
export function ownedBy(info, uid) {
  if (uid == null) return true;
  return typeof info.uid === 'bigint' ? info.uid === BigInt(uid) : info.uid === uid;
}
