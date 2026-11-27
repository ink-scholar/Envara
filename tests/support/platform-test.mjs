import nodeTest from 'node:test';

/** `test` for a file whose whole subject exists only on some platforms.
 *
 * On a listed platform this is node:test itself. Elsewhere every test is
 * reported as skipped with `reason`, and hooks are inert, so a fixture that
 * needs that platform's tools (clang, Seatbelt, process.getuid, POSIX modes)
 * is never prepared. Keep platform-neutral tests in files that use node:test
 * directly. */
export function platformTest(platforms, reason) {
  if (platforms.includes(process.platform)) return nodeTest;
  const skip = `${reason} (${process.platform})`;
  const skipped = (name, options, fn) => {
    if (typeof name === 'function') return nodeTest(name.name || 'unnamed', { skip });
    if (typeof options === 'function' || options === undefined) return nodeTest(name, { skip });
    return nodeTest(name, { ...options, skip });
  };
  const inert = () => {};
  return Object.assign(skipped, {
    skip: skipped, todo: skipped, only: skipped,
    before: inert, after: inert, beforeEach: inert, afterEach: inert,
    mock: nodeTest.mock,
  });
}

/** Tests of macOS-only features (PF routing, Seatbelt, Keychain, SSH, Claude Code, updater). */
export const macOSOnly = platformTest(['darwin'], 'macOS-only feature');

/** Tests of transports that listen on a Unix-socket path. Windows needs a
 * named pipe (\\.\pipe\...) instead; until then the feature is unavailable there. */
export const unixSocketOnly = platformTest(['darwin', 'linux'], 'Unix-socket transport; Windows named pipe pending');
