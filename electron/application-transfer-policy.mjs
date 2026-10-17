// These paths bind a scoped Home to this Mac. They are not portable sign-in
// data; exact components also cover aliases on case-insensitive macOS volumes.
export const APPLICATION_LOCAL_SELECTOR_PATH = 'Home/Library/Preferences/com.apple.security.plist';
export const APPLICATION_LOCAL_KEYCHAINS_PATH = 'Home/Library/Keychains';
const canonical = value => value.normalize('NFD').toLowerCase();
const localRoots = [APPLICATION_LOCAL_SELECTOR_PATH, APPLICATION_LOCAL_KEYCHAINS_PATH].map(canonical);

export function machineLocalApplicationEntry(relative) {
  if (typeof relative !== 'string') return false;
  const value = canonical(relative);
  return localRoots.some(root => value === root || value.startsWith(`${root}/`));
}
