import path from 'node:path';
import { realpathSync } from 'node:fs';

/** Keep source diagnostics and Mach-O debug maps independent of the checkout. */
export function swiftBuildPathOptions(checkoutRoot) {
  const root = path.resolve(checkoutRoot);
  let physicalRoot;
  try { physicalRoot = realpathSync(root); }
  catch (error) { if (error.code !== 'ENOENT') throw error; physicalRoot = root; }
  const prefixes = [...new Set([root, physicalRoot])];
  const mappedRoot = '/envara/src';
  const compilationDirectory = `${mappedRoot}/native/macos-app-routing`;
  return [
    // Shipping helpers do not include dSYMs or their checkout-local objects.
    '-debug-info-format', 'none',
    ...prefixes.flatMap(prefix => [
      '-Xswiftc', '-file-prefix-map', '-Xswiftc', `${prefix}=${mappedRoot}`,
      '-Xswiftc', '-debug-prefix-map', '-Xswiftc', `${prefix}=${mappedRoot}`,
      '-Xcc', `-ffile-prefix-map=${prefix}=${mappedRoot}`,
      '-Xcc', `-fdebug-prefix-map=${prefix}=${mappedRoot}`,
    ]),
    '-Xswiftc', '-file-compilation-dir', '-Xswiftc', compilationDirectory,
    '-Xswiftc', '-prefix-serialized-debugging-options',
    '-Xcc', `-fdebug-compilation-dir=${compilationDirectory}`,
    // ld writes input-object paths into OSO symbols independently of DWARF.
    '-Xlinker', '-oso_prefix', '-Xlinker', `${physicalRoot}${path.sep}`,
  ];
}
