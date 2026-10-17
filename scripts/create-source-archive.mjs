import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { constants, createWriteStream, realpathSync, readlinkSync } from 'node:fs';
import { link, lstat, open, readdir, readlink, realpath, rm } from 'node:fs/promises';
import { pipeline } from 'node:stream/promises';
import { create } from 'tar';

const within = (root, filename) => {
  const relative = path.relative(root, filename);
  return relative === '' || relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
};
const metadataName = () => { throw Object.assign(new Error('ARCHIVE_MACOS_METADATA_NAME'), { code: 'ARCHIVE_MACOS_METADATA_NAME' }); };

// tar's portable mode must not silently change source permissions. This is
// modeFix from the pinned tar API, including its extra directory execute bits.
function requirePortableMode(info, relative) {
  const mode = info.mode & 0o7777;
  let archived = (mode | 0o600) & ~0o22;
  if (info.isDirectory()) {
    if (archived & 0o400) archived |= 0o100;
    if (archived & 0o40) archived |= 0o10;
    if (archived & 0o4) archived |= 0o1;
  }
  if (archived !== mode) throw new Error(`Source mode ${mode.toString(8)} cannot be preserved by portable tar: ${relative}`);
}

async function isAppleDouble(filename, info) {
  if (!info.isFile() || !path.basename(filename).startsWith('._') || info.size < 8) return false;
  const file = await open(filename, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const current = await file.stat();
    if (current.dev !== info.dev || current.ino !== info.ino || current.size !== info.size) {
      throw new Error('Source changed while checking AppleDouble metadata.');
    }
    const magic = Buffer.alloc(8);
    const { bytesRead } = await file.read(magic, 0, 8, 0);
    return bytesRead === 8 && magic.readUInt32BE(0) === 0x00051607 && [0x00010000, 0x00020000].includes(magic.readUInt32BE(4));
  } finally { await file.close(); }
}

/** Archive a stable source tree without host metadata or changing source bytes/modes. */
export async function createSourceArchive({ sourceDir, destination } = {}) {
  if (![sourceDir, destination].every(value => typeof value === 'string' && path.isAbsolute(value))) {
    throw new Error('Source and destination must be absolute paths.');
  }
  const sourceInfo = await lstat(sourceDir);
  if (!sourceInfo.isDirectory() || sourceInfo.isSymbolicLink()) throw new Error('Source must be a physical directory.');
  const root = await realpath(sourceDir);
  const prefix = path.basename(root);
  if (!prefix || prefix.includes('\\')) throw new Error('Source directory needs a portable archive name.');
  if (prefix.startsWith('._') || prefix === '__MACOSX') metadataName();
  const parent = await realpath(path.dirname(destination));
  const output = path.join(parent, path.basename(destination));
  if (within(root, output)) throw new Error('Archive destination must be outside the source tree.');
  const inventory = new Map();
  let excludedMetadataCount = 0;
  async function visit(relative) {
    const filename = path.resolve(root, relative);
    const info = await lstat(filename);
    const basename = path.basename(filename);
    if (relative !== '.') {
      if (await isAppleDouble(filename, info)) { excludedMetadataCount++; return; }
      // Ambiguous names may contain genuine source. Refuse instead of deleting it.
      if (basename.startsWith('._') || basename === '__MACOSX') metadataName();
    }
    if (!info.isDirectory() && !info.isFile() && !info.isSymbolicLink()) {
      throw new Error(`Unsupported source entry type: ${relative}`);
    }
    requirePortableMode(info, relative);
    const resolved = await realpath(filename);
    if (!within(root, resolved)) throw new Error(`Source symlink escapes the source tree: ${relative}`);
    let target;
    if (info.isSymbolicLink()) {
      target = await readlink(filename);
      if (path.isAbsolute(target) || path.win32.isAbsolute(target) || target.includes('\\') ||
          !within(root, path.resolve(path.dirname(filename), target))) {
        throw new Error(`Source symlink target is not a safe relative path: ${relative}`);
      }
    }
    // './' also prevents tar.create from interpreting an @name as another tar.
    const member = relative === '.' ? './' : `./${relative.split(path.sep).join('/')}`;
    inventory.set(member, { info, target, resolved });
    if (info.isDirectory()) {
      for (const name of (await readdir(filename)).sort()) {
        if (name.includes('\\')) throw new Error('Source entry contains a non-portable path separator.');
        await visit(path.join(relative, name));
      }
    }
  }
  await visit('.');
  const includedTargets = new Set([...inventory.keys()].map(member => path.resolve(root, member)));
  for (const [member, entry] of inventory) {
    if (entry.target !== undefined && !includedTargets.has(entry.resolved)) {
      throw new Error(`Source symlink points to excluded metadata: ${member}`);
    }
  }
  const temporary = path.join(parent, `.${path.basename(output)}.stage-${randomUUID()}`);
  let changedSource;
  try {
    const archive = create({ cwd: root, prefix, portable: true, noMtime: true, noPax: false,
      gzip: { portable: true }, noDirRecurse: true, follow: false, strict: true,
      filter(member, current) {
        try {
          const expected = inventory.get(member);
          const filename = path.resolve(root, member);
          if (!expected || ['dev', 'ino', 'mode', 'size', 'mtimeMs'].some(key => current[key] !== expected.info[key]) ||
              realpathSync(filename) !== expected.resolved ||
              expected.target !== undefined && readlinkSync(filename) !== expected.target) {
            throw new Error(`Source changed before archiving: ${member}`);
          }
          return true;
        } catch (error) {
          // tar calls filters from fs callbacks; report after the stream settles
          // instead of throwing an uncaught exception from that callback.
          changedSource ??= error;
          return false;
        }
      },
    }, [...inventory.keys()]);
    await pipeline(archive, createWriteStream(temporary, { flags: 'wx', mode: 0o600 }));
    if (changedSource) throw changedSource;
    // Exclusive publication keeps an existing destination intact, including on failure.
    await link(temporary, output);
    return { destination: output, entryCount: inventory.size, excludedMetadataCount };
  } finally { await rm(temporary, { force: true }); }
}
