import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createHash, randomUUID } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { chmod, lstat, mkdir, readFile, realpath, rename, rm, writeFile } from 'node:fs/promises';

const execute = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const source = path.join(root, 'native/macos-updater/main.swift');
const builder = fileURLToPath(import.meta.url);
export const MAC_UPDATER_EXECUTABLE = 'EnvaraUpdater';
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const failure = () => Object.assign(new Error('macOS update helper is unavailable.'), { code: 'APP_UPDATE_HELPER_INVALID' });

export function macUpdaterOutputDirectory(architecture = process.arch) {
  if (architecture !== 'arm64') throw failure();
  return path.join(root, 'build', 'updater', `darwin-${architecture}`);
}

async function checkedFile(filename, executable = false) {
  const stat = await lstat(filename);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.mode & 0o022
    || executable && !(stat.mode & 0o111) || await realpath(filename) !== filename) throw failure();
  return readFile(filename);
}

export async function checkMacUpdaterResources(directory = macUpdaterOutputDirectory(), architecture = process.arch) {
  if (process.platform !== 'darwin' || architecture !== 'arm64') throw failure();
  const manifest = JSON.parse(await checkedFile(path.join(directory, 'manifest.json')));
  const executable = path.join(directory, MAC_UPDATER_EXECUTABLE);
  if (manifest.schemaVersion !== 1 || manifest.platform !== 'darwin' || manifest.architecture !== architecture
    || manifest.executable !== MAC_UPDATER_EXECUTABLE || manifest.sha256 !== hash(await checkedFile(executable, true))
    || manifest.sourceSha256 !== hash(await readFile(source)) || manifest.builderSha256 !== hash(await readFile(builder))) throw failure();
  await execute('/usr/bin/codesign', ['--verify', '--strict', executable], { timeout: 30000, maxBuffer: 65536 });
  return manifest;
}

/** Compiles in an owned temporary directory and publishes only source-matching
 * ad-hoc signed resources. Does not invoke the updater, install an app, or quit
 * any process. Callers may select a disposable output for native fixtures. */
export async function buildMacUpdater({ directory = macUpdaterOutputDirectory(), architecture = process.arch } = {}) {
  if (process.platform !== 'darwin' || architecture !== 'arm64') throw failure();
  const sourceBytes = await readFile(source), builderBytes = await readFile(builder);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const state = await lstat(directory);
  if (!state.isDirectory() || state.isSymbolicLink() || state.mode & 0o022 || state.uid !== process.getuid()
    || await realpath(directory) !== directory) throw failure();
  const staged = path.join(directory, `.build-${randomUUID()}`);
  await mkdir(staged, { mode: 0o700 });
  const executable = path.join(staged, MAC_UPDATER_EXECUTABLE);
  try {
    const frozenSource = path.join(staged, 'main.swift');
    await writeFile(frozenSource, sourceBytes, { flag: 'wx', mode: 0o600 });
    await execute('/usr/bin/swiftc', ['-O', '-whole-module-optimization', '-module-name', MAC_UPDATER_EXECUTABLE,
      '-target', 'arm64-apple-macos13.0', '-file-prefix-map', `${staged}=.`, '-file-prefix-map', `${root}=.`,
      '-debug-prefix-map', `${staged}=.`, '-debug-prefix-map', `${root}=.`, frozenSource, '-o', executable],
    { timeout: 120000, maxBuffer: 1024 * 1024 });
    await chmod(executable, 0o755);
    await execute('/usr/bin/codesign', ['--force', '--sign', '-', '--timestamp=none', '--identifier', 'io.envara.updater', executable],
      { timeout: 30000, maxBuffer: 65536 });
    await execute('/usr/bin/codesign', ['--verify', '--strict', executable], { timeout: 30000, maxBuffer: 65536 });
    if (!sourceBytes.equals(await readFile(source)) || !builderBytes.equals(await readFile(builder))) throw failure();
    const manifest = { schemaVersion: 1, platform: 'darwin', architecture, executable: MAC_UPDATER_EXECUTABLE,
      sha256: hash(await readFile(executable)), sourceSha256: hash(sourceBytes), builderSha256: hash(builderBytes) };
    await writeFile(path.join(staged, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
    await rename(executable, path.join(directory, MAC_UPDATER_EXECUTABLE));
    await rename(path.join(staged, 'manifest.json'), path.join(directory, 'manifest.json'));
    return await checkMacUpdaterResources(directory, architecture);
  } finally { await rm(staged, { recursive: true, force: true }); }
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  try {
    const args = process.argv.slice(2);
    if (args.length > 1 || args.length === 1 && args[0] !== '--check') throw failure();
    const manifest = args.length ? await checkMacUpdaterResources() : await buildMacUpdater();
    process.stdout.write(`${JSON.stringify({ status: args.length ? 'verified' : 'built', architecture: manifest.architecture })}\n`);
  } catch { process.stderr.write('APP_UPDATE_HELPER_INVALID\n'); process.exitCode = 1; }
}
