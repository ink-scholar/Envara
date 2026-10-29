import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createHash, randomUUID } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { chmod, lstat, mkdir, readFile, realpath, rename, rm, writeFile } from 'node:fs/promises';

const execute = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const source = path.join(root, 'native/macos-claude-keychain/main.c');
const builder = fileURLToPath(import.meta.url);
export const CLAUDE_KEYCHAIN_EXECUTABLE = 'envara-claude-keychain';
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const failure = message => Object.assign(new Error(message), { code: 'CLAUDE_KEYCHAIN_RESOURCE_INVALID' });

export function claudeKeychainOutputDirectory(architecture = process.arch) {
  if (!['arm64', 'x64'].includes(architecture)) throw failure('Unsupported macOS keychain helper architecture.');
  return path.join(root, 'build', 'claude-keychain', `darwin-${architecture}`);
}

async function checkedFile(filename, { executable = false } = {}) {
  const stat = await lstat(filename);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.mode & 0o022
    || executable && !(stat.mode & 0o111) || await realpath(filename) !== filename) throw failure('Unsafe keychain helper resource.');
  return readFile(filename);
}

export async function checkClaudeKeychainResources(directory = claudeKeychainOutputDirectory(), architecture = process.arch) {
  const manifest = JSON.parse(await checkedFile(path.join(directory, 'manifest.json')));
  const binary = await checkedFile(path.join(directory, CLAUDE_KEYCHAIN_EXECUTABLE), { executable: true });
  if (manifest.schemaVersion !== 1 || manifest.platform !== 'darwin' || manifest.architecture !== architecture
    || manifest.executable !== CLAUDE_KEYCHAIN_EXECUTABLE || manifest.sha256 !== hash(binary)
    || manifest.sourceSha256 !== hash(await readFile(source)) || manifest.builderSha256 !== hash(await readFile(builder)))
    throw failure('Keychain helper does not match reviewed source and builder.');
  return manifest;
}

export async function buildClaudeKeychainResources({ directory = claudeKeychainOutputDirectory(), architecture = process.arch } = {}) {
  if (process.platform !== 'darwin' || !['arm64', 'x64'].includes(architecture)) throw failure('Build this helper on macOS.');
  const sourceBytes = await readFile(source), builderBytes = await readFile(builder);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const state = await lstat(directory);
  if (!state.isDirectory() || state.isSymbolicLink() || state.mode & 0o022 || await realpath(directory) !== directory)
    throw failure('Unsafe keychain helper output directory.');
  const staged = path.join(directory, `.build-${randomUUID()}`);
  await mkdir(staged, { mode: 0o700 });
  const executable = path.join(staged, CLAUDE_KEYCHAIN_EXECUTABLE);
  try {
    const frozenSource = path.join(staged, 'main.c');
    await writeFile(frozenSource, sourceBytes, { flag: 'wx', mode: 0o600 });
    await execute('/usr/bin/clang', ['-arch', architecture === 'x64' ? 'x86_64' : 'arm64', '-mmacosx-version-min=13.0',
      '-Os', '-Wall', '-Wextra', '-Werror', '-Wno-deprecated-declarations', '-fvisibility=hidden',
      `-ffile-prefix-map=${staged}=.`, `-ffile-prefix-map=${root}=.`, frozenSource, '-framework', 'Security', '-framework', 'CoreFoundation', '-o', executable],
    { timeout: 60000, maxBuffer: 1024 * 1024 });
    await chmod(executable, 0o755);
    await execute('/usr/bin/codesign', ['--force', '--sign', '-', '--identifier', 'io.envara.claude-keychain', executable],
      { timeout: 30000, maxBuffer: 65536 });
    await execute('/usr/bin/codesign', ['--verify', '--strict', executable], { timeout: 30000, maxBuffer: 65536 });
    if (!sourceBytes.equals(await readFile(source)) || !builderBytes.equals(await readFile(builder)))
      throw failure('Keychain helper source changed during its build; no resource was published.');
    const manifest = { schemaVersion: 1, platform: 'darwin', architecture, executable: CLAUDE_KEYCHAIN_EXECUTABLE,
      sha256: hash(await readFile(executable)), sourceSha256: hash(sourceBytes), builderSha256: hash(builderBytes) };
    await writeFile(path.join(staged, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
    await rename(executable, path.join(directory, CLAUDE_KEYCHAIN_EXECUTABLE));
    await rename(path.join(staged, 'manifest.json'), path.join(directory, 'manifest.json'));
    return await checkClaudeKeychainResources(directory, architecture);
  } finally { await rm(staged, { recursive: true, force: true }); }
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  try {
    const args = process.argv.slice(2);
    if (args.length > 1 || args.length === 1 && args[0] !== '--check') throw failure('Use no arguments to build, or --check to inspect.');
    if (process.platform !== 'darwin' && !args.length) process.stdout.write('{"status":"skipped","reason":"macOS only"}\n');
    else {
      if (process.platform !== 'darwin') throw failure('Inspect this helper on macOS.');
      const manifest = args[0] === '--check' ? await checkClaudeKeychainResources() : await buildClaudeKeychainResources();
      process.stdout.write(`${JSON.stringify({ status: args[0] === '--check' ? 'verified' : 'built', architecture: manifest.architecture })}\n`);
    }
  } catch (error) { process.stderr.write(`${error.code ?? 'CLAUDE_KEYCHAIN_BUILD_FAILED'}: ${error.message}\n`); process.exitCode = 1; }
}
