import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { spawn, execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { promisify } from 'node:util';

const root = fileURLToPath(new URL('..', import.meta.url));
const requireApp = createRequire(path.join(root, 'package.json'));
const execute = promisify(execFile);
const nativePackages = ['node-pty', '@xterm/headless', 'socks', 'https-proxy-agent', 'socks-proxy-agent', 'ipaddr.js'];
const rendererPackages = ['@xterm/xterm', '@xterm/addon-fit'];

/** Compiler flags belong only to the rebuild child, never the user's process. */
export async function nativeRebuildEnvironment({ env = process.env, platform = process.platform, checkoutRoot = root, homeDirectory = os.homedir() } = {}) {
  const result = { ...env };
  if (platform !== 'darwin') return result;
  const checkout = path.resolve(checkoutRoot);
  let physical = checkout;
  try { physical = await fs.realpath(checkout); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  const prefixes = [...new Map([[homeDirectory, '/envara/build-home'], [checkout, '/envara/src'], [physical, '/envara/src']])];
  const quote = value => `'${value.replaceAll("'", "'\"'\"'")}'`;
  const flags = [...prefixes.flatMap(([prefix, replacement]) => [
    `-ffile-prefix-map=${prefix}=${replacement}`, `-fdebug-prefix-map=${prefix}=${replacement}`,
  ]), '-fdebug-compilation-dir=/envara/src/node_modules/node-pty', '-g0'].map(quote).join(' ');
  for (const key of ['CFLAGS', 'CXXFLAGS']) result[key] = [env[key], flags].filter(Boolean).join(' ');
  // Remove N_SO/N_OSO debug-map entries at link time, before the linker's ad-hoc
  // signature is written; keep all runtime and undefined binding symbols.
  result.LDFLAGS = [env.LDFLAGS, '-Wl,-S'].filter(Boolean).join(' ');
  return result;
}

export async function verifyNativeBuildPaths(directory, { platform = process.platform, checkoutRoot = root, homeDirectory = os.homedir() } = {}) {
  if (platform !== 'darwin') return;
  // Also refuse a cached/prebuilt artifact from another build user's checkout.
  const prefixes = new Set([path.resolve(checkoutRoot), homeDirectory, '/Users/', '/home/', '/private/var/folders/', '/var/folders/']);
  try { prefixes.add(await fs.realpath(checkoutRoot)); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  for (const name of ['pty.node', 'spawn-helper']) {
    const bytes = await fs.readFile(path.join(directory, 'build/Release', name));
    if ([...prefixes].some(prefix => prefix && bytes.includes(Buffer.from(prefix)))) {
      throw new Error('node-pty still contains a local source or build path. Rebuild from source.');
    }
  }
}

async function packageDirectory(name, from = root) {
  let current = from;
  while (true) {
    const candidate = path.join(current, 'node_modules', name);
    try {
      const metadata = JSON.parse(await fs.readFile(path.join(candidate, 'package.json'), 'utf8'));
      if (metadata.name === name) return { directory: candidate, metadata };
    } catch (error) { if (error.code !== 'ENOENT' && error.code !== 'ENOTDIR') throw error; }
    const parent = path.dirname(current);
    if (parent === current) throw new Error(`Installed dependency ${name} was not found.`);
    current = parent;
  }
}

async function atomicWrite(destination, contents) {
  const temporary = `${destination}.tmp-${process.pid}`;
  await fs.writeFile(temporary, contents, { mode: 0o644 });
  try { await fs.rename(temporary, destination); }
  finally { await fs.rm(temporary, { force: true }); }
}

export async function copyDependencyLicenses(destination = path.join(root, 'build/native/licenses')) {
  await fs.mkdir(destination, { recursive: true });
  const seen = new Set();
  const packages = [];
  async function visit(name, from, renderer = false) {
    const { directory, metadata } = await packageDirectory(name, from);
    if (seen.has(directory)) return;
    seen.add(directory);
    const prefix = `${metadata.name.replace(/[@/]/g, '-')}-${metadata.version}`;
    const entries = await fs.readdir(directory, { withFileTypes: true });
    const files = entries.filter(entry => entry.isFile() && /^(LICENSE|LICENCE|COPYING|NOTICE)([.-]|$)/i.test(entry.name));
    const notices = [];
    for (const file of files) {
      const outputName = `${prefix}-${file.name}`;
      await atomicWrite(path.join(destination, outputName), await fs.readFile(path.join(directory, file.name)));
      notices.push(outputName);
    }
    if (metadata.name === 'node-pty') {
      const winpty = path.join(directory, 'deps/winpty/LICENSE');
      try {
        const outputName = `${prefix}-winpty-LICENSE`;
        await atomicWrite(path.join(destination, outputName), await fs.readFile(winpty));
        notices.push(outputName);
      } catch (error) { if (error.code !== 'ENOENT') throw error; }
      const outputName = `${prefix}-Microsoft-Terminal-LICENSE`;
      await atomicWrite(path.join(destination, outputName), await fs.readFile(path.join(root, 'third_party/npm-licenses/Microsoft-Terminal-LICENSE')));
      notices.push(outputName);
    }
    if (metadata.name === 'proxy-agent-negotiate' && metadata.version === '1.1.0' && metadata.license === 'MIT' && !notices.length) {
      const outputName = `${prefix}-supplementary-NOTICE.txt`;
      await atomicWrite(path.join(destination, outputName), await fs.readFile(path.join(root, 'third_party/npm-licenses/proxy-agent-negotiate-NOTICE.txt')));
      notices.push(outputName);
    }
    // The headless 6.0.0 npm archive omits LICENSE. Preserve the unmodified
    // notice from the matching official xterm.js source tag instead.
    if (metadata.name === '@xterm/headless' && metadata.version === '6.0.0' && metadata.license === 'MIT' && !notices.length) {
      const outputName = `${prefix}-LICENSE`;
      await atomicWrite(path.join(destination, outputName), await fs.readFile(path.join(root, 'third_party/npm-licenses/Xterm-6.0.0-LICENSE')));
      notices.push(outputName);
    }
    if (!notices.length) throw new Error(`No distributed license notice was found for ${metadata.name}.`);
    packages.push({ name: metadata.name, version: metadata.version, license: metadata.license, renderer, notices });
    for (const dependency of Object.keys(metadata.dependencies || {})) await visit(dependency, directory, renderer);
  }
  for (const name of nativePackages) await visit(name, root);
  for (const name of rendererPackages) await visit(name, root, true);
  packages.sort((a, b) => a.name.localeCompare(b.name));
  await atomicWrite(path.join(destination, 'manifest.json'), `${JSON.stringify({ packages }, null, 2)}\n`);
  return packages;
}

async function executableHelpers(directory) {
  if (process.platform === 'win32') return;
  for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
    const candidate = path.join(directory, entry.name);
    if (entry.isDirectory()) await executableHelpers(candidate);
    else if (entry.isFile() && entry.name === 'spawn-helper') await fs.chmod(candidate, 0o755);
  }
}

export async function verifyNativePty(electronPath = requireApp('electron')) {
  return new Promise((resolve, reject) => {
    let output = '';
    let errors = '';
    const child = spawn(electronPath, [path.join(root, 'scripts/check-native-pty.cjs')], {
      cwd: root,
      env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const timeout = setTimeout(() => { child.kill(); reject(new Error('Electron PTY subprocess timed out.')); }, 15000);
    child.stdout.on('data', data => { output = (output + data).slice(-8192); });
    child.stderr.on('data', data => { errors = (errors + data).slice(-8192); });
    child.on('error', error => { clearTimeout(timeout); reject(error); });
    child.on('exit', code => {
      clearTimeout(timeout);
      if (code !== 0) return reject(new Error(errors.trim() || 'Electron PTY subprocess failed.'));
      try {
        const result = JSON.parse(output.trim().split('\n').at(-1));
        if (!result.ok || result.arch !== process.arch || result.platform !== process.platform) throw new Error('PTY target does not match the native build host.');
        resolve(result);
      } catch (error) { reject(error); }
    });
  });
}

export async function prepareNative({ forceRebuild = false } = {}) {
  const metadata = JSON.parse(await fs.readFile(path.join(root, 'package.json'), 'utf8'));
  const installedElectron = (await packageDirectory('electron')).metadata.version;
  if (installedElectron !== metadata.devDependencies.electron) throw new Error('Electron differs from the pinned build dependency. Run npm ci.');
  const nodePty = await packageDirectory('node-pty');
  await executableHelpers(nodePty.directory);
  let verification;
  if (!forceRebuild) {
    try { await verifyNativeBuildPaths(nodePty.directory); verification = await verifyNativePty(); }
    catch { console.info('Preparing node-pty from source for the pinned Electron runtime.'); }
  }
  if (!verification) {
    const rebuildCLI = path.join(path.dirname(requireApp.resolve('@electron/rebuild')), 'cli.js');
    await execute(process.execPath, [rebuildCLI, '--module-dir', root, '--version', installedElectron,
      '--arch', process.arch, '--platform', process.platform, '--only', 'node-pty', '--force', '--build-from-source', '--jobs', '2'], {
      cwd: root, env: await nativeRebuildEnvironment(), timeout: 180000, maxBuffer: 2 * 1024 * 1024,
    });
    await executableHelpers(nodePty.directory);
    await verifyNativeBuildPaths(nodePty.directory);
    verification = await verifyNativePty();
  }
  const packages = await copyDependencyLicenses();
  console.info(`Electron ${verification.electron} PTY ready (${verification.platform}/${verification.arch}, Node-API ${verification.napi}); ${packages.length} license records prepared.`);
  return verification;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  prepareNative({ forceRebuild: process.argv.includes('--force-rebuild') }).catch(error => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
