import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { execFile as execFileCallback } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { selectedZipFiles, tarGzFiles } from './prepare-playwright-driver.mjs';
import { buildPeerVerifier, inspectDependency, lock } from '../native/macos-local-routing/dependency.mjs';

const execute = promisify(execFileCallback);
const root = fileURLToPath(new URL('../', import.meta.url));
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const requireDigest = (bytes, expected) => {
  if (digest(bytes) !== expected) throw new Error('Original macOS routing dependency integrity mismatch.');
  return bytes;
};

/** Prepare signed original resources. This never installs or activates anything. */
export async function buildMacOSLocalRouting() {
  if (process.platform !== 'darwin') throw new Error('Build the macOS routing component on macOS.');
  const outputParent = path.join(root, 'build/app-routing');
  const cache = path.join(root, '.cache/macos-local-routing/artifacts');
  await fs.mkdir(cache, { recursive: true });
  const wheelFile = path.join(cache, `${lock.wheelSha256}.whl`);
  let wheel;
  try { wheel = requireDigest(await fs.readFile(wheelFile), lock.wheelSha256); }
  catch {
    const result = await execute('/usr/bin/curl', ['--fail', '--location', '--silent', '--show-error', '--connect-timeout', '20', '--max-time', '180', '--proto', '=https', '--proto-redir', '=https', lock.wheelUrl], { encoding: 'buffer', maxBuffer: 64 * 1024 * 1024 });
    wheel = requireDigest(result.stdout, lock.wheelSha256);
    await fs.writeFile(wheelFile, wheel, { mode: 0o600 });
  }
  const archiveName = 'mitmproxy_macos/Mitmproxy Redirector.app.tar';
  const archive = selectedZipFiles(wheel, new Set([archiveName])).get(archiveName);
  if (!archive) throw new Error('Original Redirector archive is absent.');
  requireDigest(archive, lock.appArchiveSha256);
  const prefix = 'Mitmproxy Redirector.app/';
  const files = tarGzFiles(gzipSync(archive));
  if (!files.size || [...files.keys()].some(name => !name.startsWith(prefix))) throw new Error('Unexpected original Redirector archive entries.');
  await fs.mkdir(outputParent, { recursive: true });
  const stage = await fs.mkdtemp(path.join(outputParent, '.macos-local-'));
  const output = path.join(outputParent, 'macos-local');
  const backup = `${output}.previous-${randomUUID()}`;
  let movedOld = false;
  try {
    await fs.chmod(stage, 0o700);
    const resources = path.join(stage, 'Resources');
    for (const [name, bytes] of files) {
      const destination = path.join(resources, name);
      await fs.mkdir(path.dirname(destination), { recursive: true });
      await fs.writeFile(destination, bytes, { mode: name.includes('/Contents/MacOS/') ? 0o755 : 0o644 });
    }
    const appPath = path.join(resources, 'Mitmproxy Redirector.app');
    const proof = await inspectDependency({ appPath });
    if (!proof.binaryVerified || !proof.gatekeeperAccepted) throw new Error('Prepared original dependency did not pass signature and Gatekeeper verification.');
    await buildPeerVerifier(path.join(stage, 'EnvaraPeerVerifier'));
    await execute('/usr/bin/clang', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', path.join(root, 'native/macos-local-routing/install-original.c'), '-o', path.join(stage, 'EnvaraInstallOriginal')], { timeout: 15000 });
    await fs.copyFile(path.join(root, 'native/macos-local-routing/dependency-lock.json'), path.join(stage, 'dependency-lock.json'));
    await fs.copyFile(path.join(root, 'native/macos-local-routing/Mitmproxy-LICENSE'), path.join(stage, 'Mitmproxy-LICENSE'));
    const manifest = {
      schemaVersion: 1, platform: 'darwin', architecture: process.arch,
      package: lock.package, version: lock.version, sourceCommit: lock.sourceCommit,
      originalApp: 'Resources/Mitmproxy Redirector.app', peerVerifier: 'EnvaraPeerVerifier', installer: 'EnvaraInstallOriginal',
      originalSignaturePreserved: true, signatureVerified: true, gatekeeperAccepted: true,
      installed: false, activated: false, ready: false,
      acceptance: { tcp: false, udp: false, dns: false, childProcesses: false, failClosed: false },
    };
    await fs.writeFile(path.join(stage, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o644 });
    try {
      const info = await fs.lstat(output);
      if (!info.isDirectory() || info.isSymbolicLink()) throw new Error('Invalid macOS routing output directory.');
      await fs.rename(output, backup); movedOld = true;
    } catch (error) { if (error.code !== 'ENOENT') throw error; }
    await fs.rename(stage, output);
    if (movedOld) await fs.rm(backup, { recursive: true });
    return manifest;
  } catch (error) {
    if (movedOld) {
      try { await fs.access(output); } catch { await fs.rename(backup, output); }
    }
    throw error;
  } finally { await fs.rm(stage, { recursive: true, force: true }); }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const manifest = await buildMacOSLocalRouting();
  console.log(JSON.stringify(manifest));
}
