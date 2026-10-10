import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { execFile as execFileCallback } from 'node:child_process';
import { promisify } from 'node:util';
import { inspectDependency, lock } from '../native/macos-local-routing/dependency.mjs';

const execute = promisify(execFileCallback);
const root = fileURLToPath(new URL('../', import.meta.url));
const resources = path.join(root, 'build/app-routing/macos-local');

export async function installOriginalMacOSRouting({ install = false } = {}) {
  if (process.platform !== 'darwin') throw new Error('macOS required.');
  const source = path.join(resources, 'Resources/Mitmproxy Redirector.app');
  const bundled = await inspectDependency({ appPath: source });
  if (!bundled.binaryVerified || !bundled.gatekeeperAccepted) throw new Error('Prepare and verify the original signed component first.');
  const existing = await inspectDependency();
  if (!install) return { operation: 'plan', bundledVerified: true, existing: { present: existing.present, verified: existing.binaryVerified },
    destination: lock.installedAppPath, overwritesExisting: false, activatesExtension: false, installsCertificate: false };
  if (existing.present) {
    if (!existing.binaryVerified || !existing.gatekeeperAccepted) throw new Error('An existing Redirector is present. It will not be changed.');
    return { operation: 'reuse', originalSignatureVerified: true, activated: false };
  }
  const stage = `/Applications/.EnvaraRoutingStage-${randomUUID()}.app`;
  await fs.mkdir(stage, { mode: 0o700 });
  try {
    // Copies only the verified Redirector. The certificate-truster is not part
    // of the prepared resources, and no system preferences are changed.
    await fs.cp(source, stage, { recursive: true, force: false, errorOnExist: true, preserveTimestamps: true });
    const staged = await inspectDependency({ appPath: stage });
    if (!staged.binaryVerified || !staged.gatekeeperAccepted) throw new Error('Staged original signature verification failed.');
    await fs.chmod(stage, 0o755);
    await execute(path.join(resources, 'EnvaraInstallOriginal'), [stage], { timeout: 5000, env: { PATH: '/usr/bin:/bin' } });
    const installed = await inspectDependency();
    if (!installed.binaryVerified || !installed.gatekeeperAccepted) throw new Error('Installed component could not be verified; preserve it for inspection.');
    return { operation: 'installed', originalSignatureVerified: true, activated: false, ready: false };
  } finally { await fs.rm(stage, { recursive: true, force: true }); }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.slice(2).some(arg => arg !== '--install')) throw new Error('Only explicit --install is supported; default is read-only.');
  console.log(JSON.stringify(await installOriginalMacOSRouting({ install: process.argv.includes('--install') })));
}
