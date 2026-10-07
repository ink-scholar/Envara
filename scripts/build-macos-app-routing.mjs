import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cleanSigningArtifacts, outputDirectory, signingOptions } from '../native/macos-app-routing/build-support.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const source = path.join(root, 'native/macos-app-routing');
const options = signingOptions(process.argv.slice(2), process.env);
const output = outputDirectory(root, options.mode);
const scratch = path.join(output, '.swift-build');
const helper = path.join(output, 'EnvaraAppRouting.app');
const extension = path.join(helper, 'Contents/Library/SystemExtensions/io.envara.app-routing.proxy.systemextension');

async function run(command, args, { input, capture = false, ...settings } = {}) {
  return await new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd: source, stdio: capture ? ['pipe', 'pipe', 'pipe'] : 'inherit', ...settings });
    let stdout = '', stderr = '';
    if (capture) {
      child.stdout.on('data', chunk => { stdout += chunk; });
      child.stderr.on('data', chunk => { stderr += chunk; });
      child.stdin.end(input ?? '');
    }
    child.once('error', reject);
    child.once('exit', code => code === 0 ? resolve(stdout) : reject(new Error(capture ? `${command} failed (${code}): ${stderr.trim()}` : `${command} failed (${code})`)));
  });
}

if (process.platform !== 'darwin') throw new Error('The macOS app-routing helper must be built on macOS with Xcode.');
const argumentsForSwift = ['build', '-c', 'release', '--scratch-path', scratch];
if (options.mode === 'development') argumentsForSwift.push('-Xswiftc', '-DENVARA_LOCAL_DEVELOPMENT_ROUTING');
await run('swift', argumentsForSwift);

// Validate the exact bytes before touching the output bundle. No network,
// keychain creation, profile installation or extension activation occurs here.
let proof, profileBytes;
const privateTemporary = await fs.mkdtemp(path.join(scratch, 'signing-input-'));
try {
  await fs.chmod(privateTemporary, 0o700);
  if (options.signing) {
    profileBytes = await Promise.all([options.hostProfile, options.extensionProfile].map(filename => fs.readFile(filename)));
    const copies = ['host.provisionprofile', 'provider.provisionprofile'].map(name => path.join(privateTemporary, name));
    for (let index = 0; index < copies.length; index++) await fs.writeFile(copies[index], profileBytes[index], { mode: 0o600 });
    proof = JSON.parse(await run(path.join(scratch, 'release/EnvaraRoutingSigningCheck'), [], {
      capture: true, input: JSON.stringify({ mode: options.mode, identity: options.identity, hostProfile: copies[0], extensionProfile: copies[1] }),
    }));
    const hash = bytes => createHash('sha256').update(bytes).digest('hex');
    if (proof.verified !== true || proof.mode !== options.mode || proof.host?.teamIdentifier !== proof.provider?.teamIdentifier ||
      proof.host?.certificateSHA256 !== proof.provider?.certificateSHA256 ||
      proof.host?.profileSHA256 !== hash(profileBytes[0]) || proof.provider?.profileSHA256 !== hash(profileBytes[1])) {
      throw new Error('Signing profile proof does not match the exact input bytes.');
    }
  }
  await cleanSigningArtifacts(helper, extension);
  await fs.rm(path.join(output, 'manifest.json'), { force: true });
  await fs.mkdir(path.join(helper, 'Contents/MacOS'), { recursive: true });
  await fs.mkdir(path.join(extension, 'Contents/MacOS'), { recursive: true });
  await fs.mkdir(path.join(helper, 'Contents/Resources'), { recursive: true });
  for (const [from, to] of [
    [path.join(scratch, 'release/EnvaraAppRoutingHelper'), path.join(helper, 'Contents/MacOS/EnvaraAppRoutingHelper')],
    [path.join(scratch, 'release/EnvaraAppProxy'), path.join(extension, 'Contents/MacOS/EnvaraAppProxy')],
    [path.join(source, 'Resources/Helper-Info.plist'), path.join(helper, 'Contents/Info.plist')],
    [path.join(source, 'Resources/Extension-Info.plist'), path.join(extension, 'Contents/Info.plist')],
  ]) await fs.copyFile(from, to);
  await fs.chmod(path.join(helper, 'Contents/MacOS/EnvaraAppRoutingHelper'), 0o755);
  await fs.chmod(path.join(extension, 'Contents/MacOS/EnvaraAppProxy'), 0o755);

  if (options.signing) {
    await fs.writeFile(path.join(helper, 'Contents/embedded.provisionprofile'), profileBytes[0], { mode: 0o600 });
    await fs.writeFile(path.join(extension, 'Contents/embedded.provisionprofile'), profileBytes[1], { mode: 0o600 });
    const receipt = process.env.ENVARA_MAC_ACCEPTANCE_RECEIPT;
    if (receipt) await fs.copyFile(receipt, path.join(helper, 'Contents/Resources/routing-acceptance.plist'));
    const entitlementFiles = [];
    for (const [index, name] of ['Helper', 'Extension'].entries()) {
      const original = JSON.parse(await run('/usr/bin/plutil', ['-convert', 'json', '-o', '-', path.join(source, `Resources/${name}.entitlements.plist`)], { capture: true }));
      const item = index === 0 ? proof.host : proof.provider;
      original['com.apple.developer.networking.networkextension'] = [proof.networkEntitlement];
      original['com.apple.developer.team-identifier'] = item.teamIdentifier;
      original['com.apple.application-identifier'] = item.applicationIdentifier;
      const filename = path.join(privateTemporary, `${name}.entitlements.plist`);
      await run('/usr/bin/plutil', ['-convert', 'xml1', '-o', filename, '-'], { capture: true, input: JSON.stringify(original) });
      await fs.chmod(filename, 0o600); entitlementFiles.push(filename);
    }
    const timestamp = options.mode === 'developer-id' ? ['--timestamp'] : ['--timestamp=none'];
    const identity = proof.host.certificateSHA1;
    await run('/usr/bin/codesign', ['--force', '--options', 'runtime', ...timestamp, '--sign', identity,
      '--entitlements', entitlementFiles[1], extension]);
    await run('/usr/bin/codesign', ['--force', '--options', 'runtime', ...timestamp, '--sign', identity,
      '--entitlements', entitlementFiles[0], helper]);
    const marker = options.mode === 'development' ? '1.2.840.113635.100.6.1.12' : '1.2.840.113635.100.6.1.13';
    for (const bundle of [extension, helper]) await run('/usr/bin/codesign', ['--verify', '--strict', '--deep', '-R',
      `anchor apple generic and certificate leaf[field.${marker}] exists`, bundle]);
  }
  await fs.writeFile(path.join(output, 'manifest.json'), JSON.stringify({
    version: 1, platform: 'darwin', architecture: process.arch,
    helper: 'EnvaraAppRouting.app/Contents/MacOS/EnvaraAppRoutingHelper', args: ['--rpc'],
    signed: options.signing, signingMode: options.mode, profileVerification: proof ?? { verified: false },
    activated: false, installedProfile: false,
  }, null, 2));
  console.log(`Built macOS application-routing source (${options.mode}; activation and real acceptance still required)`);
} finally {
  await fs.rm(privateTemporary, { recursive: true, force: true });
}
