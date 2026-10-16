import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { swiftBuildPathOptions } from './macos-swift-build-paths.mjs';
import { cleanSigningArtifacts, outputDirectory, signingOptions } from '../native/macos-app-routing/build-support.mjs';
import { copyProviderVerbatim, fingerprintProvider, productionIdentity, providerRecord, readProviderReuse,
  validateReceiptProvider } from '../native/macos-app-routing/provider-reuse.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const source = path.join(root, 'native/macos-app-routing');
const options = signingOptions(process.argv.slice(2), process.env);
const output = outputDirectory(root, options.mode, options.acceptance);
const scratch = path.join(output, '.swift-build');
const { hostIdentifier, providerIdentifier, applicationGroup: groupIdentifier } = productionIdentity;
const runtimeNamespace = options.acceptance ? 'owned-fixture-acceptance' : 'production';
const helper = path.join(output, options.acceptance ? 'EnvaraRoutingAcceptance.app' : 'EnvaraAppRouting.app');
const extension = path.join(helper, `Contents/Library/SystemExtensions/${providerIdentifier}.systemextension`);
const fixtures = ['one', 'two'].map((slot, index) => ({
  slot, name: `EnvaraRoutingFixture${index === 0 ? 'One' : 'Two'}`, identifier: `io.envara.routing.fixture.${slot}`,
}));

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
const reusePath = options.reuseProvider ?? (options.acceptance
  ? path.join(outputDirectory(root, options.mode), 'manifest.json') : undefined);
// Inspect source/receipt bytes before changing build output. Signing authority is
// checked below by the native Security validator; a manifest is never authority.
const reused = reusePath ? await readProviderReuse(reusePath, { mode: options.mode }) : undefined;
let receiptBytes;
if (options.receipt) {
  receiptBytes = await fs.readFile(options.receipt);
  if (receiptBytes.length > 1_048_576) throw new Error('Native receipt exceeds its size limit.');
  const receipt = JSON.parse(await run('/usr/bin/plutil', ['-convert', 'json', '-o', '-', '-'], { capture: true, input: receiptBytes }));
  const osMajor = Number.parseInt(await run('/usr/bin/sw_vers', ['-productVersion'], { capture: true }), 10);
  if (!Number.isInteger(osMajor)) throw new Error('Current macOS version could not be verified.');
  validateReceiptProvider(receipt, reused.fingerprint, { osMajor });
}
// Keep desktop development responsive on the user's Mac.
const argumentsForSwift = ['build', '-c', 'release', '--jobs', '2', '--scratch-path', scratch,
  ...swiftBuildPathOptions(root)];
if (options.mode === 'development') argumentsForSwift.push('-Xswiftc', '-DENVARA_LOCAL_DEVELOPMENT_ROUTING');
if (options.acceptance) argumentsForSwift.push('-Xswiftc', '-DENVARA_NATIVE_ROUTING_ACCEPTANCE');
if (reused) {
  // --product prevents compiling a second Provider with acceptance flags. The
  // sole Provider we distribute here is the previously sealed production copy.
  for (const product of ['EnvaraAppRoutingHelper', 'EnvaraRoutingSigningCheck',
    ...(options.acceptance ? ['EnvaraRoutingAcceptanceFixture'] : [])]) {
    await run('swift', [...argumentsForSwift, '--product', product]);
  }
} else { await run('swift', argumentsForSwift); }

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
      capture: true, input: JSON.stringify({ mode: options.mode, identity: options.identity, hostProfile: copies[0], extensionProfile: copies[1],
        ...(reused ? { providerBundle: reused.bundle } : {}) }),
    }));
    const hash = bytes => createHash('sha256').update(bytes).digest('hex');
    if (proof.verified !== true || proof.mode !== options.mode || proof.host?.teamIdentifier !== proof.provider?.teamIdentifier ||
      proof.host?.certificateSHA256 !== proof.provider?.certificateSHA256 ||
      proof.host?.profileSHA256 !== hash(profileBytes[0]) || proof.provider?.profileSHA256 !== hash(profileBytes[1])) {
      throw new Error('Signing profile proof does not match the exact input bytes.');
    }
    if (reused) {
      const bundled = proof.providerBundle, previous = reused.manifest.profileVerification;
      const fields = ['teamIdentifier', 'applicationIdentifier', 'certificateSHA256', 'certificateSHA1', 'profileSHA256'];
      if (!bundled || previous.mode !== options.mode || previous.networkEntitlement !== proof.networkEntitlement ||
          fields.some(key => bundled[key] !== proof.provider[key] || previous.provider?.[key] !== bundled[key]) ||
          previous.host?.teamIdentifier !== proof.host.teamIdentifier ||
          previous.host?.certificateSHA256 !== proof.host.certificateSHA256) {
        throw new Error('Reused provider authorization does not match the exact signing inputs.');
      }
    }
  }
  const stagedProvider = path.join(privateTemporary, `${providerIdentifier}.systemextension`);
  if (reused) await copyProviderVerbatim(reused.bundle, stagedProvider, reused.fingerprint);
  // The staging copy protects receipt finalization when source and destination
  // are the same production bundle. Never clean/re-sign the staging Provider.
  await cleanSigningArtifacts(helper, ...(reused ? [] : [extension]));
  // Only this build owns the output host. Remove stale providers from an older
  // acceptance-ID build instead of accidentally sealing two extensions.
  await fs.rm(path.join(helper, 'Contents/Library/SystemExtensions'), { recursive: true, force: true });
  await fs.rm(path.join(helper, 'Contents/Helpers'), { recursive: true, force: true });
  await fs.rm(path.join(helper, 'Contents/Resources/acceptance-fixtures.json'), { force: true });
  await fs.rm(path.join(helper, 'Contents/Resources/provider-reuse.json'), { force: true });
  await fs.rm(path.join(output, 'manifest.json'), { force: true });
  await fs.mkdir(path.join(helper, 'Contents/MacOS'), { recursive: true });
  await fs.mkdir(path.join(extension, 'Contents/MacOS'), { recursive: true });
  await fs.mkdir(path.join(helper, 'Contents/Resources'), { recursive: true });
  for (const [from, to] of [
    [path.join(scratch, 'release/EnvaraAppRoutingHelper'), path.join(helper, 'Contents/MacOS/EnvaraAppRoutingHelper')],
    [path.join(source, 'Resources/Helper-Info.plist'), path.join(helper, 'Contents/Info.plist')],
  ]) await fs.copyFile(from, to);
  await fs.chmod(path.join(helper, 'Contents/MacOS/EnvaraAppRoutingHelper'), 0o755);
  if (reused) {
    await fs.rm(extension, { recursive: true, force: true });
    await copyProviderVerbatim(stagedProvider, extension, reused.fingerprint);
  } else {
    await fs.copyFile(path.join(scratch, 'release/EnvaraAppProxy'), path.join(extension, 'Contents/MacOS/EnvaraAppProxy'));
    await fs.copyFile(path.join(source, 'Resources/Extension-Info.plist'), path.join(extension, 'Contents/Info.plist'));
    await fs.chmod(path.join(extension, 'Contents/MacOS/EnvaraAppProxy'), 0o755);
  }

  async function writePlist(value, filename) {
    await run('/usr/bin/plutil', ['-convert', 'xml1', '-o', filename, '-'], { capture: true, input: JSON.stringify(value) });
  }
  if (options.acceptance) {
    {
      const filename = path.join(helper, 'Contents/Info.plist');
      const info = JSON.parse(await run('/usr/bin/plutil', ['-convert', 'json', '-o', '-', filename], { capture: true }));
      info.CFBundleIdentifier = hostIdentifier;
      info.CFBundleName = 'Envara Routing Acceptance';
      await writePlist(info, filename);
    }
    for (const fixture of fixtures) {
      fixture.bundle = path.join(helper, `Contents/Helpers/${fixture.name}.app`);
      fixture.executable = path.join(fixture.bundle, 'Contents/MacOS/EnvaraRoutingAcceptanceFixture');
      await fs.mkdir(path.dirname(fixture.executable), { recursive: true });
      await fs.copyFile(path.join(scratch, 'release/EnvaraRoutingAcceptanceFixture'), fixture.executable);
      await fs.chmod(fixture.executable, 0o755);
      await writePlist({ CFBundleIdentifier: fixture.identifier, CFBundleName: fixture.name,
        CFBundleExecutable: 'EnvaraRoutingAcceptanceFixture', CFBundlePackageType: 'APPL', CFBundleVersion: '1',
        CFBundleShortVersionString: '1.0', LSMinimumSystemVersion: '13.0', LSUIElement: true,
      }, path.join(fixture.bundle, 'Contents/Info.plist'));
    }
  }
  if (!reused) {
    const filename = path.join(extension, 'Contents/Info.plist');
    const info = JSON.parse(await run('/usr/bin/plutil', ['-convert', 'json', '-o', '-', filename], { capture: true }));
    info.NetworkExtension ??= {};
    info.NetworkExtension.NEMachServiceName = `${groupIdentifier}.service`;
    await writePlist(info, filename);
  }
  if (reused) await fs.writeFile(path.join(helper, 'Contents/Resources/provider-reuse.json'), JSON.stringify({
    version: 1, providerIdentifier, provider: providerRecord(reused.fingerprint, `${providerIdentifier}.systemextension`),
    runtimeNamespace, acceptanceOnly: options.acceptance,
  }, null, 2));

  if (options.signing) {
    await fs.writeFile(path.join(helper, 'Contents/embedded.provisionprofile'), profileBytes[0], { mode: 0o600 });
    if (!reused) await fs.writeFile(path.join(extension, 'Contents/embedded.provisionprofile'), profileBytes[1], { mode: 0o600 });
    if (receiptBytes) await fs.writeFile(path.join(helper, 'Contents/Resources/routing-acceptance.plist'), receiptBytes, { mode: 0o600 });
    const entitlementFiles = [];
    for (const [index, name] of ['Helper', 'Extension'].entries()) {
      const original = JSON.parse(await run('/usr/bin/plutil', ['-convert', 'json', '-o', '-', path.join(source, `Resources/${name}.entitlements.plist`)], { capture: true }));
      const item = index === 0 ? proof.host : proof.provider;
      original['com.apple.developer.networking.networkextension'] = [proof.networkEntitlement];
      original['com.apple.developer.team-identifier'] = item.teamIdentifier;
      original['com.apple.application-identifier'] = item.applicationIdentifier;
      original['com.apple.security.application-groups'] = [groupIdentifier];
      const filename = path.join(privateTemporary, `${name}.entitlements.plist`);
      await run('/usr/bin/plutil', ['-convert', 'xml1', '-o', filename, '-'], { capture: true, input: JSON.stringify(original) });
      await fs.chmod(filename, 0o600); entitlementFiles.push(filename);
    }
    const timestamp = options.mode === 'developer-id' ? ['--timestamp'] : ['--timestamp=none'];
    const identity = proof.host.certificateSHA1;
    if (!reused) await run('/usr/bin/codesign', ['--force', '--options', 'runtime', ...timestamp, '--sign', identity,
      '--entitlements', entitlementFiles[1], extension]);
    if (options.acceptance) for (const fixture of fixtures) await run('/usr/bin/codesign',
      ['--force', '--options', 'runtime', ...timestamp, '--sign', identity, fixture.bundle]);
    if (options.acceptance) await writeFixtureManifest();
    await run('/usr/bin/codesign', ['--force', '--options', 'runtime', ...timestamp, '--sign', identity,
      '--entitlements', entitlementFiles[0], helper]);
    const marker = options.mode === 'development' ? '1.2.840.113635.100.6.1.12' : '1.2.840.113635.100.6.1.13';
    for (const bundle of [extension, helper]) await run('/usr/bin/codesign', ['--verify', '--strict', '--deep', '-R',
      `anchor apple generic and certificate leaf[field.${marker}] exists`, bundle]);
  }
  if (options.acceptance && !options.signing) await writeFixtureManifest();
  async function writeFixtureManifest() {
    const entries = {};
    for (const fixture of fixtures) entries[fixture.slot] = { identifier: fixture.identifier,
      bundle: `${fixture.name}.app`, sha256: createHash('sha256').update(await fs.readFile(fixture.executable)).digest('hex') };
    await fs.writeFile(path.join(helper, 'Contents/Resources/acceptance-fixtures.json'), JSON.stringify({ version: 1, fixtures: entries }, null, 2));
  }
  const providerFingerprint = await fingerprintProvider(extension);
  if (reused && (providerFingerprint.bundleSHA256 !== reused.fingerprint.bundleSHA256 ||
      providerFingerprint.binarySHA256 !== reused.fingerprint.binarySHA256)) {
    throw new Error('Host sealing changed the tested production provider bundle.');
  }
  await fs.writeFile(path.join(output, 'manifest.json'), JSON.stringify({
    version: 1, platform: 'darwin', architecture: process.arch,
    helper: `${path.basename(helper)}/Contents/MacOS/EnvaraAppRoutingHelper`, args: [options.acceptance ? '--acceptance-rpc' : '--rpc'],
    signed: options.signing, signingMode: options.mode, profileVerification: proof ?? { verified: false },
    activated: false, installedProfile: false, acceptanceOnly: options.acceptance,
    hostIdentifier, providerIdentifier, applicationGroup: groupIdentifier,
    runtimeNamespace, provider: providerRecord(providerFingerprint,
      `${path.basename(helper)}/Contents/Library/SystemExtensions/${providerIdentifier}.systemextension`),
    reusedProductionProvider: Boolean(reused),
    productionReceiptAllowed: !options.acceptance,
  }, null, 2));
  console.log(`Built macOS application-routing source (${options.mode}; activation and real acceptance still required)`);
} finally {
  await fs.rm(privateTemporary, { recursive: true, force: true });
}
