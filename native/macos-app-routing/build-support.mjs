import fs from 'node:fs/promises';
import path from 'node:path';

export function signingOptions(argv, env = {}) {
  let reuseProvider;
  for (let index = 0; index < argv.length; index++) {
    if (argv[index] !== '--reuse-provider') continue;
    if (reuseProvider || !argv[index + 1] || argv[index + 1].startsWith('--')) {
      throw new Error('One explicit production provider manifest is required for --reuse-provider.');
    }
    reuseProvider = path.resolve(argv[++index]);
  }
  const production = argv.includes('--sign'), development = argv.includes('--development-sign');
  if (production && development) throw new Error('Choose only one signing mode.');
  const requested = env.ENVARA_MAC_SIGN_MODE;
  if (requested && !['unsigned', 'developer-id', 'development'].includes(requested)) throw new Error('Unknown macOS signing mode.');
  const explicit = development ? 'development' : production ? 'developer-id' : undefined;
  if (requested && explicit && requested !== explicit) throw new Error('CLI and environment signing modes disagree.');
  const mode = explicit ?? requested ?? 'unsigned';
  const identity = env.ENVARA_MAC_SIGN_IDENTITY;
  const hostProfile = env.ENVARA_MAC_HOST_PROFILE, extensionProfile = env.ENVARA_MAC_EXTENSION_PROFILE;
  if (mode !== 'unsigned') {
    const prefix = mode === 'development' ? 'Apple Development:' : 'Developer ID Application:';
    if (!identity?.startsWith(prefix) || !hostProfile || !extensionProfile) {
      throw new Error(`Explicit ${prefix} identity and both provisioning-profile paths are required.`);
    }
  }
  const acceptance = argv.includes('--acceptance'), receipt = env.ENVARA_MAC_ACCEPTANCE_RECEIPT;
  if (receipt && acceptance) throw new Error('An acceptance helper cannot include a production acceptance receipt.');
  if (receipt && (mode === 'unsigned' || !reuseProvider)) {
    throw new Error('A receipt build requires signing and explicit --reuse-provider of the tested production manifest.');
  }
  return { mode, identity, hostProfile, extensionProfile, signing: mode !== 'unsigned', acceptance, reuseProvider, receipt };
}

export function outputDirectory(root, mode, acceptance = false) {
  if (acceptance) return path.join(root, 'build/acceptance-app-routing/macos');
  return path.join(root, mode === 'development' ? 'build/development-app-routing/macos' : 'build/app-routing/macos');
}

export async function cleanSigningArtifacts(host, ...providers) {
  for (const bundle of [host, ...providers]) {
    for (const relative of ['Contents/embedded.provisionprofile', 'Contents/_CodeSignature', '_CodeSignature',
      'Contents/CodeResources', 'Contents/Resources/routing-acceptance.plist']) {
      await fs.rm(path.join(bundle, relative), { recursive: true, force: true });
    }
  }
}
