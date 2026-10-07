import fs from 'node:fs/promises';
import path from 'node:path';

export function signingOptions(argv, env = {}) {
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
  return { mode, identity, hostProfile, extensionProfile, signing: mode !== 'unsigned' };
}

export function outputDirectory(root, mode) {
  return path.join(root, mode === 'development' ? 'build/development-app-routing/macos' : 'build/app-routing/macos');
}

export async function cleanSigningArtifacts(host, provider) {
  for (const bundle of [host, provider]) {
    for (const relative of ['Contents/embedded.provisionprofile', 'Contents/_CodeSignature', '_CodeSignature',
      'Contents/CodeResources', 'Contents/Resources/routing-acceptance.plist']) {
      await fs.rm(path.join(bundle, relative), { recursive: true, force: true });
    }
  }
}
