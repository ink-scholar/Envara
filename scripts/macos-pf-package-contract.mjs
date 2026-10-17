import assert from 'node:assert/strict';

export const PF_AUTHORIZATION_PACKAGE_DIRECTORY = 'build/package-resources/local-authorization';

/** Read the reviewed literal pin without importing the Electron runtime. */
export function parsePFPackageCandidate(source) {
  const matches = [...String(source).matchAll(/export const PF_NOTION_TRIAL_CANDIDATE = Object\.freeze\(\{\s*authorizerSHA256: '([0-9a-f]{64})',\s*manifestSHA256: '([0-9a-f]{64})',\s*\}\);/g)];
  assert.equal(matches.length, 1, 'Exactly one literal reviewed PF candidate pin is required');
  const [, authorizerSHA256, manifestSHA256] = matches[0];
  return { authorizerSHA256, manifestSHA256, carrierName: `EnvaraPFAuthorization-${manifestSHA256.slice(0, 12)}.app` };
}
