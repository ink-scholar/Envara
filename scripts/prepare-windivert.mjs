import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { selectedZipFiles, tarGzFiles } from './prepare-playwright-driver.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
export const WINDIVERT = Object.freeze({
  version: '2.2.2',
  commit: '1789526ecfb9ff5397c94f9f54c1a3dc2fb60440',
  archiveUrl: 'https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip',
  archiveSha256: '63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15',
  sourceSha256: '2955621df8f6ef32ad65170f0c0f11bd2f261cf5a960624f416d0b9c6343e99c',
  dllSha256: 'c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2',
  driverSha256: '8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2',
});
export function sha256(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
function verified(bytes, digest) {
  if (sha256(bytes) !== digest) throw new Error('Pinned WinDivert artifact SHA-256 mismatch.');
  return bytes;
}
function cachedDownload(url, digest, cache) {
  const file = path.join(cache, digest);
  try { return verified(readFileSync(file), digest); } catch { /* Download exact pinned bytes. */ }
  const bytes = execFileSync('curl', ['--fail', '--location', '--silent', '--show-error', '--connect-timeout', '20', '--max-time', '180', url], {
    encoding: null, maxBuffer: 32 * 1024 * 1024,
  });
  verified(bytes, digest);
  mkdirSync(cache, { recursive: true });
  writeFileSync(file, bytes);
  return bytes;
}
export function extractWinDivert(archive, source) {
  verified(archive, WINDIVERT.archiveSha256);
  verified(source, WINDIVERT.sourceSha256);
  const prefix = 'WinDivert-2.2.2-A/';
  const wanted = ['x64/WinDivert.dll', 'x64/WinDivert64.sys', 'x64/WinDivert.lib', 'include/windivert.h', 'LICENSE', 'README'];
  const files = selectedZipFiles(archive, new Set(wanted.map(name => prefix + name)));
  const result = new Map();
  for (const name of wanted) {
    if (!files.has(prefix + name)) throw new Error(`WinDivert archive is missing ${name}.`);
    result.set(name, files.get(prefix + name));
  }
  verified(result.get('x64/WinDivert.dll'), WINDIVERT.dllSha256);
  verified(result.get('x64/WinDivert64.sys'), WINDIVERT.driverSha256);
  const sourceFiles = tarGzFiles(source);
  const sourceRoot = `WinDivert-${WINDIVERT.commit}/`;
  for (const name of ['LICENSE', 'include/windivert.h', 'sys/windivert.c', 'dll/windivert.c', 'msvc-build.bat']) {
    if (!sourceFiles.has(sourceRoot + name)) throw new Error(`WinDivert source is missing ${name}.`);
  }
  return result;
}
export function prepareWinDivert({ destination = path.join(root, '.cache/windivert/sdk'), cache = path.join(root, '.cache/windivert/archives') } = {}) {
  const sourceUrl = `https://codeload.github.com/basil00/WinDivert/tar.gz/${WINDIVERT.commit}`;
  const archive = cachedDownload(WINDIVERT.archiveUrl, WINDIVERT.archiveSha256, cache);
  const source = cachedDownload(sourceUrl, WINDIVERT.sourceSha256, cache);
  const files = extractWinDivert(archive, source);
  for (const [name, bytes] of files) {
    const target = path.join(destination, name);
    mkdirSync(path.dirname(target), { recursive: true });
    writeFileSync(target, bytes);
  }
  writeFileSync(path.join(destination, 'WinDivert-corresponding-source.tar.gz'), source);
  writeFileSync(path.join(destination, 'provenance.json'), JSON.stringify({
    ...WINDIVERT, sourceUrl, architecture: 'x64',
    relationship: 'Unmodified official DLL and signed driver; dynamically loaded by EnvaraCapture.dll. No private driver re-signing.',
    signatureVerification: 'Original certificate table retained. Windows Authenticode trust, Secure Boot/HVCI and driver loading require native acceptance.',
    correspondingSource: 'WinDivert-corresponding-source.tar.gz',
  }, null, 2) + '\n');
  return destination;
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { console.log(`Prepared pinned WinDivert x64 dependency: ${prepareWinDivert()}`); }
  catch (error) { console.error(error.message); process.exitCode = 1; }
}
