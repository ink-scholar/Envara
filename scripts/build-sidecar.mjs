import { createHash, randomUUID } from 'node:crypto';
import { execFile as execFileCallback } from 'node:child_process';
import { access, chmod, mkdir, readFile, readdir, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { treeSha256 } from './prepare-playwright-driver.mjs';

const execFile = promisify(execFileCallback);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const GO_VERSION = '1.25.0';

export function nativeGoTarget(platform = process.platform, arch = process.arch) {
  const goos = { darwin: 'darwin', win32: 'windows', linux: 'linux' }[platform];
  const goarch = { x64: 'amd64', arm64: 'arm64' }[arch];
  if (!goos || !goarch) throw new Error(`Unsupported native sidecar target ${platform}/${arch}.`);
  return { goos, goarch, executable: platform === 'win32' ? 'BrowseForge-sidecar.exe' : 'BrowseForge-sidecar' };
}

async function exists(file) { try { await access(file); return true; } catch { return false; } }

async function copyLicense(source, destination) {
  // Go's immutable module cache uses 0444 files. Build outputs must remain
  // replaceable on subsequent runs without changing source-cache permissions.
  const temporary = `${destination}.tmp-${randomUUID()}`;
  try {
    await writeFile(temporary, await readFile(source), { mode: 0o644, flag: 'wx' });
    if (process.platform === 'win32' && await exists(destination)) {
      await chmod(destination, 0o644);
      await rm(destination);
    }
    await rename(temporary, destination);
  } finally { await rm(temporary, { force: true }); }
}

export async function copyModuleLicenses(cache, output) {
  await mkdir(output, { recursive: true });
  const dependencies = [
    ['github.com/go-chi/chi/v5@v5.1.0', 'go-chi'],
    ['github.com/mxschmitt/playwright-go@v0.6100.0', 'playwright-go'],
    ['golang.org/x/net@v0.53.0', 'golang-x-net'],
    ['gopkg.in/yaml.v3@v3.0.1', 'yaml-v3'],
    ['github.com/deckarep/golang-set/v2@v2.8.0', 'golang-set'],
    ['github.com/go-jose/go-jose/v3@v3.0.5', 'go-jose'],
    ['github.com/go-stack/stack@v1.8.1', 'go-stack'],
  ];
  const copied = [];
  for (const [modulePath, label] of dependencies) {
    const directory = path.join(cache, modulePath);
    if (!await exists(directory)) continue;
    for (const name of await readdir(directory)) {
      if (!/^(?:LICENSE|COPYING|NOTICE)(?:\..*)?$/i.test(name)) continue;
      const destination = `${label}-${name}`;
      await copyLicense(path.join(directory, name), path.join(output, destination));
      copied.push(destination);
    }
  }
  return copied.sort();
}

export async function buildSidecar({ rootDir = ROOT, outputDir = path.join(rootDir, 'build', 'backend'), env = process.env, goExecutable = env.ENVARA_GO_BINARY || 'go' } = {}) {
  const target = nativeGoTarget();
  if (env.GOOS && env.GOOS !== target.goos || env.GOARCH && env.GOARCH !== target.goarch) {
    throw new Error('Build the sidecar on a native CI runner for the packaging target.');
  }
  const sourceDir = path.join(rootDir, 'third_party', 'browseforge');
  const goMod = await readFile(path.join(sourceDir, 'go.mod'), 'utf8');
  if (!goMod.includes(`go ${GO_VERSION}`)) throw new Error('Update the pinned Go toolchain to match the vendored module.');
  const sourceTreeSha256 = await treeSha256(sourceDir);
  const prototype = path.join(rootDir, 'test-artifacts', 'sidecar-prototype');
  const prototypeModules = path.join(prototype, 'go-mod-cache');
  const prototypeBuildCache = path.join(prototype, 'go-cache');
  const moduleCache = env.GOMODCACHE || (await exists(prototypeModules) ? prototypeModules : path.join(rootDir, '.cache', 'go-mod'));
  const buildCache = env.GOCACHE || (await exists(prototypeBuildCache) ? prototypeBuildCache : path.join(rootDir, '.cache', 'go-build'));
  const buildEnv = {
    ...env, GOOS: target.goos, GOARCH: target.goarch, CGO_ENABLED: '0',
    GOTOOLCHAIN: `go${GO_VERSION}`, GOMODCACHE: path.resolve(moduleCache), GOCACHE: path.resolve(buildCache),
  };
  await mkdir(outputDir, { recursive: true });
  const temporary = path.join(outputDir, `.${target.executable}-${randomUUID()}`);
  const binary = path.join(outputDir, target.executable);
  try {
    const app = JSON.parse(await readFile(path.join(rootDir, 'package.json'), 'utf8'));
    const version = `2.1.15-envara.${app.version}`;
    const toolchain = (await execFile(goExecutable, ['version'], { cwd: sourceDir, env: buildEnv })).stdout.trim();
    if (!toolchain.includes(`go${GO_VERSION} `)) throw new Error('Go toolchain version did not match the pinned build.');
    await execFile(goExecutable, [
      'build', '-trimpath', '-buildvcs=false', '-mod=readonly',
      '-ldflags', `-s -w -buildid= -X main.Version=${version}`, '-o', temporary, './cmd/server',
    ], { cwd: sourceDir, env: buildEnv, maxBuffer: 16 * 1024 * 1024 });
    if (process.platform !== 'win32') await chmod(temporary, 0o755);
    const check = (await execFile(temporary, ['version'], { timeout: 15000 })).stdout.trim();
    if (check !== `BrowseForge ${version}`) throw new Error('Compiled sidecar version check failed.');
    if (await treeSha256(sourceDir) !== sourceTreeSha256) throw new Error('Vendored sources changed during the build; rerun after edits settle.');
    const licenseDir = path.join(outputDir, 'licenses');
    const licenses = await copyModuleLicenses(buildEnv.GOMODCACHE, licenseDir);
    await copyLicense(path.join(sourceDir, 'LICENSE'), path.join(licenseDir, 'BrowseForge-LICENSE'));
    licenses.push('BrowseForge-LICENSE');
    // The bundled EasyPrivacy list is embedded unmodified; its licence and
    // attribution travel with the binary.
    const trackerListDir = path.join(sourceDir, 'internal', 'browser', 'trackerlists', 'easyprivacy');
    const trackerList = JSON.parse(await readFile(path.join(trackerListDir, 'provenance.json'), 'utf8'));
    await copyLicense(path.join(trackerListDir, 'NOTICE.md'), path.join(licenseDir, 'EasyPrivacy-NOTICE.md'));
    licenses.push('EasyPrivacy-NOTICE.md');
    const goRoot = (await execFile(goExecutable, ['env', 'GOROOT'], { cwd: sourceDir, env: buildEnv })).stdout.trim();
    await copyLicense(path.join(goRoot, 'LICENSE'), path.join(licenseDir, 'Go-LICENSE'));
    licenses.push('Go-LICENSE');
    const provenance = {
      schema: 'envara.browseforge-sidecar', version: 1, upstreamVersion: '2.1.15', envaraVersion: app.version,
      upstreamCommit: 'fa9e0bb670e749706a9c8f2d4095333347d6c521',
      goVersion: GO_VERSION, goos: target.goos, goarch: target.goarch, cgo: false,
      buildFlags: ['-trimpath', '-buildvcs=false', '-mod=readonly', '-s', '-w', '-buildid='],
      sourceTreeSha256,
      trackerList: { name: trackerList.list, source: trackerList.source, commit: trackerList.commit, files: trackerList.files.length },
      binarySha256: createHash('sha256').update(await readFile(temporary)).digest('hex'),
      licenses: licenses.sort(),
    };
    // The artifact is replaced only after compilation and the executable check.
    if (process.platform === 'win32' && await exists(binary)) await rm(binary);
    await rename(temporary, binary);
    await writeFile(path.join(outputDir, 'sidecar-provenance.json'), `${JSON.stringify(provenance, null, 2)}\n`);
    return { binary, provenance };
  } catch (error) { await rm(temporary, { force: true }); throw error; }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const built = await buildSidecar();
    console.log(`Built native BrowseForge sidecar: ${built.binary}`);
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
