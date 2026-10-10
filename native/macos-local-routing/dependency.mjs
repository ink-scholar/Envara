// Read-only inspection. Never extracts into /Applications, installs a CA,
// changes preferences, starts an app, or activates a Network Extension.
import { createHash } from 'node:crypto'
import fs from 'node:fs/promises'
import path from 'node:path'
import { execFile as execFileCallback } from 'node:child_process'
import { promisify } from 'node:util'
import { fileURLToPath } from 'node:url'

const execFile = promisify(execFileCallback)
export const lock = JSON.parse(await fs.readFile(new URL('./dependency-lock.json', import.meta.url), 'utf8'))
export const moduleDirectory = path.dirname(fileURLToPath(import.meta.url))
const extensionRelative = `Contents/Library/SystemExtensions/${lock.extensionIdentifier}.systemextension`
const authorizedExtensionStates = new Set(['activated enabled'])

// OS approval persists when no controller is connected. Use an exact state
// whitelist; "activated waiting for user" and unrelated extensions do not count.
export function hasOriginalExtensionAuthorization(systemExtensions) {
  return Array.isArray(systemExtensions) && systemExtensions.some(extension => extension &&
    extension.teamIdentifier === lock.teamIdentifier && extension.bundleIdentifier === lock.extensionIdentifier &&
    authorizedExtensionStates.has(extension.state))
}
async function command(executable, args) {
  return execFile(executable, args, { timeout: 15000, maxBuffer: 512 * 1024, env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin' } })
}
async function info(bundle) {
  const { stdout } = await command('/usr/bin/plutil', ['-convert', 'json', '-o', '-', path.join(bundle, 'Contents/Info.plist')])
  return JSON.parse(stdout)
}
async function signature(bundle, architecture) {
  const { stderr } = await command('/usr/bin/codesign', ['-d', '--verbose=4', '--arch', architecture, bundle])
  const values = Object.fromEntries(stderr.split('\n').map(line => line.match(/^(Identifier|TeamIdentifier|CDHash)=(.+)$/)).filter(Boolean).map(match => [match[1], match[2]]))
  return values
}
async function digest(filename) {
  const handle = await fs.open(filename, 'r')
  try { return createHash('sha256').update(await handle.readFile()).digest('hex') } finally { await handle.close() }
}
async function rejectSymlinkAncestors(filename) {
  for (let current = filename; ; current = path.dirname(current)) {
    if ((await fs.lstat(current)).isSymbolicLink()) throw new Error('dependency symlink unsupported')
    if (path.dirname(current) === current) break
  }
}
export async function inspectDependency({ appPath = lock.installedAppPath, assessGatekeeper = true } = {}) {
  const result = {
    package: lock.package, packageVersion: lock.version, sourceCommit: lock.sourceCommit,
    appPath, present: false, binaryVerified: false, gatekeeperAccepted: false,
    systemExtensions: [], compatibilityVerified: false,
    capabilities: { tcpStreamBridge: true, capture: false, dns: false, children: false, failClosed: false },
    ready: false, protectedLaunchAllowed: false,
  }
  if (process.platform !== 'darwin') return { ...result, reason: 'macOS required' }
  try {
    if (!path.isAbsolute(appPath) || appPath.includes('\0')) throw new Error('absolute app path required')
    const stat = await fs.lstat(appPath)
    // Presence means that any filesystem entry exists, including an ordinary
    // file or dangling symlink. Trust is a separate check, and an installer must
    // never replace an existing untrusted entry by treating it as absent.
    result.present = true
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('invalid dependency bundle')
    // /tmp is a normal macOS symlink; canonicalise inspection-only paths. Runtime
    // activation below is restricted to the original /Applications path.
    const canonical = await fs.realpath(appPath)
    const extension = path.join(canonical, extensionRelative)
    const appExecutable = path.join(canonical, 'Contents/MacOS/Mitmproxy Redirector')
    const extensionExecutable = path.join(extension, 'Contents/MacOS', lock.extensionIdentifier)
    await rejectSymlinkAncestors(appExecutable); await rejectSymlinkAncestors(extensionExecutable)
    const [appInfo, extensionInfo, appHash, extensionHash] = await Promise.all([info(canonical), info(extension), digest(appExecutable), digest(extensionExecutable)])
    for (const [plist, identifier] of [[appInfo, lock.appIdentifier], [extensionInfo, lock.extensionIdentifier]]) {
      if (plist.CFBundleIdentifier !== identifier || plist.CFBundleVersion !== lock.bundleVersion || plist.CFBundleShortVersionString !== lock.bundleShortVersion || plist.LSMinimumSystemVersion !== lock.minimumMacOS) throw new Error('dependency bundle version mismatch')
    }
    if (appHash !== lock.appExecutableSha256 || extensionHash !== lock.extensionExecutableSha256) throw new Error('dependency executable hash mismatch')
    await command('/usr/bin/codesign', ['--verify', '--deep', '--strict', canonical])
    for (const architecture of ['arm64', 'x86_64']) {
      const [appSignature, extensionSignature] = await Promise.all([signature(canonical, architecture), signature(extension, architecture)])
      for (const [signed, identifier, cdhash] of [[appSignature, lock.appIdentifier, lock.appCDHashes[architecture]], [extensionSignature, lock.extensionIdentifier, lock.extensionCDHashes[architecture]]]) {
        if (signed.Identifier !== identifier || signed.TeamIdentifier !== lock.teamIdentifier || signed.CDHash !== cdhash) throw new Error('dependency signing identity mismatch')
      }
    }
    result.binaryVerified = true
    result.bundleVersion = lock.bundleShortVersion; result.teamIdentifier = lock.teamIdentifier
    if (assessGatekeeper) {
      try { await command('/usr/sbin/spctl', ['--assess', '--type', 'execute', canonical]); result.gatekeeperAccepted = true } catch { result.gatekeeperReason = 'Gatekeeper assessment did not accept the original bundle' }
    }
    result.reason = 'Original signed dependency verified; activation and networking acceptance remain separate'
  } catch (error) {
    result.reason = error.code === 'ENOENT' ? 'Original Redirector is not installed' : (error.message.startsWith('dependency') || error.message.startsWith('invalid') || error.message.startsWith('absolute') ? error.message : 'Dependency verification failed')
  }
  try {
    const { stdout } = await command('/usr/bin/systemextensionsctl', ['list'])
    result.systemExtensions = stdout.split('\n').filter(line => /^[*\s]+[A-Z0-9]{10}\s+\S+/.test(line)).map(line => {
      const match = line.match(/^([*\s]+)\s+([A-Z0-9]{10})\s+(\S+)\s+\(([^)]+)\).*\[([^\]]+)\]/)
      return match ? { teamIdentifier: match[2], bundleIdentifier: match[3], version: match[4], state: match[5] } : null
    }).filter(Boolean)
    result.extensionInventoryAvailable = true
  } catch { result.extensionInventoryAvailable = false }
  return result
}

export async function inspectArtifactDigest(filename, expectedHash) {
  return typeof expectedHash === 'string' && /^[a-f0-9]{64}$/.test(expectedHash) && await digest(filename) === expectedHash
}

export async function buildPeerVerifier(outputPath) {
  if (process.platform !== 'darwin' || !path.isAbsolute(outputPath)) throw new Error('native macOS build path required')
  await command('/usr/bin/clang', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', path.join(moduleDirectory, 'process-peer.c'), '-framework', 'Security', '-framework', 'CoreFoundation', '-o', outputPath])
}
