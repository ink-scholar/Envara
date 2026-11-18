import path from 'node:path';
import * as fs from 'node:fs/promises';
import { claudeInstallationStatus, resolveClaudeInstallation } from './claude-code-installation.mjs';
import { componentVersion, componentVersionSnapshot } from '../shared/component-versions.mjs';
import { PF_INSTALL_ROOT, pfInstallationPlan, verifyPFInstallation } from '../native/macos-pf-routing/controller.mjs';

// Reuse the installation authority's ownership, permissions and file-hash
// checks without starting a helper or querying/changing PF. The verifier accepts
// only the fixed manifest version in this installation contract; runtime
// verification ("pf/1") is a separate protocol, not the installed version.
export async function inspectPFComponent({ fileSystem = fs, verify = verifyPFInstallation } = {}) {
  try { await fileSystem.lstat(PF_INSTALL_ROOT); }
  catch (error) { return { status: error?.code === 'ENOENT' ? 'missing' : 'unknown' }; }
  try {
    const result = await verify({ fileSystem });
    if (result?.verified !== true || result?.manifestVerified !== true) return { status: 'untrusted' };
    const version = componentVersion(pfInstallationPlan().manifest.version);
    return version ? { status: 'installed', version } : { status: 'unknown' };
  } catch { return { status: 'unknown' }; }
}

// Read the validated environment-owned entry only. Do not execute `--version`:
// a status page must not start a CLI, prepare Keychain state or contact a provider.
export async function inspectClaudeComponent({ home, inspect = claudeInstallationStatus, resolve = resolveClaudeInstallation } = {}) {
  const status = await inspect({ home });
  if (status?.installed !== true) return { installed: false, ...(status?.errorCode ? { errorCode: 'CLAUDE_CODE_INSTALLATION_INVALID' } : {}) };
  try {
    const executable = await resolve({ home });
    const version = componentVersion(path.basename(executable));
    return { installed: true, version };
  } catch { return { installed: false, errorCode: 'CLAUDE_CODE_INSTALLATION_INVALID' }; }
}

export async function readComponentVersions({ snapshot, terminal = null, platform = process.platform, arch = process.arch,
  now = () => Date.now(), inspectClaude = inspectClaudeComponent, inspectPF = inspectPFComponent } = {}) {
  if (!snapshot || !Array.isArray(snapshot.profiles)) throw new TypeError('A workspace snapshot is required.');
  let terminals = null;
  if (terminal) {
    await terminal.ready;
    try { terminals = await terminal.snapshot(); } catch { /* Unknown ownership is reported explicitly. */ }
  }
  const supported = platform === 'darwin' && ['arm64', 'x64'].includes(arch) && !!terminal;
  let pfInstallation = null;
  if (snapshot.applicationRouting?.backend === 'pf-utun' && platform === 'darwin') {
    try { pfInstallation = await inspectPF(); }
    catch { pfInstallation = { status: 'unknown' }; }
  }
  const claude = [];
  for (const profile of snapshot.profiles) {
    if (typeof profile?.id !== 'string' || !/^[A-Za-z0-9_-]{1,96}$/.test(profile.id)) continue;
    if (!terminal || typeof terminal.profilesDir !== 'string' || !path.isAbsolute(terminal.profilesDir)) {
      claude.push({ profileId: profile.id, status: 'unknown', supported }); continue;
    }
    try {
      const result = await inspectClaude({ home: path.join(terminal.profilesDir, profile.id, 'home') });
      claude.push({ profileId: profile.id, supported, installed: result?.installed === true,
        version: componentVersion(result?.version), ...(result?.errorCode ? { errorCode: 'CLAUDE_CODE_INSTALLATION_INVALID' } : {}) });
    } catch { claude.push({ profileId: profile.id, status: 'unknown', supported }); }
  }
  return componentVersionSnapshot({ snapshot, terminals, claude, pfInstallation, platform, arch, checkedAt: new Date(now()).toISOString() });
}
