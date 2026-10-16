// What an environment export carries, and where an import puts it back. The
// browser, terminal and Claude data return immediately; an attached
// application's data waits until that application has run once in the new
// environment, because only the privileged keeper creates its directories.
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { cp, lstat, mkdir, readFile, readdir, realpath, rename, rm, rmdir, writeFile } from 'node:fs/promises';
import { pfAttachEnvironmentId, pfApplicationRegistrationId } from '../native/macos-pf-routing/policy.mjs';
import { ATTACHED_APPLICATION_DATA_ROOT, REGENERABLE_CACHE_ENTRIES } from './application-data.mjs';
import { EXPORT_SCHEMA, checkedExportPassword, writeEnvironmentExport } from './environment-export.mjs';
import { claudeAccountId } from './claude-account-store.mjs';

const fail = (message, code) => Object.assign(new Error(message), { code });
const LIVE_TERMINAL = new Set(['starting', 'running', 'closing']);
const APPLICATION_LEAVES = ['UserData', 'Home', 'Extensions'];
/* Regenerable or per-run files; everything else in the data is kept. */
const TRANSIENT = new Set([...REGENERABLE_CACHE_ENTRIES, 'SingletonLock', 'SingletonSocket', 'SingletonCookie',
  'DevToolsActivePort', 'code.lock']);
const TERMINAL_EXCLUDED = new Set(['tmp', 'home/.cache', 'home/.local/share/claude', 'home/.local/bin/claude']);
const SCOPES = new Set(['browser', 'terminal', 'application']);
const SHELL_FILES = new Set(['.envara_history', '.gitconfig', '.npmrc', '.zshenv', '.zshrc', '.bashrc']);
function selectedTerminalEntry(relative, accountId) {
  const parts = relative.split('/');
  if (parts[0] === 'home') return parts.length === 1 || parts.length === 2 && SHELL_FILES.has(parts[1]);
  if (parts[0] === 'claude') return accountId === 'default';
  if (parts[0] === 'claude-accounts') return accountId !== 'default' && (parts.length === 1 || parts[1] === accountId);
  return false;
}
export const EXPORT_NOTICE = '包含环境配置，以及浏览器、终端与 Claude、附加软件保存在磁盘上的登录数据。不含钥匙串里的令牌（例如 Claude Code 凭据、VS Code 密钥），在另一台 Mac 上这些登录通常需要重新完成。拿到此文件和密码的人可以使用其中的登录。';

const identityKey = identity => createHash('sha256').update(String(identity)).digest('hex').slice(0, 32);
const pendingDirectory = (dataDir, profileId, identity) => path.join(dataDir, 'imports', 'applications', profileId, identityKey(identity));
async function directory(target) {
  try { const info = await lstat(target); return info.isDirectory() && !info.isSymbolicLink(); }
  catch (error) { if (error.code === 'ENOENT') return false; throw error; }
}
async function present(target) {
  try { return await lstat(target); }
  catch (error) { if (error.code === 'ENOENT') return null; throw error; }
}
async function checkedDirectory(target, uid = process.getuid?.()) {
  const info = await lstat(target);
  if (!info.isDirectory() || info.isSymbolicLink() || await realpath(target) !== path.resolve(target) ||
      (uid != null && info.uid !== uid && info.uid !== 0))
    throw fail('导入资料目录包含不安全的链接，未恢复。', 'IMPORT_TARGET_UNSAFE');
}
async function emptyTarget(target) {
  const info = await present(target);
  if (!info) return false;
  if (!info.isDirectory() || info.isSymbolicLink()) throw fail('导入目标已存在，未覆盖。', 'IMPORT_TARGET_NOT_EMPTY');
  if ((await readdir(target)).length) throw fail('导入目标已有资料，未覆盖。', 'IMPORT_TARGET_NOT_EMPTY');
  return true;
}
/* Staging remains intact until the complete import succeeds. Copying rather
 * than consuming it makes a failed import genuinely retryable. */
async function copyInto(source, target) {
  await cp(source, target, { recursive: true, errorOnExist: true, force: false, verbatimSymlinks: true });
}
async function applicationsOf(applications, profileId) {
  return applications ? (await applications.snapshot()).applications.filter(item => item.profileId === profileId) : [];
}
async function pendingApplications(dataDir, profileId, bound) {
  if (!dataDir) return [];
  const parent = path.join(dataDir, 'imports', 'applications', profileId);
  if (!await directory(parent)) return [];
  await checkedDirectory(parent);
  const result = [];
  for (const name of await readdir(parent)) {
    if (!/^[a-f0-9]{32}$/.test(name)) continue;
    const target = path.join(parent, name);
    await checkedDirectory(target);
    const filename = path.join(target, 'pending.json'), info = await present(filename);
    if (!info?.isFile() || info.isSymbolicLink() || info.size > 65536)
      throw fail('待恢复的软件资料不完整，请先重新绑定该软件后再导出。', 'EXPORT_PENDING_APPLICATION_UNRESOLVED');
    let item;
    try { item = JSON.parse(await readFile(filename, 'utf8')); } catch { /* fixed refusal below */ }
    const current = bound.find(application => application.identity === item?.identity);
    const bundle = item?.path ?? current?.path;
    if (typeof item?.identity !== 'string' || identityKey(item.identity) !== name || typeof item.name !== 'string' ||
        typeof bundle !== 'string' || !path.isAbsolute(bundle))
      throw fail('待恢复的软件资料不完整，请先重新绑定该软件后再导出。', 'EXPORT_PENDING_APPLICATION_UNRESOLVED');
    result.push({ ...item, path: bundle });
  }
  return result;
}

/** Refuses while anything of the environment runs: live databases copied
 * mid-write would not restore. */
export async function assertEnvironmentIdle({ profile, terminal, applications, scope = 'environment', applicationId }) {
  if (scope !== 'environment' && !SCOPES.has(scope)) throw fail('请选择要导出的浏览器、终端或软件。', 'EXPORT_SCOPE_INVALID');
  if (scope === 'environment' || scope === 'application') await applications?.routing?.notionTrial?.housekeeping;
  if ((scope === 'environment' || scope === 'browser') && ['running', 'starting', 'stopping', 'closing'].includes(profile.status))
    throw fail('请先停止此浏览器，再导出。', 'EXPORT_ENVIRONMENT_RUNNING');
  if (scope === 'environment' || scope === 'terminal') {
    const sessions = (await terminal?.snapshot({ id: profile.id }))?.profiles?.find(item => item.profileId === profile.id)?.sessions ?? [];
    if (sessions.some(session => LIVE_TERMINAL.has(session.status))) throw fail('请先关闭此环境的终端会话，再导出。', 'EXPORT_ENVIRONMENT_RUNNING');
  }
  if (scope !== 'environment' && scope !== 'application') return;
  for (const application of (await applicationsOf(applications, profile.id)).filter(item => scope === 'environment' || item.id === applicationId)) {
    const trial = applications.routing?.controlledNotionTrialSnapshot?.({ applicationId: application.id });
    if (trial?.active === true || trial?.cleanupUncertain === true || ['starting', 'running', 'stopping'].includes(application.status))
      throw fail(`请先停止此环境的附加软件「${application.name}」，再导出。`, 'EXPORT_ENVIRONMENT_RUNNING');
  }
}

export async function exportEnvironment({ profile, password, file, service, terminal, applications, appVersion, dataDir,
  scope = 'environment', accountId = 'default', applicationId,
  root = ATTACHED_APPLICATION_DATA_ROOT, platform = process.platform }) {
  checkedExportPassword(password);
  await assertEnvironmentIdle({ profile, terminal, applications, scope, applicationId });
  if ((scope === 'environment' || scope === 'browser') && typeof service.remote === 'function' && typeof service.assertStopped === 'function') {
    // Native snapshots use "error" for both old failed launches and an existing
    // session whose health is unknown. Only the backend can distinguish them.
    // Legacy/fixture services without both methods retain the status fallback.
    await service.assertStopped(await service.remote(), profile.id);
  }
  const document = await service.call('exportProfiles', { id: profile.id });
  const sources = [];
  if ((scope === 'environment' || scope === 'browser') && typeof service.checkedDirectory === 'function') sources.push({ section: 'browser',
    root: path.join(await service.checkedDirectory({ id: profile.id }), 'browser-data'), exclude: (_relative, name) => TRANSIENT.has(name) });
  let accounts = [];
  let selectedAccount = null;
  if (scope === 'terminal') {
    claudeAccountId(accountId);
    selectedAccount = await terminal?.claudeAccounts?.get(profile.id, accountId);
    if (!selectedAccount || !terminal?.profilesDir) throw fail('此 Claude 登录档案已不存在，请重新选择。', 'CLAUDE_ACCOUNT_NOT_FOUND');
  }
  if ((scope === 'environment' || scope === 'terminal') && terminal?.profilesDir) {
    sources.push({ section: 'terminal', root: path.join(terminal.profilesDir, profile.id), exclude: (relative, name) => {
      if (TERMINAL_EXCLUDED.has(relative) || TRANSIENT.has(name)) return true;
      if (scope === 'environment') return false; // Existing internal legacy-export callers; the desktop offers only SCOPES.
      return !selectedTerminalEntry(relative, accountId);
    } });
    accounts = selectedAccount ? (accountId === 'default' ? [] : [{ id: selectedAccount.id, name: selectedAccount.name }])
      : (await terminal.claudeAccounts?.list(profile.id) ?? []).filter(account => !account.default).map(({ id, name }) => ({ id, name }));
  }
  const exported = [];
  const includesApplications = scope === 'environment' || scope === 'application';
  const bound = includesApplications ? await applicationsOf(applications, profile.id) : [];
  if (scope === 'application' && !bound.some(item => item.id === applicationId)) throw fail('未找到要导出的附加软件。', 'EXPORT_APPLICATION_NOT_FOUND');
  if (scope === 'application' && platform !== 'darwin') throw fail('此平台尚不支持软件数据导出。', 'EXPORT_SCOPE_INVALID');
  const pending = scope === 'environment' && platform === 'darwin' ? await pendingApplications(dataDir, profile.id, bound) : [];
  const candidates = [...bound, ...pending.filter(item => !bound.some(application => application.identity === item.identity))];
  if (platform === 'darwin') for (const application of candidates.filter(item => scope === 'environment' || item.id === applicationId)) {
    let registration; try { registration = path.join(root, pfAttachEnvironmentId(profile.id), pfApplicationRegistrationId(application.path)); } catch { continue; }
    const section = `app-${exported.length}`;
    exported.push({ section, identity: application.identity, name: application.name, path: application.path });
    // A re-export before the first application stop must carry the imported
    // data, rather than the empty first-run directories waiting to receive it.
    const pending = dataDir && pendingDirectory(dataDir, profile.id, application.identity);
    sources.push({ section, root: pending && await directory(pending) ? pending : registration,
      exclude: (relative, name) => relative === name ? !APPLICATION_LEAVES.includes(name) : TRANSIENT.has(name) });
  }
  const manifest = { schema: EXPORT_SCHEMA, version: 1, createdAt: new Date().toISOString(), envara: appVersion ?? null,
    ...(SCOPES.has(scope) ? { scope } : {}), profile: document,
    terminal: { accounts, ...(selectedAccount ? { selectedAccountId: accountId, selectedAccountName: selectedAccount.name } : {}) },
    applications: exported, keychainIncluded: false };
  const written = await writeEnvironmentExport({ file, password, manifest, sources });
  return { ...written, applications: exported.map(item => item.name) };
}

/** Validates an export's manifest before anything is imported. */
export function checkedExportManifest(manifest) {
  if (manifest?.schema !== EXPORT_SCHEMA || manifest.version !== 1 ||
      manifest?.profile?.schema !== 'envara.profiles' || manifest.profile.version !== 2 || !Array.isArray(manifest.profile.profiles) ||
      manifest.profile.profiles.length !== 1 || !Array.isArray(manifest.applications) || manifest.applications.length > 100 ||
      manifest.applications.some((item, index) => item?.section !== `app-${index}` || typeof item.identity !== 'string' || typeof item.path !== 'string' ||
        !item.identity || /[\0\r\n]/.test(item.identity) || !path.isAbsolute(item.path) || /[\0\r\n]/.test(item.path) ||
        typeof item.name !== 'string' || !item.name.trim()) || !Array.isArray(manifest.terminal?.accounts ?? []) ||
      !manifest.profile.profiles[0] || typeof manifest.profile.profiles[0] !== 'object' || Array.isArray(manifest.profile.profiles[0]) ||
      new Set(manifest.applications.map(item => item.identity)).size !== manifest.applications.length)
    throw fail('文件不是有效的 Envara 环境导出。', 'EXPORT_FORMAT_INVALID');
  const ids = new Set(), names = new Set(['默认'.normalize('NFKC').toLocaleLowerCase('en-US')]);
  const accounts = manifest.terminal?.accounts ?? [];
  if (accounts.length > 19) throw fail('文件不是有效的 Envara 环境导出。', 'EXPORT_FORMAT_INVALID');
  for (const account of accounts) {
    try { claudeAccountId(account?.id); } catch { throw fail('文件不是有效的 Envara 环境导出。', 'EXPORT_FORMAT_INVALID'); }
    const name = account?.name;
    const key = typeof name === 'string' ? name.trim().normalize('NFKC').toLocaleLowerCase('en-US') : '';
    if (account.id === 'default' || ids.has(account.id) || !key || name.trim().length > 80 || /[\x00-\x1f\x7f]/.test(name) || names.has(key))
      throw fail('文件不是有效的 Envara 环境导出。', 'EXPORT_FORMAT_INVALID');
    ids.add(account.id); names.add(key);
  }
  if (manifest.scope != null) {
    const scope = manifest.scope, selected = manifest.terminal?.selectedAccountId;
    let valid = SCOPES.has(scope);
    if (scope === 'terminal') {
      try { claudeAccountId(selected); } catch { valid = false; }
      valid &&= manifest.applications.length === 0 && (selected === 'default' ? accounts.length === 0 : accounts.length === 1 && accounts[0].id === selected);
    } else valid &&= accounts.length === 0 && selected == null && (scope === 'browser' ? manifest.applications.length === 0 : manifest.applications.length === 1);
    if (!valid) throw fail('文件不是有效的 Envara 独立数据导出。', 'EXPORT_FORMAT_INVALID');
  }
  return manifest;
}

async function checkedStagingScope(staging, manifest) {
  if (manifest.scope == null) return; // Existing whole-environment files remain importable.
  const allowed = new Set([manifest.scope === 'browser' ? 'browser' : manifest.scope === 'terminal' ? 'terminal' : 'app-0']);
  for (const name of await readdir(staging)) if (!allowed.has(name)) throw fail('导入文件包含其他类型的资料，未恢复。', 'EXPORT_FORMAT_INVALID');
  if (manifest.scope !== 'terminal' || !await directory(path.join(staging, 'terminal'))) return;
  const check = async (parent, relative = '') => {
    for (const name of await readdir(parent)) {
      const child = relative ? `${relative}/${name}` : name;
      if (!selectedTerminalEntry(child, manifest.terminal.selectedAccountId))
        throw fail('终端导入包含其他登录档案，未恢复。', 'EXPORT_FORMAT_INVALID');
      if (await directory(path.join(parent, name))) await check(path.join(parent, name), child);
    }
  };
  await check(path.join(staging, 'terminal'));
}

/** Puts a decrypted export into the newly created environment. */
export async function restoreEnvironment({ staging, manifest, profileId, service, terminal, applications, dataDir, platform = process.platform }) {
  checkedExportManifest(manifest);
  if (typeof profileId !== 'string' || !/^[A-Za-z0-9_-]{1,96}$/.test(profileId)) throw fail('导入环境标识无效。', 'EXPORT_FORMAT_INVALID');
  await checkedDirectory(staging);
  await checkedStagingScope(staging, manifest);
  const restored = { ...(manifest.scope ? { scope: manifest.scope } : {}), browser: false, terminal: false, applications: [] };
  const plans = [], committed = [];
  let terminalTarget = null, createdTerminalRoot = false;
  const browser = path.join(staging, 'browser');
  if (await directory(browser) && typeof service.checkedDirectory === 'function') {
    const parent = await service.checkedDirectory({ id: profileId });
    await checkedDirectory(parent);
    const target = path.join(parent, 'browser-data');
    plans.push({ source: browser, target, existed: await emptyTarget(target) });
    restored.browser = true;
  }
  const terminalSource = path.join(staging, 'terminal');
  if (await directory(terminalSource) && terminal?.profilesDir) {
    await checkedDirectory(terminal.profilesDir);
    const target = terminalTarget = path.join(terminal.profilesDir, profileId);
    if (await present(target)) await checkedDirectory(target);
    for (const name of await readdir(terminalSource)) {
      const destination = path.join(target, name);
      plans.push({ source: path.join(terminalSource, name), target: destination, existed: await emptyTarget(destination) });
    }
    restored.terminal = true;
  }
  for (const application of manifest.applications) {
    const source = path.join(staging, application.section);
    if (!await directory(source)) continue;
    const pending = pendingDirectory(dataDir, profileId, application.identity);
    await mkdir(path.dirname(pending), { recursive: true, mode: 0o700 });
    await checkedDirectory(path.dirname(pending));
    plans.push({ source, target: pending, existed: await emptyTarget(pending), application });
  }
  try {
    if (terminalTarget && !await present(terminalTarget)) { await mkdir(terminalTarget, { mode: 0o700 }); createdTerminalRoot = true; }
    // Prepare every copy before changing any destination. A later copy or
    // account-metadata error rolls the whole fresh environment back.
    for (const plan of plans) {
      plan.temporary = path.join(path.dirname(plan.target), `.envara-import-${randomUUID()}`);
      await copyInto(plan.source, plan.temporary);
      if (plan.application) await writeFile(path.join(plan.temporary, 'pending.json'),
        JSON.stringify({ identity: plan.application.identity, name: plan.application.name, path: plan.application.path }), { mode: 0o600 });
    }
    for (const plan of plans) {
      try {
        // A desktop reservation cannot stop external writers. Remove only an
        // actually empty directory; recursive removal could erase data written
        // since emptyTarget() ran while the incoming copy was being prepared.
        if (plan.existed) await rmdir(plan.target);
        await rename(plan.temporary, plan.target); committed.push(plan);
      } catch (error) {
        if (['ENOTEMPTY', 'EEXIST'].includes(error.code)) throw fail('导入目标已有资料，未覆盖。', 'IMPORT_TARGET_NOT_EMPTY');
        throw error;
      }
    }
    if (restored.terminal && manifest.terminal?.accounts?.length) await terminal.claudeAccounts?.adopt(profileId, manifest.terminal.accounts);
  } catch (error) {
    for (const plan of committed.reverse()) await rm(plan.target, { recursive: true, force: true });
    for (const plan of plans) {
      if (plan.temporary) await rm(plan.temporary, { recursive: true, force: true });
      if (plan.existed && !await present(plan.target)) await mkdir(plan.target, { mode: 0o700 });
    }
    if (createdTerminalRoot && !(await readdir(terminalTarget)).length) await rm(terminalTarget, { recursive: true });
    throw error;
  }
  // Binding is independent of whether the application has ever created data.
  for (const application of manifest.applications) {
    const entry = { name: application.name, bound: false, reason: null };
    try {
      const local = await applications?.inspectApplication(application.path, { platform });
      if (!local || local.identity !== application.identity) entry.reason = 'APPLICATION_NOT_FOUND';
      else { await applications.saveApplication({ application: { profileId, path: application.path, name: application.name } }); entry.bound = true; }
    } catch (error) { entry.reason = error.code ?? 'APPLICATION_NOT_FOUND'; }
    restored.applications.push(entry);
  }
  return restored;
}

/** After an attached application's first clean stop in its environment, its
 * directories exist; imported sign-in data then replaces that first run's. */
export async function applyPendingApplicationData({ application, dataDir, root = ATTACHED_APPLICATION_DATA_ROOT, uid = process.getuid?.() }) {
  const pending = pendingDirectory(dataDir, application.profileId, application.identity);
  if (!await directory(pending)) return { applied: false };
  const registration = path.join(root, pfAttachEnvironmentId(application.profileId), pfApplicationRegistrationId(application.path));
  await checkedDirectory(pending, uid);
  await checkedDirectory(registration, uid);
  const plans = [];
  // Validate every leaf first. Never empty UserData and only then discover
  // that a later Home/Extensions leaf is missing, linked or not owned.
  for (const name of APPLICATION_LEAVES) {
    const source = path.join(pending, name);
    if (!await directory(source)) continue;
    const leaf = path.join(registration, name), info = await present(leaf);
    if (!info?.isDirectory() || info.isSymbolicLink() || info.uid !== uid) throw fail('附加软件数据目录不安全，未恢复。', 'IMPORT_TARGET_UNSAFE');
    plans.push({ source, leaf, old: [], added: [] });
  }
  try {
    for (const plan of plans) {
      plan.work = path.join(plan.leaf, `.envara-import-${randomUUID()}`);
      await mkdir(plan.work, { mode: 0o700 });
      plan.backup = path.join(plan.work, 'backup');
      await mkdir(plan.backup, { mode: 0o700 });
      plan.incoming = path.join(plan.work, 'incoming');
      await copyInto(plan.source, plan.incoming);
    }
    for (const plan of plans) {
      for (const child of await readdir(plan.leaf)) {
        if (path.join(plan.leaf, child) === plan.work) continue;
        await rename(path.join(plan.leaf, child), path.join(plan.backup, child)); plan.old.push(child);
      }
      for (const child of await readdir(plan.incoming)) {
        await rename(path.join(plan.incoming, child), path.join(plan.leaf, child)); plan.added.push(child);
      }
    }
  } catch (error) {
    for (const plan of [...plans].reverse()) {
      for (const child of plan.added) await rm(path.join(plan.leaf, child), { recursive: true, force: true });
      for (const child of plan.old) await rename(path.join(plan.backup, child), path.join(plan.leaf, child));
      if (plan.work) await rm(plan.work, { recursive: true, force: true });
    }
    // The original pending data has not been consumed and can be retried.
    throw error;
  }
  for (const plan of plans) await rm(plan.work, { recursive: true, force: true });
  await rm(pending, { recursive: true, force: true });
  return { applied: true };
}
