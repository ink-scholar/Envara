// Shared by session preparation and its copied, per-invocation launch check.
// Keep this module standalone: no application token or credential is written here.
import path from 'node:path';
import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { pathToFileURL } from 'node:url';

const execute = promisify(execFile);
const MAX_SETTINGS_BYTES = 1024 * 1024;
const fail = (message, code) => Object.assign(new Error(message), { code });
const invalid = () => fail('此境舱的 Claude 设置无法安全读取，请检查 settings.json。', 'CLAUDE_CODE_SETTINGS_INVALID');
const policyConflict = () => fail('此境舱的 Claude 设置会覆盖会话网络或目录；请移除冲突后重试。', 'CLAUDE_CODE_SESSION_POLICY_CONFLICT');
const accountConflict = () => fail('此境舱的 Claude 设置含 API、网关或外部登录配置；请移除冲突后使用账号登录会话。', 'CLAUDE_CODE_ACCOUNT_CONFIGURATION_CONFLICT');
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const absolute = value => typeof value === 'string' && path.isAbsolute(value) && path.normalize(value) === value && !/[\x00-\x1f\x7f]/.test(value);
const validEnvironment = value => object(value) && Object.entries(value).every(([key, item]) => /^[A-Za-z_][A-Za-z0-9_]*$/.test(key) && typeof item === 'string' && !item.includes('\0'));

export const CLAUDE_ACCOUNT_ENV = new Set([
  'ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'ANTHROPIC_BASE_URL', 'ANTHROPIC_CUSTOM_HEADERS',
  'ANTHROPIC_AWS_API_KEY', 'ANTHROPIC_AWS_BASE_URL', 'ANTHROPIC_AWS_WORKSPACE_ID',
  'ANTHROPIC_BEDROCK_BASE_URL', 'ANTHROPIC_BEDROCK_MANTLE_BASE_URL',
  'ANTHROPIC_FOUNDRY_API_KEY', 'ANTHROPIC_FOUNDRY_AUTH_TOKEN', 'ANTHROPIC_FOUNDRY_BASE_URL', 'ANTHROPIC_FOUNDRY_RESOURCE',
  'ANTHROPIC_VERTEX_BASE_URL', 'ANTHROPIC_VERTEX_PROJECT_ID', 'ANTHROPIC_PROFILE',
  'ANTHROPIC_FEDERATION_RULE_ID', 'ANTHROPIC_ORGANIZATION_ID', 'ANTHROPIC_WORKSPACE_ID', 'AWS_BEARER_TOKEN_BEDROCK',
  'CLAUDE_CODE_USE_ANTHROPIC_AWS', 'CLAUDE_CODE_USE_BEDROCK', 'CLAUDE_CODE_USE_FOUNDRY', 'CLAUDE_CODE_USE_MANTLE', 'CLAUDE_CODE_USE_VERTEX',
  'CLAUDE_CODE_SKIP_ANTHROPIC_AWS_AUTH', 'CLAUDE_CODE_SKIP_BEDROCK_AUTH', 'CLAUDE_CODE_SKIP_FOUNDRY_AUTH', 'CLAUDE_CODE_SKIP_MANTLE_AUTH', 'CLAUDE_CODE_SKIP_VERTEX_AUTH',
  'CLAUDE_CODE_OAUTH_TOKEN', 'CLAUDE_CODE_OAUTH_REFRESH_TOKEN', 'CLAUDE_CODE_OAUTH_SCOPES',
  'CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST', 'DISABLE_LOGIN_COMMAND',
]);
export const CLAUDE_CONTEXT_ENV = new Set([
  'HOME', 'USERPROFILE', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_DATA_HOME', 'XDG_STATE_HOME',
  'CLAUDE_CONFIG_DIR', 'ANTHROPIC_CONFIG_DIR', 'HISTFILE', 'ZDOTDIR', 'NPM_CONFIG_USERCONFIG', 'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_NOSYSTEM',
  'TMPDIR', 'TMP', 'TEMP', 'TZ', 'LANG', 'LC_ALL', 'PATH', 'BROWSER', 'NODE_USE_ENV_PROXY', 'NO_PROXY', 'no_proxy',
  'ENVARA_LINK_SOCKET', 'ENVARA_BROWSER_SOCKET',
  'SSH_AUTH_SOCK', 'ENVARA_SSH_CONFIG', 'ENVARA_SSH_TARGETS', 'ENVARA_SSH_CONNECTIONS',
]);
export const CLAUDE_PRIVATE_ENV = new Set(['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy',
  'ENVARA_LINK_TOKEN', 'ENVARA_BROWSER_TOKEN', 'ENVARA_SSH_PROXY_URL']);
export const CLAUDE_SESSION_BREAKING_ENV = new Set(['CLAUDE_CODE_SUBPROCESS_ENV_SCRUB', 'NODE_OPTIONS', 'BUN_OPTIONS', 'LD_PRELOAD', 'DYLD_INSERT_LIBRARIES']);

function accountValueActive(key, value) {
  if (value === '') return false;
  const boolean = key.startsWith('CLAUDE_CODE_USE_') || key.startsWith('CLAUDE_CODE_SKIP_')
    || key === 'CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST' || key === 'DISABLE_LOGIN_COMMAND';
  return !boolean || !/^(0|false|no|off)$/i.test(value);
}

export function validateClaudeEnvironment(environment) {
  if (!validEnvironment(environment)) throw fail('Claude Code 会话环境无效。', 'CLAUDE_CODE_INVALID_CONFIGURATION');
  if (Object.entries(environment).some(([key, value]) => CLAUDE_ACCOUNT_ENV.has(key) && accountValueActive(key, value))) throw accountConflict();
  if (Object.entries(environment).some(([key, value]) => CLAUDE_SESSION_BREAKING_ENV.has(key) && value !== '')) throw policyConflict();
}

export function validateClaudeSettings(settings, environment, { basePath } = {}) {
  if (!object(settings) || settings.env !== undefined && !validEnvironment(settings.env)) throw invalid();
  validateClaudeEnvironment(environment);
  if (basePath !== undefined && (typeof basePath !== 'string' || !basePath || basePath.length > 65536
    || /[\x00-\x1f\x7f]/.test(basePath) || basePath.split(path.delimiter).some(value => !absolute(value)))) throw policyConflict();
  const variables = settings.env ?? {};
  if (Object.entries(variables).some(([key, value]) => CLAUDE_ACCOUNT_ENV.has(key) && accountValueActive(key, value))) throw accountConflict();
  if (Object.entries(variables).some(([key, value]) => CLAUDE_SESSION_BREAKING_ENV.has(key) && value !== '')) throw policyConflict();
  for (const key of ['apiKeyHelper', 'awsAuthRefresh', 'awsCredentialExport', 'gcpAuthRefresh', 'forceLoginGatewayUrl']) {
    if (settings[key] != null && settings[key] !== '') throw accountConflict();
  }
  if (settings.forceLoginMethod != null && settings.forceLoginMethod !== 'claudeai') throw accountConflict();
  if (settings.proxyAuthHelper != null && settings.proxyAuthHelper !== '') throw policyConflict();
  for (const [key, value] of Object.entries(variables)) {
    // The session overlay prepends its own Claude wrapper to this fixed base.
    // A previously valid lower-precedence PATH remains harmless underneath it.
    if (key === 'PATH' && basePath !== undefined && value === basePath) continue;
    if ((CLAUDE_CONTEXT_ENV.has(key) || CLAUDE_PRIVATE_ENV.has(key) || key.startsWith('ENVARA_')) && value !== (environment[key] ?? '')) throw policyConflict();
  }
}

// Reject links even when their target is missing. Missing ordinary components
// mean this optional settings file does not exist; permission errors do not.
async function settingsPath(filename) {
  if (!absolute(filename)) throw invalid();
  let current = path.parse(filename).root;
  const components = filename.slice(current.length).split(path.sep).filter(Boolean);
  for (let index = 0; index < components.length; index++) {
    current = path.join(current, components[index]);
    let info;
    try { info = await lstat(current); } catch (error) { if (error.code === 'ENOENT') return null; throw invalid(); }
    if (info.isSymbolicLink() || index < components.length - 1 && !info.isDirectory()) throw invalid();
    if (index === components.length - 1) return info;
  }
  throw invalid();
}

export async function readClaudeSettings(filename) {
  let handle;
  try {
    const before = await settingsPath(filename);
    if (!before) return {};
    if (!before.isFile() || before.size > MAX_SETTINGS_BYTES || before.mode & 0o022) throw invalid();
    handle = await open(filename, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const opened = await handle.stat();
    if (!opened.isFile() || opened.dev !== before.dev || opened.ino !== before.ino || opened.size > MAX_SETTINGS_BYTES
      || opened.mode !== before.mode) throw invalid();
    const buffer = Buffer.alloc(MAX_SETTINGS_BYTES + 1);
    let count = 0;
    while (count < buffer.length) {
      const result = await handle.read(buffer, count, buffer.length - count, null);
      if (!result.bytesRead) break;
      count += result.bytesRead;
    }
    const after = await handle.stat();
    if (count > MAX_SETTINGS_BYTES || count !== opened.size || after.dev !== opened.dev || after.ino !== opened.ino
      || after.mode !== opened.mode || after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs || after.size !== opened.size) throw invalid();
    const value = JSON.parse(buffer.toString('utf8', 0, count));
    if (!object(value) || value.env !== undefined && !validEnvironment(value.env)) throw invalid();
    return value;
  } catch { throw invalid(); }
  finally { try { await handle?.close(); } catch { throw invalid(); } }
}

async function directory(filename) {
  try {
    if (!absolute(filename)) throw invalid();
    const info = await lstat(filename);
    if (!info.isDirectory() || info.isSymbolicLink() || await realpath(filename) !== filename) throw invalid();
    return info;
  } catch { throw invalid(); }
}

async function ownedEntry(filename, { optional = false } = {}) {
  try {
    const info = await lstat(filename);
    return !info.isSymbolicLink() && (!process.getuid || info.uid === process.getuid());
  } catch (error) { if (optional && error.code === 'ENOENT') return true; throw invalid(); }
}

function gitOptions(home) {
  return {
    env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', HOME: home, LANG: 'C', LC_ALL: 'C',
      GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_OPTIONAL_LOCKS: '0', GIT_TERMINAL_PROMPT: '0' },
    timeout: 3000, maxBuffer: 128 * 1024, encoding: 'utf8', windowsHide: true,
  };
}

async function gitExecutable(home, platform, executeGit) {
  try {
    let filename = '/usr/bin/git';
    if (platform === 'darwin') {
      // /usr/bin/git may be Apple's installation-launching stub. Query the
      // already-selected tools first, then execute their real Git directly.
      const selected = await executeGit('/usr/bin/xcode-select', ['-p'], gitOptions(home));
      const tools = typeof selected?.stdout === 'string' ? selected.stdout.trimEnd() : '';
      if (!absolute(tools)) throw invalid();
      await directory(tools);
      filename = path.join(tools, 'usr', 'bin', 'git');
    }
    const canonical = await realpath(filename), info = await lstat(canonical);
    if (!info.isFile() || !(info.mode & 0o111) || info.mode & 0o022
      || process.getuid && info.uid !== 0 && info.uid !== process.getuid()) throw invalid();
    return canonical;
  } catch { throw invalid(); }
}

async function gitOutput(executable, cwd, args, home, executeGit) {
  const result = await executeGit(executable, ['-C', cwd, ...args], gitOptions(home));
  if (typeof result?.stdout !== 'string') throw invalid();
  return result.stdout;
}

async function localRoot({ cwd, home, platform, executeGit }) {
  if (platform === 'win32') return cwd;
  // Avoid invoking macOS's Git developer-tools stub for an ordinary folder.
  // Only metadata is needed to determine whether Git discovery is applicable.
  let marker = null;
  for (let current = cwd; ; current = path.dirname(current)) {
    try { await lstat(path.join(current, '.git')); marker = current; break; }
    catch (error) { if (error.code !== 'ENOENT') throw invalid(); }
    if (path.dirname(current) === current) break;
  }
  if (!marker) return cwd;
  // This documented fallback also avoids asking Git to accept a repository
  // it would classify as foreign before we can determine its root.
  if (marker === home || !await ownedEntry(marker) || !await ownedEntry(path.join(marker, '.git'))
    || !await ownedEntry(path.join(marker, '.claude'), { optional: true })) return cwd;
  const executable = await gitExecutable(home, platform, executeGit);
  let root;
  try { root = (await gitOutput(executable, cwd, ['rev-parse', '--show-toplevel'], home, executeGit)).trimEnd(); }
  catch (error) {
    // Git's ordinary outside-repository result is the only discovery fallback.
    if (error.code === 128 && typeof error.stderr === 'string' && /^fatal: not a git repository(?:[\s(:]|$)/.test(error.stderr)) return cwd;
    throw invalid();
  }
  if (!absolute(root)) throw invalid();
  await directory(root);
  if (root === home || !await ownedEntry(root) || !await ownedEntry(path.join(root, '.git'))
    || !await ownedEntry(path.join(root, '.claude'), { optional: true })) return cwd;
  let output;
  try { output = await gitOutput(executable, cwd, ['worktree', 'list', '--porcelain', '-z'], home, executeGit); }
  catch { throw invalid(); }
  // Git lists its main checkout first. NUL-delimited porcelain keeps spaces
  // and line breaks from being interpreted as another worktree record.
  const boundary = output.indexOf('\0\0');
  if (boundary < 0) throw invalid();
  const firstRecord = output.slice(0, boundary).split('\0');
  const first = firstRecord[0];
  if (!first.startsWith('worktree ')) throw invalid();
  const main = first.slice('worktree '.length);
  if (!absolute(main)) throw invalid();
  await directory(main);
  // A bare common repository has no main checkout/.git. The native CLI uses
  // the invocation directory's local settings for its linked worktrees.
  if (firstRecord.includes('bare')) {
    if (firstRecord.length !== 2) throw invalid();
    return cwd;
  }
  if (main === home || !await ownedEntry(main) || !await ownedEntry(path.join(main, '.git'))
    || !await ownedEntry(path.join(main, '.claude'), { optional: true })) return cwd;
  return main;
}

export async function resolveClaudeSettingsFiles({ configDir, home, cwd = process.cwd(), environment = process.env,
  platform = process.platform, executeGit = execute } = {}) {
  validateClaudeEnvironment(environment);
  if (!absolute(configDir) || !absolute(home) || !absolute(cwd) || environment.HOME !== home
    || environment.USERPROFILE !== home || environment.CLAUDE_CONFIG_DIR !== configDir
    || environment.ANTHROPIC_CONFIG_DIR !== path.join(configDir, 'anthropic')) throw policyConflict();
  await directory(configDir); await directory(home); await directory(cwd);
  const local = await localRoot({ cwd, home, platform, executeGit });
  return [...new Set([path.join(configDir, 'settings.json'), path.join(cwd, '.claude', 'settings.json'),
    path.join(cwd, '.claude', 'settings.local.json'), path.join(local, '.claude', 'settings.local.json')])];
}

export async function preflightClaudeSettings(options = {}) {
  const environment = options.environment ?? process.env;
  const files = await resolveClaudeSettingsFiles({ ...options, environment });
  for (const filename of files) validateClaudeSettings(await readClaudeSettings(filename), environment, { basePath: options.basePath });
  return true;
}

export async function runClaudeSettingsCheck(argv = process.argv.slice(2), environment = process.env) {
  try {
    if (![4, 6].includes(argv.length) || argv[0] !== '--check' || argv[2] !== '--home'
      || argv.length === 6 && argv[4] !== '--base-path') throw invalid();
    await preflightClaudeSettings({ configDir: argv[1], home: argv[3], environment,
      ...(argv.length === 6 ? { basePath: argv[5] } : {}) });
    return 0;
  } catch (error) {
    const known = new Set(['CLAUDE_CODE_SETTINGS_INVALID', 'CLAUDE_CODE_SESSION_POLICY_CONFLICT',
      'CLAUDE_CODE_ACCOUNT_CONFIGURATION_CONFLICT', 'CLAUDE_CODE_INVALID_CONFIGURATION']);
    const safe = known.has(error?.code) ? error : invalid();
    process.stderr.write(`envara: ${safe.code}: ${safe.message}\n`);
    return 64;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  process.exitCode = await runClaudeSettingsCheck();
}
