import path from 'node:path';
import { constants } from 'node:fs';
import { access, chmod, lstat, mkdir, readFile, realpath, rm, stat, writeFile } from 'node:fs/promises';
import { resolveClaudeInstallation } from './claude-code-installation.mjs';
import { CLAUDE_ACCOUNT_ENV, CLAUDE_CONTEXT_ENV, readClaudeSettings, validateClaudeEnvironment, validateClaudeSettings } from './claude-code-settings.mjs';

const fail = (message, code = 'CLAUDE_CODE_INVALID_CONFIGURATION') => Object.assign(new Error(message), { code });
const absolute = value => typeof value === 'string' && path.isAbsolute(value) && !/[\0\r\n]/.test(value);
const policyConflict = () => fail('此境舱的 Claude 设置会覆盖会话网络或目录；请移除冲突后重试。', 'CLAUDE_CODE_SESSION_POLICY_CONFLICT');
const shellQuote = value => `'${value.replaceAll("'", "'\\''")}'`;

function claudeShim({ node, resolver, settingsCheck, config, home, runtime, basePath }, args) {
  // These options belong to the terminal's binding. Scalar option order and
  // variadic --mcp-config merging are not reliable override prevention.
  const reserved = ['--mcp-config', '--strict-mcp-config', '--no-strict-mcp-config', '--settings', '--setting-sources',
    '--chrome', '--no-chrome', '--bare', '--safe-mode', '--restricted'];
  return `#!/bin/sh
# Envara: explicit user invocation, fixed browser and environment configuration.
for envara_arg in "$@"; do
  case "\${envara_arg}" in
    --) break ;;
    ${reserved.flatMap(flag => [flag, `${flag}=*`]).join('|')})
      printf 'envara: %s\\n' '此会话的浏览器和隔离配置已固定，不能用这些参数覆盖。可用 claude mcp add 添加自定义 MCP；模型、权限和会话恢复参数可以正常使用。' >&2
      exit 64 ;;
  esac
done
if [ -e ${shellQuote(path.join(home, '.config', 'anthropic'))} ] || [ -L ${shellQuote(path.join(home, '.config', 'anthropic'))} ]; then
  if (umask 077; /bin/mkdir ${shellQuote(path.join(runtime, 'legacy-anthropic-notice'))} 2>/dev/null); then
    printf '%s\\n' '旧版共用的 Console 登录资料仍保留，请在所选档案重新登录。' >&2
  fi
fi
NODE_OPTIONS= BUN_OPTIONS= ${[node, settingsCheck, '--check', config, '--home', home, '--base-path', basePath].map(shellQuote).join(' ')} || exit 78
envara_claude=$(NODE_OPTIONS= BUN_OPTIONS= ${[node, resolver, '--resolve', home].map(shellQuote).join(' ')}) || exit 126
exec "\${envara_claude}" ${args.map(shellQuote).join(' ')} "$@"
`;
}

async function checkedDirectory(root, { owned = false } = {}) {
  if (!absolute(root) || path.resolve(root) !== root) throw fail('Claude Code 会话目录无效。');
  const info = await lstat(root);
  if (!info.isDirectory() || info.isSymbolicLink() || owned && (info.mode & 0o022 || process.getuid && info.uid !== process.getuid())
    || await realpath(root) !== root) throw fail('Claude Code 会话目录包含不安全的链接。', 'CLAUDE_CODE_UNSAFE_PATH');
}

async function sessionPolicy({ directories, environment, privacy }) {
  validateClaudeEnvironment(environment);
  await checkedDirectory(directories?.home);
  await checkedDirectory(directories?.claude);
  const user = await readClaudeSettings(path.join(directories.claude, 'settings.json'));
  if (environment.HOME !== directories.home || environment.USERPROFILE !== directories.home || environment.CLAUDE_CONFIG_DIR !== directories.claude) throw policyConflict();
  if (directories.anthropic !== path.join(directories.claude, 'anthropic') || environment.ANTHROPIC_CONFIG_DIR !== directories.anthropic) throw policyConflict();
  await checkedDirectory(directories.anthropic, { owned: true });
  const mode = typeof privacy === 'string' ? privacy : privacy?.mode ?? 'standard';
  if (!['off', 'standard', 'strict'].includes(mode)) throw fail('Claude Code 隐私设置无效。');
  const launch = { ...environment, DISABLE_AUTOUPDATER: '1', DO_NOT_TRACK: mode === 'off' ? '' : '1',
    DISABLE_TELEMETRY: mode === 'off' ? '' : '1', DISABLE_ERROR_REPORTING: mode === 'off' ? '' : '1',
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: mode === 'strict' ? '1' : '' };
  validateClaudeSettings(user, launch);
  const pins = Object.fromEntries([...CLAUDE_CONTEXT_ENV].filter(key => launch[key] !== undefined).map(key => [key, launch[key]]));
  for (const key of ['DISABLE_AUTOUPDATER', 'DO_NOT_TRACK', 'DISABLE_TELEMETRY', 'DISABLE_ERROR_REPORTING', 'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC']) pins[key] = launch[key];
  // These are non-secret empty pins, not credential copies. An existing API or
  // token configuration is rejected above rather than silently discarded.
  for (const key of CLAUDE_ACCOUNT_ENV) pins[key] = '';
  return { environment: launch, settings: { forceLoginMethod: 'claudeai', sandbox: { enabled: false }, env: pins } };
}

async function executableFile(filename) {
  if (!absolute(filename)) throw fail('Claude Code 程序路径无效。');
  const canonical = await realpath(filename);
  const info = await stat(canonical);
  if (!info.isFile() || (process.platform !== 'win32' && (info.mode & 0o022))) throw fail('Claude Code 程序文件不可信。');
  await access(canonical, constants.R_OK | constants.X_OK);
  return canonical;
}

/** Resolve installed programs without invoking a login shell, aliases or cwd. */
export async function findClaudeExecutable({ hostHome, platform = process.platform, additionalExecutablePaths = [] } = {}) {
  if (!absolute(hostHome) || !Array.isArray(additionalExecutablePaths) || additionalExecutablePaths.some(value => !absolute(value))) {
    throw fail('Claude Code 程序搜索目录无效。');
  }
  const locations = platform === 'win32'
    ? [path.join(hostHome, '.local', 'bin'), ...additionalExecutablePaths,
      path.join(hostHome, 'AppData', 'Local', 'Microsoft', 'WinGet', 'Links')]
    : [path.join(hostHome, '.local', 'bin'), ...additionalExecutablePaths, '/opt/homebrew/bin', '/usr/local/bin', '/usr/bin', '/bin'];
  for (const directory of new Set(locations)) {
    try { return await executableFile(path.join(directory, platform === 'win32' ? 'claude.exe' : 'claude')); }
    catch (error) {
      if (!['ENOENT', 'ENOTDIR', 'EACCES', 'EPERM', 'CLAUDE_CODE_INVALID_CONFIGURATION'].includes(error?.code)) throw error;
    }
  }
  throw fail('未找到本机 Claude Code，请先安装后重新创建会话。', 'CLAUDE_CODE_NOT_INSTALLED');
}

async function privateRoot(root) {
  await checkedDirectory(root);
  await chmod(root, 0o700);
}

/** Session-only launch settings; existing Claude settings and auth stay intact. */
export async function prepareClaudeSession({ sessionId, directories, installation, mcpServer, environment, privacy } = {}) {
  if (typeof sessionId !== 'string' || !/^[A-Za-z0-9_-]{1,96}$/.test(sessionId)) throw fail('Claude Code 会话标识无效。');
  if (!mcpServer || Object.keys(mcpServer).some(key => !['command', 'args'].includes(key)) || !absolute(mcpServer.command)
    || !Array.isArray(mcpServer.args) || mcpServer.args.length > 32
    || mcpServer.args.some(value => typeof value !== 'string' || value.length > 8192 || /[\0\r\n]/.test(value))) {
    throw fail('Claude Code 浏览器连接配置无效。');
  }
  if (typeof directories?.home !== 'string' || installation?.home !== directories.home || installation?.entryPath !== path.join(directories.home, '.local/bin/claude')
    || installation?.versionsDirectory !== path.join(directories.home, '.local/share/claude/versions')) throw fail('Claude Code 安装目录无效。', 'CLAUDE_CODE_INSTALLATION_INVALID');
  const selected = await resolveClaudeInstallation(installation);
  // mcpServer.command is the app's physical bundled Node, not Electron/app.asar.
  const node = await executableFile(mcpServer.command);
  if (environment?.XDG_DATA_HOME !== undefined && environment.XDG_DATA_HOME !== path.join(directories.home, '.local/share')) throw policyConflict();
  const root = directories?.temp;
  await privateRoot(root);
  const policy = await sessionPolicy({ directories, environment, privacy });
  const runtime = path.join(root, `claude-${sessionId}`);
  // Existing sessions, files and links are never replaced or adopted.
  try { await mkdir(runtime, { mode: 0o700 }); }
  catch (error) { if (error.code === 'EEXIST') throw fail('Claude Code 会话目录已存在，请重新创建会话。', 'CLAUDE_CODE_SESSION_EXISTS'); throw error; }
  const identity = await lstat(runtime);
  let removed = false;
  const cleanup = async () => {
    if (removed) return;
    let current;
    try { current = await lstat(runtime); }
    catch (error) { if (error.code === 'ENOENT') { removed = true; return; } throw error; }
    if (!current.isDirectory() || current.isSymbolicLink() || current.dev !== identity.dev || current.ino !== identity.ino
      || await realpath(runtime) !== runtime) throw fail('Claude Code 会话目录已改变，未删除未知文件。', 'CLAUDE_CODE_UNSAFE_PATH');
    await rm(runtime, { recursive: true, force: true });
    removed = true;
  };
  try {
    await chmod(runtime, 0o700);
    const mcp = path.join(runtime, 'mcp.json');
    const settings = path.join(runtime, 'settings.json');
    const binDirectory = path.join(runtime, 'bin');
    const wrapperPath = path.join(binDirectory, 'claude');
    const resolver = path.join(runtime, 'claude-installation-check.mjs');
    const settingsCheck = path.join(runtime, 'claude-code-settings.mjs');
    await mkdir(binDirectory, { mode: 0o700 });
    // The shell and Claude's own subprocesses resolve the same wrapper, even
    // after Claude reapplies its --settings env block. Never modify host PATH.
    const sessionPath = [binDirectory, path.dirname(installation.entryPath), policy.environment.PATH].filter(Boolean).join(path.delimiter);
    policy.environment.PATH = sessionPath;
    policy.settings.env.PATH = sessionPath;
    // Tokens and route credentials are inherited through the child environment,
    // never copied into these JSON files or into the user's Claude settings.
    await writeFile(mcp, JSON.stringify({ mcpServers: { envara_browser: { type: 'stdio', command: mcpServer.command, args: [...mcpServer.args] } } }), { mode: 0o600, flag: 'wx' });
    // The caller applies Envara's process-tree fence. macOS cannot nest a
    // second Seatbelt profile for Claude's Bash subprocesses inside that fence.
    // CLI settings pin the non-secret context above user settings. Sensitive
    // route/link values are checked at startup only and stay in the inherited
    // environment. User settings can still reload; this is not an auth policy
    // or a replacement for Envara's process network fence and browser broker.
    await writeFile(settings, JSON.stringify(policy.settings), { mode: 0o600, flag: 'wx' });
    // Add the session broker to Claude's normal MCP discovery. Strict mode
    // would silently hide MCPs added by the user or by Claude in this profile.
    // The private CLI config retains the managed broker's name and binding;
    // the process fence, not an MCP allowlist, enforces the selected route.
    const args = ['--no-chrome', '--mcp-config', mcp, '--setting-sources', 'user,project,local', '--settings', settings];
    await writeFile(resolver, await readFile(new URL('./claude-code-installation.mjs', import.meta.url)), { mode: 0o600, flag: 'wx' });
    await writeFile(settingsCheck, await readFile(new URL('./claude-code-settings.mjs', import.meta.url)), { mode: 0o600, flag: 'wx' });
    await writeFile(wrapperPath, claudeShim({ node, resolver, settingsCheck, config: directories.claude, home: directories.home, runtime, basePath: environment.PATH ?? '' }, args), { mode: 0o700, flag: 'wx' });
    return { executable: selected, installation, args, environment: policy.environment, binDirectory, wrapperPath, cleanup };
  } catch (error) {
    try { await cleanup(); }
    catch {
      error.cleanupError = 'Claude 会话临时文件清理未完成，请重试关闭会话。';
      // The terminal service retains this same owned runtime for Close retries.
      // It is private authority, never part of public session metadata.
      Object.defineProperty(error, 'claudeCleanup', { value: cleanup, configurable: true });
    }
    throw error;
  }
}
