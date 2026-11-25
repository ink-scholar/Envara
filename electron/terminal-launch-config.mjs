import nodePath from 'node:path';

const pathFor = platform => platform === 'win32' ? nodePath.win32 : nodePath.posix;

/** Build only the owned child's environment. Callers provide current host
 * inputs explicitly; no process state, filesystem or credentials are read here. */
export function terminalChildEnvironment({ directories, timezone, proxyEndpoint, privacy = { mode: 'standard' },
  linkShim = null, language, hostHome, additionalExecutablePaths = [], platform, hostEnvironment }) {
  const path = pathFor(platform);
  // Build from scratch: host API keys, SSH agent and author variables are
  // deliberately absent. HOME/TZ here belong only to the new child process.
  const systemRoot = hostEnvironment.SystemRoot ?? 'C:\\Windows';
  const systemPaths = platform === 'win32'
    ? [path.join(systemRoot, 'System32'), systemRoot, path.join(systemRoot, 'System32/WindowsPowerShell/v1.0'), path.join(hostEnvironment.ProgramFiles ?? 'C:\\Program Files', 'nodejs'), path.join(hostEnvironment.ProgramFiles ?? 'C:\\Program Files', 'Git/cmd'), path.join(hostHome, 'AppData/Roaming/npm'), path.join(hostHome, 'AppData/Local/Microsoft/WindowsApps')]
    : ['/opt/homebrew/bin', '/usr/local/bin', '/usr/bin', '/bin', '/usr/sbin', '/sbin', path.join(hostHome, '.local/bin')];
  const environment = {
    PATH: [...new Set([...(linkShim ? [linkShim.directory] : []), ...additionalExecutablePaths, ...systemPaths])].join(path.delimiter),
    HOME: directories.home, USERPROFILE: directories.home,
    XDG_CONFIG_HOME: directories.config, XDG_CACHE_HOME: directories.cache, XDG_DATA_HOME: directories.data, XDG_STATE_HOME: directories.state,
    CLAUDE_CONFIG_DIR: directories.claude, ANTHROPIC_CONFIG_DIR: directories.anthropic,
    HISTFILE: directories.history, HISTSIZE: '1000', SAVEHIST: '1000',
    ZDOTDIR: directories.home, NPM_CONFIG_USERCONFIG: path.join(directories.home, '.npmrc'),
    GIT_CONFIG_GLOBAL: path.join(directories.home, '.gitconfig'), GIT_CONFIG_NOSYSTEM: '1',
    TMPDIR: directories.temp, TMP: directories.temp, TEMP: directories.temp,
    TZ: timezone, TERM: 'xterm-256color', COLORTERM: 'truecolor', TERM_PROGRAM: 'Envara',
    LANG: language.posix, LC_ALL: language.posix,
    NO_PROXY: 'localhost,127.0.0.1,::1', no_proxy: 'localhost,127.0.0.1,::1',
  };
  if (platform === 'win32') {
    for (const key of ['SystemRoot', 'WINDIR', 'ComSpec', 'PATHEXT']) if (hostEnvironment[key]) environment[key] = hostEnvironment[key];
    const drive = path.parse(directories.home).root;
    environment.HOMEDRIVE = drive.slice(0, 2); environment.HOMEPATH = directories.home.slice(2);
    // Windows tools locate per-user state through these; keep them inside the environment's own directories.
    environment.APPDATA = directories.config; environment.LOCALAPPDATA = directories.data;
  }
  if (proxyEndpoint) for (const key of ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy']) environment[key] = proxyEndpoint;
  // Node's built-in fetch/http ignore proxy variables unless this is set.
  if (proxyEndpoint) environment.NODE_USE_ENV_PROXY = '1';
  // Supported tool opt-outs apply only to this owned shell and its children.
  if (linkShim) {
    environment.BROWSER = path.join(linkShim.directory, 'browser');
    // The open shim reports links over this channel; without these it can only refuse.
    for (const key of ['ENVARA_LINK_SOCKET', 'ENVARA_LINK_TOKEN']) if (typeof linkShim[key] === 'string' && linkShim[key] && !/[\0\r\n]/.test(linkShim[key])) environment[key] = linkShim[key];
  }
  if (privacy?.mode !== 'off') Object.assign(environment, { DO_NOT_TRACK: '1', DISABLE_TELEMETRY: '1', DISABLE_ERROR_REPORTING: '1' });
  if (privacy?.mode === 'strict') environment.CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = '1';
  return environment;
}

/** Select a native interactive shell without starting it or loading host RCs. */
export function terminalShell(environment, { platform, hostEnvironment }) {
  const path = pathFor(platform);
  if (platform === 'win32') return { executable: hostEnvironment.ComSpec ?? path.join(hostEnvironment.SystemRoot ?? 'C:\\Windows', 'System32/cmd.exe'), args: ['/D', '/Q'], environment: { ...environment, PROMPT: 'envara $P$G' } };
  if (platform === 'darwin') return { executable: '/bin/zsh', args: ['-d', '-i'], environment: { ...environment, SHELL: '/bin/zsh', PS1: 'envara %~ %# ' } };
  return { executable: '/bin/bash', args: ['--noprofile', '--rcfile', path.join(environment.HOME, '.bashrc'), '-i'], environment: { ...environment, SHELL: '/bin/bash', PS1: 'envara \\w \\$ ' } };
}
