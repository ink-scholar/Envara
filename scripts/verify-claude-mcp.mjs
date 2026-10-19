/** Opt-in native Claude MCP acceptance, with no login or model request.
 * node scripts/verify-claude-mcp.mjs --claude /absolute/native/version
 * The explicitly selected program is copied through the production installer;
 * its original configuration is never used. macOS Seatbelt denies all network
 * access. Every server, plugin, credential and configuration below is disposable.
 */
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { ensureClaudeInstallation, resolveClaudeInstallation } from '../electron/claude-code-installation.mjs';
import { prepareClaudeSession } from '../electron/claude-code-session.mjs';

const usage = 'Usage: node scripts/verify-claude-mcp.mjs --claude /absolute/native/version';
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const digest = value => createHash('sha256').update(value).digest('hex');
const fileDigest = async filename => {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(filename)) hash.update(chunk);
  return hash.digest('hex');
};
const alive = pid => { try { process.kill(pid, 0); return true; } catch { return false; } };
const safeError = (message, code = 'CLAUDE_MCP_VERIFICATION_FAILED') => Object.assign(new Error(message), { code });
const fixtureSource = String.raw`import readline from 'node:readline';
import fs from 'node:fs';
import { createHash } from 'node:crypto';
const [trace, expectationFile, label] = process.argv.slice(2);
const expected = JSON.parse(fs.readFileSync(expectationFile, 'utf8'));
const contextMatches = Object.entries(expected.context).every(([key, value]) => process.env[key] === value);
const privateInherited = Object.entries(expected.privateHashes).every(([key, hash]) =>
  createHash('sha256').update(process.env[key] ?? '').digest('hex') === hash);
const record = entry => fs.appendFileSync(trace, JSON.stringify({ label, ...entry }) + '\n');
record({ event: 'start', pid: process.pid, contextMatches, privateInherited });
const input = readline.createInterface({ input: process.stdin });
input.on('line', line => {
  let message;
  try { message = JSON.parse(line); } catch { return; }
  record({ event: 'message', method: message.method, value: message.params?.arguments?.value });
  if (message.id === undefined) return;
  let result;
  if (message.method === 'initialize') result = { protocolVersion: message.params.protocolVersion,
    capabilities: { tools: {} }, serverInfo: { name: label, version: '1.0.0' } };
  else if (message.method === 'tools/list') result = { tools: [{ name: 'envara_fixture_echo',
    description: 'Echo a disposable verification marker; no external services.',
    inputSchema: { type: 'object', properties: { value: { type: 'string' } }, required: ['value'], additionalProperties: false } }] };
  else if (message.method === 'tools/call' && message.params.name === 'envara_fixture_echo') result = {
    content: [{ type: 'text', text: JSON.stringify({ fixture: label, value: message.params.arguments.value,
      contextMatches, privateInherited }) }], isError: false };
  else if (message.method === 'ping') result = {};
  else if (message.method === 'resources/list') result = { resources: [] };
  else if (message.method === 'prompts/list') result = { prompts: [] };
  const response = result === undefined
    ? { jsonrpc: '2.0', id: message.id, error: { code: -32601, message: 'Fixture method unavailable' } }
    : { jsonrpc: '2.0', id: message.id, result };
  process.stdout.write(JSON.stringify(response) + '\n');
});
`;

function containsFixtureResult(value, label, marker) {
  if (typeof value === 'string') {
    try { return containsFixtureResult(JSON.parse(value), label, marker); } catch { return false; }
  }
  if (!value || typeof value !== 'object') return false;
  if (value.fixture === label && value.value === marker && value.contextMatches === true && value.privateInherited === true) return true;
  return Object.values(value).some(item => containsFixtureResult(item, label, marker));
}

async function verify(nativeArgument, signal) {
  let stage = 'validate explicit native program';
  let temporary, temporaryIdentity, launch, proof, failure;
  const children = new Set();
  const checks = [];
  const check = message => { checks.push(message); console.log(`PASS ${message}`); };
  const groupAlive = child => {
    if (!Number.isInteger(child.pid) || child.pid <= 0) return false;
    try { process.kill(-child.pid, 0); return true; } catch (error) { return error.code !== 'ESRCH'; }
  };
  const stop = child => child.stopping ??= (async () => {
    // A detached group's leader may exit before its stdio MCP children. Keep
    // ownership until the group is observed empty, including failure paths.
    if (!groupAlive(child)) { children.delete(child); return; }
    if (!child.stdin?.destroyed) child.stdin?.end();
    for (const signal of ['SIGTERM', 'SIGKILL']) {
      try { process.kill(-child.pid, signal); } catch (error) { if (error.code !== 'ESRCH') throw error; }
      const deadline = Date.now() + 2000;
      while (groupAlive(child) && Date.now() < deadline) await sleep(25);
      if (!groupAlive(child)) { children.delete(child); return; }
    }
    throw safeError('An owned verification process group did not exit.');
  })();
  const cancel = () => { for (const child of children) void stop(child).catch(() => {}); };
  signal.addEventListener('abort', cancel);
  try {
    assert.equal(process.platform, 'darwin', 'This verifier requires the implemented macOS network fence.');
    assert(path.isAbsolute(nativeArgument), 'Select an absolute native program path.');
    const source = await realpath(nativeArgument), node = await realpath(process.execPath);
    const sourceBefore = await lstat(source), sourceHash = await fileDigest(source);
    temporary = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-claude-mcp-')));
    temporaryIdentity = await lstat(temporary);
    const directories = Object.fromEntries(['home', 'claude', 'temp', 'workspace'].map(name => [name, path.join(temporary, name)]));
    directories.anthropic = path.join(directories.claude, 'anthropic');
    for (const directory of Object.values(directories)) await mkdir(directory, { mode: 0o700 });
    const trace = path.join(temporary, 'trace.jsonl'), expectationFile = path.join(temporary, 'expectations.json');
    const fixture = path.join(temporary, 'fixture.mjs'), fence = path.join(temporary, 'fence.sb');
    const hostHome = os.homedir();
    const forbidden = [path.join(hostHome, '.claude'), path.join(hostHome, '.claude.json'),
      path.join(hostHome, 'Library/Keychains'), '/Library/Keychains'];
    if (process.env.CLAUDE_CONFIG_DIR && path.isAbsolute(process.env.CLAUDE_CONFIG_DIR)) forbidden.push(process.env.CLAUDE_CONFIG_DIR);
    // The test is stricter than a managed route: all networking is denied, and
    // host Claude/Keychain paths are blocked without opening or reading them.
    await writeFile(fence, `(version 1)\n(allow default)\n(deny network*)\n(deny file-read* ${forbidden.map(value => `(subpath ${JSON.stringify(value)})`).join(' ')})\n(deny mach-lookup (global-name "com.apple.securityd") (global-name "com.apple.SecurityServer"))\n`, { mode: 0o600 });
    await writeFile(fixture, fixtureSource, { mode: 0o600 });
    await writeFile(trace, '', { mode: 0o600 });
    const secrets = Object.fromEntries(['proxy', 'browser', 'link', 'ssh'].map(key => [key, `fixture-${randomBytes(18).toString('hex')}`]));
    const proxy = `http://fixture:${secrets.proxy}@127.0.0.1:9`;
    const environment = {
      HOME: directories.home, USERPROFILE: directories.home, CLAUDE_CONFIG_DIR: directories.claude,
      ANTHROPIC_CONFIG_DIR: directories.anthropic, TMPDIR: directories.temp, TMP: directories.temp, TEMP: directories.temp,
      XDG_CONFIG_HOME: path.join(directories.home, '.config'), XDG_CACHE_HOME: path.join(directories.home, '.cache'),
      XDG_DATA_HOME: path.join(directories.home, '.local/share'), XDG_STATE_HOME: path.join(directories.home, '.local/state'),
      PATH: `${path.dirname(node)}:/usr/bin:/bin:/usr/sbin:/sbin`, LANG: 'en_US.UTF-8', LC_ALL: 'en_US.UTF-8', TZ: 'UTC', TERM: 'dumb',
      BROWSER: '/usr/bin/false', GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1', GIT_TERMINAL_PROMPT: '0',
      HTTP_PROXY: proxy, HTTPS_PROXY: proxy, ALL_PROXY: proxy, NO_PROXY: 'localhost,127.0.0.1,::1', NODE_USE_ENV_PROXY: '1',
      ENVARA_BROWSER_TOKEN: secrets.browser, ENVARA_LINK_TOKEN: secrets.link,
      ENVARA_SSH_PROXY_URL: `http://fixture:${secrets.ssh}@127.0.0.1:9`,
      ENVARA_BROWSER_SOCKET: path.join(temporary, 'unused-browser.sock'), ENVARA_LINK_SOCKET: path.join(temporary, 'unused-links.sock'),
      MCP_TIMEOUT: '5000', MCP_TOOL_TIMEOUT: '5000',
    };
    const userSettings = path.join(directories.claude, 'settings.json');
    const projectSettings = path.join(directories.workspace, '.claude', 'settings.json');
    const localSettings = path.join(directories.workspace, '.claude', 'settings.local.json');
    await mkdir(path.dirname(projectSettings), { mode: 0o700 });
    const settings = [
      [userSettings, { env: { MCP_FIXTURE_USER_SETTING: 'user-preserved' } }],
      [projectSettings, { env: { MCP_FIXTURE_PROJECT_SETTING: 'project-preserved' } }],
      [localSettings, { env: { MCP_FIXTURE_LOCAL_SETTING: 'local-preserved' } }],
    ];
    for (const [filename, value] of settings) await writeFile(filename, JSON.stringify(value), { mode: 0o600 });
    stage = 'copy native program with the production installer';
    const installation = await ensureClaudeInstallation({ home: directories.home, source: 'local', findHostExecutable: async () => source });
    const installed = await resolveClaudeInstallation(installation), installedInfo = await lstat(installed);
    assert.notEqual(`${installedInfo.dev}:${installedInfo.ino}`, `${sourceBefore.dev}:${sourceBefore.ino}`);
    assert.equal(await fileDigest(installed), sourceHash);
    stage = 'prepare production Claude wrapper';
    launch = await prepareClaudeSession({ sessionId: 'verify_mcp', directories, installation, environment,
      privacy: { mode: 'strict' }, mcpServer: { command: node, args: [fixture, trace, expectationFile, 'bound-browser'] } });
    const runtime = path.dirname(launch.args[launch.args.indexOf('--mcp-config') + 1]);
    const privateKeys = ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'ENVARA_BROWSER_TOKEN', 'ENVARA_LINK_TOKEN', 'ENVARA_SSH_PROXY_URL'];
    const expectedContext = Object.fromEntries(['HOME', 'USERPROFILE', 'CLAUDE_CONFIG_DIR', 'ANTHROPIC_CONFIG_DIR', 'TMPDIR',
      'XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_DATA_HOME', 'XDG_STATE_HOME', 'PATH', 'TZ', 'LANG', 'LC_ALL', 'BROWSER',
      'ENVARA_BROWSER_SOCKET', 'ENVARA_LINK_SOCKET', 'DISABLE_AUTOUPDATER', 'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC']
      .map(key => [key, launch.environment[key]]));
    const privateHashes = Object.fromEntries(privateKeys.map(key => [key, digest(launch.environment[key])]));
    const writeExpectations = async sources => writeFile(expectationFile, JSON.stringify({ privateHashes, context: {
      ...expectedContext, MCP_FIXTURE_USER_SETTING: 'user-preserved',
      ...(sources === 'all' ? { MCP_FIXTURE_PROJECT_SETTING: 'project-preserved', MCP_FIXTURE_LOCAL_SETTING: 'local-preserved' } : {}),
    } }), { mode: 0o600 });
    await writeExpectations('all');
    const checkPrivateFiles = async directory => {
      for (const entry of await readdir(directory, { withFileTypes: true })) {
        const filename = path.join(directory, entry.name);
        if (entry.isDirectory()) await checkPrivateFiles(filename);
        else if (entry.isFile()) {
          const text = await readFile(filename, 'utf8');
          for (const secret of Object.values(secrets)) assert(!text.includes(secret), 'Private runtime files must not serialize credentials.');
        }
      }
    };
    await checkPrivateFiles(runtime);
    const overlay = JSON.parse(await readFile(launch.args[launch.args.indexOf('--settings') + 1], 'utf8'));
    for (const key of privateKeys) assert.equal(overlay.env[key], undefined);
    for (const [key, value] of Object.entries(expectedContext)) assert.equal(overlay.env[key], value);
    check('production installation and wrapper preserve context without writing private credentials');

    function start(executable, args) {
      if (signal.aborted) throw safeError('Verification interrupted.');
      const child = spawn('/usr/bin/sandbox-exec', ['-f', fence, executable, ...args], {
        cwd: directories.workspace, env: launch.environment, stdio: ['pipe', 'pipe', 'pipe'], detached: true,
      });
      child.closed = new Promise(resolve => child.once('close', (code, signal) => resolve({ code, signal })));
      // EPIPE is a stream error, not a ChildProcess error. Handle it even when
      // the native CLI exits between a control request and its pipe write.
      for (const stream of ['stdin', 'stdout', 'stderr']) child[stream].on('error', () => {});
      children.add(child);
      return child;
    }
    async function command(args, { executable = launch.wrapperPath, expectedCode = 0 } = {}) {
      const child = start(executable, args), output = { stdout: '', stderr: '' };
      let overflow = false, spawnFailed = false;
      for (const stream of ['stdout', 'stderr']) child[stream].on('data', chunk => {
        if (output[stream].length + chunk.length > 1024 * 1024) { overflow = true; void stop(child).catch(() => {}); }
        else output[stream] += chunk.toString('utf8');
      });
      child.once('error', () => { spawnFailed = true; });
      child.stdin.end();
      let timer, cancelCommand;
      const interrupted = new Promise((_, reject) => {
        timer = setTimeout(() => reject(safeError('The isolated command timed out.')), 20000);
        cancelCommand = () => reject(safeError('Verification interrupted.'));
        signal.addEventListener('abort', cancelCommand, { once: true });
      });
      let result;
      try { result = await Promise.race([child.closed, interrupted]); }
      finally { clearTimeout(timer); signal.removeEventListener('abort', cancelCommand); }
      assert(!overflow && !spawnFailed, 'The isolated command did not complete safely.');
      assert.equal(result.code, expectedCode, 'The isolated command returned an unexpected exit code.');
      await stop(child);
      return output;
    }
    stage = 'verify offline fence and copied native version';
    const network = await command(['--input-type=module', '-e', `import net from 'node:net';const s=net.connect({host:'192.0.2.1',port:9});s.on('connect',()=>{s.destroy();process.exitCode=1});s.on('error',e=>{console.log(JSON.stringify({denied:['EPERM','EACCES'].includes(e.code)}))});s.setTimeout(2000,()=>{s.destroy();process.exitCode=1});`], { executable: node });
    assert.equal(JSON.parse(network.stdout).denied, true);
    const versionOutput = (await command(['--version'])).stdout.trim();
    const version = /^(\d+\.\d+\.\d+(?:[-+][\w.-]+)?) \(Claude Code\)$/.exec(versionOutput)?.[1];
    assert(version, 'The selected native program must identify itself as Claude Code.');
    check('copied official CLI starts through the production wrapper under a network-denying fence');

    const fixtureArgs = label => [node, fixture, trace, expectationFile, label];
    stage = 'add disposable user, default-local and project MCPs through the wrapper';
    await command(['mcp', 'add', '--scope', 'user', 'okx', '--', ...fixtureArgs('fixture-okx-user')]);
    await command(['mcp', 'add', 'binance-mcp-server', '--', ...fixtureArgs('fixture-binance-local')]);
    await command(['mcp', 'add', '--scope', 'project', 'project_fixture', '--', ...fixtureArgs('fixture-project')]);
    await command(['mcp', 'add', 'envara_browser', '--', ...fixtureArgs('rejected-browser-collision')]);
    const saved = JSON.parse(await readFile(path.join(directories.claude, '.claude.json'), 'utf8'));
    assert(saved.mcpServers?.okx);
    assert(saved.projects?.[directories.workspace]?.mcpServers?.['binance-mcp-server']);
    assert(JSON.parse(await readFile(path.join(directories.workspace, '.mcp.json'), 'utf8')).mcpServers?.project_fixture);
    check('official mcp add persists user, default local and project scopes in the disposable profile');

    stage = 'install the disposable local plugin through the wrapper';
    const marketplace = path.join(temporary, 'marketplace'), plugin = path.join(marketplace, 'plugins', 'envara-fixture');
    await mkdir(path.join(marketplace, '.claude-plugin'), { recursive: true, mode: 0o700 });
    await mkdir(path.join(plugin, '.claude-plugin'), { recursive: true, mode: 0o700 });
    await writeFile(path.join(marketplace, '.claude-plugin', 'marketplace.json'), JSON.stringify({
      name: 'envara-verification', owner: { name: 'Disposable verification' },
      plugins: [{ name: 'envara-fixture', source: './plugins/envara-fixture', description: 'Offline verification fixture' }],
    }), { mode: 0o600 });
    await writeFile(path.join(plugin, '.claude-plugin', 'plugin.json'), JSON.stringify({ name: 'envara-fixture', version: '1.0.0' }), { mode: 0o600 });
    const [pluginCommand, ...pluginArgs] = fixtureArgs('fixture-plugin');
    await writeFile(path.join(plugin, '.mcp.json'), JSON.stringify({ mcpServers: { fixture_plugin: { command: pluginCommand, args: pluginArgs } } }), { mode: 0o600 });
    await command(['plugin', 'marketplace', 'add', marketplace, '--scope', 'user', '--json']);
    await command(['plugin', 'install', 'envara-fixture@envara-verification', '--scope', 'user', '--json']);
    const plugins = JSON.parse((await command(['plugin', 'list', '--json'])).stdout);
    assert(plugins.some(item => item.id === 'envara-fixture@envara-verification' && item.scope === 'user' && item.enabled));
    check('official plugin commands install and enable a local fixture in the disposable user scope');

    const servers = [
      { name: 'okx', label: 'fixture-okx-user', source: 'user' },
      { name: 'binance-mcp-server', label: 'fixture-binance-local', source: 'local' },
      { name: 'project_fixture', label: 'fixture-project', source: 'project' },
      { name: 'plugin:envara-fixture:fixture_plugin', label: 'fixture-plugin', source: 'plugin' },
      { name: 'envara_browser', label: 'bound-browser', source: 'dynamic' },
    ];
    async function discoveryCase({ executable = launch.wrapperPath, args = [], expected, sources = 'all' }) {
      await writeExpectations(sources);
      await writeFile(trace, '', { mode: 0o600 });
      const child = start(executable, [...args, '--print', '--input-format', 'stream-json', '--output-format', 'stream-json', '--verbose', '--no-session-persistence']);
      const pending = new Map(); let buffer = '', sequence = 0, unexpected = false, stderrBytes = 0;
      const rejectAll = () => { for (const item of pending.values()) { clearTimeout(item.timer); item.reject(safeError('Native control protocol closed.')); } pending.clear(); };
      child.once('error', rejectAll); child.once('close', rejectAll);
      child.stdin.once('error', rejectAll);
      child.stderr.on('data', chunk => { stderrBytes += chunk.length; if (stderrBytes > 1024 * 1024) void stop(child).catch(() => {}); });
      child.stdout.setEncoding('utf8');
      child.stdout.on('data', chunk => {
        buffer += chunk;
        if (buffer.length > 4 * 1024 * 1024) { unexpected = true; void stop(child).catch(() => {}); return; }
        let newline;
        while ((newline = buffer.indexOf('\n')) >= 0) {
          const line = buffer.slice(0, newline); buffer = buffer.slice(newline + 1);
          if (!line.trim()) continue;
          let frame;
          try { frame = JSON.parse(line); } catch { unexpected = true; continue; }
          if (['assistant', 'user', 'result', 'stream_event', 'control_request'].includes(frame.type)) unexpected = true;
          if (frame.type !== 'control_response') continue;
          const item = pending.get(frame.response?.request_id);
          if (!item) continue;
          pending.delete(frame.response.request_id); clearTimeout(item.timer);
          if (frame.response.subtype === 'success') item.resolve(frame.response.response);
          else item.reject(safeError('The native CLI rejected a verification control request.'));
        }
      });
      const request = request => new Promise((resolve, reject) => {
        // This transport cannot submit a user prompt or ask the model to act.
        assert(['initialize', 'mcp_status', 'mcp_call'].includes(request.subtype));
        const request_id = `envara-verification-${++sequence}`;
        const timer = setTimeout(() => { pending.delete(request_id); reject(safeError('Native control request timed out.')); }, 15000);
        pending.set(request_id, { resolve, reject, timer });
        child.stdin.write(`${JSON.stringify({ type: 'control_request', request_id, request })}\n`);
      });
      let caseFailure;
      try {
        await request({ subtype: 'initialize' });
        const deadline = Date.now() + 15000;
        let statuses;
        do {
          statuses = (await request({ subtype: 'mcp_status' }))?.mcpServers ?? [];
          if (expected.every(server => statuses.some(item => item.name === server.name))) break;
          await sleep(100);
        } while (Date.now() < deadline);
        assert.deepEqual(statuses.map(item => item.name).sort(), expected.map(item => item.name).sort(), 'Only the expected fixture MCPs should be discovered.');
        const calls = new Map();
        for (const server of expected) {
          const marker = randomBytes(12).toString('hex'); calls.set(server.label, marker);
          const result = await request({ subtype: 'mcp_call', tool: `mcp__${server.name.replace(/[^a-zA-Z0-9_-]/g, '_')}__envara_fixture_echo`,
            arguments: { value: marker }, result_not_for_model: true });
          assert(containsFixtureResult(result, server.label, marker), 'The MCP tool must return its marker and inherited context.');
        }
        statuses = (await request({ subtype: 'mcp_status' }))?.mcpServers ?? [];
        for (const server of expected) {
          const status = statuses.find(item => item.name === server.name);
          assert.equal(status?.status, 'connected'); assert.equal(status?.source, server.source);
          assert(status.tools?.some(tool => tool.name === 'envara_fixture_echo'));
        }
        child.stdin.end();
        const end = await Promise.race([child.closed, sleep(5000).then(() => null)]);
        assert.equal(end?.code, 0, 'The native process should exit after the control stream closes.');
        assert.equal(unexpected, false, 'No model-turn or permission request should occur.');
        const events = (await readFile(trace, 'utf8')).trim().split('\n').filter(Boolean).map(line => JSON.parse(line));
        assert.deepEqual([...new Set(events.filter(event => event.event === 'start').map(event => event.label))].sort(), expected.map(server => server.label).sort());
        for (const server of expected) {
          const own = events.filter(event => event.label === server.label), started = own.find(event => event.event === 'start');
          assert.equal(started?.contextMatches, true); assert.equal(started?.privateInherited, true);
          for (const method of ['initialize', 'tools/list']) assert(own.some(event => event.method === method));
          assert(own.some(event => event.method === 'tools/call' && event.value === calls.get(server.label)));
          assert.equal(alive(started.pid), false, 'Owned fixture processes must exit with the native session.');
        }
      } catch (error) {
        caseFailure = error;
      } finally {
        rejectAll();
        try { await stop(child); } catch (error) { caseFailure ??= error; }
      }
      if (caseFailure) throw caseFailure;
    }
    stage = 'discover and call all MCP scopes through the production wrapper';
    await discoveryCase({ expected: servers });
    check('fresh production wrapper discovers and calls user, default local, project and enabled plugin MCPs');
    check('CLI browser injection wins over a same-name saved MCP without starting the conflicting server');
    stage = 'verify former strict-mode regression control';
    const userArgs = [...launch.args]; userArgs[userArgs.indexOf('--setting-sources') + 1] = 'user';
    await discoveryCase({ executable: installed, args: [...userArgs, '--strict-mcp-config'], expected: servers.filter(server => server.source === 'dynamic'), sources: 'user' });
    check('strict-mode control hides saved MCPs and plugin MCPs');
    stage = 'verify former user-only settings regression control';
    await discoveryCase({ executable: installed, args: userArgs, expected: servers.filter(server => ['user', 'plugin', 'dynamic'].includes(server.source)), sources: 'user' });
    check('user-only settings control hides default local and project MCPs');
    stage = 'verify settings preflight on a later wrapper invocation';
    const projectBefore = await readFile(projectSettings, 'utf8');
    await writeFile(projectSettings, JSON.stringify({ env: { HTTPS_PROXY: 'http://fixture-conflict.invalid:9' } }), { mode: 0o600 });
    const refused = await command(['--version'], { expectedCode: 78 });
    assert(refused.stderr.includes('CLAUDE_CODE_SESSION_POLICY_CONFLICT'));
    await writeFile(projectSettings, projectBefore, { mode: 0o600 });
    check('the production wrapper rejects a conflicting project route on its next invocation');
    stage = 'verify unchanged source and persistent MCP discovery';
    await discoveryCase({ expected: servers });
    const sourceAfter = await lstat(source);
    for (const key of ['dev', 'ino', 'size', 'mtimeMs', 'ctimeMs']) assert.equal(sourceAfter[key], sourceBefore[key]);
    assert.equal(await fileDigest(source), sourceHash);
    check('a second production invocation retains MCPs and leaves the source native program unchanged');
    if (signal.aborted) throw safeError('Verification interrupted.');
    proof = { passed: true, version, checks, limitations: [
      'Only disposable stdio MCPs and a local plugin are used; real exchange MCPs, credentials and remote services are not exercised.',
      'The control channel invokes fixture tools directly without a model turn; model tool selection and interactive project approval are not exercised.',
      'This checks source modules and the selected native CLI on macOS, not a packaged application or renderer workflow.',
    ] };
  } catch (error) {
    failure = safeError(`${signal.aborted ? 'Verification interrupted' : stage}${error?.code && /^[A-Z0-9_]+$/.test(error.code) ? ` (${error.code})` : ''}`);
  } finally {
    let cleanupFailed = (await Promise.allSettled([...children].map(stop))).some(result => result.status === 'rejected');
    if (!cleanupFailed) {
      try { await launch?.cleanup(); } catch { cleanupFailed = true; }
    }
    // Preserve files when an owned process or cleanup identity is uncertain.
    if (!cleanupFailed && temporary) {
      try {
        const current = await lstat(temporary);
        assert(current.isDirectory() && !current.isSymbolicLink() && current.dev === temporaryIdentity.dev && current.ino === temporaryIdentity.ino);
        await rm(temporary, { recursive: true, force: true });
      } catch { cleanupFailed = true; }
    }
    signal.removeEventListener('abort', cancel);
    if (cleanupFailed) {
      failure ??= safeError('Owned verification cleanup failed.');
      failure.message += ' Cleanup is incomplete; disposable resources were retained.';
    }
  }
  if (failure) throw failure;
  return proof;
}

const argv = process.argv.slice(2);
if (argv.length === 1 && ['--help', '-h'].includes(argv[0])) console.log(usage);
else if (argv.length !== 2 || argv[0] !== '--claude' || !path.isAbsolute(argv[1])) {
  console.error(usage); process.exitCode = 64;
} else {
  const controller = new AbortController();
  let interrupted;
  const handlers = Object.fromEntries(['SIGINT', 'SIGTERM'].map(name => [name, () => { interrupted = name; controller.abort(); }]));
  for (const [name, handler] of Object.entries(handlers)) process.on(name, handler);
  try {
    const proof = await verify(argv[1], controller.signal);
    if (controller.signal.aborted) throw safeError('Verification interrupted.');
    console.log(JSON.stringify(proof, null, 2));
  }
  catch (error) {
    // Do not emit native stdout/stderr, full error objects, arguments or paths.
    console.error(`FAIL ${error?.code === 'CLAUDE_MCP_VERIFICATION_FAILED' ? error.message : 'Owned verification cleanup failed.'}`);
    process.exitCode = interrupted === 'SIGINT' ? 130 : interrupted === 'SIGTERM' ? 143 : 1;
  } finally {
    for (const [name, handler] of Object.entries(handlers)) process.off(name, handler);
  }
}
