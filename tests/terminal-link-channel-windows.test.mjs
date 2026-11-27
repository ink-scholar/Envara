import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { platformTest } from './support/platform-test.mjs';
import { TerminalLinkChannel, linkShimScripts } from '../electron/terminal-link-channel.mjs';
import { WINDOWS_LINK_SCRIPT, terminalChildEnvironment, windowsBrowserCommand } from '../electron/terminal-launch-config.mjs';

const windowsOnly = platformTest(['win32'], 'named pipes and PowerShell exist only on Windows');

test('the Windows shim is a single PowerShell script with a BOM and no batch file', () => {
  const scripts = linkShimScripts('win32');
  assert.deepEqual(Object.keys(scripts), [WINDOWS_LINK_SCRIPT]);
  const source = scripts[WINDOWS_LINK_SCRIPT];
  assert.equal(source.charCodeAt(0), 0xfeff, 'Windows PowerShell 5 needs the BOM for its Chinese text');
  assert.match(source, /NamedPipeClientStream/);
  assert.match(source, /\$target -notmatch '\^https\?:\/\/\\S\+\$'/);
  assert.doesNotMatch(source, /cmd(\.exe)? \/c|Start-Process|Invoke-Expression|iex /i, 'a link is never handed to a shell or the host opener');
  assert.deepEqual(Object.keys(linkShimScripts('darwin')).sort(), ['browser', 'envara-open', 'open']);
});

test('Windows $BROWSER is a PowerShell command line whose last argument receives the link', () => {
  const command = windowsBrowserCommand('C:\\Users\\Fixture\\AppData\\Roaming\\Envara\\link\\bin\\prof_1', 'C:\\Windows');
  assert.equal(command, '"C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "C:/Users/Fixture/AppData/Roaming/Envara/link/bin/prof_1/envara-open.ps1" %s');
  const directories = Object.fromEntries(['home', 'config', 'cache', 'data', 'state', 'claude', 'anthropic', 'temp', 'history'].map(key => [key, path.win32.join('D:\\Owned', key)]));
  const environment = terminalChildEnvironment({ directories, platform: 'win32', timezone: 'UTC', proxyEndpoint: null, language: { posix: 'en_US.UTF-8' },
    hostHome: 'C:\\Users\\Fixture', additionalExecutablePaths: [], hostEnvironment: { SystemRoot: 'C:\\System' },
    linkShim: { directory: 'D:\\Owned\\link\\prof_1', ENVARA_LINK_SOCKET: '\\\\.\\pipe\\envara-link-abc', ENVARA_LINK_TOKEN: 'a'.repeat(64) } });
  assert.equal(environment.BROWSER, windowsBrowserCommand('D:\\Owned\\link\\prof_1', 'C:\\System'));
  assert.equal(environment.ENVARA_LINK_SOCKET, '\\\\.\\pipe\\envara-link-abc');
});

async function channel(t, onLink) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'envara-link-windows-'));
  const links = [];
  const server = new TerminalLinkChannel({ root, onLink: async link => { links.push(link); return onLink ? onLink(link) : { opened: 'environment', browser: 'Workspace' }; } });
  t.after(async () => { await server.close(); await rm(root, { recursive: true, force: true }); });
  const pipe = await server.listen();
  const directory = await server.executableDirectory('prof_1');
  return { server, pipe, directory, links, environment: server.environment('prof_1') };
}

/* Runs the shim exactly as a $BROWSER caller would: PowerShell, the script
 * and the link as separate arguments, without any shell in between. */
function openLink(directory, environment, ...links) {
  return new Promise((resolve, reject) => {
    const powershell = path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
    const child = spawn(powershell, ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', path.join(directory, WINDOWS_LINK_SCRIPT), ...links],
      { env: { SystemRoot: process.env.SystemRoot, PATH: process.env.PATH, ...environment }, windowsHide: true });
    let stderr = '';
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.once('error', reject);
    child.once('close', code => resolve({ code, stderr }));
  });
}

windowsOnly('a terminal link travels over the named pipe to the environment browser, and URLs are never re-parsed', async t => {
  const f = await channel(t);
  assert.match(f.pipe, /^\\\\\.\\pipe\\envara-link-[0-9a-f-]{36}$/);
  assert.equal(f.environment.ENVARA_LINK_SOCKET, f.pipe);
  assert.equal((await readFile(path.join(f.directory, WINDOWS_LINK_SCRIPT), 'utf8')).charCodeAt(0), 0xfeff);
  const tricky = 'https://example.test/callback?code=1&state=2|whoami&x=%25s';
  const opened = await openLink(f.directory, f.environment, tricky, '%s');
  assert.equal(opened.code, 0, opened.stderr);
  assert.deepEqual(f.links, [{ profileId: 'prof_1', url: tricky }]);
  assert.match(opened.stderr, /Workspace/);
});

windowsOnly('the Windows shim refuses non-web arguments, a wrong token and a missing channel without opening anything', async t => {
  const f = await channel(t);
  const local = await openLink(f.directory, f.environment, 'C:\\Windows\\System32\\calc.exe');
  assert.equal(local.code, 1); assert.deepEqual(f.links, []);
  const forged = await openLink(f.directory, { ...f.environment, ENVARA_LINK_TOKEN: 'b'.repeat(64) }, 'https://example.test/');
  assert.equal(forged.code, 1); assert.deepEqual(f.links, []);
  const missing = await openLink(f.directory, { ENVARA_LINK_SOCKET: f.pipe }, 'https://example.test/');
  assert.equal(missing.code, 1); assert.deepEqual(f.links, []);
  const other = await openLink(f.directory, { ...f.environment, ENVARA_LINK_SOCKET: '\\\\.\\pipe\\someone-else' }, 'https://example.test/');
  assert.equal(other.code, 1); assert.deepEqual(f.links, []);
});
