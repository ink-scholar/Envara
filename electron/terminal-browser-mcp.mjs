// Standalone stdio transport. This file is copied out of app.asar and runs in
// the bundled Node runtime; it must import only Node built-ins. The sidecar's
// global credentials and browser endpoints never reach this process.
import http from 'node:http';
import { pathToFileURL } from 'node:url';

const string = (description, maxLength = 2048) => ({ type: 'string', description, minLength: 1, maxLength });
const integer = (minimum, maximum, description) => ({ type: 'integer', minimum, maximum, description });
const tool = (name, description, properties = {}, required = []) => ({ name, description, inputSchema: { type: 'object', properties, required, additionalProperties: false } });
export const BROWSER_TOOLS = Object.freeze([
  tool('browser_status', 'Report the terminal-bound Envara browser and network. Does not start a browser.'),
  tool('browser_navigate', 'Navigate the selected tab in this terminal\'s chosen Envara browser. Uses its existing network and profile.', { url: string('HTTP or HTTPS URL; no credentials.', 8192) }, ['url']),
  tool('browser_snapshot', 'Read the current page title, visible text and actionable elements with selectors. Use these selectors for following actions.'),
  tool('browser_click', 'Click an element in the selected tab using Playwright.', { selector: string('Selector from browser_snapshot.') }, ['selector']),
  tool('browser_fill', 'Clear a text field and type its replacement value using Playwright.', { selector: string('Selector from browser_snapshot.'), value: { type: 'string', maxLength: 20000 } }, ['selector', 'value']),
  tool('browser_press_key', 'Press a key in the selected tab. Use Playwright key names such as Enter, Tab, Escape or ControlOrMeta+A.', { key: string('Playwright key name or chord.', 100) }, ['key']),
  tool('browser_select', 'Select option values in a select element using Playwright.', { selector: string('Select element selector.'), values: { type: 'array', minItems: 1, maxItems: 50, items: { type: 'string', maxLength: 1024 } } }, ['selector', 'values']),
  tool('browser_check', 'Set a checkbox or radio button using Playwright.', { selector: string('Checkbox or radio selector.'), checked: { type: 'boolean' } }, ['selector', 'checked']),
  tool('browser_scroll', 'Scroll the page by a bounded number of CSS pixels.', { x: integer(-10000, 10000, 'Horizontal pixels, default 0.'), y: integer(-10000, 10000, 'Vertical pixels.') }, ['y']),
  tool('browser_wait_for', 'Wait for a selector to be visible in the selected tab.', { selector: string('Selector to wait for.'), timeoutMs: integer(1, 30000, 'Maximum wait in milliseconds, default 10000.') }, ['selector']),
  tool('browser_screenshot', 'Take a PNG screenshot of the selected tab.', { fullPage: { type: 'boolean' } }),
  tool('browser_tabs', 'List, create, select or close tabs belonging to the chosen Envara browser only. Tab indexes come from list.', { action: { type: 'string', enum: ['list', 'new', 'select', 'close'] }, index: integer(0, 1000, 'Required for select and close.'), url: string('Optional HTTP or HTTPS URL for new.', 8192) }, ['action']),
]);

// Kept in the existing session channel so discovery grants no new authority.
// This tool never connects to a server or starts a browser.
export const TERMINAL_TOOLS = Object.freeze([...BROWSER_TOOLS, {
  ...tool('envara_ssh_connections', 'Before an SSH task, list this terminal session\'s saved SSH authorizations and routes. Each saved alias uses its chosen host or configured-environment route; older records without a route retain the host network. The server sees the selected route\'s exit IP. Unsaved explicit user@host targets use this terminal\'s own environment proxy, never another saved connection\'s route or credentials. An unavailable or changed saved route is refused without fallback. Read-only: does not connect, confirm host fingerprints, load keys, unlock credentials or grant new access. Use SSH through the terminal tool; ready means authorized, not verified reachable.'),
  annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
}]);

const fail = (message, code = 'BROWSER_CHANNEL_UNAVAILABLE') => Object.assign(new Error(message), { code });
/** One authenticated local request. Never uses host HTTP_PROXY or a TCP fallback. */
export function requestBrowserBroker(payload, { socketPath = process.env.ENVARA_BROWSER_SOCKET, token = process.env.ENVARA_BROWSER_TOKEN, timeoutMs = 210000 } = {}) {
  if (typeof socketPath !== 'string' || !socketPath.startsWith('/') || socketPath.includes('\0') ||
      typeof token !== 'string' || !/^[a-f0-9]{64}$/.test(token)) return Promise.reject(fail('Envara browser session is unavailable. Start a new Claude Code session.'));
  const body = JSON.stringify(payload);
  return new Promise((resolve, reject) => {
    // A fresh agent avoids Node's opt-in global environment-proxy agent. This
    // request is local IPC even when Claude's remote traffic uses HTTP_PROXY.
    const request = http.request({ socketPath, agent: false, path: '/mcp', method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body), Authorization: `Bearer ${token}` } }, response => {
      const chunks = []; let size = 0;
      response.on('data', chunk => { size += chunk.length; if (size > 20 * 1024 * 1024) { response.destroy(); reject(fail('Browser response is too large.')); } else chunks.push(chunk); });
      response.on('end', () => {
        if (response.statusCode === 204) return resolve(null);
        if (response.statusCode !== 200) return reject(fail(response.statusCode === 403 ? 'This Envara browser session has ended. Start a new Claude Code session.' : 'Envara refused this browser request.'));
        try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
        catch { reject(fail('Envara returned an invalid browser response.')); }
      });
      response.on('error', () => reject(fail('Envara browser connection ended.')));
    });
    request.setTimeout(timeoutMs, () => request.destroy(fail('Envara browser request timed out.')));
    request.on('error', () => reject(fail('Cannot reach the terminal\'s Envara browser. No other browser was opened.')));
    request.end(body);
  });
}

export async function runBrowserMcp({ input = process.stdin, output = process.stdout, transport = requestBrowserBroker } = {}) {
  input.setEncoding('utf8');
  let buffered = '', queue = Promise.resolve();
  const reply = response => { if (response != null) output.write(`${JSON.stringify(response)}\n`); };
  const processLine = async line => {
    let request;
    try { request = JSON.parse(line); }
    catch { reply({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Invalid JSON.' } }); return; }
    try { reply(await transport(request)); }
    catch (error) {
      if (request && Object.hasOwn(request, 'id')) reply({ jsonrpc: '2.0', id: request.id, error: { code: -32000, message: error?.message ?? 'Envara browser session unavailable.' } });
    }
  };
  for await (const chunk of input) {
    buffered += chunk;
    if (Buffer.byteLength(buffered) > 512 * 1024) throw fail('MCP request exceeds the size limit.');
    let index;
    while ((index = buffered.indexOf('\n')) !== -1) {
      const line = buffered.slice(0, index).trim(); buffered = buffered.slice(index + 1);
      if (line) queue = queue.then(() => processLine(line));
    }
  }
  if (buffered.trim()) queue = queue.then(() => processLine(buffered.trim()));
  await queue;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runBrowserMcp().catch(() => { process.stderr.write('Envara browser MCP stopped. Start a new Claude Code session.\n'); process.exitCode = 1; });
}
