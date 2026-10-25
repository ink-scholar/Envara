import Headless from '@xterm/headless';
import { getTerminalTheme } from '../shared/terminal-theme.mjs';

const { Terminal } = Headless;

const ESC = '\x1b';
const HIGH_WATER = 128 * 1024;
const LOW_WATER = 64 * 1024;
const SYNCHRONIZED_OUTPUT_TIMEOUT_MS = 1000;
const COLOR_KEYS = ['black', 'red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'white',
  'brightBlack', 'brightRed', 'brightGreen', 'brightYellow', 'brightBlue', 'brightMagenta', 'brightCyan', 'brightWhite'];
// The pinned xterm.js 6 ANSI defaults (MIT), including defaults omitted by the
// application theme. Keep the protocol palette equal to its browser renderer.
const ANSI_DEFAULTS = ['#2e3436', '#cc0000', '#4e9a06', '#c4a000', '#3465a4', '#75507b', '#06989a', '#d3d7cf',
  '#555753', '#ef2929', '#8ae234', '#fce94f', '#729fcf', '#ad7fa8', '#34e2e2', '#eeeeec'];
const SPECIAL_KEYS = ['foreground', 'background', 'cursor'];

// XParseColor's rgb: form scales each component; its # form keeps the most
// significant eight bits. This is deliberately the same contract as xterm 6.
function parseColor(value) {
  if (typeof value !== 'string') return null;
  const rgb = /^rgb:([\da-f]{1,4})\/([\da-f]{1,4})\/([\da-f]{1,4})$/i.exec(value);
  if (rgb && rgb[1].length === rgb[2].length && rgb[1].length === rgb[3].length)
    return rgb.slice(1).map(component => Math.round(parseInt(component, 16) * 255 / (16 ** component.length - 1)));
  if (!/^#[\da-f]+$/i.test(value) || ![4, 7, 10, 13].includes(value.length)) return null;
  const width = (value.length - 1) / 3;
  return [0, 1, 2].map(index => {
    const component = parseInt(value.slice(1 + index * width, 1 + (index + 1) * width), 16);
    return width === 1 ? component << 4 : component >> ((width - 2) * 4);
  });
}

function palette(theme) {
  const result = COLOR_KEYS.map((key, index) => parseColor(theme[key]) ?? parseColor(ANSI_DEFAULTS[index]));
  const levels = [0, 95, 135, 175, 215, 255];
  for (const red of levels) for (const green of levels) for (const blue of levels) result.push([red, green, blue]);
  for (let level = 0; level < 24; level++) result.push(Array(3).fill(8 + level * 10));
  for (let index = 0; index < Math.min(240, theme.extendedAnsi?.length ?? 0); index++)
    result[index + 16] = parseColor(theme.extendedAnsi[index]) ?? result[index + 16];
  return [...result, ...SPECIAL_KEYS.map((key, index) => parseColor(theme[key]) ?? (index === 1 ? [0, 0, 0] : [255, 255, 255]))];
}

const colorReply = (identifier, color) => `${ESC}]${identifier};rgb:${color.map(channel => channel.toString(16).padStart(2, '0').repeat(2)).join('/')}${ESC}\\`;

/** One protocol state machine per owned PTY. It consumes only live output,
 * independently of views, and never replays a snapshot or accepts user input.
 * Output and resize operations share this local, callback-driven queue so a
 * resize cannot overtake bytes already submitted to xterm's asynchronous parser.
 */
export class TerminalProtocol {
  constructor({ columns = 80, rows = 24, write, getTheme = () => getTerminalTheme('dark'), onPressure = () => {} } = {}) {
    if (typeof write !== 'function' || typeof getTheme !== 'function' || typeof onPressure !== 'function') throw new TypeError('Invalid terminal protocol callbacks.');
    this.writeReply = write; this.getTheme = getTheme; this.onPressure = onPressure;
    this.disposed = false; this.queue = []; this.current = null; this.queuedBytes = 0; this.pressured = false;
    this.themeSignature = null; this.basePalette = []; this.colors = [];
    this.terminal = new Terminal({ cols: columns, rows, scrollback: 3000, cursorBlink: true, allowProposedApi: true,
      windowOptions: { getWinSizeChars: true }, logger: { trace() {}, debug() {}, info() {}, warn() {}, error() {} } });
    this.disposables = [this.terminal.onData(data => this.reply(data))];
    // The browser RenderService expires DEC 2026 after 1000 ms. Headless has
    // no renderer/watchdog, so report the same bounded synchronization window
    // without reaching into xterm internals or sending synthetic PTY input.
    this.synchronizedOutputUntil = 0;
    this.disposables.push(this.terminal.parser.registerCsiHandler({ prefix: '?', final: 'h' }, params => {
      const now = performance.now();
      if (params.includes(2026) && this.synchronizedOutputUntil <= now)
        this.synchronizedOutputUntil = now + SYNCHRONIZED_OUTPUT_TIMEOUT_MS;
      return false;
    }));
    const resetSynchronizedOutput = () => { this.synchronizedOutputUntil = 0; return false; };
    this.disposables.push(this.terminal.parser.registerCsiHandler({ prefix: '?', final: 'l' }, params => {
      if (params.includes(2026)) resetSynchronizedOutput();
      return false;
    }));
    this.disposables.push(this.terminal.parser.registerEscHandler({ final: 'c' }, resetSynchronizedOutput));
    this.disposables.push(this.terminal.parser.registerCsiHandler({ prefix: '?', intermediates: '$', final: 'p' }, params => {
      if (params[0] !== 2026) return false;
      const active = this.terminal.modes.synchronizedOutputMode && this.synchronizedOutputUntil > performance.now();
      this.reply(`${ESC}[?2026;${active ? 1 : 2}$y`);
      return true;
    }));
    this.syncTheme();
    // Color replies live in xterm's browser ThemeService, which headless does
    // not provide. Parse OSC payloads through the public parser, never a second
    // escape-sequence scanner, and retain set/reset behavior across queries.
    this.disposables.push(this.terminal.parser.registerOscHandler(4, data => {
      this.syncTheme();
      const parts = data.split(';');
      for (let index = 0; index + 1 < parts.length; index += 2) {
        if (!/^\d+$/.test(parts[index])) continue;
        const slot = Number(parts[index]);
        if (slot > 255) continue;
        this.setOrReply(slot, `4;${slot}`, parts[index + 1]);
      }
      return true;
    }));
    for (let code = 10; code <= 12; code++) this.disposables.push(this.terminal.parser.registerOscHandler(code, data => {
      this.syncTheme();
      const parts = data.split(';');
      for (let index = 0; index < Math.min(parts.length, 13 - code); index++) this.setOrReply(256 + code - 10 + index, code + index, parts[index]);
      return true;
    }));
    this.disposables.push(this.terminal.parser.registerOscHandler(104, data => {
      this.syncTheme();
      if (!data) for (let index = 0; index < 256; index++) this.colors[index] = this.basePalette[index];
      else for (const part of data.split(';')) if (/^\d+$/.test(part) && Number(part) <= 255) this.colors[Number(part)] = this.basePalette[Number(part)];
      return true;
    }));
    for (let code = 110; code <= 112; code++) this.disposables.push(this.terminal.parser.registerOscHandler(code, () => {
      this.syncTheme(); this.colors[256 + code - 110] = this.basePalette[256 + code - 110]; return true;
    }));
  }
  syncTheme() {
    let theme;
    try { theme = this.getTheme(); } catch {}
    if (!theme || typeof theme !== 'object') theme = getTerminalTheme('dark');
    const next = palette(theme), signature = JSON.stringify(next);
    if (signature !== this.themeSignature) {
      this.themeSignature = signature; this.basePalette = next; this.colors = next.slice();
    }
  }
  setOrReply(slot, identifier, value) {
    if (value === '?') this.reply(colorReply(identifier, this.colors[slot]));
    else { const color = parseColor(value); if (color) this.colors[slot] = color; }
  }
  reply(data) {
    if (this.disposed || !data) return;
    // A closed native channel can reject a reply while xterm parses on its own
    // timer. Keep that failure on this write's Promise, not an uncaught timer.
    try { this.writeReply(data); }
    catch (error) { if (this.current) this.current.error ??= error; }
  }
  pressure() {
    const paused = this.pressured ? this.queuedBytes >= LOW_WATER : this.queuedBytes > HIGH_WATER;
    if (paused !== this.pressured) { this.pressured = paused; this.onPressure(paused); }
  }
  enqueue(item) {
    if (this.disposed) return Promise.resolve(false);
    item.bytes = item.data ? Buffer.byteLength(item.data) : 0;
    const result = new Promise((resolve, reject) => { item.resolve = resolve; item.reject = reject; });
    this.queue.push(item); this.queuedBytes += item.bytes; this.pressure(); this.pump();
    return result;
  }
  complete(item, error = null) {
    if (item.done) return;
    item.done = true;
    this.queuedBytes -= item.bytes;
    if (this.current === item) this.current = null;
    this.pressure();
    const failure = error ?? item.error;
    if (failure) item.reject(failure); else item.resolve(!this.disposed);
    this.pump();
  }
  pump() {
    if (this.disposed || this.current || !this.queue.length) return;
    const item = this.current = this.queue.shift();
    try {
      this.syncTheme();
      if (item.data !== undefined) this.terminal.write(item.data, () => {
        // DECSTR resets the mode but flushes the browser's render watchdog at
        // the end of parsing. A SET later in the same write keeps its original
        // deadline; a subsequent write after the reset gets a fresh window.
        if (!this.terminal.modes.synchronizedOutputMode) this.synchronizedOutputUntil = 0;
        this.complete(item);
      });
      else {
        if (item.columns !== undefined) { item.apply?.(); this.terminal.resize(item.columns, item.rows); }
        this.complete(item);
      }
    } catch (error) { this.complete(item, error); }
  }
  write(data) { return this.enqueue({ data }); }
  resize(columns, rows, apply) { return this.enqueue({ columns, rows, apply }); }
  flush() { return this.enqueue({}); }
  dispose() {
    if (this.disposed) return;
    this.disposed = true;
    for (const subscription of this.disposables) subscription.dispose();
    this.terminal.dispose();
    if (this.current) this.complete(this.current);
    for (const item of this.queue.splice(0)) this.complete(item);
    this.colors = []; this.basePalette = [];
  }
}
