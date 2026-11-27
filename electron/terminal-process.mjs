import { execFile, fork, spawn } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const contexts = new WeakMap();
const WINDOWS_QUERY = "Get-CimInstance -ClassName Win32_Process | Where-Object { $_.CreationDate } | Select-Object @{Name='pid';Expression={[int]$_.ProcessId}},@{Name='ppid';Expression={[int]$_.ParentProcessId}},@{Name='birth';Expression={$_.CreationDate.ToUniversalTime().Ticks.ToString()}}";
const WINDOWS_SNAPSHOT = `${WINDOWS_QUERY} | ConvertTo-Json -Compress`;
const WINDOWS_END = '<<envara-snapshot-end>>';
// One long-lived metadata reader answers each "s" line with one JSON line and
// an end marker. Starting powershell.exe per snapshot costs ~0.3-1 s on
// Windows, which made periodic tracking churn and exhausted close budgets.
const WINDOWS_HELPER = `$ErrorActionPreference='Stop'; while ($null -ne ($line = [Console]::In.ReadLine())) { try { $rows = @(${WINDOWS_QUERY}); [Console]::Out.WriteLine((ConvertTo-Json -InputObject $rows -Compress)) } catch { [Console]::Out.WriteLine('!') }; [Console]::Out.WriteLine('${WINDOWS_END}'); [Console]::Out.Flush() }`;
const WINDOWS_TIMING = { pollMs: 1000, closeMs: 6000, maxCloseMs: 10000, verifyMs: 3000, sharedSnapshotMs: 400 };
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

function metadataEnvironment(platform) {
  // ps lstart uses local wall time; keep captured birth identities stable even
  // when the host timezone changes while a terminal remains open.
  if (platform !== 'win32') return { LC_ALL: 'C', TZ: 'UTC', PATH: '/usr/bin:/bin' };
  const systemRoot = process.env.SystemRoot || process.env.WINDIR || 'C:\\Windows';
  return { SystemRoot: systemRoot, WINDIR: systemRoot, PATH: `${systemRoot}\\System32;${systemRoot}\\System32\\WindowsPowerShell\\v1.0` };
}

class WindowsSnapshotReader {
  constructor() { this.child = null; this.buffer = ''; this.waiter = null; this.queue = Promise.resolve(); this.idle = null; this.unavailable = false; this.shared = null; }
  start() {
    const encoded = Buffer.from(WINDOWS_HELPER, 'utf16le').toString('base64');
    const child = spawn('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded], { windowsHide: true, env: metadataEnvironment('win32'), stdio: ['pipe', 'pipe', 'ignore'] });
    this.child = child; this.buffer = '';
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', chunk => {
      if (this.child !== child) return;
      this.buffer += chunk;
      if (this.buffer.length > 8 * 1024 * 1024) return this.discard(child, true);
      const end = this.buffer.indexOf(WINDOWS_END);
      if (end < 0 || !this.waiter) return;
      const text = this.buffer.slice(0, end).trim();
      this.buffer = this.buffer.slice(end + WINDOWS_END.length).replace(/^\r?\n/, '');
      const waiter = this.waiter; this.waiter = null;
      waiter.resolve(text);
    });
    child.stdin.on('error', () => this.discard(child, true));
    child.on('error', error => { if (error?.code === 'ENOENT') this.unavailable = true; this.discard(child, false); });
    child.on('exit', () => this.discard(child, false));
    // The reader never keeps the app or a test process alive on its own.
    child.unref(); child.stdout.unref?.(); child.stdin.unref?.();
  }
  discard(child, kill) {
    if (this.child === child) {
      this.child = null; this.buffer = '';
      const waiter = this.waiter; this.waiter = null;
      waiter?.reject(new Error('Process metadata reader stopped'));
    }
    if (kill) { try { child.kill(); } catch {} }
  }
  request(timeout) {
    const enqueued = Date.now();
    const run = () => new Promise((resolve, reject) => {
      const remaining = timeout - (Date.now() - enqueued);
      if (remaining <= 0) return reject(new Error('Process metadata request expired'));
      if (!this.child) this.start();
      const child = this.child;
      clearTimeout(this.idle);
      const timer = setTimeout(() => this.discard(child, true), remaining);
      this.waiter = {
        resolve: text => { clearTimeout(timer); this.scheduleIdle(child); resolve(text); },
        reject: error => { clearTimeout(timer); reject(error); },
      };
      child.stdin.write('s\n');
    });
    const result = this.queue.then(run, run);
    this.queue = result.catch(() => {});
    return result;
  }
  scheduleIdle(child) {
    clearTimeout(this.idle);
    this.idle = setTimeout(() => { if (this.child === child) { try { child.stdin.end(); } catch {} this.discard(child, false); } }, 15000);
    this.idle.unref();
  }
  async rows(timeout) {
    const started = Date.now();
    let text;
    if (!this.unavailable) {
      try { text = await this.request(timeout); } catch {}
    }
    // A reader that cannot start or answer falls back to a one-shot query
    // within whatever remains of the caller's budget.
    if (text === undefined) {
      const remaining = timeout - (Date.now() - started);
      if (remaining < 250) throw new Error('Process metadata unavailable');
      text = (await execFileAsync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', WINDOWS_SNAPSHOT], { timeout: remaining, maxBuffer: 4 * 1024 * 1024, windowsHide: true, env: metadataEnvironment('win32') })).stdout;
    }
    if (text === '!') throw new Error('Process metadata query failed');
    const parsed = JSON.parse(text || '[]');
    return new Map((Array.isArray(parsed) ? parsed : [parsed]).filter(row => row && Number.isSafeInteger(row.pid) && row.birth).map(row => [row.pid, { ...row, state: '' }]));
  }
  /** Periodic tracking of several terminals shares one recent snapshot. Close
   * and capture paths always request a snapshot taken after their call. */
  sharedRows(timeout) {
    if (this.shared && Date.now() - this.shared.at < WINDOWS_TIMING.sharedSnapshotMs) return this.shared.promise;
    const promise = this.rows(timeout);
    const entry = { at: Date.now(), promise };
    this.shared = entry;
    promise.catch(() => { if (this.shared === entry) this.shared = null; });
    return promise;
  }
}
const windowsSnapshots = new WindowsSnapshotReader();

function validPid(pid) {
  return Number.isSafeInteger(pid) && pid > 1 && pid !== process.pid && pid <= 2147483647;
}

// Only process metadata is requested. Arguments, commands and environment are never read.
async function processSnapshot(platform, pid, deadline, { shared = false } = {}) {
  try {
    const timeout = deadline === undefined ? (platform === 'win32' ? 5000 : 2000) : Math.max(1, Math.min(platform === 'win32' ? 5000 : 2000, deadline - Date.now()));
    if (platform === 'win32') return await (shared ? windowsSnapshots.sharedRows(timeout) : windowsSnapshots.rows(timeout));
    const args = pid === undefined ? ['-axo', 'pid=,ppid=,lstart=,stat='] : ['-p', String(pid), '-o', 'pid=,ppid=,lstart=,stat='];
    const { stdout } = await execFileAsync('/bin/ps', args, { timeout, maxBuffer: 4 * 1024 * 1024, env: metadataEnvironment(platform) });
    const rows = new Map();
    for (const line of stdout.split('\n')) {
      const match = line.trim().match(/^(\d+)\s+(\d+)\s+(.+?)\s+(\S+)$/);
      if (match) rows.set(Number(match[1]), { pid: Number(match[1]), ppid: Number(match[2]), birth: match[3].trim().replace(/\s+/g, ' '), state: match[4] });
    }
    return rows;
  } catch (error) {
    // ps exits 1 when a selected PID has gone away. Never include its stderr in a log.
    if (pid !== undefined && error.code === 1) return new Map();
    const failure = new Error('Could not read terminal process metadata');
    failure.code = 'TERMINAL_PROCESS_METADATA_UNAVAILABLE';
    throw failure;
  }
}

async function strongIdentity(row, platform) {
  if (!row || platform !== 'linux') return row;
  try {
    const raw = await readFile(`/proc/${row.pid}/stat`, 'utf8');
    const fields = raw.slice(raw.lastIndexOf(')') + 2).trim().split(/\s+/);
    return { ...row, state: fields[0], kernelBirth: fields[19] };
  } catch {
    return undefined;
  }
}

/* node-pty's Windows kill() lists the console's processes by forking its
 * conpty_console_list agent (an Electron process inside the app) with the
 * parent's stdio. When the shell has already exited the agent's AttachConsole
 * fails and a full stack trace lands in the app log; node-pty then waits five
 * seconds before falling back to the shell PID. Keep that fallback cleanup, but
 * run the agent silently and settle as soon as it exits. */
export function quietConsoleListAgent(pty, agentScript, forkProcess = fork) {
  const agent = pty?._agent;
  if (!agent || typeof agent._getConsoleProcessList !== 'function' || typeof agentScript !== 'string') return false;
  agent._getConsoleProcessList = function quietConsoleProcessList() {
    const shellPid = this._innerPid;
    return new Promise(resolve => {
      let settled = false, child = null, timer = null;
      const finish = list => { if (settled) return; settled = true; clearTimeout(timer); resolve(list); };
      try { child = forkProcess(agentScript, [String(shellPid)], { silent: true }); }
      catch { finish([shellPid]); return; }
      child.stdout?.resume(); child.stderr?.resume();
      child.once('message', message => finish(Array.isArray(message?.consoleProcessList) ? message.consoleProcessList : [shellPid]));
      child.once('exit', () => finish([shellPid]));
      child.once('error', () => finish([shellPid]));
      timer = setTimeout(() => { try { child.kill(); } catch {} finish([shellPid]); }, 5000);
    });
  };
  return true;
}

export function terminalProcessMatches(current, captured) {
  if (!current || !captured || current.pid !== captured.pid || current.birth !== captured.birth || current.state?.startsWith('Z')) return false;
  return captured.kernelBirth === undefined || current.kernelBirth === captured.kernelBirth;
}

function descendsFromApp(row, snapshot) {
  const visited = new Set();
  while (row && !visited.has(row.pid)) {
    if (row.ppid === process.pid) return true;
    visited.add(row.pid);
    row = snapshot.get(row.ppid);
  }
  return false;
}

async function refresh(state, deadline, options) {
  const snapshot = await processSnapshot(state.platform, undefined, deadline, options);
  const roots = [state.root, ...state.children.values()];
  const reachable = new Set();
  for (const captured of roots) {
    const current = await strongIdentity(snapshot.get(captured.pid), state.platform);
    if (terminalProcessMatches(current, captured)) reachable.add(captured.pid);
    else if (captured.pid !== state.root.pid) state.children.delete(captured.pid);
  }
  const childrenByParent = new Map();
  for (const row of snapshot.values()) {
    if (!validPid(row.pid) || row.state.startsWith('Z')) continue;
    const siblings = childrenByParent.get(row.ppid) || [];
    siblings.push(row);
    childrenByParent.set(row.ppid, siblings);
  }
  const queue = [...reachable];
  for (let index = 0; index < queue.length; index++) {
    for (const row of childrenByParent.get(queue[index]) || []) {
      if (reachable.has(row.pid)) continue;
      const identity = await strongIdentity(row, state.platform);
      if (!identity) continue;
      reachable.add(row.pid);
      queue.push(row.pid);
      if (row.pid !== state.root.pid) state.children.set(row.pid, identity);
    }
  }
  return reachable;
}

/** Capture an app-owned PTY shell and keep metadata-only snapshots of its children. */
export async function captureTerminalProcess(pid) {
  if (!validPid(pid)) throw new TypeError('Terminal PID must identify a child process');
  const platform = process.platform;
  const snapshot = await processSnapshot(platform);
  const root = await strongIdentity(snapshot.get(pid), platform);
  if (!root || root.state.startsWith('Z')) {
    const error = new Error('Terminal process has already exited');
    error.code = 'TERMINAL_PROCESS_EXITED';
    throw error;
  }
  if (!descendsFromApp(root, snapshot)) {
    const error = new Error('Terminal process is not owned by this app');
    error.code = 'TERMINAL_PROCESS_NOT_OWNED';
    throw error;
  }
  const state = { root, platform, children: new Map(), pending: null, closing: null, timer: null };
  await refresh(state);
  const identity = Object.freeze({ pid, platform, root: Object.freeze({ ...root }) });
  contexts.set(identity, state);
  state.timer = setInterval(() => {
    if (state.pending || state.closing) return;
    state.pending = refresh(state, undefined, { shared: true }).catch(() => {}).finally(() => { state.pending = null; });
  }, platform === 'win32' ? WINDOWS_TIMING.pollMs : 150);
  state.timer.unref();
  return identity;
}

async function currentIdentity(state, pid, deadline) {
  const snapshot = await processSnapshot(state.platform, pid, deadline);
  return strongIdentity(snapshot.get(pid), state.platform);
}

async function cleanProcessTree(state, pty, timeoutMs) {
  clearInterval(state.timer);
  const deadline = Date.now() + timeoutMs;
  const signaled = new Set();
  const skipped = new Set();
  const failures = new Set();
  let metadataAvailable = true;
  if (state.pending) {
    // A stuck metadata subprocess cannot make terminal shutdown wait forever.
    let timeout;
    const completed = await Promise.race([state.pending.then(() => true), new Promise(resolve => { timeout = setTimeout(() => resolve(false), timeoutMs); })]).finally(() => clearTimeout(timeout));
    if (!completed) metadataAvailable = false;
  }
  const refreshSafely = async () => {
    if (Date.now() >= deadline) return new Set();
    try { return await refresh(state, deadline); } catch { metadataAvailable = false; return new Set(); }
  };
  await refreshSafely();
  const windows = state.platform === 'win32';
  const targets = () => [...state.children.values(), state.root]; // Children first; PTY shell last.
  const alive = async () => {
    const result = [];
    let snapshot;
    // One metadata snapshot verifies the whole known tree; on macOS/Linux
    // signals still get a separate immediately-before-signal check for each
    // exact PID. The final verification may outlive the signal budget by a
    // snapshot's real cost, so a slow reader is not mistaken for a live tree.
    try { snapshot = await processSnapshot(state.platform, undefined, Math.max(deadline, Date.now() + (windows ? WINDOWS_TIMING.verifyMs : 100))); }
    catch { metadataAvailable = false; return targets(); }
    for (const target of targets()) {
      const current = await strongIdentity(snapshot.get(target.pid), state.platform);
      if (terminalProcessMatches(current, target)) result.push(target);
      else if (current && !current.state.startsWith('Z')) skipped.add(target.pid);
    }
    return result;
  };
  const signal = async (target, phase) => {
    if (Date.now() >= deadline) return;
    if (windows && phase !== 'SIGKILL' && target.pid !== state.root.pid) return; // Console children end with their ConPTY; no graceful signal exists for them.
    if (!windows) {
      // A Windows metadata query costs as much as the batch snapshot alive()
      // just verified, so a per-PID query there adds no tighter guarantee.
      let current;
      try { current = await currentIdentity(state, target.pid, deadline); } catch { metadataAvailable = false; return; }
      if (!terminalProcessMatches(current, target)) {
        if (current && !current.state.startsWith('Z')) skipped.add(target.pid);
        return;
      }
    }
    try {
      if (windows && target.pid === state.root.pid && phase !== 'SIGKILL' && typeof pty.kill === 'function') {
        // ConPTY first gets its normal shutdown path while its shell is still verified.
        pty.kill();
      } else if (windows) {
        // taskkill receives only a verified numeric PID. /T targets that owned tree.
        await execFileAsync('taskkill.exe', ['/PID', String(target.pid), '/T', '/F'], { timeout: Math.min(3000, Math.max(1, deadline - Date.now())), windowsHide: true, maxBuffer: 64 * 1024, env: metadataEnvironment(state.platform) });
      } else if (target.pid === state.root.pid && typeof pty.kill === 'function') {
        // Never call node-pty.kill after the root birth identity no longer matches.
        pty.kill(phase);
      } else {
        process.kill(target.pid, phase);
      }
      signaled.add(target.pid);
    } catch (error) {
      // taskkill exits 128 when the verified process ended on its own meanwhile.
      if (error.code !== 'ESRCH' && !(windows && error.code === 128)) failures.add(target.pid);
    }
  };
  const gracePause = windows ? 400 : 150;
  for (const phase of windows ? ['SIGTERM', 'SIGKILL'] : ['SIGHUP', 'SIGTERM', 'SIGKILL']) {
    if (Date.now() >= deadline) break;
    if (phase !== 'SIGKILL' && Date.now() + gracePause >= deadline) continue;
    // Windows: the tree was refreshed just before the first phase; another query there only spends budget.
    if (!windows || phase === 'SIGKILL') await refreshSafely();
    const living = await alive();
    if (!living.length) break;
    for (const target of living) await signal(target, phase);
    const pause = phase === 'SIGKILL' ? 0 : Math.min(gracePause, Math.max(0, deadline - Date.now()));
    if (pause) await delay(pause);
  }
  let remaining = await alive();
  while (remaining.length && Date.now() < deadline) {
    await delay(Math.min(50, deadline - Date.now()));
    remaining = await alive();
  }
  return {
    ok: metadataAvailable && remaining.length === 0 && skipped.size === 0,
    rootExited: metadataAvailable && !remaining.some(row => row.pid === state.root.pid),
    remainingPids: remaining.map(row => row.pid),
    signaledPids: [...signaled],
    skippedPids: [...skipped],
    failedPids: [...failures],
    metadataAvailable,
    limitations: ['Processes that detach before a metadata snapshot cannot be reliably attributed.', ...(state.platform === 'darwin' ? ['macOS ps birth markers have one-second resolution; this is process cleanup, not OS isolation.'] : [])],
  };
}

/** Idempotently close only the captured shell and children whose birth identities still match. */
export async function closeTerminalProcess({ pty, identity, timeoutMs } = {}) {
  const state = contexts.get(identity);
  if (!state || !pty || pty.pid !== state.root.pid) throw new TypeError('PTY and captured terminal identity must match');
  if (!state.closing) {
    // Windows metadata queries and ConPTY teardown take far longer than ps/signals.
    const [fallback, maximum] = state.platform === 'win32' ? [WINDOWS_TIMING.closeMs, WINDOWS_TIMING.maxCloseMs] : [1500, 5000];
    const boundedTimeout = Number.isFinite(timeoutMs) ? Math.max(250, Math.min(maximum, timeoutMs)) : fallback;
    const attempt = cleanProcessTree(state, pty, boundedTimeout);
    state.closing = attempt;
    // Concurrent callers share this attempt. An uncertain result must allow a
    // later explicit close to inspect the same captured identities again.
    void attempt.then(result => {
      if (result?.ok !== true && state.closing === attempt) state.closing = null;
    }, () => { if (state.closing === attempt) state.closing = null; });
  }
  return state.closing;
}
