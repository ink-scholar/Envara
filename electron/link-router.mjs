/* Where a link opened inside an environment goes.
 *
 * The rule is the user's: a link an environment's application or terminal asks
 * to open goes to that network group's browser, so the page loads from the
 * environment's network and location. When that group has no browser to use,
 * the link falls back to the host's default browser, which leaves through the
 * host network and is reported as such. Nothing here opens a link silently:
 * every fallback is an event the user can see.
 */
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { pfApplicationRegistrationId } from '../native/macos-pf-routing/policy.mjs';

const execute = promisify(execFile);
const LINK = value => {
  if (typeof value !== 'string' || !value || value.length > 4096 || /[\0\r\n]/.test(value)) return null;
  try {
    const url = new URL(value);
    return ['https:', 'http:'].includes(url.protocol) && !url.username && !url.password ? url.href : null;
  } catch { return null; }
};
/** A saved choice that sends links to the host's default browser on purpose. */
export const SYSTEM_BROWSER = 'system';
/** The browsers a link from this environment may use: the environment's own
 *  browser first, then the other browsers of its group on the same node, so the
 *  page leaves through the same egress the environment uses. */
export function linkBrowserCandidates(profiles = [], proxies = [], source) {
  if (!source) return [];
  const proxyId = source.proxyId ?? null, group = source.group ?? '';
  const others = profiles.filter(profile => profile.id !== source.id && profile.proxyId === proxyId && (profile.group ?? '') === group)
    .map(profile => ({ id: profile.id, name: profile.name, status: profile.status ?? 'stopped' }))
    .sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
  return [{ id: source.id, name: source.name, status: source.status ?? 'stopped', own: true }, ...others];
}
/** The browser a link goes to: the saved choice while it is still a browser of
 *  the environment's network, otherwise the environment's own browser. The host
 *  default browser is used only when it was chosen explicitly. */
export function chosenLinkBrowser(candidates = [], chosenId = null) {
  if (chosenId === SYSTEM_BROWSER) return null;
  if (chosenId && candidates.some(candidate => candidate.id === chosenId)) return chosenId;
  return candidates[0]?.id ?? null;
}

/* One process table read answers the whole question: the ancestry of the
 * sender and the command each ancestor runs. */
export async function processTable(run = execute) {
  try {
    const { stdout } = await run('/bin/ps', ['-axo', 'pid=,ppid=,command='], { timeout: 5000, maxBuffer: 16 * 1024 * 1024, env: { PATH: '/usr/bin:/bin' } });
    const rows = new Map();
    for (const line of stdout.split('\n')) {
      const match = /^\s*(\d+)\s+(\d+)\s+(.*)$/.exec(line);
      if (match) rows.set(Number(match[1]), { ppid: Number(match[2]), command: match[3].trim() });
    }
    return rows;
  } catch { return new Map(); }
}
/** The chain of process ids from a live process up to pid 1. */
export function processAncestry(rows, pid) {
  const chain = [], seen = new Set();
  let current = Number(pid);
  while (Number.isSafeInteger(current) && current > 1 && !seen.has(current) && chain.length < 64) {
    seen.add(current); chain.push(current);
    current = Number(rows.get(current)?.ppid ?? 0);
  }
  return chain;
}
/** The managed attached instance a process belongs to, by its sealed path. */
export function attachedRegistrationForCommand(command, { registrationRoot, registrationIds = [] }) {
  if (typeof command !== 'string' || !registrationRoot) return null;
  for (const id of registrationIds) if (command.startsWith(`${registrationRoot}/objects/${id}/`)) return id;
  return null;
}

export class LinkRouter {
  constructor({ service, applications, terminal, openDefault, notify = () => {}, registrationRoot, ps = execute, enabled = () => true,
    protectBrowserOperation = (_profileId, operation) => operation() }) {
    this.service = service; this.applications = applications; this.terminal = terminal; this.enabled = enabled;
    this.openDefault = openDefault; this.notify = notify; this.registrationRoot = registrationRoot; this.ps = ps;
    this.protectBrowserOperation = protectBrowserOperation;
    this.pending = new Set();
  }
  /* Links still being handed to a browser that is starting. */
  async settled() { await Promise.allSettled([...this.pending]); }
  /* A link reported by a terminal session's environment. */
  async openFromProfile({ profileId, url, source = '终端', openOutsideHere = true }) {
    const target = LINK(url);
    if (!target) throw Object.assign(new Error('链接无效。'), { code: 'LINK_INVALID' });
    const workspace = await this.service.snapshot();
    const profile = workspace.profiles.find(item => item.id === profileId);
    if (!profile) return this.openOutside(target, '环境不存在', openOutsideHere);
    const chosen = this.terminal?.linkBrowser?.(profileId) ?? null;
    return this.open({ source, url: target, profile, chosen, workspace, openOutsideHere });
  }
  /* A link reported by the system on behalf of an application that runs inside
   * an environment; the process tells which environment that is. */
  async openFromProcess({ pid, url }) {
    const target = LINK(url);
    if (!target) throw Object.assign(new Error('链接无效。'), { code: 'LINK_INVALID' });
    /* The sender is the process LaunchServices names, which may be a short-lived
     * helper; its ancestry is what identifies the application that runs here. */
    const rows = await processTable(this.ps), chain = processAncestry(rows, pid);
    const applications = (await this.applications.snapshot()).applications;
    const registrations = new Map();
    for (const application of applications) {
      try { registrations.set(pfApplicationRegistrationId(application.path), application); } catch {}
    }
    for (const candidate of chain) {
      const registrationId = attachedRegistrationForCommand(rows.get(candidate)?.command ?? '', { registrationRoot: this.registrationRoot, registrationIds: [...registrations.keys()] });
      if (!registrationId) continue;
      const application = registrations.get(registrationId);
      const workspace = await this.service.snapshot();
      const profile = workspace.profiles.find(item => item.id === application.profileId);
      if (!profile) return this.openOutside(target, `「${application.name}」的境舱不存在`, false);
      return this.open({ source: application.name, url: target, profile, chosen: application.browserProfileId ?? null, workspace, openOutsideHere: false });
    }
    const session = this.terminal?.sessionForProcess?.(chain) ?? null;
    if (session && typeof this.terminal.boundBrowserLink === 'function') {
      // Dedicated Claude sessions never inherit a later environment preference
      // or the ordinary link router's explicit system-browser fallback.
      let opening;
      try { opening = this.terminal.boundBrowserLink(session.sessionId, target); }
      catch (error) {
        this.notify({ type: 'error', message: `Claude 浏览器链接未打开：${error?.message ?? '会话已结束'}`, profileId: session.profileId });
        return { opened: 'environment', browser: 'Claude Code', profileId: session.profileId };
      }
      if (opening) {
        const pending = Promise.resolve(opening).catch(error => this.notify({ type: 'error', message: `Claude 浏览器链接未打开：${error?.message ?? '未知错误'}`, profileId: session.profileId })).catch(() => {});
        this.pending.add(pending);
        void pending.finally(() => this.pending.delete(pending));
        return { opened: 'environment', browser: 'Claude Code', profileId: session.profileId };
      }
    }
    if (session) return this.openFromProfile({ profileId: session.profileId, url: target, source: '终端', openOutsideHere: false });
    /* A link from an application that is not in any environment is the user's
     * ordinary browsing: it goes to their usual browser without a word. */
    return this.openOutside(target, '来源不是境舱中的软件', false, { quiet: true });
  }
  /* The answer is the decision, given at once. A stopped browser takes seconds
   * to start, and neither the terminal nor the system's link helper should wait
   * for it: the helper gives up after three seconds and would then open the
   * link a second time, outside the environment. The outcome is reported. */
  async open({ source, url, profile, chosen, workspace, openOutsideHere = true }) {
    // Off in Settings, or this environment chose it: this Mac's own browser.
    if (chosen === SYSTEM_BROWSER || this.enabled() === false) return this.openOutside(url, null, openOutsideHere);
    const candidates = linkBrowserCandidates(workspace.profiles, workspace.proxies, profile);
    const browserId = chosenLinkBrowser(candidates, chosen);
    if (!browserId) return this.openOutside(url, `${profile.name} 没有可用的浏览器`, openOutsideHere);
    const browser = workspace.profiles.find(item => item.id === browserId) ?? profile;
    /* A saved browser that left this network is not followed out of it: the
     * link stays in the environment's own browser, and the user is told. */
    const replaced = Boolean(chosen) && chosen !== browserId;
    const opening = Promise.resolve().then(() => this.protectBrowserOperation(browserId, () => this.service.openProfileLink({ id: browserId, url }))).then(
      () => this.notify({ type: 'link', message: replaced ? `${source}的链接已在「${browser.name}」中打开；原先选定的浏览器不在这个网络里` : `${source}的链接已在「${browser.name}」中打开`, detail: url, profileId: browserId }),
      /* A browser that refuses is not a reason to send the link out of the
       * environment quietly; it is reported and the link stays closed. */
      error => this.notify({ type: 'error', message: `链接没有在「${browser.name}」中打开：${error?.message ?? '未知错误'}`, detail: url, profileId: browserId }))
      .catch(() => {}); // a window closing mid-report must not become an unhandled rejection
    this.pending.add(opening);
    void opening.finally(() => this.pending.delete(opening));
    return { opened: 'environment', browser: browser.name, profileId: browserId, ...(replaced ? { replaced: true } : {}) };
  }
  async openOutside(url, reason, openHere = true, { quiet = false } = {}) {
    if (openHere) await this.openDefault(url);
    if (!quiet) this.notify({ type: 'warning', message: reason ? `环境没有可用的浏览器（${reason}），链接已交给系统默认浏览器，不经过境舱网络。` : '按设置交给系统默认浏览器打开，不经过境舱网络。', detail: url, outside: true });
    return { opened: 'default', browser: null, profileId: null, outside: true };
  }
}
