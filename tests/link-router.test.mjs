import test from 'node:test';
import assert from 'node:assert/strict';
import { LinkRouter, SYSTEM_BROWSER, linkBrowserCandidates, chosenLinkBrowser, processAncestry, processTable, attachedRegistrationForCommand } from '../electron/link-router.mjs';
import { pfApplicationRegistrationId } from '../native/macos-pf-routing/policy.mjs';

// The sealed copy of a real application is named by its registration id, derived
// from the bundle path it was copied from, so the fixture uses the real value.
const registration = pfApplicationRegistrationId('/Applications/Notion.app');

const profiles = [
  { id: 'prof_ph', name: '菲律宾 · 工作', proxyId: 'node_ph', group: '菲律宾' },
  { id: 'prof_ph2', name: '菲律宾 · 二号', proxyId: 'node_ph', group: '菲律宾' },
  { id: 'prof_ph3', name: '菲律宾 · 三号', proxyId: 'node_ph', group: '菲律宾' },
  { id: 'prof_us', name: '美国 · 测试', proxyId: 'node_us', group: '美国' }];
const service = { snapshot: async () => ({ profiles, proxies: [{ id: 'node_ph' }, { id: 'node_us' }] }),
  openProfileLink: async ({ id, url }) => ({ profileId: id, opened: 'tab', url }) };
const rows = new Map([[100, { ppid: 90, command: `/Library/PrivilegedHelperTools/io.envara.pf-apps/objects/${registration}/v1/Snapshot.app/Contents/MacOS/Notion` }],
  [90, { ppid: 1, command: '/Library/PrivilegedHelperTools/io.envara.pf-routing/envara-pf-native app-tunnel-run' }],
  [200, { ppid: 400, command: '/bin/zsh -d -i' }], [400, { ppid: 1, command: '/Applications/Envara.app/Contents/MacOS/Envara' }],
  [300, { ppid: 1, command: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' }]]);
const notifier = () => { const seen = []; const notify = event => seen.push(event); notify.seen = seen; return notify; };

function router({ applications = [], terminal = null, openDefault = async () => {} } = {}) {
  const notify = notifier();
  const value = new LinkRouter({ service, applications: { snapshot: async () => ({ applications }) }, terminal, openDefault, notify,
    registrationRoot: '/Library/PrivilegedHelperTools/io.envara.pf-apps', ps: async () => ({ stdout: [...rows].map(([pid, row]) => `${pid} ${row.ppid} ${row.command}`).join('\n') }) });
  return { value, notify };
}

test('an environment’s own browser comes first, then its group’s browsers on the same node', () => {
  const candidates = linkBrowserCandidates(profiles, [], profiles[0]);
  assert.equal(candidates[0].id, 'prof_ph'); assert.equal(candidates[0].own, true);
  assert.deepEqual(candidates.slice(1).map(item => item.id).sort(), ['prof_ph2', 'prof_ph3']);
  // An environment alone on its network still has a browser: its own.
  assert.deepEqual(linkBrowserCandidates(profiles, [], profiles[3]).map(item => item.id), ['prof_us'], 'another group shares no browser');
  // No choice means the environment's own browser; a stale choice falls back to it,
  // never out of the environment; only an explicit choice reaches the host browser.
  assert.equal(chosenLinkBrowser(candidates, null), 'prof_ph');
  assert.equal(chosenLinkBrowser(candidates, 'prof_ph2'), 'prof_ph2');
  assert.equal(chosenLinkBrowser(candidates, 'prof_us'), 'prof_ph', 'a browser from another group is refused in favour of the own browser');
  assert.equal(chosenLinkBrowser(candidates, SYSTEM_BROWSER), null);
});

test('a link from an attached application opens in its chosen browser inside the environment', async () => {
  const application = { id: 'app_notion', name: 'Notion', path: '/Applications/Notion.app', profileId: 'prof_ph', browserProfileId: 'prof_ph2' };

  const { value, notify } = router({ applications: [application] });
  const result = await value.openFromProcess({ pid: 100, url: 'https://accounts.google.com/signin' });
  // The decision comes back at once; the browser reports when it has opened the page.
  assert.equal(result.opened, 'environment'); assert.equal(result.browser, '菲律宾 · 二号'); assert.equal(result.profileId, 'prof_ph2'); assert.equal(result.outside, undefined);
  await value.settled();
  assert.equal(notify.seen.length, 1); assert.equal(notify.seen[0].type, 'link'); assert.match(notify.seen[0].message, /菲律宾 · 二号/);
  // The application's own sealed copy is what identifies it, not the sender's name.
  assert.equal(attachedRegistrationForCommand(rows.get(100).command, { registrationRoot: '/Library/PrivilegedHelperTools/io.envara.pf-apps', registrationIds: [registration] }), registration);
  assert.equal(attachedRegistrationForCommand('/usr/bin/open', { registrationRoot: '/Library/PrivilegedHelperTools/io.envara.pf-apps', registrationIds: [registration] }), null);
});

test('a link from a managed terminal opens in that environment’s browser', async () => {
  const terminal = { sessionForProcess: chain => chain.includes(200) ? { profileId: 'prof_ph', sessionId: 'term_1' } : null, linkBrowser: id => id === 'prof_ph' ? 'prof_ph2' : null };
  const { value } = router({ terminal });
  const result = await value.openFromProcess({ pid: 200, url: 'https://claude.ai/oauth' });
  assert.equal(result.browser, '菲律宾 · 二号'); assert.equal(result.outside, undefined);
  await value.settled();
});

test('with no saved choice a link opens in the environment’s own browser', async () => {
  const opened = [];
  const terminal = { sessionForProcess: () => ({ profileId: 'prof_us', sessionId: 'term_2' }), linkBrowser: () => null };
  const { value, notify } = router({ terminal, openDefault: async url => opened.push(url) });
  const result = await value.openFromProcess({ pid: 300, url: 'https://example.com' });
  assert.deepEqual({ opened: result.opened, profileId: result.profileId, outside: result.outside }, { opened: 'environment', profileId: 'prof_us', outside: undefined });
  await value.settled();
  assert.deepEqual(opened, [], 'nothing reached the host browser');
  assert.match(notify.seen.at(-1).message, /美国 · 测试/);
});

test('the decision does not wait for a browser that is still starting', async () => {
  let release;
  const slow = { ...service, openProfileLink: () => new Promise(resolve => { release = resolve; }) };
  const notify = notifier();
  const value = new LinkRouter({ service: slow, applications: { snapshot: async () => ({ applications: [] }) }, terminal: { linkBrowser: () => null }, openDefault: async () => {}, notify, registrationRoot: '/x', ps: async () => ({ stdout: '' }) });
  const result = await value.openFromProfile({ profileId: 'prof_ph', url: 'https://example.com' });
  assert.equal(result.opened, 'environment');
  assert.equal(notify.seen.length, 0, 'nothing is claimed before the browser has it');
  release({ opened: 'loaded' }); await value.settled();
  assert.equal(notify.seen.at(-1).type, 'link');
  // A browser that fails to open the page is reported, and nothing goes outside.
  const failing = new LinkRouter({ service: { ...service, openProfileLink: async () => { throw new Error('浏览器启动失败'); } }, applications: { snapshot: async () => ({ applications: [] }) }, terminal: { linkBrowser: () => null }, openDefault: async () => { throw new Error('must not open outside'); }, notify, registrationRoot: '/x', ps: async () => ({ stdout: '' }) });
  await failing.openFromProfile({ profileId: 'prof_ph', url: 'https://example.com' }); await failing.settled();
  assert.equal(notify.seen.at(-1).type, 'error'); assert.match(notify.seen.at(-1).message, /浏览器启动失败/);
});

test('only an explicit system-default choice sends a link to the host browser, and says so', async () => {
  const opened = [];
  const terminal = { sessionForProcess: () => ({ profileId: 'prof_ph', sessionId: 'term_3' }), linkBrowser: () => SYSTEM_BROWSER };
  const { value, notify } = router({ terminal, openDefault: async url => opened.push(url) });
  // From a terminal's own open command, Envara opens it in the host browser itself.
  const direct = await value.openFromProfile({ profileId: 'prof_ph', url: 'https://example.com' });
  assert.deepEqual({ opened: direct.opened, browser: direct.browser, outside: direct.outside }, { opened: 'default', browser: null, outside: true });
  assert.deepEqual(opened, ['https://example.com/']);
  assert.equal(notify.seen.at(-1).outside, true);
  assert.match(notify.seen.at(-1).message, /不经过境舱网络/);
  // Reported by the system's link helper, the helper opens it; Envara never opens it twice.
  const viaHelper = await value.openFromProcess({ pid: 200, url: 'https://example.com' });
  assert.deepEqual({ opened: viaHelper.opened, browser: viaHelper.browser }, { opened: 'default', browser: null });
  assert.deepEqual(opened, ['https://example.com/'], 'opened once, not again');
});

test('a saved browser that left the network is not followed out of it', async () => {
  const terminal = { sessionForProcess: () => ({ profileId: 'prof_ph', sessionId: 'term_4' }), linkBrowser: () => 'prof_us' };
  const { value, notify } = router({ terminal });
  const result = await value.openFromProcess({ pid: 200, url: 'https://example.com' });
  assert.equal(result.profileId, 'prof_ph'); assert.equal(result.replaced, true);
  await value.settled();
  assert.match(notify.seen.at(-1).message, /不在这个网络/);
});

test('an unrelated application is never routed, and a bad link is refused', async () => {
  const opened = [];
  const { value, notify } = router({ openDefault: async url => opened.push(url) });
  const unrelated = await value.openFromProcess({ pid: 300, url: 'https://example.com' });
  assert.deepEqual({ opened: unrelated.opened, browser: unrelated.browser }, { opened: 'default', browser: null }, 'the helper opens it in the previous default browser');
  assert.equal(notify.seen.length, 0, 'ordinary browsing from another application raises no message');
  for (const url of ['file:///etc/passwd', 'javascript:alert(1)', 'https://user:pass@example.com', 'x'.repeat(5000), 'not a url', '']) {
    await assert.rejects(() => value.openFromProcess({ pid: 100, url }), { code: 'LINK_INVALID' }, url.slice(0, 20));
  }
  assert.deepEqual(opened, [], 'Envara itself opened nothing: neither the unrelated link nor the malformed ones');
});

test('the process table is read once and ancestry is bounded and cycle-safe', () => {
  const parsed = new Map([[1, { ppid: 0, command: 'init' }], [2, { ppid: 1, command: 'a b c' }]]);
  assert.deepEqual(processAncestry(parsed, 2), [2]);
  assert.deepEqual(processAncestry(new Map([[3, { ppid: 4 }], [4, { ppid: 3 }]]), 3), [3, 4]);
  assert.notDeepEqual(processAncestry(parsed, 999), [], 'an unknown pid cannot be attributed to an environment');
  assert.deepEqual(processAncestry(parsed, 999), [999]);
  const table = async () => ({ stdout: '  100   90 /bin/x --flag value\n  90     1 /bin/y\n' });
  return processTable(table).then(rows => assert.deepEqual(rows.get(100), { ppid: 90, command: '/bin/x --flag value' }));
});

test('with links set to this Mac’s browser in Settings, every link goes there and is marked as outside', async () => {
  const opened = [];
  const notify = notifier();
  const value = new LinkRouter({ service, applications: { snapshot: async () => ({ applications: [] }) }, terminal: { linkBrowser: () => 'prof_ph2' },
    openDefault: async url => opened.push(url), notify, registrationRoot: '/x', ps: async () => ({ stdout: '' }), enabled: () => false });
  const result = await value.openFromProfile({ profileId: 'prof_ph', url: 'https://example.com' });
  assert.deepEqual({ opened: result.opened, outside: result.outside }, { opened: 'default', outside: true });
  assert.deepEqual(opened, ['https://example.com/'], 'even a saved environment browser is not used while the setting is off');
  assert.match(notify.seen.at(-1).message, /不经过境舱网络/);
});

test('the desktop wiring reads the application service when a link arrives, not before it exists', async () => {
  const { readFile } = await import('node:fs/promises');
  const main = await readFile(new URL('../electron/main.mjs', import.meta.url), 'utf8');
  const construction = main.indexOf('linkRouter = new LinkRouter('), created = main.indexOf('applications = new ApplicationService(');
  assert.ok(construction > 0 && created > construction, 'the router is built first');
  assert.match(main.slice(construction, construction + 400), /applications: \{ snapshot: async \(\) => applications \? applications\.snapshot\(\)/);
  assert.doesNotMatch(main.slice(construction, construction + 200), /LinkRouter\(\{ service, applications,/);
});
