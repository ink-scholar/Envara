import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const pane = await readFile(path.join(root, 'src/TerminalPane.jsx'), 'utf8');

/** The session list the pane shows is one expression; this reads it back so the
 *  rule is checked rather than assumed. */
const visibleRule = source => /\(sessions \?\? \[\]\)\.filter\(session => activeStatuses\.has\(session\.status\)\)/.test(source);

test('an ended terminal session is not offered as a tab or in the environment rows', () => {
  assert.ok(visibleRule(pane), 'the tab list is built from live sessions only');
  // Every place that lists sessions for the user goes through that filter.
  for (const [name, pattern] of [
    ['selected environment tabs', /const sessions = liveSessions\(selectedMetadata\?\.sessions\);/],
    ['cross-environment list', /flatMap\(profile => liveSessions\(profile\.sessions\)\)/],
    ['environment tabs', /liveSessions\(terminalState\.profiles\.find\(item => item\.profileId === profile\.id\)\?\.sessions\)/],
  ]) assert.match(pane, pattern, name);
  // A closed session must not stay selected, which is what made it look alive.
  assert.match(pane, /const selectedSession = sessions\.find\(session => session\.sessionId === activeSessions\[activeProfileId\]\) \?\? sessions\.at\(-1\) \?\? null;/);
  assert.ok(!/sessions\.at\(-1\)(?! \?\? null)/.test(pane), 'the fallback is the last live session, never the last finished one');
});

test('a new terminal is three choices: network, browser and folder', () => {
  // Both entry points open the chooser rather than starting a shell at once.
  assert.equal((pane.match(/onClick=\{openNewSessionChooser\}/g) ?? []).length, 2);
  // The network list is built from the environments' nodes, and the browser
  // list ends with the system browser, said to leave the environment.
  assert.match(pane, /const networks = terminalNetworks\(profiles\);/);
  assert.match(pane, /<option value=\{SYSTEM_BROWSER\}>\{`\$\{t\('系统默认浏览器'\)\} · \$\{t\('不经过境舱网络'\)\}`\}<\/option>/);
  // The folder is picked in the native dialog and only its token travels.
  assert.match(pane, /api\.call\('pickTerminalDirectory', \{ id: host\.id \}\)/);
  assert.match(pane, /directoryToken: newSession\.directory\?\.token \?\? null/);
  // It is always a new process, never the running one or a duplicate of it.
  assert.match(pane, /forceNew\s*\?\s*await api\.call\('openTerminal', \{ id: profileId, columns: 100, rows: 12, fresh: true/);
  // Where its links open is saved with the environment the terminal runs in.
  assert.match(pane, /api\.call\('setTerminalLinkBrowser', \{ id: host\.id, browserProfileId: wanted \}\)/);
});
