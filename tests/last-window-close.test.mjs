import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { backgroundWork, holdsLastWindowClose, lastWindowCloseDialog, lastWindowCloseLanguages } from '../electron/last-window-close.mjs';
import { languages } from '../shared/interface-languages.mjs';

test('background work counts only active terminal sessions and applications', () => {
  const work = backgroundWork({
    terminals: { profiles: [
      { sessions: [{ status: 'running' }, { status: 'closed' }, { status: 'error' }] },
      { sessions: [{ status: 'closing' }, { status: 'starting' }] },
      { sessions: [] },
    ] },
    applications: { applications: [{ status: 'stopping' }, { status: 'stopped' }] },
  });
  assert.deepEqual(work, { terminals: 3, applications: 1, any: true });
  assert.deepEqual(backgroundWork({}), { terminals: 0, applications: 0, any: false });
  assert.deepEqual(backgroundWork({ terminals: undefined, applications: undefined }).any, false);
});

test('only the last window on Windows and Linux is held, and never while quitting or once confirmed', () => {
  const base = { platform: 'win32', remainingViews: 1, quitting: false, confirmed: false };
  assert.equal(holdsLastWindowClose(base), true);
  assert.equal(holdsLastWindowClose({ ...base, platform: 'linux' }), true);
  assert.equal(holdsLastWindowClose({ ...base, platform: 'darwin' }), false);
  assert.equal(holdsLastWindowClose({ ...base, remainingViews: 2 }), false);
  assert.equal(holdsLastWindowClose({ ...base, quitting: true }), false);
  assert.equal(holdsLastWindowClose({ ...base, confirmed: true }), false);
});

test('the confirmation defaults to cancel and exists in all nine interface languages', () => {
  assert.deepEqual([...lastWindowCloseLanguages].sort(), [...languages].sort());
  for (const language of languages) {
    const options = lastWindowCloseDialog(language, { terminals: 2, applications: 1 });
    assert.equal(options.buttons.length, 2);
    assert.equal(options.defaultId, 1);
    assert.equal(options.cancelId, 1);
    assert.match(options.message, /3/);
    for (const value of [options.title, options.detail, ...options.buttons]) assert.ok(value.length > 0);
  }
  assert.equal(lastWindowCloseDialog('xx', { terminals: 1, applications: 0 }).buttons[0], 'End and Quit');
  assert.match(lastWindowCloseDialog('en', { terminals: 1, applications: 0 }).message, /1 terminal or attached app session is/);
});

test('the main process holds the last close and quits through the owned shutdown path', async () => {
  const source = await readFile(new URL('../electron/main.mjs', import.meta.url), 'utf8');
  assert.match(source, /view\.on\('close', event => \{\s*if \(!holdsLastWindowClose\(/);
  assert.match(source, /lastWindowCloseConfirmed = true;\s*app\.quit\(\);/);
});
