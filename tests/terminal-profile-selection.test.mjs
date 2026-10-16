import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { reconcileTerminalProfile } from '../src/terminal-profile-selection.mjs';

test('a manual tab or newly created session survives unchanged outer selection and periodic snapshots', () => {
  const base = { selectedProfileId: 'environment_a', previousSelectedProfileId: 'environment_a', profileIds: ['environment_a', 'environment_b'] };
  assert.equal(reconcileTerminalProfile({ ...base, activeProfileId: 'environment_b' }), 'environment_b');
  for (let snapshot = 0; snapshot < 10; snapshot++) {
    assert.equal(reconcileTerminalProfile({ ...base, activeProfileId: 'environment_b', profileIds: [...base.profileIds] }), 'environment_b');
  }
  assert.equal(reconcileTerminalProfile({ ...base, selectedProfileId: 'environment_b', activeProfileId: 'environment_b' }), 'environment_b');
});

test('a genuine outer selection still changes the terminal environment', () => {
  assert.equal(reconcileTerminalProfile({ activeProfileId: 'environment_b', selectedProfileId: 'environment_a',
    previousSelectedProfileId: 'environment_b', profileIds: ['environment_a', 'environment_b'] }), 'environment_a');
});

test('removed environments fall back only to an existing selected environment or the first available', () => {
  assert.equal(reconcileTerminalProfile({ activeProfileId: 'removed', selectedProfileId: 'b', previousSelectedProfileId: 'b', profileIds: ['a', 'b'] }), 'b');
  assert.equal(reconcileTerminalProfile({ activeProfileId: 'removed', selectedProfileId: 'removed', previousSelectedProfileId: 'removed', profileIds: ['a', 'b'] }), 'a');
  assert.equal(reconcileTerminalProfile({ activeProfileId: 'removed', selectedProfileId: 'removed', previousSelectedProfileId: 'removed', profileIds: [] }), null);
  assert.equal(reconcileTerminalProfile({ activeProfileId: 'b', selectedProfileId: 'removed', previousSelectedProfileId: 'a', profileIds: ['a', 'b'] }), 'b');
});

test('terminal tab, keyboard, creation and open-window choices synchronize the outer context and export owner', async () => {
  const pane = await readFile(new URL('../src/TerminalPane.jsx', import.meta.url), 'utf8');
  const app = await readFile(new URL('../src/App.jsx', import.meta.url), 'utf8');
  assert.match(app, /<TerminalDock[^>]+onSelectProfile=\{setSelectedId\}/);
  assert.match(pane, /callbacksRef\.current\.onSelectProfile\?\.\(profileId\)/);
  assert.match(pane, /target => \{ selectProfile\(target\.id\); clearFailure\(\); \}/);
  assert.match(pane, /onClick=\{\(\) => \{ selectProfile\(profile\.id\); clearFailure\(\); \}\}/);
  assert.match(pane, /selectProfile\(profileId\); setFocusVersion/);
  assert.match(pane, /selectProfile\(openRequest\.profileId\)/);
  assert.match(pane, /\}, \[selectedProfileId, profileIds\]\)/);
  assert.doesNotMatch(pane, /\[selectedProfileId, profileIds, activeProfileId, profiles\]/);
});
