import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readdir, lstat, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { managedApplicationProcess, showManagedApplicationWindow } from '../electron/application-window.mjs';
import { eraseAttachedApplicationData } from '../electron/application-data.mjs';
import { pfAttachEnvironmentId } from '../native/macos-pf-routing/policy.mjs';

const registration = '4bf0f214-bcaa-4cea-af6f-b7e29800b4c5', other = '11111111-2222-4333-8444-555555555555';
const keeper = '/Library/PrivilegedHelperTools/io.envara.pf-routing/envara-pf-native';
const copy = id => `/Library/PrivilegedHelperTools/io.envara.pf-apps/objects/${id}/3273e380-df3c-4478-b876-2e8406bf6fa7/Snapshot.app/Contents`;
const listing = rows => rows.map(row => row.join(' ')).join('\n');

test('only the main executable of the sealed copy, started by the root keeper as this user, is the managed instance', () => {
  const base = [[100, 1, 0, keeper], [200, 100, 501, `${copy(registration)}/MacOS/Notion`],
    [201, 200, 501, `${copy(registration)}/Frameworks/Notion Helper.app/Contents/MacOS/Notion Helper`]];
  assert.equal(managedApplicationProcess(listing(base), { registrationId: registration, uid: 501 }), 200);
  // Not started by the keeper, another user, another registration, or the original bundle.
  assert.equal(managedApplicationProcess(listing([[300, 1, 501, `${copy(registration)}/MacOS/Notion`]]), { registrationId: registration, uid: 501 }), null);
  assert.equal(managedApplicationProcess(listing([[100, 1, 0, keeper], [200, 100, 502, `${copy(registration)}/MacOS/Notion`]]), { registrationId: registration, uid: 501 }), null);
  assert.equal(managedApplicationProcess(listing([[100, 1, 0, keeper], [200, 100, 501, `${copy(other)}/MacOS/Notion`]]), { registrationId: registration, uid: 501 }), null);
  assert.equal(managedApplicationProcess(listing([[100, 1, 0, keeper], [200, 100, 501, '/Applications/Notion.app/Contents/MacOS/Notion']]), { registrationId: registration, uid: 501 }), null);
  assert.equal(managedApplicationProcess(listing([[100, 1, 501, keeper], [200, 100, 501, `${copy(registration)}/MacOS/Notion`]]), { registrationId: registration, uid: 501 }), null, 'a keeper path not run by root is no keeper');
  // Two candidates is no answer.
  assert.equal(managedApplicationProcess(listing([...base, [202, 100, 501, `${copy(registration)}/MacOS/Notion`]]), { registrationId: registration, uid: 501 }), null);
  assert.equal(managedApplicationProcess(listing(base), { registrationId: 'not-a-uuid', uid: 501 }), null);
});

test('the window is reopened by process id only, and a missing instance or macOS refusal is reported, never a launch', async () => {
  const calls = [];
  const run = (reply, base = [[100, 1, 0, keeper], [200, 100, 501, `${copy(registration)}/MacOS/Notion`]]) => (file, args, options, done) => {
    calls.push([file, ...args]);
    if (file === '/bin/ps') return done(null, listing(base));
    return done(null, reply);
  };
  assert.deepEqual(await showManagedApplicationWindow({ registrationId: registration, uid: 501, run: run('0') }), { shown: true });
  const reopen = calls.find(call => call[0] === '/usr/bin/osascript');
  assert.equal(reopen.at(-1), '200', 'the pid travels as an argument, never inside the script');
  assert.ok(!calls.some(call => call[0] === '/usr/bin/open'));
  await assert.rejects(showManagedApplicationWindow({ registrationId: registration, uid: 501, run: run('-1743') }), { code: 'APPLICATION_WINDOW_NOT_PERMITTED' });
  await assert.rejects(showManagedApplicationWindow({ registrationId: registration, uid: 501, run: run('-600') }), { code: 'APPLICATION_WINDOW_UNAVAILABLE' });
  calls.length = 0;
  await assert.rejects(showManagedApplicationWindow({ registrationId: registration, uid: 501, run: run('0', [[100, 1, 0, keeper]]) }), { code: 'APPLICATION_WINDOW_UNAVAILABLE' });
  assert.deepEqual(calls.map(call => call[0]), ['/bin/ps'], 'nothing is sent without a running managed instance');
});

test('sign-in data is cleared for one application or a whole environment, only inside user-owned UserData', async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'envara-app-data-')); t.after(() => rm(root, { recursive: true, force: true }));
  const environment = path.join(root, pfAttachEnvironmentId('prof_fixture_owner'));
  for (const id of [registration, other]) {
    await mkdir(path.join(environment, id, 'UserData', 'Local Storage'), { recursive: true });
    await writeFile(path.join(environment, id, 'UserData', 'Cookies'), 'session');
  }
  const uid = process.getuid();
  assert.deepEqual(await eraseAttachedApplicationData('prof_fixture_owner', { registrationId: registration, root, uid, platform: 'darwin' }), [registration]);
  assert.deepEqual(await readdir(path.join(environment, registration, 'UserData')), []);
  assert.deepEqual((await readdir(path.join(environment, other, 'UserData'))).sort(), ['Cookies', 'Local Storage'], 'another application keeps its data');
  await assert.rejects(eraseAttachedApplicationData('prof_fixture_owner', { root, uid: uid + 1, platform: 'darwin' }), { code: 'APPLICATION_DATA_NOT_CLEARED' }, 'foreign-owned layout must be reported, never treated as absent');
  assert.deepEqual((await readdir(path.join(environment, other, 'UserData'))).sort(), ['Cookies', 'Local Storage'], 'foreign-owned data remains untouched');
  assert.deepEqual((await eraseAttachedApplicationData('prof_fixture_owner', { root, uid, platform: 'darwin' })).sort(), [other, registration].sort());
  assert.deepEqual(await readdir(path.join(environment, other, 'UserData')), []);
  assert.deepEqual(await eraseAttachedApplicationData('prof_missing', { root, uid, platform: 'darwin' }), []);
  // An entry that cannot be removed is reported instead of a cleared result.
  await writeFile(path.join(environment, registration, 'UserData', 'Cookies'), 'session');
  const stuck = { readdir, lstat, rm: async () => {} };
  await assert.rejects(eraseAttachedApplicationData('prof_fixture_owner', { registrationId: registration, root, uid, platform: 'darwin', fs: stuck }),
    error => error.code === 'APPLICATION_DATA_NOT_CLEARED' && error.incomplete.includes(registration));
});
