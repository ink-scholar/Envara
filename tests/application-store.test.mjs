import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { mkdtemp, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import { ApplicationStore } from '../electron/application-store.mjs';

test('an oversized UTF-8 binding update preserves the last readable application store', async t => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-application-store-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  const store = new ApplicationStore(root);
  const application = index => ({ id: `app_${index}`, profileId: 'environment', name: `Synthetic ${index}`,
    path: `/Applications/Synthetic${index}.app`, executablePath: `/Applications/Synthetic${index}.app/Contents/MacOS/main`,
    identity: `synthetic:${index}`, args: [] });
  const existing = [application(0)];
  await store.write(existing);
  const before = await readFile(store.filename, 'utf8');
  const update = [application(0), application(1)].map(item => ({ ...item, args: Array.from({ length: 128 }, () => '界'.repeat(8192)) }));
  await assert.rejects(store.write(update), { code: 'APPLICATION_STORAGE_UNAVAILABLE' });
  assert.equal(await readFile(store.filename, 'utf8'), before);
  assert.deepEqual(await store.read(), existing);
  assert.deepEqual(await new ApplicationStore(root).read(), existing);
  assert.deepEqual(await readdir(store.root), ['applications.json']);
});

test('duplicate binding ids and software identities are rejected on both write and reload', async t => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-application-store-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  const store = new ApplicationStore(root);
  const first = { id: 'app_one', profileId: 'environment', name: 'Synthetic', path: '/Applications/Synthetic.app',
    executablePath: '/Applications/Synthetic.app/Contents/MacOS/main', identity: 'synthetic:one', args: [] };
  await store.write([first]);
  const before = await readFile(store.filename, 'utf8');
  for (const second of [{ ...first, identity: 'synthetic:two' }, { ...first, id: 'app_two' }]) {
    const applications = [first, second];
    await assert.rejects(store.write(applications), { code: 'APPLICATION_STORAGE_UNAVAILABLE' });
    assert.equal(await readFile(store.filename, 'utf8'), before);
    await writeFile(store.filename, JSON.stringify({ schema: 'envara.applications', version: 1, applications }));
    await assert.rejects(store.read(), { code: 'APPLICATION_STORAGE_UNAVAILABLE' });
    await writeFile(store.filename, before);
    assert.deepEqual(await store.read(), [first]);
  }
});

test('stored schema and collection types reject invalid data without changing write-input errors', async t => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-application-store-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  const store = new ApplicationStore(root);
  await store.write([]);
  for (const document of [
    { schema: 'other', version: 1, applications: [] },
    { schema: 'envara.applications', version: 2, applications: [] },
    { schema: 'envara.applications', version: 1, applications: {} },
  ]) {
    await writeFile(store.filename, JSON.stringify(document));
    await assert.rejects(store.read(), { code: 'APPLICATION_STORAGE_UNAVAILABLE' });
  }
  await assert.rejects(store.write(null), TypeError);
});
