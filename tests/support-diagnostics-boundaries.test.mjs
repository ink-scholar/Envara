import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readdirSync, symlinkSync, unlinkSync } from 'node:fs';
import { mkdtemp, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { collectSupportDiagnostics, exportSupportDiagnostics, SUPPORT_DIAGNOSTICS_SECTIONS } from '../electron/support-diagnostics.mjs';

test('every section has an independent timeout and late reader rejection cannot change the collected result', async () => {
  const started = [], reject = [];
  const readers = Object.fromEntries(SUPPORT_DIAGNOSTICS_SECTIONS.map(name => [name, () => {
    started.push(name); return new Promise((_resolve, fail) => reject.push(fail));
  }]));
  const document = await collectSupportDiagnostics({ readers, timeoutMs: 10, nowMs: () => 0 });
  assert.deepEqual(started, SUPPORT_DIAGNOSTICS_SECTIONS);
  for (const section of SUPPORT_DIAGNOSTICS_SECTIONS) assert.deepEqual(document.sections[section], { collection: 'failed', reason: 'timeout' });
  const encoded = JSON.stringify(document);
  for (const fail of reject) fail(new Error('PRIVATE_LATE_SECTION_ERROR'));
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(JSON.stringify(document), encoded);
  assert.equal(encoded.includes('PRIVATE_LATE_SECTION_ERROR'), false);
});

test('a selected file replaced by a symlink during save is rejected without touching its referent or leaving temporary data', async t => {
  if (process.platform === 'win32') return t.skip('Creating a symlink may require Windows privileges.');
  const directory = await realpath(await mkdtemp(path.join(tmpdir(), 'envara-support-boundary-')));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const target = path.join(directory, 'selected.json'), keep = path.join(directory, 'keep.json');
  await writeFile(target, 'old-selected'); await writeFile(keep, 'unrelated-file-to-preserve');
  let replaced = false;
  await assert.rejects(exportSupportDiagnostics({ nowMs: () => 0,
    showSaveDialog: async () => ({ filePath: target }),
    checkOpen: () => {
      if (!replaced && readdirSync(directory).some(name => name.startsWith('.envara-support-'))) {
        unlinkSync(target); symlinkSync(keep, target); replaced = true;
      }
    },
  }), { code: 'SUPPORT_DIAGNOSTICS_SAVE_FAILED' });
  assert.equal(replaced, true); assert.equal(existsSync(target), true);
  assert.equal(await readFile(keep, 'utf8'), 'unrelated-file-to-preserve');
  assert.deepEqual((await readdir(directory)).sort(), ['keep.json', 'selected.json']);
});
