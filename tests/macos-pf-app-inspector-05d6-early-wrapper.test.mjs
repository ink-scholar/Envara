import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import { promisify } from 'node:util';
import { execFile } from 'node:child_process';

test('actual producer preserves the three early observations on recorded-processes refusal without later observations', async () => {
  assert.notEqual(process.getuid(), 0);
  const root = path.resolve(import.meta.dirname, '..');
  const filename = path.join(root, 'tests/macos-pf-app-inspector-05d6-wrapper.test.mjs');
  const bytes = await readFile(filename);
  assert.equal(createHash('sha256').update(bytes).digest('hex'), 'e596085b55cf79edb1481203c7feacafc6009f11f79c2d02fbd962b9b2314d3e');
  // Reuse the frozen real native producer and separate strict consumer. Only
  // the producer's controlled failure point and assertions differ here.
  let source = bytes.toString();
  source = source.replace("'../scripts/lib/macos-fixed-inspector-05d6-stage.mjs'", JSON.stringify(pathToFileURL(path.join(root, 'scripts/lib/macos-fixed-inspector-05d6-stage.mjs')).href));
  source = source.replace("path.resolve(import.meta.dirname, '../native/macos-pf-routing')", JSON.stringify(path.join(root, 'native/macos-pf-routing')));
  const point = ' int scope=0;out[@"gidScopeObservation"]=';
  assert.equal(source.split(point).length, 2);
  source = source.replace(point, ' if(!strcmp(argv[2],"early")){[out removeObjectForKey:@"recordedProcesses"];out[@"gate"]=@"recorded-processes";close(state);close(fixturePF);close(run);return emitInspection(out);}\n' + point);
  source = source.replace("['available', 'unavailable', 'partial', 'legacy-tables', 'legacy-children', 'legacy-hook']", "['early']");
  source = source.replace('assert.equal(input.journal.present, true); assert.equal(input.journal.eventCount, 2);', "assert.equal(input.ok, false); assert.equal(input.gate, 'recorded-processes'); for (const key of ['recordedProcesses', 'journal', 'activeClasses', 'gidScopeObservation', 'stablePrivateSnapshotVerified']) assert.equal(input[key], undefined, key);");
  source = source.replace('assert.equal(input.activeClasses.classes.length, 6); assert.equal(input.lastJournalRevisionAndCountMatchActiveFilter, true);', 'assert.equal(input.lastJournalRevisionAndCountMatchActiveFilter, undefined);');
  source = source.replaceAll("mode === 'partial'", "mode === 'early'").replaceAll("mode !== 'partial'", "mode !== 'early'");
  source = source.replace("for (const key of ['ownedTablesEmptyObserved', 'ownedChildrenEmptyObserved', 'nativeHookStatusAvailable']) assert.equal(typeof output[key], 'boolean', key);", "for (const key of ['registryObservation', 'ticketStoreObservation', 'kernelCustodyObservation']) assert.deepEqual(output[key], input[key], key);");
  const directory = await mkdtemp(path.join(tmpdir(), 'envara-05d6-early-producer-consumer-'));
  try {
    const fixture = path.join(directory, 'early.test.mjs');
    await writeFile(fixture, source, { flag: 'wx', mode: 0o600 });
    const env = { ...process.env }; delete env.NODE_TEST_CONTEXT;
    const { stdout } = await promisify(execFile)(process.execPath, ['--test', '--test-name-pattern=actual inspector writer', fixture], { timeout: 30000, env });
    assert.match(stdout, /pass 1/);
    assert.match(stdout, /fail 0/);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
