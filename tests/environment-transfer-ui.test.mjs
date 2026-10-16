import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { browserExportActive, environmentTransferModalPending, importedDataLabel } from '../src/environment-transfer-ui.mjs';
import { translationCatalog } from '../src/i18n.mjs';

test('only an active browser or its own start/stop blocks the browser export state', () => {
  for (const status of ['starting', 'running', 'stopping', 'closing']) assert.equal(browserExportActive({ id: 'browser_1', status }), true, status);
  for (const status of ['stopped', 'error', undefined]) {
    const profile = { id: 'browser_1', status, terminal: { status: 'running' }, applications: [{ status: 'running' }] };
    assert.equal(browserExportActive(profile, { 'openTerminal:browser_1': true, 'startApplication:app_1': true }), false, 'other consumers do not block an idle browser');
    assert.equal(browserExportActive(profile, { 'startProfile:browser_1': true }), true);
    assert.equal(browserExportActive(profile, { 'stopProfile:browser_1': true }), true);
    assert.equal(browserExportActive(profile, { 'startProfile:browser_2': true }), false, 'another browser does not block this one');
  }
});

test('export remains open for every dismissal until the save operation returns, including native cancellation', async () => {
  const modal = { type: 'exportData', scope: 'terminal', profile: { id: 'environment_1' } };
  const pending = new Set(); let dismissed = 0;
  const close = () => { if (!environmentTransferModalPending(modal, pending)) dismissed++; };
  let resolve;
  const nativeSave = new Promise(done => { resolve = done; });
  pending.add('exportEnvironment:environment_1');
  const operation = nativeSave.finally(() => pending.delete('exportEnvironment:environment_1'));
  // Each UI path reaches closeModal, whose ref already holds the reservation.
  for (const trigger of ['close icon', 'Escape', 'backdrop', 'cancel']) { close(trigger); assert.equal(dismissed, 0); }
  resolve({ canceled: true });
  assert.deepEqual(await operation, { canceled: true });
  close(); assert.equal(dismissed, 1, 'native dialog cancellation unlocks normal dismissal');
});

test('export success and failure both release dismissal without affecting another environment', async () => {
  const modal = { type: 'exportData', scope: 'browser', profile: { id: 'browser_1' } }, pending = new Set(['exportEnvironment:browser_2']);
  assert.equal(environmentTransferModalPending(modal, pending), false);
  for (const outcome of ['success', 'failure']) {
    pending.add('exportEnvironment:browser_1');
    assert.equal(environmentTransferModalPending(modal, pending), true);
    try { if (outcome === 'failure') throw new Error('write failed'); }
    catch { /* The UI retains its form and reports the error. */ }
    finally { pending.delete('exportEnvironment:browser_1'); }
    assert.equal(environmentTransferModalPending(modal, pending), false);
    assert.deepEqual([...pending], ['exportEnvironment:browser_2']);
  }
});

test('import password and mapping views retain their exact pending reservation until safe to cancel', () => {
  for (const type of ['importPassword', 'importMapping']) {
    const modal = { type, session: { importId: 'import_1' } }, pending = new Set(['importProfiles:import_1']);
    assert.equal(environmentTransferModalPending(modal, pending), true);
    assert.equal(environmentTransferModalPending(modal, { 'importProfiles:import_1': true }), true);
    pending.delete('importProfiles:import_1');
    assert.equal(environmentTransferModalPending(modal, pending), false);
    assert.equal(environmentTransferModalPending(modal, new Set(['importProfiles:import_2'])), false);
  }
  for (const modal of [null, { type: 'editProfile' }, { type: 'exportData' }, { type: 'importPassword' }]) assert.equal(environmentTransferModalPending(modal, new Set()), false);
});

test('decrypted manifest scope determines the displayed category and all categories are translated', () => {
  for (const [scope, label] of [['browser', '浏览器'], ['terminal', '终端'], ['application', '附加软件'], ['environment', '环境'], [undefined, '环境'], [null, '环境'], ['unknown', '导入数据']]) {
    assert.equal(importedDataLabel(scope), label);
    for (const [language, catalog] of Object.entries(translationCatalog)) assert.equal(typeof catalog[label], 'string', `${language}/${label}`);
  }
});

test('UI connects all dismissal paths to the reservation and three export entries retain distinct scopes', async () => {
  const source = await readFile(new URL('../src/App.jsx', import.meta.url), 'utf8');
  const close = source.slice(source.indexOf('const closeModal = useCallback('), source.indexOf('const perform = async'));
  assert.ok(close.indexOf('environmentTransferModalPending(modalRef.current, pendingRef.current)') < close.indexOf('setModal(null)'));
  const modal = source.slice(source.indexOf('function Modal('), source.indexOf('function Field('));
  assert.match(modal, /event\.key === "Escape"[\s\S]*?onClose\(\)/);
  assert.match(modal, /event\.target === event\.currentTarget\) onClose\(\)/);
  assert.match(modal, /label=\{t\("关闭"\)\} onClick=\{onClose\}/);
  assert.match(source, /disabled=\{!api\.isDesktop \|\| browserExportActive\(profile, pending\) \|\| busy\}/);
  assert.match(source, /scope: "browser", profile: selected/);
  assert.match(source, /scope: "terminal", profile: selected/);
  assert.match(source, /scope: "application", profile, application/);
  assert.match(source, /scope: modal\.scope, password/);
  assert.match(source, /modal\.scope === "terminal" \? \{ accountId \}/);
  assert.match(source, /modal\.scope === "application" \? \{ applicationId: modal\.application\.id \}/);
  assert.match(source, /importedDataLabel\(session\.scope\)/);
});
