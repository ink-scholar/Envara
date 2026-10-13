import test from 'node:test';
import assert from 'node:assert/strict';
import { createApplicationIcons, electronApplicationIcon } from '../electron/application-icons.mjs';
import { LocalApplicationCatalog } from '../electron/local-application-catalog.mjs';

const png = 'data:image/png;base64,iVBORw0KGgo=';

test('only a bundle the catalog or a saved binding holds is rendered, once, and a failure is just no icon', async () => {
  const rendered = [], known = new Set(['/Applications/Notion.app', '/Applications/Broken.app']);
  const icon = createApplicationIcons({ isKnown: async target => known.has(target),
    render: async target => { rendered.push(target); if (target.includes('Broken')) throw new Error('unreadable'); return png; } });
  assert.deepEqual(await icon({ path: '/Users/someone/Secret.app' }), { icon: null });
  for (const path of ['relative/Notion.app', '/Applications/Notion.app\n', 42, undefined]) assert.deepEqual(await icon({ path }), { icon: null });
  assert.deepEqual(rendered, [], 'an unknown or malformed path is never rendered');
  assert.deepEqual(await icon({ path: '/Applications/Notion.app' }), { icon: png });
  assert.deepEqual(await icon({ path: '/Applications/Notion.app' }), { icon: png });
  assert.deepEqual(await icon({ path: '/Applications/Broken.app' }), { icon: null });
  assert.deepEqual(rendered, ['/Applications/Notion.app', '/Applications/Broken.app']);
});

test('icons render a few at a time and anything but a PNG data URL is dropped', async () => {
  let running = 0, peak = 0; const release = [];
  const icon = createApplicationIcons({ concurrency: 2, isKnown: async () => true,
    render: target => new Promise(resolve => { running++; peak = Math.max(peak, running);
      release.push(() => { running--; resolve(target.endsWith('Odd.app') ? 'javascript:alert(1)' : png); }); }) });
  const pending = ['/Applications/A.app', '/Applications/B.app', '/Applications/C.app', '/Applications/Odd.app'].map(path => icon({ path }));
  for (let released = 0; released < 4;) { await new Promise(resolve => setImmediate(resolve)); if (release.length) { release.shift()(); released++; } }
  const results = await Promise.all(pending);
  assert.equal(peak, 2);
  assert.deepEqual(results.map(result => result.icon), [png, png, png, null]);
});

test('the Electron renderer never asks macOS for the large file icon', async () => {
  const sizes = [], image = (empty, label) => ({ isEmpty: () => empty, resize: () => ({ toDataURL: () => `data:image/png;base64,${label}` }) });
  const render = electronApplicationIcon({ app: { getFileIcon: async (target, options) => { sizes.push(options.size); return image(false, 'file'); } },
    nativeImage: { createThumbnailFromPath: async () => { throw new Error('no thumbnail'); } } });
  assert.equal(await render('/Applications/Notion.app'), 'data:image/png;base64,file');
  assert.deepEqual(sizes, ['normal']);
  const thumbnail = electronApplicationIcon({ app: { getFileIcon: async () => { throw new Error('unused'); } },
    nativeImage: { createThumbnailFromPath: async () => image(false, 'thumb') } });
  assert.equal(await thumbnail('/Applications/Notion.app'), 'data:image/png;base64,thumb');
});

test('the catalog knows only bundles its last scan listed and never scans to answer', () => {
  const catalog = new LocalApplicationCatalog({ platform: 'darwin', roots: ['/Applications'] });
  assert.equal(catalog.knows('/Applications/Notion.app'), false);
  catalog.cached = { applications: [{ path: '/Applications/Notion.app' }], scanComplete: true, at: 0 };
  assert.equal(catalog.knows('/Applications/Notion.app'), true);
  assert.equal(catalog.knows('/Applications/Other.app'), false);
  assert.equal(catalog.knows('Applications/Notion.app'), false);
  assert.equal(catalog.pending, null);
});
