import test from 'node:test';
import assert from 'node:assert/strict';
import { browseForgeRegionFor, preferredEngine } from '../shared/engine-choice.mjs';

const engines = [
  { id: 'browseforge-chromium', supported: true, installed: true },
  { id: 'camoufox', supported: true, installed: false, experimental: true },
  { id: 'cloakbrowser', supported: true, installed: true },
];

test('a new environment uses CloakBrowser unless another engine was chosen and is usable', () => {
  assert.equal(preferredEngine(engines, null), 'cloakbrowser', 'after a reset there is no saved choice');
  assert.equal(preferredEngine(engines, 'browseforge-chromium'), 'browseforge-chromium');
  assert.equal(preferredEngine(engines, 'camoufox'), 'cloakbrowser', 'a saved engine that is not installed is not used');
  assert.equal(preferredEngine([{ id: 'browseforge-chromium', supported: true, installed: true }], null), 'browseforge-chromium');
  assert.equal(preferredEngine([], null), 'cloakbrowser');
});

test('BrowseForge Chromium gets its region from the confirmed location when one of its presets fits', () => {
  const at = (countryCode, label, region) => ({ location: { confirmed: true, countryCode, label, ...(region ? { region } : {}) } });
  assert.equal(browseForgeRegionFor(at('US', 'Brooklyn, New York, United States')), 'us-ny');
  assert.equal(browseForgeRegionFor(at('US', 'Los Angeles, California, United States')), 'us-ca');
  assert.equal(browseForgeRegionFor(at('CA', 'Vancouver', 'British Columbia')), 'ca-bc');
  assert.equal(browseForgeRegionFor({ network: { ok: true, countryCode: 'US', region: 'Texas' } }), 'us-tx');
  // Outside every preset no label can make that engine work, so none is invented.
  assert.equal(browseForgeRegionFor(at('MY', 'Petaling, Selangor, Malaysia')), null);
  assert.equal(browseForgeRegionFor(at('US', 'Seattle, Washington, United States')), null);
  // An unconfirmed location is not used; a saved label always wins.
  assert.equal(browseForgeRegionFor({ location: { confirmed: false, countryCode: 'US', label: 'New York' } }), null);
  assert.equal(browseForgeRegionFor({ region: 'us-ny', location: { confirmed: true, countryCode: 'MY', label: 'Malaysia' } }), 'us-ny');
});
