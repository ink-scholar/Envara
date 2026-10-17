import test from 'node:test';
import assert from 'node:assert/strict';
import { machineLocalApplicationEntry } from '../electron/application-transfer-policy.mjs';

test('application transfer excludes only the scoped Home selector and Keychains tree, including macOS path aliases', () => {
  for (const relative of ['Home/Library/Preferences/com.apple.security.plist',
    'Home/Library/Preferences/com.apple.security.plist/forged-child',
    'Home/Library/Keychains', 'Home/Library/Keychains/local/keychain-db',
    'Home/library/preferences/COM.APPLE.SECURITY.PLIST', 'Home/Library/Keychains/local'])
    assert.equal(machineLocalApplicationEntry(relative), true, relative);
  for (const relative of ['', 'Home', 'Home/Library/Preferences/other.plist',
    'Home/Library/Preferences/com.apple.security.plist.backup', 'Home/Library/Keychains-offline/document',
    'Home/Library/Application Support/offline', 'UserData/Library/Preferences/com.apple.security.plist',
    'Extensions/Home/Library/Keychains', 'Home/elsewhere/com.apple.security.plist'])
    assert.equal(machineLocalApplicationEntry(relative), false, relative);
});
