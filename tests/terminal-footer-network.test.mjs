import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('the terminal footer never shows the internal unknown network mode as a label', async () => {
  const source = await readFile(new URL('../src/TerminalPane.jsx', import.meta.url), 'utf8');
  assert.match(source, /shownNetwork\?\.mode && shownNetwork\.mode !== 'unknown' \? String\(shownNetwork\.mode\)\.toUpperCase\(\) : t\('启动后读取环境网络设置。'\)/);
});
