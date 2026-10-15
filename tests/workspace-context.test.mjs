import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { applicationWorkspaceContext, installedProcessLocales, resolveProcessLanguage } from '../electron/workspace-context.mjs';

const execute = promisify(execFile);
const available = ['C', 'C.UTF-8', 'en_US.UTF-8', 'en_GB.UTF-8', 'en_PH.UTF-8', 'zh_CN.UTF-8', 'zh_HK.UTF-8', 'sr_RS.UTF-8', 'sr_RS.UTF-8@latin'];

test('process language uses installed UTF-8 locales and preserves region or script when available', () => {
  assert.deepEqual(resolveProcessLanguage('en-PH', available), { requested: 'en-PH', effective: 'en-PH', posix: 'en_PH.UTF-8', fallback: false });
  assert.deepEqual(resolveProcessLanguage('zh-Hant-HK', available), { requested: 'zh-Hant-HK', effective: 'zh-HK', posix: 'zh_HK.UTF-8', fallback: false });
  assert.deepEqual(resolveProcessLanguage('sr-Latn-RS', available), { requested: 'sr-Latn-RS', effective: 'sr-Latn-RS', posix: 'sr_RS.UTF-8@latin', fallback: false });
});

test('unsupported languages use stable explicit fallbacks, never an arbitrary installed host language', () => {
  assert.deepEqual(resolveProcessLanguage('ms-MY', available), { requested: 'ms-MY', effective: 'en-US', posix: 'en_US.UTF-8', fallback: true });
  assert.deepEqual(resolveProcessLanguage('en-MY', available), { requested: 'en-MY', effective: 'en-US', posix: 'en_US.UTF-8', fallback: true });
  for (const input of [null, undefined, '', '../../private', 'not_a_language_tag!', 'x'.repeat(100)]) {
    assert.deepEqual(resolveProcessLanguage(input, available), { requested: 'en-US', effective: 'en-US', posix: 'en_US.UTF-8', fallback: false });
  }
  assert.equal(resolveProcessLanguage('zz-ZZ', available).effective, 'en-US');
  assert.deepEqual(resolveProcessLanguage('ms-MY', ['zh_CN.UTF-8', 'C.UTF-8']), { requested: 'ms-MY', effective: 'C', posix: 'C.UTF-8', fallback: true });
  assert.deepEqual(resolveProcessLanguage('ms-MY', ['en_US', 'C']), { requested: 'ms-MY', effective: 'C', posix: 'C', fallback: true });
  assert.deepEqual(resolveProcessLanguage('ms-MY', []), { requested: 'ms-MY', effective: 'C', posix: 'C', fallback: true });
});

test('application context passes the shared locale without changing the requested browser language', async () => {
  const context = { id: 'profile_a', locale: 'ms-MY', timezone: 'Asia/Kuala_Lumpur', privacy: { mode: 'standard' } };
  const calls = [];
  const terminal = {
    snapshot: async () => ({ profiles: [{ profileId: 'profile_a', cwd: '/owned/project' }] }),
    directories: async () => ({ home: '/owned/home' }),
    languageFor: locale => resolveProcessLanguage(locale, available),
    childEnvironment: (...args) => { calls.push(args); const selected = resolveProcessLanguage(args[5], available); return { LANG: selected.posix, LC_ALL: selected.posix }; },
  };
  const result = await applicationWorkspaceContext('profile_a', { terminal, service: { resolveWorkspaceContext: async () => context } });
  assert.equal(calls[0][5], 'ms-MY'); assert.equal(calls[0][4], null);
  assert.equal(result.locale, 'ms-MY'); assert.equal(result.language.effective, 'en-US');
  assert.deepEqual(result.environment, { LANG: 'en_US.UTF-8', LC_ALL: 'en_US.UTF-8' });
  assert.deepEqual(context, { id: 'profile_a', locale: 'ms-MY', timezone: 'Asia/Kuala_Lumpur', privacy: { mode: 'standard' } });
});

test('macOS native locale and ICU are checked separately with owned non-networking children', { skip: process.platform !== 'darwin' }, async () => {
  const host = { LANG: process.env.LANG, LC_ALL: process.env.LC_ALL };
  const locales = await installedProcessLocales();
  assert.equal(await installedProcessLocales(), locales);
  for (const requested of ['en-PH', 'ms-MY']) {
    const selected = resolveProcessLanguage(requested, locales);
    assert(locales.includes(selected.posix));
    const env = { PATH: '/usr/bin:/bin', LANG: selected.posix, LC_ALL: selected.posix };
    const native = await execute('/usr/bin/locale', ['charmap'], { env, timeout: 3000 });
    const intl = await execute(process.execPath, ['-p', 'new Intl.DateTimeFormat().resolvedOptions().locale'], { env, timeout: 3000 });
    if (selected.effective !== 'C') {
      assert.equal(native.stdout.trim(), 'UTF-8');
      assert.equal(intl.stdout.trim(), selected.effective);
    }
  }
  const neutral = await execute(process.execPath, ['-p', 'new Intl.DateTimeFormat().resolvedOptions().locale'], { env: { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C' }, timeout: 3000 });
  assert.equal(neutral.stdout.trim(), 'en-US', 'ICU maps native neutral C to its own English default on this runtime');
  assert.deepEqual({ LANG: process.env.LANG, LC_ALL: process.env.LC_ALL }, host);
});
