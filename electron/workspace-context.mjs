import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execute = promisify(execFile);
let processLocales;

/** Inspect the native locale catalogue once; never inherit the host language. */
export function installedProcessLocales() {
  if (!processLocales) processLocales = (process.platform === 'win32'
    ? Promise.resolve(['C'])
    : execute('/usr/bin/locale', ['-a'], { env: { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C' }, timeout: 3000, maxBuffer: 128 * 1024 })
      .then(({ stdout }) => stdout.split(/\r?\n/).map(value => value.trim()).filter(Boolean)).catch(() => ['C']));
  return processLocales;
}

function canonicalLanguage(value) {
  try {
    if (typeof value !== 'string' || value.length > 64 || !/^[A-Za-z0-9_-]+$/.test(value)) return 'en-US';
    return new Intl.Locale(value.replaceAll('_', '-')).baseName;
  } catch { return 'en-US'; }
}

/** Native UTF-8 language shared by owned children, with an explicit fallback.
 * ICU/Intl accepting a language does not mean libc has that POSIX locale.
 * C is neutral: Intl-based tools can independently report an English default.
 */
export function resolveProcessLanguage(locale, available = ['C']) {
  const requested = canonicalLanguage(locale);
  const target = new Intl.Locale(requested).maximize();
  const choices = [...new Set(available)].sort().flatMap(posix => {
    if (typeof posix !== 'string') return [];
    const match = /^([a-z]{2,3})(?:_([a-z0-9]{2,3}))?\.utf-?8(?:@(latin))?$/i.exec(posix);
    if (!match) return [];
    try {
      const effective = new Intl.Locale(`${match[1]}${match[3] ? '-Latn' : ''}${match[2] ? `-${match[2]}` : ''}`).baseName;
      return [{ posix, effective, locale: new Intl.Locale(effective).maximize() }];
    } catch { return []; }
  });
  const sameLanguage = choices.filter(choice => choice.locale.language === target.language);
  const exact = sameLanguage.find(choice => choice.locale.region === target.region && choice.locale.script === target.script);
  const defaultRegion = new Intl.Locale(target.language, target.script ? { script: target.script } : {}).maximize().region;
  const selected = exact
    ?? sameLanguage.find(choice => choice.locale.script === target.script && choice.locale.region === defaultRegion)
    ?? sameLanguage.find(choice => choice.locale.script === target.script)
    ?? sameLanguage[0]
    ?? choices.find(choice => choice.effective === 'en-US');
  if (selected) return { requested, effective: selected.effective, posix: selected.posix, fallback: !exact };
  const neutral = available.find(value => typeof value === 'string' && /^C\.utf-?8$/i.test(value)) ?? 'C';
  return { requested, effective: 'C', posix: neutral, fallback: true };
}

const regionLocales = Object.freeze({ CN: 'zh-CN', TW: 'zh-TW', HK: 'zh-HK', SG: 'en-SG', PH: 'en-PH', US: 'en-US', GB: 'en-GB', AU: 'en-AU', CA: 'en-CA', NZ: 'en-NZ', IE: 'en-IE', IN: 'en-IN', MY: 'ms-MY', ID: 'id-ID', TH: 'th-TH', VN: 'vi-VN', JP: 'ja-JP', KR: 'ko-KR', DE: 'de-DE', FR: 'fr-FR', ES: 'es-ES', IT: 'it-IT', NL: 'nl-NL', PT: 'pt-PT', BR: 'pt-BR', MX: 'es-MX', TR: 'tr-TR', RU: 'ru-RU', UA: 'uk-UA', PL: 'pl-PL', SE: 'sv-SE', NO: 'nb-NO', DK: 'da-DK', FI: 'fi-FI', CH: 'de-CH', AT: 'de-AT', AE: 'ar-AE', ZA: 'en-ZA' });

/** A locale preset for an observed country; it does not change interface language. */
export function localeForCountry(countryCode) {
  return regionLocales[String(countryCode ?? '').toUpperCase()] ?? 'en-US';
}

/** Private native launch context. Never send this object through renderer IPC. */
export async function applicationWorkspaceContext(profileId, { service, terminal }) {
  const context = await service.resolveWorkspaceContext(profileId, { force: true });
  const state = await terminal.snapshot({ id: profileId });
  const cwd = state.profiles?.find(item => item.profileId === profileId)?.cwd;
  if (!cwd || !path.isAbsolute(cwd)) throw Object.assign(new Error('请先为此境舱选择工作目录。'), { code: 'APPLICATION_DIRECTORY_REQUIRED' });
  const directories = await terminal.directories(profileId);
  const language = terminal.languageFor(context.locale);
  const environment = terminal.childEnvironment(directories, context.timezone, null, context.privacy, null, context.locale);
  // This scopes locale variables only. Arbitrary GUI applications may use
  // their own preferences or OS language APIs instead of these variables.
  return { ...context, profileId, cwd, environment, language };
}
