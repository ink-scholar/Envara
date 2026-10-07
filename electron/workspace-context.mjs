import path from 'node:path';

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
  const environment = terminal.childEnvironment(directories, context.timezone, null, context.privacy);
  return { ...context, profileId, cwd, environment };
}
