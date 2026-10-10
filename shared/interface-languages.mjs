// One catalog for the renderer, desktop validation and packaged resources.
export const languageOptions = Object.freeze([
  { code: 'zh-CN', nativeName: '简体中文', englishName: 'Simplified Chinese' },
  { code: 'zh-TW', nativeName: '繁體中文', englishName: 'Traditional Chinese' },
  { code: 'en', nativeName: 'English', englishName: 'English' },
  { code: 'ja', nativeName: '日本語', englishName: 'Japanese' },
  { code: 'ko', nativeName: '한국어', englishName: 'Korean' },
  { code: 'es', nativeName: 'Español', englishName: 'Spanish' },
  { code: 'fr', nativeName: 'Français', englishName: 'French' },
  { code: 'de', nativeName: 'Deutsch', englishName: 'German' },
  { code: 'pt-BR', nativeName: 'Português (Brasil)', englishName: 'Brazilian Portuguese' },
].map(option => Object.freeze(option)));

export const languages = Object.freeze(languageOptions.map(option => option.code));
export const isInterfaceLanguage = value => typeof value === 'string' && languages.includes(value);
export const localeForInterfaceLanguage = language => language === 'en' ? 'en-US' : isInterfaceLanguage(language) ? language : 'en-US';

export function recommendInterfaceLanguage(preferences = []) {
  const values = typeof preferences === 'string' ? [preferences] : Array.isArray(preferences) ? preferences : [];
  for (const value of values) {
    if (typeof value !== 'string') continue;
    let locale;
    try { locale = new Intl.Locale(value.replaceAll('_', '-')); } catch { continue; }
    if (locale.language === 'zh') {
      return locale.script === 'Hant' || (!locale.script && ['TW', 'HK', 'MO'].includes(locale.region)) ? 'zh-TW' : 'zh-CN';
    }
    if (locale.language === 'pt') return 'pt-BR';
    if (isInterfaceLanguage(locale.language)) return locale.language;
  }
  return 'en';
}
