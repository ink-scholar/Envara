export { languages, languageOptions } from '../shared/interface-languages.mjs';
import baseEnglish from './locales/en.json' with { type: 'json' };
import traditionalChinese from './locales/zh-TW.json' with { type: 'json' };
import japanese from './locales/ja.json' with { type: 'json' };
import korean from './locales/ko.json' with { type: 'json' };
import spanish from './locales/es.json' with { type: 'json' };
import french from './locales/fr.json' with { type: 'json' };
import german from './locales/de.json' with { type: 'json' };
import portuguese from './locales/pt-BR.json' with { type: 'json' };
import { networkFlowEnglish } from './network-flow-english.mjs';
import { networkFlowTranslations } from './network-flow-translations.mjs';
import { networkStatusEnglish, networkStatusTranslations } from './network-status-translations.mjs';
import { workspaceToolsEnglish, workspaceToolsTranslations } from './workspace-tools-translations.mjs';
import { supportDiagnosticsEnglish, supportDiagnosticsTranslations } from './support-diagnostics-translations.mjs';
import { componentVersionsEnglish, componentVersionsTranslations } from './component-versions-translations.mjs';
import { browserSiteDataEnglish, browserSiteDataTranslations } from './browser-site-data-translations.mjs';
import { terminalManagementEnglish, terminalManagementTranslations } from './terminal-management-translations.mjs';
import { terminalAttachmentTranslations } from './terminal-attachment-translations.mjs';
import { workCombinationEnglish, workCombinationTranslations } from './work-combinations-translations.mjs';
import { RUNTIME_VERIFICATION_TRANSLATIONS } from './runtime-verification-translations.mjs';
import { cacheMaintenanceEnglish, cacheMaintenanceTranslations } from './cache-maintenance-translations.mjs';
import { applicationUpdatesEnglish, applicationUpdatesTranslations } from './application-updates-translations.mjs';

const workspaceFeatureCatalogs = [
  { en: workspaceToolsEnglish, ...workspaceToolsTranslations },
  { en: supportDiagnosticsEnglish, ...supportDiagnosticsTranslations },
  { en: componentVersionsEnglish, ...componentVersionsTranslations },
  { en: browserSiteDataEnglish, ...browserSiteDataTranslations },
  { en: terminalManagementEnglish, ...terminalManagementTranslations },
  terminalAttachmentTranslations,
  { en: workCombinationEnglish, ...workCombinationTranslations },
  RUNTIME_VERIFICATION_TRANSLATIONS,
  { en: cacheMaintenanceEnglish, ...cacheMaintenanceTranslations },
  { en: applicationUpdatesEnglish, ...applicationUpdatesTranslations },
];
const workspaceFeatureLanguage = language => Object.assign({}, ...workspaceFeatureCatalogs.map(catalog => catalog[language]));

export const english = {
  ...baseEnglish,
  ...networkFlowEnglish,
  ...networkStatusEnglish,
  ...workspaceFeatureLanguage('en'),
};

const localizedCatalog = (language, base) => Object.freeze({
  ...base, ...networkFlowTranslations[language], ...networkStatusTranslations[language], ...workspaceFeatureLanguage(language),
});

export const translationCatalog = Object.freeze({
  'zh-CN': Object.freeze({
    ...Object.fromEntries(Object.keys(english).map(key => [key, key])),
    '下载独立安装（推荐）': '下载安装（推荐）',
    "Camoufox 自动管理设备指纹，无需设置内存。固定模板会固定外层窗口尺寸。": "固定模板也会固定窗口尺寸。",
    "浏览器语言与 Envara 界面语言独立；网站可能自行选择语言。": "与界面语言独立。",
    "不使用境舱浏览器；链接会交给系统默认浏览器，不经过境舱网络。": "使用系统浏览器，不经过环境网络。",
    "普通终端和附加软件的链接使用境舱浏览器；关闭后改用本机浏览器。Claude 会话的链接与浏览器工具仍使用绑定的境舱浏览器。": "关闭后，终端与软件的链接改用系统浏览器（环境外）。Claude 会话不受影响。",
    "附加软件自己打开的链接（例如登录）要 macOS 允许后才能交给境舱浏览器；终端里的链接不受影响。": "允许后，软件链接可在环境浏览器中打开。",
    "先验证代理，再确认位置与时区。": "验证代理 → 确认位置",
    "点击查询后，地址会经所选代理发送给 Photon 地点服务。结果用于模拟位置。": "经所选代理向 Photon 查询，用于模拟位置。",
    "使用已确认的网络环境；定位支持取决于软件。": "定位支持取决于软件。",
  }),
  'zh-TW': localizedCatalog('zh-TW', traditionalChinese),
  en: Object.freeze(english),
  ja: localizedCatalog('ja', japanese),
  ko: localizedCatalog('ko', korean),
  es: localizedCatalog('es', spanish),
  fr: localizedCatalog('fr', french),
  de: localizedCatalog('de', german),
  'pt-BR': localizedCatalog('pt-BR', portuguese),
});

export function translate(value, language = 'zh-CN', vars = {}) {
  if (typeof value !== 'string') return value;
  const dictionary = Object.hasOwn(translationCatalog, language) ? translationCatalog[language] : english;
  // The main process includes a specific failure after this fixed prefix.
  // Translate known details while preserving unknown diagnostics verbatim.
  const proxyCorePrefix = '代理网络内核启动失败：';
  if (!Object.hasOwn(english, value) && value.startsWith(proxyCorePrefix)) {
    const detail = value.slice(proxyCorePrefix.length);
    value = '代理网络内核启动失败：{message}';
    vars = { ...vars, message: Object.hasOwn(dictionary, detail) ? dictionary[detail] : Object.hasOwn(english, detail) ? english[detail] : detail };
  }
  let result = Object.hasOwn(dictionary, value) ? dictionary[value] : Object.hasOwn(english, value) ? english[value] : value;
  for (const [key, replacement] of Object.entries(vars ?? {})) result = result.replaceAll(`{${key}}`, String(replacement));
  return result;
}
