import { localeForInterfaceLanguage } from "../shared/interface-languages.mjs";

export const profileDimensions = profile => profile?.width && profile?.height ? `${profile.width} × ${profile.height}` : "内核默认";

export const protocolLabel = protocol => protocol === "anytls" ? "AnyTLS" : String(protocol || "代理").toUpperCase();

export const networkPlace = network => [...new Set([network?.country || network?.countryCode, network?.region, network?.city].filter(Boolean))].join(" · ");

export function bytes(value) {
  if (value == null || !Number.isFinite(Number(value))) return "—";
  if (Number(value) === 0) return "0 B";
  const i = Math.min(Math.floor(Math.log(Number(value)) / Math.log(1024)), 3);
  return `${(Number(value) / 1024 ** i).toFixed(i > 0 ? 1 : 0)} ${["B", "KB", "MB", "GB"][i]}`;
}

export function relativeTime(value, language, t) {
  if (!value) return t("尚未启动");
  const difference = Math.max(0, Date.now() - new Date(value).getTime());
  if (!Number.isFinite(difference)) return "—";
  if (difference < 60000) return t("刚刚");
  const locale = localeForInterfaceLanguage(language);
  const relative = new Intl.RelativeTimeFormat(locale, { numeric: "always" });
  if (difference < 3600000) return relative.format(-Math.floor(difference / 60000), "minute");
  if (difference < 86400000) return relative.format(-Math.floor(difference / 3600000), "hour");
  return new Date(value).toLocaleDateString(locale);
}
