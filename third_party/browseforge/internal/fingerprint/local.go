package fingerprint

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

var (
	primaryIPGeoURL = "https://undo.im/json"
	legacyIPGeoURL  = "http://ip-api.com/json/?fields=countryCode,timezone"
)

type GeoDetectionResult struct {
	Timezone string
	Locale   string
	Source   string
	Status   string
}

func (r GeoDetectionResult) Values() (timezone, locale string) {
	return r.Timezone, r.Locale
}

// AdjustToLocal adjusts fingerprint geo fields to match the actual public IP
func AdjustToLocal(fp map[string]any) {
	// Always check actual public IP first (handles VPN/WireGuard scenarios)
	if country, tz := detectPublicIPGeo(); country != "" {
		geo, ok := countryToGeo[country]
		if ok {
			fp["timezone"] = tz
			fp["locale:language"] = geo.Language[:2]
			fp["locale:region"] = country
			fp["navigator.language"] = geo.Language
			fp["navigator.languages"] = geo.Languages
			fp["headers.Accept-Language"] = buildAcceptLanguage(geo.Languages)
			return
		}
	}

	// Fallback: use local system timezone
	tz := detectLocalTimezone()
	country := timezoneToCountry(tz)
	if geo, ok := countryToGeo[country]; ok {
		fp["timezone"] = tz
		fp["locale:language"] = geo.Language[:2]
		fp["locale:region"] = country
		fp["navigator.language"] = geo.Language
		fp["navigator.languages"] = geo.Languages
		fp["headers.Accept-Language"] = buildAcceptLanguage(geo.Languages)
	} else {
		fp["timezone"] = tz
	}
}

// detectPublicIPGeo queries a free API to get the actual public IP's country and timezone
func detectPublicIPGeo() (country, timezone string) {
	client := &http.Client{Timeout: 5 * time.Second}
	return queryIPGeo(client)
}

// DetectProxyGeo returns timezone, locale, and provenance detected through the proxy.
func DetectProxyGeo(proxyType, host string, port int, username, password string) GeoDetectionResult {
	client := buildProxyClient(proxyType, host, port, username, password)
	country, tz := queryIPGeo(client)
	if country == "" {
		timezone, locale := configuredGeoFallback()
		return GeoDetectionResult{Timezone: timezone, Locale: locale, Source: "configured_fallback", Status: "geo_provider_unavailable"}
	}
	geo, ok := countryToGeo[country]
	if !ok {
		return GeoDetectionResult{Timezone: fallbackTimezone(tz), Locale: fallbackLocale(), Source: "provider_unknown_country", Status: "fallback_locale"}
	}
	return GeoDetectionResult{Timezone: fallbackTimezone(tz), Locale: geo.Language, Source: "provider", Status: "detected"}
}

// DetectProxyGeoResult returns timezone and locale detected through the proxy.
func DetectProxyGeoResult(proxyType, host string, port int, username, password string) (timezone, locale string) {
	return DetectProxyGeo(proxyType, host, port, username, password).Values()
}

// DetectLocalGeo returns timezone, locale, and provenance from the machine's public IP.
func DetectLocalGeo() GeoDetectionResult {
	client := &http.Client{Timeout: 5 * time.Second}
	country, tz := queryIPGeo(client)
	if country == "" {
		if configuredTZ, configuredLocale := configuredGeoFallback(); configuredTZ != "" {
			return GeoDetectionResult{Timezone: configuredTZ, Locale: configuredLocale, Source: "configured_fallback", Status: "geo_provider_unavailable"}
		}
		tz = detectLocalTimezone()
		country = timezoneToCountry(tz)
		geo, ok := countryToGeo[country]
		if !ok {
			return GeoDetectionResult{Timezone: fallbackTimezone(tz), Locale: fallbackLocale(), Source: "system_timezone", Status: "fallback_locale"}
		}
		return GeoDetectionResult{Timezone: fallbackTimezone(tz), Locale: geo.Language, Source: "system_timezone", Status: "geo_provider_unavailable"}
	}
	geo, ok := countryToGeo[country]
	if !ok {
		return GeoDetectionResult{Timezone: fallbackTimezone(tz), Locale: fallbackLocale(), Source: "provider_unknown_country", Status: "fallback_locale"}
	}
	return GeoDetectionResult{Timezone: fallbackTimezone(tz), Locale: geo.Language, Source: "provider", Status: "detected"}
}

// DetectLocalGeoResult returns timezone and locale from the machine's public IP.
func DetectLocalGeoResult() (timezone, locale string) {
	return DetectLocalGeo().Values()
}

func queryIPGeo(client *http.Client) (country, timezone string) {
	if country, timezone := queryUndoIPGeo(client, primaryIPGeoURL); country != "" && timezone != "" {
		return country, timezone
	}
	return queryLegacyIPGeo(client, legacyIPGeoURL)
}

func queryUndoIPGeo(client *http.Client, endpoint string) (country, timezone string) {
	resp, err := client.Get(endpoint)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", ""
	}

	var result struct {
		CF struct {
			Country  string `json:"country"`
			Timezone string `json:"timezone"`
		} `json:"cf"`
	}
	if json.NewDecoder(resp.Body).Decode(&result) != nil {
		return "", ""
	}
	return strings.TrimSpace(result.CF.Country), strings.TrimSpace(result.CF.Timezone)
}

func queryLegacyIPGeo(client *http.Client, endpoint string) (country, timezone string) {
	resp, err := client.Get(endpoint)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", ""
	}

	var result struct {
		CountryCode string `json:"countryCode"`
		Timezone    string `json:"timezone"`
	}
	if json.NewDecoder(resp.Body).Decode(&result) != nil {
		return "", ""
	}
	return strings.TrimSpace(result.CountryCode), strings.TrimSpace(result.Timezone)
}

func buildProxyClient(proxyType, host string, port int, username, password string) *http.Client {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	if proxyType == "socks5" {
		var auth *proxy.Auth
		if username != "" {
			auth = &proxy.Auth{User: username, Password: password}
		}
		dialer, err := proxy.SOCKS5("tcp", addr, auth, proxy.Direct)
		if err == nil {
			return &http.Client{
				Timeout: 10 * time.Second,
				Transport: &http.Transport{
					Dial: dialer.Dial,
				},
			}
		}
	}

	// HTTP/HTTPS proxy
	proxyURL := &url.URL{Scheme: proxyType, Host: addr}
	if username != "" {
		proxyURL.User = url.UserPassword(username, password)
	}
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}
}

func configuredGeoFallback() (timezone, locale string) {
	timezone = strings.TrimSpace(os.Getenv("BROWSEFORGE_DEFAULT_TIMEZONE"))
	if timezone == "" {
		timezone = strings.TrimSpace(os.Getenv("TZ"))
	}
	locale = strings.TrimSpace(os.Getenv("BROWSEFORGE_DEFAULT_LOCALE"))
	if locale == "" {
		country := timezoneToCountry(timezone)
		if geo, ok := countryToGeo[country]; ok {
			locale = geo.Language
		}
	}
	if locale == "" {
		locale = "en-US"
	}
	return timezone, locale
}

func fallbackTimezone(detected string) string {
	detected = strings.TrimSpace(detected)
	if detected != "" {
		return detected
	}
	timezone, _ := configuredGeoFallback()
	if timezone != "" {
		return timezone
	}
	return detectLocalTimezone()
}

func fallbackLocale() string {
	_, locale := configuredGeoFallback()
	return locale
}

func detectLocalTimezone() string {
	// Method 1: Go's time.Local
	zone, _ := time.Now().Zone()

	// Method 2: macOS/Linux system timezone (more accurate)
	if out, err := exec.Command("readlink", "/etc/localtime").Output(); err == nil {
		// /etc/localtime -> /var/db/timezone/zoneinfo/Asia/Taipei
		parts := strings.Split(strings.TrimSpace(string(out)), "/zoneinfo/")
		if len(parts) == 2 {
			return parts[1]
		}
	}

	// Method 3: macOS systemsetup
	if out, err := exec.Command("systemsetup", "-gettimezone").Output(); err == nil {
		// "Time Zone: Asia/Taipei"
		s := strings.TrimSpace(string(out))
		if idx := strings.Index(s, ": "); idx >= 0 {
			return s[idx+2:]
		}
	}

	// Fallback: map Go zone abbreviation
	return zoneAbbrevToTZ(zone)
}

var timezoneCountryMap = map[string]string{
	"Asia/Taipei":         "TW",
	"Asia/Tokyo":          "JP",
	"Asia/Seoul":          "KR",
	"Asia/Shanghai":       "CN",
	"Asia/Hong_Kong":      "HK",
	"Asia/Singapore":      "SG",
	"Asia/Bangkok":        "TH",
	"Asia/Ho_Chi_Minh":    "VN",
	"Asia/Jakarta":        "ID",
	"Asia/Manila":         "PH",
	"Asia/Kuala_Lumpur":   "MY",
	"Asia/Kolkata":        "IN",
	"Asia/Dubai":          "AE",
	"Asia/Jerusalem":      "IL",
	"Europe/London":       "GB",
	"Europe/Berlin":       "DE",
	"Europe/Paris":        "FR",
	"Europe/Rome":         "IT",
	"Europe/Madrid":       "ES",
	"Europe/Amsterdam":    "NL",
	"Europe/Stockholm":    "SE",
	"Europe/Warsaw":       "PL",
	"Europe/Istanbul":     "TR",
	"Europe/Kyiv":         "UA",
	"Europe/Moscow":       "RU",
	"America/New_York":    "US",
	"America/Chicago":     "US",
	"America/Denver":      "US",
	"America/Los_Angeles": "US",
	"America/Toronto":     "CA",
	"America/Sao_Paulo":   "BR",
	"America/Mexico_City": "MX",
	"Australia/Sydney":    "AU",
}

func timezoneToCountry(tz string) string {
	if c, ok := timezoneCountryMap[tz]; ok {
		return c
	}
	// Guess from timezone prefix
	if strings.HasPrefix(tz, "America/") {
		return "US"
	}
	if strings.HasPrefix(tz, "Europe/") {
		return "DE"
	}
	if strings.HasPrefix(tz, "Asia/") {
		return "JP"
	}
	return "US"
}

func zoneAbbrevToTZ(abbrev string) string {
	m := map[string]string{
		"CST":  "Asia/Taipei", // Could be US Central, but on a TW machine it's likely Taipei
		"JST":  "Asia/Tokyo",
		"KST":  "Asia/Seoul",
		"EST":  "America/New_York",
		"PST":  "America/Los_Angeles",
		"MST":  "America/Denver",
		"GMT":  "Europe/London",
		"CET":  "Europe/Berlin",
		"IST":  "Asia/Kolkata",
		"AEST": "Australia/Sydney",
	}
	if tz, ok := m[abbrev]; ok {
		return tz
	}
	return "America/New_York"
}
