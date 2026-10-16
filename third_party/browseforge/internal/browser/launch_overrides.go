package browser

import (
	"fmt"
	"regexp"
	"strings"

	"browseforge/internal/config"
	"browseforge/internal/profile"
	bfruntime "browseforge/internal/runtime"
)

func requiresLaunchGeo(p *profile.Profile) bool {
	return p == nil || p.LaunchOverrides == nil || p.LaunchOverrides.Timezone == "" || p.LaunchOverrides.Locale == ""
}

func cloakBrowserNativeIdentityArgs(persona chromiumLaunchPersona) []string {
	// Cloak's native CLI accepts OS names (windows/macos/linux), while the
	// navigator surface and UA persona use Win32/MacIntel/Linux x86_64. Passing
	// the web-exposed platform here is silently ignored by macOS v145.
	return []string{
		"--fingerprint-timezone=" + persona.Native.Locale.Timezone,
		"--fingerprint-locale=" + persona.Native.Locale.Locale,
		"--fingerprint-platform=" + persona.Native.Platform.OS,
	}
}

func launchGeoOverrides(p *profile.Profile, timezone, locale string) (string, string, error) {
	if p == nil {
		return "", "", fmt.Errorf("profile is nil")
	}
	if err := profile.ValidateLaunchOverrides(p.LaunchOverrides); err != nil {
		return "", "", err
	}
	if p.LaunchOverrides != nil {
		if p.LaunchOverrides.Timezone != "" {
			timezone = p.LaunchOverrides.Timezone
		}
		if p.LaunchOverrides.Locale != "" {
			locale = p.LaunchOverrides.Locale
		}
	}
	return timezone, locale, nil
}

func launchTargetOS(p *profile.Profile) (string, error) {
	if p == nil {
		return "", fmt.Errorf("profile is nil")
	}
	if err := profile.ValidateLaunchOverrides(p.LaunchOverrides); err != nil {
		return "", err
	}
	if p.LaunchOverrides != nil && p.LaunchOverrides.TargetOS != "" {
		return p.LaunchOverrides.TargetOS, nil
	}
	if p.Identity != nil && p.Identity.TargetOS != "" {
		switch p.Identity.TargetOS {
		case "macos", "windows", "linux":
			return p.Identity.TargetOS, nil
		default:
			return "", fmt.Errorf("identity.target_os must be macos, windows, or linux")
		}
	}
	return "", nil
}

// Copy a runtime policy instead of mutating shared settings when several
// profiles with different platforms launch through the same provider.
func chromiumLaunchPolicyForProfile(p *profile.Profile, policy *config.CloakBrowserConfig) (*config.CloakBrowserConfig, error) {
	targetOS, err := launchTargetOS(p)
	if err != nil || targetOS == "" {
		return policy, err
	}
	copy := config.CloakBrowserConfig{}
	if policy != nil {
		copy = *policy
	}
	copy.FingerprintPlatform = targetOS
	return &copy, nil
}

var (
	firefoxVersionPattern = regexp.MustCompile(`Firefox/([0-9]+(?:\.[0-9]+)*)`)
	localeScriptPattern   = regexp.MustCompile(`^[A-Za-z]{4}$`)
	localeRegionPattern   = regexp.MustCompile(`^(?:[A-Za-z]{2}|[0-9]{3})$`)
)

// These settings are consumed by Camoufox's native configuration. They do not
// inject JavaScript getters. OS identity is kept coherent across UA/platform/
// oscpu; font and WebGL packs remain the selected provider's responsibility.
func applyCamoufoxLaunchOverrides(camouConfig map[string]any, p *profile.Profile, goarch string) error {
	targetOS, err := launchTargetOS(p)
	if err != nil {
		return err
	}
	if p.LaunchOverrides != nil {
		if timezone := p.LaunchOverrides.Timezone; timezone != "" {
			camouConfig["timezone"] = timezone
		}
		if locale := p.LaunchOverrides.Locale; locale != "" {
			parts := strings.Split(locale, "-")
			camouConfig["locale:language"] = parts[0]
			delete(camouConfig, "locale:region")
			delete(camouConfig, "locale:script")
			for _, part := range parts[1:] {
				if localeScriptPattern.MatchString(part) {
					camouConfig["locale:script"] = part
				} else if localeRegionPattern.MatchString(part) {
					camouConfig["locale:region"] = part
				}
			}
			camouConfig["locale:all"] = locale
			camouConfig["navigator.language"] = locale
			acceptLanguage := acceptLanguageForLocale(locale)
			camouConfig["navigator.languages"] = navigatorLanguagesFromAcceptLanguage(acceptLanguage)
			camouConfig["headers.Accept-Language"] = acceptLanguage
		}
	}
	if targetOS == "" {
		return nil
	}
	version := strings.Split(strings.TrimPrefix(bfruntime.CamoufoxVersion, "v"), ".")[0] + ".0"
	if ua, ok := camouConfig["navigator.userAgent"].(string); ok {
		if match := firefoxVersionPattern.FindStringSubmatch(ua); len(match) > 1 {
			version = match[1]
		}
	}
	var userAgentOS, navigatorPlatform, oscpu string
	switch targetOS {
	case "macos":
		userAgentOS, navigatorPlatform, oscpu = "Macintosh; Intel Mac OS X 10.15", "MacIntel", "Intel Mac OS X 10.15"
	case "windows":
		userAgentOS, navigatorPlatform, oscpu = "Windows NT 10.0; Win64; x64", "Win32", "Windows NT 10.0; Win64; x64"
	case "linux":
		navigatorPlatform = "Linux x86_64"
		if goarch == "arm64" {
			navigatorPlatform = "Linux aarch64"
		}
		userAgentOS, oscpu = "X11; "+navigatorPlatform, navigatorPlatform
	}
	camouConfig["navigator.platform"] = navigatorPlatform
	camouConfig["navigator.oscpu"] = oscpu
	camouConfig["navigator.userAgent"] = fmt.Sprintf("Mozilla/5.0 (%s; rv:%s) Gecko/20100101 Firefox/%s", userAgentOS, version, version)
	return nil
}
